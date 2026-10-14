"""응답 기반 취약점 판정 (웹서버 앱 취약 여부)"""
import re
import html
import difflib

# DB 오류 시그니처 (에러 기반 SQLi 판단용)
_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PLS-\d{5}|"
    r"Unclosed quotation mark|Microsoft OLE DB|ODBC .*Driver|"
    r"PostgreSQL.*ERROR|syntax error at or near|"
    r"quoted string not properly terminated|SQLite3?::|"
    r"Warning.*mysqli?|Incorrect syntax near)",
    re.IGNORECASE)

TIME_THRESHOLD = 4.5  # 시간 기반: 이 이상 지연되면 취약 정황 (패턴 SLEEP 5초 기준)

# 시스템 파일 노출 시그니처 (경로 순회/LFI)
_LFI_RE = re.compile(
    r"(root:.*?:0:0:|\[extensions\]|\[fonts\]|for 16-bit app support)",
    re.IGNORECASE)

# 명령 실행 결과 시그니처 (명령 주입)
_CMDI_RE = re.compile(
    r"(uid=\d+\([^)]*\)\s*gid=\d+|Volume Serial Number|Windows IP Configuration)",
    re.IGNORECASE)

# SSTI 수식 평가 결과 마커 (1234*5678)
_SSTI_MARK = '7006652'
_SSTI_EXPR = '1234*5678'

_BODY_SIM_THRESHOLD = 0.98  # 이 이상이면 baseline과 본문이 사실상 동일


def _header_get(headers, name):
    """대소문자 무시하고 헤더 값 조회"""
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def _baseline_equivalent(result, baseline):
    """공격 응답이 baseline과 사실상 동등한지 (상태코드 동일 & 본문 유사도 높음)"""
    if not (baseline and baseline['ok'] and result['ok']):
        return False
    if result['status'] != baseline['status']:
        return False
    if result['body'] == baseline['body']:
        return True
    ratio = difflib.SequenceMatcher(None, result['body'], baseline['body']).ratio()
    return ratio >= _BODY_SIM_THRESHOLD


def _looks_blocked(result):
    """명시적 차단/오류로 보이는 응답인지 (4xx 또는 not found류 문구)"""
    if not result['ok']:
        return False
    if result['status'] and 400 <= result['status'] < 500:
        return True
    return bool(re.search(r'not found|forbidden|blocked', result['body'], re.IGNORECASE))


def _reflected(result, payload, baseline=None):
    """distinctive한 payload가 본문에 raw/escape 형태로 반사됐는지 (baseline에 이미 있으면 제외)"""
    if not payload or len(payload.strip()) < 4 or not any(c.isalnum() for c in payload):
        return False
    base = baseline['body'] if baseline and baseline.get('ok') else ''
    for form in (payload, html.escape(payload)):
        if form in result['body'] and form not in base:
            return True
    return False


def judge_sqli(result, payload, baseline):
    """SQLi 응답 판정 -> (verdict, evidence, confidence)"""
    if not result['ok']:
        return 'INCONCLUSIVE', result['error'], '낮음'
    base_body = baseline['body'] if baseline and baseline['ok'] else ''
    # 에러 기반: 공격 응답엔 DB 오류가 있고 정상 응답엔 없음 (신뢰도 높음)
    m = _SQL_ERROR_RE.search(result['body'])
    if m and not _SQL_ERROR_RE.search(base_body):
        return 'VULNERABLE', f'DB 오류 노출: {m.group(0)}', '높음'
    # 시간 기반: 정상은 빠른데 공격만 지연 (재확인 전이므로 중간)
    base_t = baseline['elapsed'] if baseline and baseline['ok'] else 0
    if result['elapsed'] >= TIME_THRESHOLD and base_t < TIME_THRESHOLD:
        return 'VULNERABLE', f'응답 지연 {result["elapsed"]:.1f}s (시간 기반)', '중간'
    # DB오류·지연 없음 & baseline과 동등 -> 블라인드 여지는 남으므로 중간 신뢰도 SAFE
    if _baseline_equivalent(result, baseline):
        return 'SAFE', 'DB 오류·지연 없음, 응답이 기준선과 동등', '중간'
    # 입력이 데이터로 에코될 뿐 오류·지연 없음 (블라인드 여지로 중간)
    if _reflected(result, payload, baseline):
        return 'SAFE', 'DB 오류·지연 없음, 입력이 데이터로 반사됨', '중간'
    return 'INCONCLUSIVE', '', '낮음'


def judge_xss(result, payload, baseline):
    """XSS 응답 판정 -> (verdict, evidence, confidence)"""
    if not result['ok']:
        return 'INCONCLUSIVE', result['error'], '낮음'
    body = result['body']
    ctype = _header_get(result['headers'], 'Content-Type') or ''
    is_html = 'text/html' in ctype.lower() or 'application/xhtml' in ctype.lower()
    nosniff = (_header_get(result['headers'], 'X-Content-Type-Options') or '').lower() == 'nosniff'
    # 페이로드가 원형 그대로 반사됨
    if payload in body:
        if is_html:
            return 'VULNERABLE', '페이로드 원형 반사됨 (HTML 문맥, 실행 가능)', '높음'
        if ctype and nosniff:
            return 'SAFE', f'원형 반사되나 비실행 문맥({ctype}) + nosniff', '중간'
        return 'VULNERABLE', '페이로드 원형 반사됨 (문맥 불명확)', '중간'
    # 인코딩되어 반사되면 안전(치환)
    if html.escape(payload, quote=False) in body:
        return 'SAFE', '페이로드가 인코딩되어 반사됨', '높음'
    return 'INCONCLUSIVE', '반사되지 않음', '낮음'


def judge_traversal(result, payload, baseline):
    """경로 순회/LFI 응답 판정 -> (verdict, evidence, confidence)"""
    if not result['ok']:
        return 'INCONCLUSIVE', result['error'], '낮음'
    base_body = baseline['body'] if baseline and baseline['ok'] else ''
    m = _LFI_RE.search(result['body'])
    # baseline에는 없고 공격 응답에만 시그니처가 있을 때만 취약 (오탐 방지)
    if m and not _LFI_RE.search(base_body):
        return 'VULNERABLE', f'시스템 파일 노출: {m.group(0)[:40]}', '높음'
    if not m and (_baseline_equivalent(result, baseline) or _looks_blocked(result)):
        return 'SAFE', '파일 노출 없음, 기준선과 동등하거나 차단됨', '중간'
    if not m and _reflected(result, payload, baseline):
        return 'SAFE', '파일 노출 없음, 입력이 데이터로 반사됨', '중간'
    return 'INCONCLUSIVE', '파일 내용 미노출', '낮음'


def judge_cmdi(result, payload, baseline):
    """명령 주입 응답 판정 -> (verdict, evidence, confidence)"""
    if not result['ok']:
        return 'INCONCLUSIVE', result['error'], '낮음'
    base_body = baseline['body'] if baseline and baseline['ok'] else ''
    m = _CMDI_RE.search(result['body'])
    if m and not _CMDI_RE.search(base_body):
        return 'VULNERABLE', f'명령 실행 결과 노출: {m.group(0)[:40]}', '높음'
    if not m and (_baseline_equivalent(result, baseline) or _looks_blocked(result)):
        return 'SAFE', '명령 실행 결과 없음, 기준선과 동등하거나 차단됨', '중간'
    if not m and _reflected(result, payload, baseline):
        return 'SAFE', '명령 실행 결과 없음, 입력이 데이터로 반사됨', '중간'
    return 'INCONCLUSIVE', '명령 결과 미노출', '낮음'


def judge_ssti(result, payload, baseline):
    """SSTI 응답 판정 -> (verdict, evidence, confidence)"""
    if not result['ok']:
        return 'INCONCLUSIVE', result['error'], '낮음'
    base_body = baseline['body'] if baseline and baseline['ok'] else ''
    body = result['body']
    # 템플릿 수식이 서버에서 평가되어 결과값이 반환됨
    if _SSTI_MARK in body and _SSTI_MARK not in base_body:
        return 'VULNERABLE', '템플릿 수식이 서버에서 평가됨 (SSTI)', '높음'
    # 수식이 원형 그대로(미평가) 반사됨 -> 템플릿 엔진 미평가, 안전 가능성 높음
    if _SSTI_EXPR in body and _SSTI_MARK not in body:
        return 'SAFE', '수식이 원형 반사됨 (평가되지 않음)', '높음'
    # 반사도 평가도 없음
    return 'SAFE', '수식 반사·평가 모두 없음', '중간'


_JUDGES = {
    'sqli': judge_sqli,
    'xss': judge_xss,
    'traversal': judge_traversal,
    'cmdi': judge_cmdi,
    'ssti': judge_ssti,
}


def judge(category, result, payload, baseline):
    """카테고리에 맞는 판정 적용 -> (verdict, evidence, confidence)"""
    fn = _JUDGES.get(category)
    if fn is None:
        return 'INCONCLUSIVE', '판정 미지원 카테고리', '낮음'
    return fn(result, payload, baseline)
