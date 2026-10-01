"""응답 기반 취약점 판정 (웹서버 앱 취약 여부)"""
import re
import html

# DB 오류 시그니처 (에러 기반 SQLi 판단용)
_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PLS-\d{5}|"
    r"Unclosed quotation mark|Microsoft OLE DB|ODBC .*Driver|"
    r"PostgreSQL.*ERROR|syntax error at or near|"
    r"quoted string not properly terminated|SQLite3?::|"
    r"Warning.*mysqli?|Incorrect syntax near)",
    re.IGNORECASE)

TIME_THRESHOLD = 4.5  # 시간 기반: 이 이상 지연되면 취약 정황 (패턴 SLEEP 5초 기준)


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
    return 'INCONCLUSIVE', '', '낮음'


def judge_xss(result, payload, baseline):
    """XSS 응답 판정 -> (verdict, evidence, confidence)"""
    if not result['ok']:
        return 'INCONCLUSIVE', result['error'], '낮음'
    body = result['body']
    # 페이로드가 원형 그대로 반사되면 취약
    if payload in body:
        return 'VULNERABLE', '페이로드 원형 반사됨', '높음'
    # 인코딩되어 반사되면 안전(치환)
    if html.escape(payload, quote=False) in body:
        return 'SAFE', '페이로드가 인코딩되어 반사됨', '높음'
    return 'INCONCLUSIVE', '반사되지 않음', '낮음'


_JUDGES = {'sqli': judge_sqli, 'xss': judge_xss}


def judge(category, result, payload, baseline):
    """카테고리에 맞는 판정 적용 -> (verdict, evidence, confidence)"""
    fn = _JUDGES.get(category)
    if fn is None:
        return 'INCONCLUSIVE', '판정 미지원 카테고리', '낮음'
    return fn(result, payload, baseline)
