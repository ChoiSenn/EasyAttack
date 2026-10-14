"""전체 점검 오케스트레이터: 모든 정책 실행 후 리포트용 결과 생성"""
from datetime import datetime
from urllib.parse import urlsplit

from utils.attacks import pattern, blind
from utils.attacks._common import summarize

_CONF_ORDER = {'높음': 3, '중간': 2, '낮음': 1}


def _findings(name, results):
    """취약 근거를 사람이 읽는 설명으로 변환"""
    evs = [r['evidence'] for r in results if r['verdict'] == 'VULNERABLE']
    out = []
    if name == 'SQL Injection':
        if any('DB 오류' in e for e in evs):
            out.append('에러 기반 SQL Injection 취약 — DB 오류 메시지 노출, 입력값 검증·에러 처리 미흡')
        if any('지연' in e for e in evs):
            out.append('시간 기반 블라인드 SQL Injection 취약 — 조작된 지연이 응답에 반영됨')
    elif name == 'XSS':
        if evs:
            out.append('반사형 XSS 취약 — 입력값이 이스케이프 없이 응답에 출력됨')
    elif name == 'Blind SQL Injection':
        if evs:
            out.append('부울 기반 블라인드 SQL Injection 취약 — 참/거짓 조건에 따라 응답 분기')
    elif name == 'Path Traversal':
        if evs:
            out.append('경로 순회/LFI 취약 — 시스템 파일 내용이 응답에 노출됨')
    elif name == 'Command Injection':
        if evs:
            out.append('OS 명령 주입 취약 — 주입한 명령 실행 결과가 응답에 노출됨')
    elif name == 'SSTI':
        if evs:
            out.append('서버 템플릿 인젝션(SSTI) 취약 — 템플릿 수식이 서버에서 평가됨')
    return out


def _policy(name, results):
    """단일 정책 결과를 리포트용 dict로 요약"""
    overall, counts = summarize(results)
    confs = [r['confidence'] for r in results if r['verdict'] == 'VULNERABLE']
    confidence = max(confs, key=lambda c: _CONF_ORDER.get(c, 0)) if confs else '-'
    return {
        'name': name,
        'verdict': overall,
        'confidence': confidence,
        'findings': _findings(name, results),
        'counts': counts,
        'total': len(results),
    }


def run_full_scan(url, param='q', timeout=10, verify=True):
    """URL 하나로 모든 정책을 점검하고 리포트용 결과 반환"""
    parts = urlsplit(url if '://' in url else f'http://{url}')
    scheme = parts.scheme or 'http'
    target = parts.netloc
    path = parts.path or '/'

    # (패턴 카테고리, 보고서 정책명)
    pattern_policies = [
        ('sqli', 'SQL Injection'),
        ('xss', 'XSS'),
        ('traversal', 'Path Traversal'),
        ('cmdi', 'Command Injection'),
        ('ssti', 'SSTI'),
    ]
    policies = []
    for category, name in pattern_policies:
        _, r = pattern.run(target, category, param=param, path=path,
                           scheme=scheme, timeout=timeout, verify=verify)
        policies.append(_policy(name, r))
    _, r = blind.run_boolean(target, param=param, path=path,
                             scheme=scheme, timeout=timeout, verify=verify)
    policies.append(_policy('Blind SQL Injection', r))

    if any(p['verdict'] == '취약' for p in policies):
        overall = '취약'
    elif all(p['verdict'] == '안전' for p in policies):
        overall = '안전'
    else:
        overall = '판단불가'
    return {
        'url': f'{scheme}://{target}{path}',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'overall': overall,
        'policies': policies,
    }
