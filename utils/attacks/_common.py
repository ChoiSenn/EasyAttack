"""공격 실행기 공용 헬퍼"""
from urllib.parse import quote

from utils.packet_sender import send_http


def _sanitize_header_value(value):
    """헤더/쿠키 값에서 전송을 깨뜨리는 개행(CR/LF) 제거 (헤더 스플리팅 방지)"""
    return value.replace('\r', '').replace('\n', '')


def inject(target, param, value, path='/', method='GET', timeout=10, scheme='http',
          verify=True, location='query'):
    """value를 param에 주입해 전송. location: query/url(기본, 별칭)/header/cookie/body"""
    if location == 'header':
        headers = {param: _sanitize_header_value(value)}
        return send_http(target, method, path=path, headers=headers,
                         timeout=timeout, scheme=scheme, verify=verify)
    if location == 'cookie':
        headers = {'Cookie': f'{param}={_sanitize_header_value(value)}'}
        return send_http(target, method, path=path, headers=headers,
                         timeout=timeout, scheme=scheme, verify=verify)
    if location == 'body':
        return send_http(target, 'POST', path=path, data={param: value},
                         timeout=timeout, scheme=scheme, verify=verify)
    if method.upper() == 'POST':
        return send_http(target, 'POST', path=path, data={param: value},
                         timeout=timeout, scheme=scheme, verify=verify)
    sep = '&' if '?' in path else '?'
    return send_http(target, 'GET', path=f'{path}{sep}{param}={quote(value)}',
                     timeout=timeout, scheme=scheme, verify=verify)


def summarize(results):
    """판정 결과 종합 -> (overall, counts)"""
    counts = {'VULNERABLE': 0, 'SAFE': 0, 'INCONCLUSIVE': 0}
    for r in results:
        counts[r['verdict']] = counts.get(r['verdict'], 0) + 1
    if counts['VULNERABLE'] > 0:
        overall = '취약'
    elif counts['SAFE'] > 0:
        overall = '안전'
    else:
        overall = '판단불가'
    return overall, counts
