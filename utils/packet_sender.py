"""HTTP 통신 전송 유틸리티"""
import ssl
import time
import urllib.parse
import urllib.request
import urllib.error


def _normalize_url(target, path='/', scheme='http'):
    """target을 완전한 URL로 정규화 (스킴 없으면 scheme 부여)"""
    if target.startswith(('http://', 'https://')):
        return target
    return f'{scheme}://{target}{path}'


def _encode_body(data, headers):
    """POST 바디 인코딩 (dict면 폼 인코딩, str/bytes는 그대로)"""
    if data is None:
        return None
    if isinstance(data, dict):
        headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        return urllib.parse.urlencode(data).encode()
    return data.encode() if isinstance(data, str) else data


def send_http(target, method='GET', path='/', data=None, headers=None,
              timeout=10, scheme='http', verify=True):
    """HTTP 요청 전송 후 응답을 dict로 반환

    반환: {ok, status, reason, headers, body, url, elapsed, error}
    차단 응답(4xx/5xx)도 예외가 아닌 정상 결과로 반환한다.
    verify=False면 https 인증서 검증을 생략한다(만료/자체서명 대상용).
    """
    url = _normalize_url(target, path, scheme)
    headers = dict(headers or {})
    body_bytes = _encode_body(data, headers)
    req = urllib.request.Request(url, data=body_bytes, method=method, headers=headers)
    context = None if verify else ssl._create_unverified_context()
    start = time.perf_counter()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            return {
                'ok': True,
                'status': resp.status,
                'reason': resp.reason,
                'headers': dict(resp.getheaders()),
                'body': body,
                'url': resp.geturl(),
                'elapsed': time.perf_counter() - start,
                'error': None,
            }
    except urllib.error.HTTPError as e:
        # WAF 차단 등 4xx/5xx: 응답 자체를 결과로 취급
        body = e.read().decode('utf-8', errors='replace')
        return {
            'ok': True,
            'status': e.code,
            'reason': e.reason,
            'headers': dict(e.headers),
            'body': body,
            'url': e.url,
            'elapsed': time.perf_counter() - start,
            'error': None,
        }
    except urllib.error.URLError as e:
        return {'ok': False, 'status': None, 'reason': None, 'headers': {},
                'body': '', 'url': url, 'elapsed': time.perf_counter() - start,
                'error': str(e.reason)}
    except Exception as e:
        return {'ok': False, 'status': None, 'reason': None, 'headers': {},
                'body': '', 'url': url, 'elapsed': time.perf_counter() - start,
                'error': str(e)}


def send_http_get(target, path='/', headers=None, timeout=10, scheme='http', verify=True):
    """HTTP GET 전송"""
    return send_http(target, 'GET', path=path, headers=headers,
                     timeout=timeout, scheme=scheme, verify=verify)


def send_http_post(target, path='/', data=None, headers=None, timeout=10, scheme='http', verify=True):
    """HTTP POST 전송 (data: dict면 폼 전송)"""
    return send_http(target, 'POST', path=path, data=data, headers=headers,
                     timeout=timeout, scheme=scheme, verify=verify)


def format_summary(result):
    """응답 성공 여부를 한 줄로 요약 (예: HTTP 200 OK <- http://example.com/)"""
    if not result['ok']:
        return f'전송 실패: {result["error"]}'
    return f'HTTP {result["status"]} {result["reason"]} <- {result["url"]}'


def format_response(result, body_limit=2000):
    """send_http_get 결과를 사람이 읽을 텍스트로 변환"""
    if not result['ok']:
        return f'오류: {result["error"]}'

    lines = [f'HTTP {result["status"]} {result["reason"]}', '']
    for k, v in result['headers'].items():
        lines.append(f'{k}: {v}')
    lines.append('')

    body = result['body']
    if len(body) > body_limit:
        body = body[:body_limit] + f'\n... (생략, 전체 {len(result["body"])}바이트)'
    lines.append(body)
    return '\n'.join(lines)
