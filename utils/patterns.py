"""패턴 파일 로더 (포맷 v2: 주입 위치 지정 지원)"""
import os

PATTERN_DIR = os.path.join(os.path.dirname(__file__), '..', 'patterns')

_VALID_LOCATIONS = {'url', 'header', 'cookie', 'body'}
_DEFAULT_NAME = {'url': 'q', 'header': 'User-Agent', 'cookie': 'test', 'body': 'data'}


def list_categories():
    """patterns/ 의 카테고리(파일명) 목록 반환"""
    if not os.path.isdir(PATTERN_DIR):
        return []
    return sorted(f[:-4] for f in os.listdir(PATTERN_DIR) if f.endswith('.txt'))


def _is_comment(line):
    """주석 줄 여부 ('# ' 또는 단독 '#'; '#{...}' 같은 페이로드는 제외)"""
    s = line.lstrip()
    return s == '#' or s.startswith('# ')


def _parse_line(line):
    """한 줄을 엔트리로 파싱. '[location:name] payload'/'[location] payload'/평문 지원

    평문(대괄호 없음)은 explicit=False로 표시해, 호출부가 자신의 기본
    위치/파라미터명으로 덮어쓸 수 있게 한다(기존 동작 호환용).
    """
    if line.startswith('['):
        close = line.find(']')
        if close != -1:
            inside = line[1:close]
            loc, _, name = inside.partition(':')
            loc = loc.strip().lower()
            if loc in _VALID_LOCATIONS:
                rest = line[close + 1:]
                payload = rest[1:] if rest.startswith(' ') else rest.lstrip()
                name = name.strip() or _DEFAULT_NAME[loc]
                return {'location': loc, 'name': name, 'payload': payload, 'explicit': True}
    # 평문 줄(또는 알 수 없는 location) = 기본 url:q, 비명시 처리 (기존과 동일하게 strip)
    return {'location': 'url', 'name': 'q', 'payload': line.strip(), 'explicit': False}


def load_entries(category):
    """카테고리의 엔트리 목록 반환. 각 엔트리: {'location','name','payload', 'explicit'}"""
    path = os.path.join(PATTERN_DIR, f'{category}.txt')
    with open(path, encoding='utf-8') as f:
        lines = [ln.rstrip('\n') for ln in f if ln.strip() and not _is_comment(ln)]
    return [_parse_line(ln) for ln in lines]


def load_single(category):
    """카테고리의 대표(첫 번째) 엔트리 반환. 없으면 None"""
    entries = load_entries(category)
    return entries[0] if entries else None


def load_patterns(category):
    """카테고리의 페이로드 문자열 목록 반환 (하위호환; 주석/빈 줄 제외)"""
    return [e['payload'] for e in load_entries(category)]
