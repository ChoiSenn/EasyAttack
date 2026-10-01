"""패턴 파일 로더"""
import os

PATTERN_DIR = os.path.join(os.path.dirname(__file__), '..', 'patterns')


def list_categories():
    """patterns/ 의 카테고리(파일명) 목록 반환"""
    if not os.path.isdir(PATTERN_DIR):
        return []
    return sorted(f[:-4] for f in os.listdir(PATTERN_DIR) if f.endswith('.txt'))


def load_patterns(category):
    """카테고리의 페이로드 목록 반환 (주석/빈 줄 제외)"""
    path = os.path.join(PATTERN_DIR, f'{category}.txt')
    with open(path, encoding='utf-8') as f:
        return [ln.strip() for ln in f
                if ln.strip() and not ln.lstrip().startswith('#')]
