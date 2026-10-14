"""패턴 기반 공격 실행기 (SQLi, XSS 등)"""
from utils.patterns import load_entries, load_single
from utils.verdict import judge, TIME_THRESHOLD
from utils.attacks._common import inject, summarize


def _confirm_timing(target, param, payload, path, method, timeout, scheme, verify, r, location='query'):
    """시간 기반 후보를 재전송해 네트워크 지연과 구분 (보정)"""
    again = inject(target, param, payload, path, method, timeout, scheme, verify, location)
    if again['ok'] and again['elapsed'] >= TIME_THRESHOLD:
        r['confidence'] = '높음'
        r['evidence'] += ' (재확인됨)'
    else:
        r['verdict'], r['confidence'] = 'INCONCLUSIVE', '낮음'
        r['evidence'] = '지연 재현 안 됨 (네트워크 추정)'


def run(target, category, param='q', path='/', method='GET', timeout=10, scheme='http',
       verify=True, location='query'):
    """정상 요청(기준선) 후 모든 패턴을 주입 전송하고 판정. (baseline, results) 반환

    포맷 v2(위치 지정) 엔트리는 자신의 location/name으로, 평문(위치 미지정)
    엔트리는 이 함수의 location/param 인자로 주입한다(기존 동작 호환).
    """
    baseline = inject(target, param, 'test', path, method, timeout, scheme, verify, location)

    results = []
    for entry in load_entries(category):
        payload = entry['payload']
        loc, name = (entry['location'], entry['name']) if entry['explicit'] else (location, param)
        r = inject(target, name, payload, path, method, timeout, scheme, verify, loc)
        r['payload'] = payload
        r['verdict'], r['evidence'], r['confidence'] = judge(category, r, payload, baseline)
        # 시간 기반 취약 후보는 재확인으로 보정
        if r['verdict'] == 'VULNERABLE' and r['evidence'].startswith('응답 지연'):
            _confirm_timing(target, name, payload, path, method, timeout, scheme, verify, r, loc)
        results.append(r)
    return baseline, results


def run_single(target, category, timeout=10, scheme='http', verify=True):
    """대표(첫) 패턴 1개만 해당 위치로 전송. 판정 없이 응답 결과만 반환"""
    entry = load_single(category)
    if entry is None:
        return None
    return inject(target, entry['name'], entry['payload'], path='/', method='GET',
                 timeout=timeout, scheme=scheme, verify=verify, location=entry['location'])


def format_results(baseline, results):
    """패턴 공격 결과를 요약 텍스트로 변환"""
    base = f'기준선: HTTP {baseline["status"]} ({baseline["elapsed"]:.1f}s)' \
        if baseline['ok'] else f'기준선 실패: {baseline["error"]}'
    lines = [base]

    for r in results:
        status = r['status'] if r['ok'] else 'ERR'
        ev = f'  ({r["evidence"]})' if r['evidence'] else ''
        lines.append(f'[{r["verdict"]}/{r["confidence"]}] {status} {r["payload"]}{ev}')

    overall, c = summarize(results)
    lines.append(f'== 종합: {overall} '
                 f'(취약 {c["VULNERABLE"]} / 안전 {c["SAFE"]} / '
                 f'판단불가 {c["INCONCLUSIVE"]}, 총 {len(results)}) ==')
    return '\n'.join(lines)
