"""known-vuln / known-safe 픽스처 기반 회귀 테스트 (6종 판정 파이프라인).

판정 로직 개선 ①~④ 반영본. 로컬 목 서버로만 통신(외부 전송 없음).
공격 실행기(pattern/blind) -> verdict.judge -> summarize 까지 실제 파이프라인을 탄다.
judge_* 문맥/SAFE 분기는 크래프팅한 result dict 로 단위 검증한다.
"""
import html
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mock_server import start_mock_server            # noqa: E402
from utils.attacks import pattern, blind             # noqa: E402
from utils.attacks._common import summarize          # noqa: E402
from utils import verdict                            # noqa: E402

_PATTERN_CATS = ['sqli', 'xss', 'traversal', 'cmdi', 'ssti']
_NORMAL_BODY = '<html><body><p>Search service ready.</p></body></html>'
_XSS = '<script>alert(1)</script>'


def _res(body, headers=None, status=200, elapsed=0.1, ok=True, error=None):
    """judge_* 단위 테스트용 응답 dict 생성"""
    return {'ok': ok, 'status': status, 'headers': headers or {},
            'body': body, 'elapsed': elapsed, 'url': '', 'error': error}


def _distinctive(payload):
    """verdict._reflected 구별성 가드와 동일 규칙 (strip 후 len>=4 & 영숫자 1개 이상)"""
    return len(payload.strip()) >= 4 and any(ch.isalnum() for ch in payload)


class _MockBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.target = start_mock_server()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()


class KnownVulnTests(_MockBase):
    """known-vuln 대상 -> 종합 '취약' (미탐 0 이어야 한다)"""

    def _run_pattern(self, cat):
        _, results = pattern.run(self.target, cat, path=f'/{cat}/vuln')
        return summarize(results)

    def test_pattern_vuln_detected(self):
        for cat in _PATTERN_CATS:
            with self.subTest(category=cat):
                overall, counts = self._run_pattern(cat)
                self.assertEqual(overall, '취약',
                                 f'{cat}: known-vuln 미탐 (종합={overall}, {counts})')
                self.assertGreaterEqual(counts['VULNERABLE'], 1,
                                        f'{cat}: VULNERABLE 0건 (미탐)')

    def test_blind_vuln_detected(self):
        _, results = blind.run_boolean(self.target, path='/blind/vuln')
        overall, counts = summarize(results)
        self.assertEqual(overall, '취약', f'blind: known-vuln 미탐 ({counts})')
        self.assertGreaterEqual(counts['VULNERABLE'], 1, 'blind: VULNERABLE 0건 (미탐)')


class KnownSafeTests(_MockBase):
    """known-safe 대상 -> '취약' 아님. 가능하면 '안전'을 적극 확정(판단불가 아님)."""

    def _run_pattern(self, cat, kind='safe'):
        _, results = pattern.run(self.target, cat, path=f'/{cat}/{kind}')
        return summarize(results)

    def test_pattern_safe_no_false_positive(self):
        for cat in _PATTERN_CATS:
            with self.subTest(category=cat):
                overall, counts = self._run_pattern(cat)
                self.assertEqual(counts['VULNERABLE'], 0,
                                 f'{cat}: 오탐 {counts["VULNERABLE"]}건 (false positive)')
                self.assertNotEqual(overall, '취약', f'{cat}: known-safe 오탐')

    def test_blind_safe_no_false_positive(self):
        _, results = blind.run_boolean(self.target, path='/blind/safe')
        overall, counts = summarize(results)
        self.assertEqual(counts['VULNERABLE'], 0,
                         f'blind: 오탐 {counts["VULNERABLE"]}건 (false positive)')

    def test_xss_safe_affirmative(self):
        overall, counts = self._run_pattern('xss')
        self.assertEqual(overall, '안전', f'xss-safe 종합={overall} ({counts})')
        self.assertEqual(counts['INCONCLUSIVE'], 0)

    def test_traversal_safe_affirmative(self):
        overall, counts = self._run_pattern('traversal')
        self.assertEqual(overall, '안전', f'traversal-safe 종합={overall} ({counts})')

    def test_ssti_safe_affirmative(self):
        overall, counts = self._run_pattern('ssti')
        self.assertEqual(overall, '안전', f'ssti-safe 종합={overall} ({counts})')

    def test_blind_safe_affirmative(self):
        _, results = blind.run_boolean(self.target, path='/blind/safe')
        overall, counts = summarize(results)
        self.assertEqual(overall, '안전', f'blind-safe 종합={overall} ({counts})')

    def test_allsafe_sqli_cmdi_are_affirmatively_safe(self):
        for cat in ('sqli', 'cmdi'):
            with self.subTest(category=cat):
                _, results = pattern.run(self.target, cat, path='/allsafe')
                overall, counts = summarize(results)
                self.assertEqual(overall, '안전',
                                 f'{cat}: allsafe 종합={overall} ({counts})')
                self.assertEqual(counts['VULNERABLE'], 0)
                self.assertGreaterEqual(counts['SAFE'], 1)

    def test_reflective_sqli_cmdi_safe_is_affirmatively_safe(self):
        # W1 + 구별성 가드: 반사형 무해 응답에서 distinctive 페이로드는 SAFE,
        # 초단문/구두점(' " ') 1' 등)은 거짓 반사가 제거되어 INCONCLUSIVE(오탐 아닌 정직한 판단).
        for cat in ('sqli', 'cmdi'):
            with self.subTest(category=cat):
                _, results = pattern.run(self.target, cat, path=f'/{cat}/safe')
                overall, counts = summarize(results)
                self.assertEqual(overall, '안전',
                                 f'{cat}-safe 종합={overall} ({counts})')
                self.assertEqual(counts['VULNERABLE'], 0,
                                 f'{cat}-safe 오탐 ({counts})')
                self.assertGreaterEqual(counts['SAFE'], 1,
                                        f'{cat}-safe SAFE 0건 ({counts})')
                for r in results:
                    if _distinctive(r['payload']):
                        self.assertEqual(r['verdict'], 'SAFE',
                                         f'{cat}: distinctive {r["payload"]!r} -> {r["verdict"]}')
                    else:
                        self.assertEqual(r['verdict'], 'INCONCLUSIVE',
                                         f'{cat}: non-distinctive {r["payload"]!r} -> {r["verdict"]}')


class XssContextTests(unittest.TestCase):
    """개선 ④: judge_xss 가 Content-Type/nosniff 문맥을 반영하는지 (단위)."""

    def test_html_raw_reflection_is_vulnerable_high(self):
        v, ev, c = verdict.judge_xss(
            _res('x ' + _XSS + ' y', {'Content-Type': 'text/html; charset=utf-8'}),
            _XSS, None)
        self.assertEqual((v, c), ('VULNERABLE', '높음'))

    def test_json_nosniff_raw_reflection_is_safe(self):
        v, ev, c = verdict.judge_xss(
            _res('{"q":"' + _XSS + '"}',
                 {'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff'}),
            _XSS, None)
        self.assertEqual(v, 'SAFE')

    def test_json_without_nosniff_raw_reflection_is_vulnerable_medium(self):
        v, ev, c = verdict.judge_xss(
            _res('{"q":"' + _XSS + '"}', {'Content-Type': 'application/json'}),
            _XSS, None)
        self.assertEqual((v, c), ('VULNERABLE', '중간'))

    def test_escaped_reflection_is_safe_high(self):
        v, ev, c = verdict.judge_xss(
            _res('x ' + html.escape(_XSS, quote=False) + ' y', {'Content-Type': 'text/html'}),
            _XSS, None)
        self.assertEqual((v, c), ('SAFE', '높음'))

    def test_not_reflected_is_inconclusive(self):
        v, ev, c = verdict.judge_xss(_res('nothing here', {'Content-Type': 'text/html'}), _XSS, None)
        self.assertEqual(v, 'INCONCLUSIVE')


class NewVerdictBehaviorTests(unittest.TestCase):
    """개선 ②③: traversal baseline 가드와 비-XSS 카테고리 SAFE 도입(단위)."""

    def test_traversal_baseline_guard_suppresses_preexisting_signature(self):
        body = 'docs example: root:x:0:0:root:/root:/bin/bash'
        v, ev, c = verdict.judge_traversal(_res(body), '/etc/passwd', _res(body))
        self.assertNotEqual(v, 'VULNERABLE')

    def test_traversal_attack_only_signature_is_vulnerable(self):
        v, ev, c = verdict.judge_traversal(
            _res('root:x:0:0:root:/root:/bin/bash'), '/etc/passwd', _res('normal page'))
        self.assertEqual(v, 'VULNERABLE')

    def test_non_xss_categories_can_return_safe_when_baseline_equivalent(self):
        clean = _res(_NORMAL_BODY)
        base = _res(_NORMAL_BODY)
        for fn, payload in ((verdict.judge_sqli, "' OR 1=1--"),
                            (verdict.judge_traversal, '/etc/passwd'),
                            (verdict.judge_cmdi, '; id'),
                            (verdict.judge_ssti, '{{1234*5678}}')):
            with self.subTest(fn=fn.__name__):
                v, ev, c = fn(clean, payload, base)
                self.assertEqual(v, 'SAFE', f'{fn.__name__} 가 SAFE 를 못 냄')

    def test_ssti_whitespace_variant_is_safe_medium(self):
        body = '<html>Template: {{ 1234 * 5678 }}</html>'
        v, ev, c = verdict.judge_ssti(_res(body), '{{ 1234 * 5678 }}', _res(body))
        self.assertEqual((v, c), ('SAFE', '중간'))


class SafeDoesNotMaskVulnTests(unittest.TestCase):
    """개선 ③ 안전성: SAFE 도입이 실제 취약을 안전으로 접지 않는가 (위험한 FN)."""

    def test_timebased_delay_wins_over_baseline_equivalence(self):
        base = _res('SAME BODY')
        delayed = _res('SAME BODY', elapsed=5.0)
        v, ev, c = verdict.judge_sqli(delayed, '1 AND SLEEP(5)', base)
        self.assertEqual(v, 'VULNERABLE')

    def test_db_error_wins_over_baseline_equivalence(self):
        base = _res('SAME BODY')
        err = _res('SAME BODY you have an error in your SQL syntax; near')
        v, ev, c = verdict.judge_sqli(err, "'", base)
        self.assertEqual(v, 'VULNERABLE')

    def test_blind_divergence_is_vulnerable_not_safe(self):
        base = _res('A' * 500)
        v, ev, c = blind.judge_boolean(base, _res('A' * 500), _res('B' * 50))
        self.assertEqual(v, 'VULNERABLE')

    def test_blind_subtle_difference_is_inconclusive_not_safe(self):
        base = _res('A' * 500)
        v, ev, c = blind.judge_boolean(base, _res('A' * 500), _res('A' * 460 + 'C' * 40))
        self.assertEqual(v, 'INCONCLUSIVE')


class ReflectiveSafeTests(unittest.TestCase):
    """W1: 반사형 무해 응답(오류·결과 없음 + 입력 반사) -> SAFE/중간 (단위)."""

    def test_sqli_reflected_no_error_is_safe_medium(self):
        payload = "' OR 1=1--"
        body = 'Search results for ' + html.escape(payload)
        v, ev, c = verdict.judge_sqli(_res(body), payload, _res(_NORMAL_BODY))
        self.assertEqual((v, c), ('SAFE', '중간'))

    def test_cmdi_reflected_no_result_is_safe_medium(self):
        payload = '; id'
        body = 'echo: ' + html.escape(payload, quote=False)
        v, ev, c = verdict.judge_cmdi(_res(body), payload, _res(_NORMAL_BODY))
        self.assertEqual((v, c), ('SAFE', '중간'))

    def test_traversal_reflected_no_file_is_safe_medium(self):
        payload = '/etc/passwd'
        body = 'You provided: ' + html.escape(payload)
        v, ev, c = verdict.judge_traversal(_res(body), payload, _res(_NORMAL_BODY))
        self.assertEqual((v, c), ('SAFE', '중간'))

    def test_quotefalse_only_reflection_is_no_longer_safe(self):
        # 수정 확인: quote=False 분기 제거. raw 미반사 & html.escape(quote=True) 미일치이고
        # quote=False 형태로만 나타나면 더 이상 반사로 인정하지 않는다 -> INCONCLUSIVE.
        payload = "<b>'x'"
        body = 'got ' + html.escape(payload, quote=False) + ' end'
        self.assertNotIn(payload, body)                 # raw 미반사
        self.assertNotIn(html.escape(payload), body)    # quote=True 미일치
        v, ev, c = verdict.judge_sqli(_res(body), payload, _res(_NORMAL_BODY))
        self.assertEqual(v, 'INCONCLUSIVE')

    def test_distinctive_echo_is_reflected_safe(self):
        # 수정 확인: distinctive 페이로드가 실제 에코되면 반사 인정 -> SAFE/중간 유지.
        cases = [
            (verdict.judge_sqli, "' OR '1'='1"),
            (verdict.judge_sqli, "admin'--"),
            (verdict.judge_cmdi, '; id'),
            (verdict.judge_traversal, '/etc/passwd'),
        ]
        for fn, payload in cases:
            with self.subTest(fn=fn.__name__, payload=payload):
                self.assertTrue(_distinctive(payload))
                body = 'echo: ' + html.escape(payload) + ' end'
                v, ev, c = fn(_res(body), payload, _res(_NORMAL_BODY))
                self.assertEqual((v, c), ('SAFE', '중간'),
                                 f'{fn.__name__} {payload!r} -> {(v, c)}')


class NonReflectedInconclusiveTests(unittest.TestCase):
    """미반사 + baseline 비동등 -> INCONCLUSIVE (SAFE 로 성급히 단정 금지)."""

    def test_sqli_not_reflected_not_equivalent_is_inconclusive(self):
        v, ev, c = verdict.judge_sqli(
            _res('totally unrelated content'), "' OR 1=1--", _res(_NORMAL_BODY))
        self.assertEqual(v, 'INCONCLUSIVE')

    def test_cmdi_not_reflected_not_equivalent_is_inconclusive(self):
        v, ev, c = verdict.judge_cmdi(
            _res('totally unrelated content'), '; id', _res(_NORMAL_BODY))
        self.assertEqual(v, 'INCONCLUSIVE')

    def test_traversal_not_reflected_not_equivalent_is_inconclusive(self):
        v, ev, c = verdict.judge_traversal(
            _res('totally unrelated content'), '/etc/passwd', _res(_NORMAL_BODY))
        self.assertEqual(v, 'INCONCLUSIVE')

    def test_bare_quote_not_actually_reflected_is_inconclusive(self):
        # 수정 확인(이전 거짓 SAFE 버그 해소): 바디에 따옴표 문자가 있을 뿐 실제 에코가 없는데
        # 초단문 페이로드(' / ")가 반사로 오인되던 문제. 구별성 가드로 반사 아님 -> INCONCLUSIVE.
        page = '<html><body><a href="/home">nothing echoed</a></body></html>'
        for payload in ("'", '"'):
            with self.subTest(payload=payload):
                v, ev, c = verdict.judge_sqli(_res(page), payload, _res(_NORMAL_BODY))
                self.assertEqual(v, 'INCONCLUSIVE',
                                 f'{payload!r} -> {v} (거짓 SAFE 재발)')

    def test_reflected_baseline_guard_suppresses_preexisting_echo(self):
        # 수정 확인(baseline 가드): distinctive 페이로드가 공격 응답에 있어도
        # baseline 본문에 이미 있던 형태면 반사로 보지 않는다 -> SAFE 아님(INCONCLUSIVE).
        payload = "' OR 1=1--"
        base = _res('note: ' + payload + ' already present ' + 'X' * 300)
        # 본문은 baseline 과 충분히 달라 _baseline_equivalent 는 거짓, 그러나 payload 는 양쪽에 존재
        attack = _res('different layout ' + payload + ' here ' + 'Y' * 300)
        self.assertIn(payload, base['body'])
        self.assertIn(payload, attack['body'])
        v, ev, c = verdict.judge_sqli(attack, payload, base)
        self.assertEqual(v, 'INCONCLUSIVE',
                         'baseline 에 이미 있던 에코를 반사로 오인 (가드 미동작)')


class ReflectionDoesNotMaskVulnTests(unittest.TestCase):
    """위험 FN: 오류/지연/명령결과/파일시그니처가 있으면 반사 여부와 무관하게 VULNERABLE."""

    def test_sqli_reflected_plus_db_error_is_vulnerable(self):
        payload = "'"
        body = ('Search for ' + html.escape(payload)
                + ' -> You have an error in your SQL syntax; near')
        v, ev, c = verdict.judge_sqli(_res(body), payload, _res(_NORMAL_BODY))
        self.assertEqual(v, 'VULNERABLE')

    def test_sqli_reflected_plus_delay_is_vulnerable(self):
        payload = '1 AND SLEEP(5)'
        body = 'Search results for ' + html.escape(payload)
        v, ev, c = verdict.judge_sqli(_res(body, elapsed=5.0), payload, _res(_NORMAL_BODY))
        self.assertEqual(v, 'VULNERABLE')

    def test_cmdi_reflected_plus_command_output_is_vulnerable(self):
        payload = '; id'
        body = ('echo ' + html.escape(payload, quote=False)
                + ' -> uid=0(root) gid=0(root) groups=0(root)')
        v, ev, c = verdict.judge_cmdi(_res(body), payload, _res(_NORMAL_BODY))
        self.assertEqual(v, 'VULNERABLE')

    def test_traversal_reflected_plus_file_signature_is_vulnerable(self):
        payload = '/etc/passwd'
        body = ('path ' + html.escape(payload)
                + ' -> root:x:0:0:root:/root:/bin/bash')
        v, ev, c = verdict.judge_traversal(_res(body), payload, _res(_NORMAL_BODY))
        self.assertEqual(v, 'VULNERABLE')



if __name__ == '__main__':
    unittest.main(verbosity=2)
