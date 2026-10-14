"""run_full_scan 종합 판정(개선 ①: overall 3값화) 회귀 테스트.

이전엔 'VULNERABLE 없으면 안전'으로 접어 판단불가 대상을 '안전'으로 오보고했다(과거 Critical).
개선 후: 취약 1건↑ -> '취약' / 전부 '안전' -> '안전' / 그 외(판단불가 혼재) -> '판단불가'.
로컬 목 서버로만 통신(외부 전송 없음).
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mock_server import start_mock_server   # noqa: E402
from utils import scan                       # noqa: E402


class ScanOverallThreeValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.target = start_mock_server()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _scan(self, path):
        res = scan.run_full_scan(self.target + path)
        return res, {p['name']: p['verdict'] for p in res['policies']}

    def test_mixed_inconclusive_target_is_not_reported_safe(self):
        # [과거 Critical 수정 검증] /cmdi/safe 는 일부 정책이 '판단불가'로 끝난다.
        # 과거엔 종합이 '안전'으로 접혔다 — 이제는 '판단불가'여야 한다.
        res, verdicts = self._scan('/cmdi/safe')
        self.assertIn('판단불가', verdicts.values(),
                      f'전제: 일부 정책이 판단불가여야 한다 ({verdicts})')
        self.assertNotIn('취약', verdicts.values())
        self.assertEqual(res['overall'], '판단불가',
                         f"판단불가 혼재인데 종합={res['overall']} (과거 '안전' 오보고 재발)")

    def test_all_safe_target_is_reported_safe(self):
        # 모든 정책이 '안전'으로 확정되는 대상 -> 종합 '안전'.
        res, verdicts = self._scan('/allsafe')
        self.assertTrue(all(v == '안전' for v in verdicts.values()),
                        f'전제: 전 정책 안전이어야 한다 ({verdicts})')
        self.assertEqual(res['overall'], '안전', f"종합={res['overall']} ({verdicts})")

    def test_vulnerable_target_is_reported_vulnerable(self):
        # 취약 1건 이상 -> 종합 '취약'.
        res, verdicts = self._scan('/sqli/vuln')
        self.assertEqual(verdicts['SQL Injection'], '취약')
        self.assertEqual(res['overall'], '취약', f"종합={res['overall']} ({verdicts})")

    def test_blind_vulnerable_target_is_reported_vulnerable(self):
        res, verdicts = self._scan('/blind/vuln')
        self.assertEqual(verdicts['Blind SQL Injection'], '취약')
        self.assertEqual(res['overall'], '취약', f"종합={res['overall']} ({verdicts})")


if __name__ == '__main__':
    unittest.main(verbosity=2)
