# tests — 회귀 테스트 (reviewer 소유)

표준 라이브러리 `unittest`만 사용한다(외부 의존성 없음). 모든 통신은 로컬
목 서버(`127.0.0.1`, 임의 포트)로만 이뤄지며 **외부 네트워크 전송이 없다**.

## 실행법

프로젝트 루트(`EasyAttack/`)에서:

```
python -m unittest discover tests
```

상세 출력:

```
python -m unittest discover -s tests -v
```

Windows 콘솔 한글 깨짐 방지:

```
set PYTHONUTF8=1 && python -m unittest discover tests
```

## 구성

- `mock_server.py` — 취약/안전 엔드포인트를 제공하는 목 HTTP 서버.
  - 취약: `/sqli/vuln`(DB 오류), `/xss/vuln`(원형 반사), `/traversal/vuln`(passwd·win.ini),
    `/cmdi/vuln`(id·ipconfig 출력), `/ssti/vuln`(수식 평가 7006652), `/blind/vuln`(참/거짓 상이).
  - 안전(반사형): `/*/safe` — 입력을 escape 해 반영. sqli/cmdi 는 baseline 비동등이라
    보수적으로 '판단불가'로 끝나고, xss/traversal/ssti/blind 는 '안전'을 확정한다.
  - 안전(baseline 동등): `/allsafe` — 큰 상수 패딩 + escape 반영으로 전 카테고리가
    SAFE 로 수렴(판정 ③ 검증 및 scan 종합 '안전' 검증용).

- `test_verdicts.py`
  - `KnownVulnTests` — 6종 모두 종합 "취약" 확인 → 미탐 0.
  - `KnownSafeTests` — 오탐 0 + 가능한 경우 '안전' 적극 확정, sqli/cmdi 반사형은
    보수적 '판단불가'임을 명시.
  - `XssContextTests` — judge_xss 의 Content-Type/nosniff 문맥 판정(개선 ④).
  - `NewVerdictBehaviorTests` — traversal baseline 가드(②)·비-XSS SAFE 도입(③).
  - `SafeDoesNotMaskVulnTests` — SAFE 도입이 실제 취약(지연/오류/부울분기)을
    안전으로 접지 않음(위험한 FN 없음).

- `test_scan_characterization.py`
  - `ScanOverallThreeValueTests` — run_full_scan 종합 3값(①): 취약/안전/판단불가.
    특히 판단불가 혼재 대상을 '안전'으로 오보고하던 과거 Critical 의 수정 검증.

## 주의 (코어 호출 규약)

`send_http`의 `_normalize_url`은 target에 스킴(`http://`)이 있으면 path/쿼리를 버린다.
따라서 테스트는 target을 `host:port`(스킴 없이)로, 경로는 `path=` 인자로 분리해 넘긴다.
