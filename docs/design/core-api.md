# 코어 공개 API 계약 (core-api.md)

> 상태: **APPROVED (확정)** — 2026-10-14 사용자 승인.
> 이 문서가 팀 전체의 단일 기준(source of truth)이다. 프론트엔드(cli/·gui/)는 여기 정의된
> 함수만 호출한다. **이 계약 변경은 사용자 승인 필요 결정이다.** 승인 전 구현 금지.

## 1. 계층 / 소유권 요약
| 역할 | 편집 범위 | 규칙 |
|------|-----------|------|
| core-dev | `utils/**`, `patterns/**`, `cli/**` | 코어 로직·CLI. API 변경은 승인 후 |
| gui-dev | `gui/**` | 코어 공개 API만 호출, 코어 수정 금지 |
| reviewer | `tests/**` (그 외 읽기전용) | 기능 코드 수정 금지 |

세 역할의 편집 디렉터리는 **서로 겹치지 않는다**(동일 파일 공유 금지의 물리적 보장).

## 2. 공통 응답 스키마 (send_http 반환 dict)
```
ok(bool), status(int|None), reason(str|None), headers(dict),
body(str), url(str), elapsed(float, 초), error(str|None)
```
- 4xx/5xx(차단 포함)도 예외가 아니라 `ok=True` 결과로 반환.
- 공격 실행기 결과에는 추가로: `payload`(blind는 `pair`), `verdict`, `evidence`, `confidence`.

## 3. 판정 enum
- verdict: `VULNERABLE` / `SAFE` / `INCONCLUSIVE`
- confidence: `높음` / `중간` / `낮음`
- SAFE 판정 기준(2026-10-14): baseline 동등/명시적 차단, 또는 무해 반사(구별성·baseline 가드 적용). VULNERABLE이 항상 우선. `run_full_scan`의 종합 overall도 3값(취약/안전/판단불가). 상세: dev_history/03-detection-logic.md.

## 4. 공개 함수 시그니처
```python
# utils.network
resolve_to_ip(domain_or_ip) -> str|None
ping_host(host, count=4) -> str
is_valid_ip(ip_string) -> bool

# utils.packet_sender   (verify=False면 https 인증서 검증 생략)
send_http(target, method='GET', path='/', data=None, headers=None, timeout=10, scheme='http', verify=True) -> dict
send_http_get(target, path='/', headers=None, timeout=10, scheme='http', verify=True) -> dict
send_http_post(target, path='/', data=None, headers=None, timeout=10, scheme='http', verify=True) -> dict
format_summary(result) -> str
format_response(result, body_limit=2000) -> str

# utils.patterns
list_categories() -> list[str]
load_patterns(category) -> list[str]

# utils.attacks.pattern   (location: 'url'|'query'|'header'|'cookie'|'body'; 평문 엔트리 기본 위치)
run(target, category, param='q', path='/', method='GET', timeout=10, scheme='http', verify=True, location='url') -> (baseline, results)
run_single(target, category, timeout=10, scheme='http', verify=True) -> result|None   # 대표(첫) 엔트리 1개만 전송, 판정 없음
format_results(baseline, results) -> str

# utils.attacks.blind
run_boolean(target, param='q', path='/', method='GET', timeout=10, scheme='http', verify=True) -> (baseline, results)
format_results(baseline, results) -> str

# utils.verdict
judge(category, result, payload, baseline) -> (verdict, evidence, confidence)

# utils.scan / utils.report
run_full_scan(url, param='q', timeout=10, verify=True) -> dict
save_report(scan, path=None, out_dir='reports') -> str
render_html(scan) -> str
```

## 4a. 주입 위치(location) + 패턴 포맷 v2 — 2026-10-14 승인
`location` 값:
- `url`(=`query`, 기본) — `?name=payload`
- `header` — 요청 헤더 `name: payload` (기본 name='User-Agent')
- `cookie` — `Cookie: name=payload` (기본 name='test')
- `body` — POST 폼 필드 `name=payload` (기본 name='data')

**패턴 파일 포맷 v2** (`patterns/*.txt`): 줄마다 `[location:name] payload` / `[location] payload` / 평문.
- 평문(대괄호 없음) 줄 = 기본 `url:q`, 호출부 location/param로 덮어쓰기 가능(기존 파일 호환).
- **첫 비주석 줄 = 대표**(단일 실행용). 로더: `load_entries`/`load_single`/`load_patterns`(payload만).
- **단일 실행**: `pattern --single`(또는 GUI 버튼) → `run_single`로 대표 1개만 전송, **판정 없이 응답만** 출력(WAF 탐지 확인은 사용자/WAF 쪽에서).
- 스캔: 전체 엔트리를 각자 location으로 전송 + 판정(대표 포함).
CLI `--location`은 `url|query|header|cookie|body`(평문 엔트리 기본 위치).

## 5. 확장 지점 (API 변경 없이 가능한 것)
- 패턴 카테고리 추가: `patterns/<cat>.txt` + `verdict.judge_<cat>` 등록 (+ 전체점검이면 `scan`에 등록)
- 새 공격 형태: `utils/attacks/<type>.py` 모듈 + CLI 서브커맨드 + GUI 버튼
- 위는 **API 시그니처 변경이 아니므로** 승인 불필요(단, 심각도 분류/리포트 포맷/페이로드 구조
  변경은 승인 필요 — CLAUDE.md 참조).

## 6. 변경 절차
1. 시그니처/스키마/enum 변경 제안 → 2. 사용자 승인 → 3. 이 문서 갱신 → 4. 구현.
구현과 문서가 어긋나면 **코드가 정답**이며, 발견 즉시 이 문서를 맞춘다.
