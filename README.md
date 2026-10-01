# EasyAttack

쉽고 빠르게 재미있게 취약점 공격 날리기

악용하지 마시고 용법/용량에 맞춰 본인 웹서버 취약점 테스트 용도 또는 웹방화벽 탐지 테스트 용도로만 사용하세요.


## 설치

```
pip install -r requirements.txt
```


## 실행 방법

인자 없이 실행하면 **GUI**, 인자를 주면 **CLI**로 동작합니다.

```
python main.py                     # GUI 실행
python main.py <명령> [인자] [옵션]   # CLI 실행
```


## CLI 사용 매뉴얼

### nslookup (별칭: dns, resolve)

도메인 또는 IP를 IP 주소로 조회합니다.

```
python main.py nslookup <host>
```

| 인자 | 설명 |
|------|------|
| `host` | 조회할 도메인 또는 IP |

예) `python main.py nslookup google.com`

---

### ping

호스트에 ping을 전송합니다.

```
python main.py ping <host> [-c COUNT]
```

| 인자/옵션 | 기본값 | 설명 |
|-----------|--------|------|
| `host` | | ping을 보낼 도메인 또는 IP |
| `-c`, `--count` | 4 | ping 패킷 개수 |

예) `python main.py ping 8.8.8.8 -c 2`

---

### httpget (별칭: get)

대상에 HTTP GET을 전송하고 응답 요약을 출력합니다.

```
python main.py httpget <target> [-p PATH] [--scheme http|https] [-t TIMEOUT]
```

| 인자/옵션 | 기본값 | 설명 |
|-----------|--------|------|
| `target` | | 대상 도메인/IP 또는 전체 URL |
| `-p`, `--path` | `/` | 요청 경로 |
| `--scheme` | `http` | 스킴 (`http` / `https`) |
| `-t`, `--timeout` | 10 | 타임아웃(초) |

예) `python main.py httpget example.com --scheme https -p /login`

---

### pattern

패턴 기반 공격(SQLi, XSS 등)을 전송하고 취약 여부를 판정합니다. 결과는 화면에만 출력됩니다.

```
python main.py pattern <target> <category> [--param P] [--path PATH] [--method GET|POST] [--scheme http|https] [-t TIMEOUT]
python main.py pattern --list
```

| 인자/옵션 | 기본값 | 설명 |
|-----------|--------|------|
| `target` | | 대상 도메인/IP 또는 URL |
| `category` | | 패턴 카테고리 (`sqli`, `xss`) |
| `--param` | `q` | 페이로드를 주입할 파라미터명 |
| `--path` | `/` | 요청 경로 |
| `--method` | `GET` | HTTP 메서드 (`GET` / `POST`) |
| `--scheme` | `http` | 스킴 (`http` / `https`) |
| `-t`, `--timeout` | 10 | 타임아웃(초) |
| `--list` | | 사용 가능한 패턴 카테고리 목록 출력 |

예) `python main.py pattern example.com sqli --method POST`

---

### blind

부울 기반 블라인드 SQL Injection을 점검합니다(참/거짓 응답 차이로 판정). 결과는 화면에만 출력됩니다.

```
python main.py blind <target> [--param P] [--path PATH] [--method GET|POST] [--scheme http|https] [-t TIMEOUT]
```

| 인자/옵션 | 기본값 | 설명 |
|-----------|--------|------|
| `target` | | 대상 도메인/IP 또는 URL |
| `--param` | `q` | 주입할 파라미터명 |
| `--path` | `/` | 요청 경로 |
| `--method` | `GET` | HTTP 메서드 (`GET` / `POST`) |
| `--scheme` | `http` | 스킴 (`http` / `https`) |
| `-t`, `--timeout` | 10 | 타임아웃(초) |

예) `python main.py blind example.com --path /search`

---

### fullscan

URL 하나로 **모든 정책**을 점검하고 결과를 **HTML 보고서**로 저장합니다.

```
python main.py fullscan <url> [--param P] [-o OUTPUT] [-t TIMEOUT]
```

| 인자/옵션 | 기본값 | 설명 |
|-----------|--------|------|
| `url` | | 대상 URL (예: `https://example.com/page`) |
| `--param` | `q` | 주입할 파라미터명 |
| `-o`, `--output` | `reports/report_<시각>.html` | 보고서 저장 경로 |
| `-t`, `--timeout` | 10 | 타임아웃(초) |

예) `python main.py fullscan https://example.com/board -o result.html`
