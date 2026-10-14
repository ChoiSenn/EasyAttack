"""테스트용 로컬 목 HTTP 서버 (취약/안전 엔드포인트 제공, 외부 전송 없음)"""
import html
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 블라인드용 응답 본문: 참=긴 정상 페이지, 거짓=짧은 '결과 없음' 페이지
_FULL = "<html><body><h1>Product 42</h1><p>" + ("In stock. " * 20) + "</p></body></html>"
_EMPTY = "<html><body><p>No matching records found.</p></body></html>"
_NORMAL = "<html><body><p>Search service ready.</p></body></html>"


def _cond_true(value):
    """주입된 부울 조건의 참/거짓을 실제로 평가 (취약 서버가 분기하는 데 사용)"""
    truths = [a == b for a, b in
              re.findall(r"[\"']?(\w+)[\"']?\s*=\s*[\"']?(\w+)[\"']?", value)]
    if not truths:
        return True
    if re.search(r"\bOR\b", value, re.I):
        return any(truths)
    return all(truths)


def _render(path, q):
    """경로+입력(q)에 따라 취약/안전 응답 본문을 생성"""
    # ---- SQL Injection ----
    if path == '/sqli/vuln':
        if "'" in q or '"' in q:
            return ("<html><body>You have an error in your SQL syntax; "
                    "check the manual near '" + html.escape(q) + "'</body></html>")
        return _NORMAL
    if path == '/sqli/safe':
        return f"<html><body>Search results for {html.escape(q)}</body></html>"

    # ---- XSS (반사) ----
    if path == '/xss/vuln':
        return f"<html><body>You searched: {q}</body></html>"
    if path == '/xss/safe':
        return f"<html><body>You searched: {html.escape(q, quote=False)}</body></html>"

    # ---- Path Traversal / LFI ----
    if path == '/traversal/vuln':
        if any(m in q for m in ('passwd', 'win.ini', '..', '/etc/')):
            return ("root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "[extensions]\n[fonts]\n; for 16-bit app support")
        return _NORMAL
    if path == '/traversal/safe':
        return f"<html><body>File not found: {html.escape(q)}</body></html>"

    # ---- Command Injection ----
    if path == '/cmdi/vuln':
        if any(c in q for c in ('id', 'ipconfig', 'dir')):
            return ("uid=0(root) gid=0(root) groups=0(root)\n"
                    "Windows IP Configuration\n Volume Serial Number is 1A2B-3C4D")
        return _NORMAL
    if path == '/cmdi/safe':
        return f"<html><body>Command disabled: {html.escape(q)}</body></html>"

    # ---- SSTI (서버측 수식 평가) ----
    if path == '/ssti/vuln':
        m = re.search(r"(\d+)\s*\*\s*(\d+)", q)
        if m:
            return f"<html><body>Result: {int(m.group(1)) * int(m.group(2))}</body></html>"
        return _NORMAL
    if path == '/ssti/safe':
        return f"<html><body>Template: {html.escape(q)}</body></html>"

    # ---- Blind (부울 기반) ----
    if path == '/blind/vuln':
        return _FULL if _cond_true(q) else _EMPTY
    if path == '/blind/safe':
        return _FULL  # 조건과 무관하게 항상 동일 (취약 아님)

    # ---- All-safe (입력 비의존: baseline 과 동등) + 큰 상수 패딩에 escape 반영 ----
    # 모든 카테고리 판정이 SAFE 로 수렴하는 대상 (scan 종합 '안전' 검증용).
    if path == '/allsafe':
        pad = 'stable content line. ' * 200
        return ('<html><body>' + pad + 'echo: '
                + html.escape(q, quote=False) + '</body></html>')

    return _NORMAL


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query).get('q', [''])[0]
        body = _render(parsed.path, q).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # 테스트 출력 조용히


def start_mock_server():
    """목 서버를 백그라운드 스레드로 기동 -> (server, 'host:port')"""
    server = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f'{host}:{port}'
