"""전체 점검 결과를 HTML 보고서로 생성"""
import os
import html
from datetime import datetime

_COLORS = {'취약': '#d9534f', '안전': '#5cb85c', '판단불가': '#999'}


def _badge(verdict):
    """판정을 색상 배지 HTML로"""
    color = _COLORS.get(verdict, '#999')
    return f'<span style="background:{color};color:#fff;padding:2px 10px;' \
           f'border-radius:4px;font-size:13px">{html.escape(verdict)}</span>'


def _policy_row(p):
    """정책 하나를 표 행으로"""
    findings = ''.join(f'<li>{html.escape(f)}</li>' for f in p['findings']) \
        or '<li style="color:#777">특이사항 없음</li>'
    return (
        '<tr>'
        f'<td>{html.escape(p["name"])}</td>'
        f'<td>{_badge(p["verdict"])}</td>'
        f'<td>{html.escape(p["confidence"])}</td>'
        f'<td><ul style="margin:0;padding-left:18px">{findings}</ul></td>'
        f'<td style="text-align:center">{p["counts"]["VULNERABLE"]}/{p["total"]}</td>'
        '</tr>'
    )


def render_html(scan):
    """점검 결과 dict -> HTML 문자열"""
    rows = ''.join(_policy_row(p) for p in scan['policies'])
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<title>EasyAttack 점검 보고서</title>
<style>
 body{{font-family:'Malgun Gothic',sans-serif;max-width:900px;margin:30px auto;color:#222}}
 h1{{border-bottom:2px solid #333;padding-bottom:8px}}
 table{{width:100%;border-collapse:collapse;margin-top:16px}}
 th,td{{border:1px solid #ccc;padding:10px;text-align:left;vertical-align:top}}
 th{{background:#f2f2f2}}
 .meta{{color:#555;font-size:14px;line-height:1.7}}
</style></head><body>
<h1>EasyAttack 취약점 점검 보고서</h1>
<div class="meta">
 <b>대상 URL:</b> {html.escape(scan['url'])}<br>
 <b>점검 시각:</b> {html.escape(scan['timestamp'])}<br>
 <b>종합 판정:</b> {_badge(scan['overall'])}
</div>
<table>
 <tr><th>정책</th><th>판정</th><th>신뢰도</th><th>내용</th><th>탐지</th></tr>
 {rows}
</table>
<p class="meta">※ 본 보고서는 인가된 대상에 대한 자체 취약점/웹방화벽 테스트 용도로만 사용해야 합니다.</p>
</body></html>"""


def save_report(scan, path=None, out_dir='reports'):
    """보고서를 파일로 저장하고 경로 반환"""
    if path is None:
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = os.path.join(out_dir, f'report_{stamp}.html')
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(render_html(scan))
    return path
