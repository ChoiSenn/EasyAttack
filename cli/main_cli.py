"""EasyAttack CLI 인터페이스"""
import argparse
import sys

from utils.network import resolve_to_ip, ping_host
from utils.packet_sender import send_http_get, format_summary
from utils.patterns import list_categories
from utils.attacks import pattern, blind
from utils import scan, report


def cmd_nslookup(args):
    """도메인/IP를 IP 주소로 조회"""
    ip = resolve_to_ip(args.host)
    if ip:
        print(ip)
        return 0
    print(f'오류: {args.host}의 IP 주소를 찾을 수 없습니다.', file=sys.stderr)
    return 1


def cmd_ping(args):
    """호스트에 ping 전송"""
    result = ping_host(args.host, count=args.count)
    print(result, end='' if result.endswith('\n') else '\n')
    return 1 if result.startswith('오류:') else 0


def cmd_httpget(args):
    """대상에 HTTP GET 전송 후 응답 출력"""
    result = send_http_get(args.target, path=args.path, timeout=args.timeout,
                           scheme=args.scheme, verify=not args.insecure)
    print(format_summary(result))
    return 0 if result['ok'] else 1


def cmd_pattern(args):
    """패턴 기반 공격 전송 (SQLi, XSS 등)"""
    if args.list:
        print('\n'.join(list_categories()))
        return 0
    if not args.target or not args.category:
        print('오류: target과 category가 필요합니다. (목록: --list)', file=sys.stderr)
        return 2
    baseline, results = pattern.run(args.target, args.category, param=args.param,
                                    path=args.path, method=args.method,
                                    timeout=args.timeout, scheme=args.scheme,
                                    verify=not args.insecure, location=args.location)
    print(pattern.format_results(baseline, results))
    return 0


def cmd_blind(args):
    """부울 기반 블라인드 SQLi 점검"""
    baseline, results = blind.run_boolean(args.target, param=args.param,
                                          path=args.path, method=args.method,
                                          timeout=args.timeout, scheme=args.scheme,
                                          verify=not args.insecure)
    print(blind.format_results(baseline, results))
    return 0


def cmd_fullscan(args):
    """전체 점검: 모든 정책 실행 후 HTML 보고서 생성"""
    result = scan.run_full_scan(args.url, param=args.param, timeout=args.timeout,
                                verify=not args.insecure)
    # 화면 요약
    print(f'대상: {result["url"]}  종합: {result["overall"]}')
    for p in result['policies']:
        print(f'  - {p["name"]}: {p["verdict"]} '
              f'({p["counts"]["VULNERABLE"]}/{p["total"]})')
    path = report.save_report(result, path=args.output)
    print(f'보고서 저장: {path}')
    return 0


def build_parser():
    """CLI 인자 파서 생성"""
    parser = argparse.ArgumentParser(
        prog='easyattack',
        description='EasyAttack - 웹서버/웹방화벽 테스트용 트래픽 도구 (CLI)',
    )
    subparsers = parser.add_subparsers(dest='command', metavar='command')
    subparsers.required = True

    p_nslookup = subparsers.add_parser(
        'nslookup', aliases=['dns', 'resolve'],
        help='도메인 또는 IP를 IP 주소로 조회',
    )
    p_nslookup.add_argument('host', help='조회할 도메인 또는 IP')
    p_nslookup.set_defaults(func=cmd_nslookup)

    p_ping = subparsers.add_parser('ping', help='호스트에 ping 전송')
    p_ping.add_argument('host', help='ping을 보낼 도메인 또는 IP')
    p_ping.add_argument('-c', '--count', type=int, default=4, help='ping 패킷 개수 (기본값: 4)')
    p_ping.set_defaults(func=cmd_ping)

    p_get = subparsers.add_parser('httpget', aliases=['get'], help='HTTP GET 전송')
    p_get.add_argument('target', help='대상 도메인/IP 또는 전체 URL')
    p_get.add_argument('-p', '--path', default='/', help='요청 경로 (기본값: /)')
    p_get.add_argument('--scheme', default='http', choices=['http', 'https'], help='스킴 (기본값: http)')
    p_get.add_argument('-k', '--insecure', action='store_true', help='https 인증서 검증 생략')
    p_get.add_argument('-t', '--timeout', type=int, default=10, help='타임아웃 초 (기본값: 10)')
    p_get.set_defaults(func=cmd_httpget)

    p_pat = subparsers.add_parser('pattern', help='패턴 기반 공격 전송 (SQLi, XSS 등)')
    p_pat.add_argument('target', nargs='?', help='대상 도메인/IP 또는 URL')
    p_pat.add_argument('category', nargs='?', help='패턴 카테고리 (예: sqli, xss)')
    p_pat.add_argument('--param', default='q', help='주입할 파라미터명 (기본값: q)')
    p_pat.add_argument('--path', default='/', help='요청 경로 (기본값: /)')
    p_pat.add_argument('--method', default='GET', choices=['GET', 'POST'], help='HTTP 메서드')
    p_pat.add_argument('--location', default='query', choices=['query', 'header', 'cookie'],
                       help='주입 위치 (기본값: query)')
    p_pat.add_argument('--scheme', default='http', choices=['http', 'https'], help='스킴 (기본값: http)')
    p_pat.add_argument('-k', '--insecure', action='store_true', help='https 인증서 검증 생략')
    p_pat.add_argument('-t', '--timeout', type=int, default=10, help='타임아웃 초 (기본값: 10)')
    p_pat.add_argument('--list', action='store_true', help='패턴 카테고리 목록 출력')
    p_pat.set_defaults(func=cmd_pattern)

    p_blind = subparsers.add_parser('blind', help='부울 기반 블라인드 SQLi 점검')
    p_blind.add_argument('target', help='대상 도메인/IP 또는 URL')
    p_blind.add_argument('--param', default='q', help='주입할 파라미터명 (기본값: q)')
    p_blind.add_argument('--path', default='/', help='요청 경로 (기본값: /)')
    p_blind.add_argument('--method', default='GET', choices=['GET', 'POST'], help='HTTP 메서드')
    p_blind.add_argument('--scheme', default='http', choices=['http', 'https'], help='스킴 (기본값: http)')
    p_blind.add_argument('-k', '--insecure', action='store_true', help='https 인증서 검증 생략')
    p_blind.add_argument('-t', '--timeout', type=int, default=10, help='타임아웃 초 (기본값: 10)')
    p_blind.set_defaults(func=cmd_blind)

    p_full = subparsers.add_parser('fullscan', help='전체 점검 후 HTML 보고서 생성')
    p_full.add_argument('url', help='대상 URL (예: https://example.com/page)')
    p_full.add_argument('--param', default='q', help='주입할 파라미터명 (기본값: q)')
    p_full.add_argument('-o', '--output', help='보고서 저장 경로 (기본값: reports/report_시각.html)')
    p_full.add_argument('-k', '--insecure', action='store_true', help='https 인증서 검증 생략')
    p_full.add_argument('-t', '--timeout', type=int, default=10, help='타임아웃 초 (기본값: 10)')
    p_full.set_defaults(func=cmd_fullscan)

    return parser


def run(argv=None):
    """CLI 진입점. 종료 코드 반환"""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(run())
