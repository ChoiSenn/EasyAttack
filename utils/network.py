"""네트워크 유틸리티 함수 모듈"""
import socket
import subprocess
import platform


def is_valid_ip(ip_string):
    """
    입력된 문자열이 유효한 IP 주소인지 확인
    
    Args:
        ip_string (str): 확인할 IP 주소 문자열
        
    Returns:
        bool: 유효한 IP 주소면 True, 아니면 False
    """
    try:
        socket.inet_aton(ip_string)
        return True
    except socket.error:
        return False


def resolve_to_ip(domain_or_ip):
    """
    도메인 또는 IP 주소를 IP 주소로 변환
    
    Args:
        domain_or_ip (str): 도메인명 또는 IP 주소
        
    Returns:
        str: IP 주소
        None: 변환 실패 시
    """
    # 입력값이 이미 IP 주소인 경우
    if is_valid_ip(domain_or_ip):
        return domain_or_ip
    
    # 도메인인 경우 DNS 조회
    try:
        ip = socket.gethostbyname(domain_or_ip)
        return ip
    except socket.gaierror:
        return None


def ping_host(host, count=4):
    """
    호스트에 ping을 보내고 결과를 반환
    
    Args:
        host (str): ping을 보낼 호스트 (도메인 또는 IP)
        count (int): ping 패킷 개수 (기본값: 4)
        
    Returns:
        str: ping 결과 문자열
    """
    try:
        # 운영체제에 따라 ping 명령어 인자 조정
        if platform.system().lower() == 'windows':
            result = subprocess.run(
                ['ping', '-n', str(count), host],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='cp949'
            )
        else:
            result = subprocess.run(
                ['ping', '-c', str(count), host],
                capture_output=True,
                text=True,
                timeout=10
            )
        
        return result.stdout
    except subprocess.TimeoutExpired:
        return f'오류: ping 시간 초과 ({host})'
    except Exception as e:
        return f'오류: ping 실행 실패 - {str(e)}'

