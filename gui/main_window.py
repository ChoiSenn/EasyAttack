"""PyQt GUI 메인 윈도우 모듈"""
import webbrowser
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QLabel, QTextEdit, QComboBox,
                             QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from utils.network import resolve_to_ip, ping_host
from utils.packet_sender import send_http_get, format_summary
from utils.patterns import list_categories
from utils.attacks import pattern, blind
from utils import scan, report


class PingWorker(QThread):
    """ping 실행을 위한 워커 스레드"""
    finished = pyqtSignal(str)

    def __init__(self, host, count=4):
        super().__init__()
        self.host = host
        self.count = count

    def run(self):
        """백그라운드에서 ping 실행"""
        result = ping_host(self.host, self.count)
        self.finished.emit(result)


class HttpGetWorker(QThread):
    """HTTP GET 전송을 위한 워커 스레드"""
    finished = pyqtSignal(str)

    def __init__(self, target, scheme='http', verify=True):
        super().__init__()
        self.target = target
        self.scheme = scheme
        self.verify = verify

    def run(self):
        """백그라운드에서 HTTP GET 전송"""
        result = send_http_get(self.target, scheme=self.scheme, verify=self.verify)
        self.finished.emit(format_summary(result))


class PatternWorker(QThread):
    """패턴 기반 공격 전송을 위한 워커 스레드"""
    finished = pyqtSignal(str)

    def __init__(self, target, category, method='GET', scheme='http', verify=True):
        super().__init__()
        self.target = target
        self.category = category
        self.method = method
        self.scheme = scheme
        self.verify = verify

    def run(self):
        """백그라운드에서 패턴 공격 전송"""
        baseline, results = pattern.run(self.target, self.category, method=self.method,
                                        scheme=self.scheme, verify=self.verify)
        self.finished.emit(pattern.format_results(baseline, results))


class BlindWorker(QThread):
    """부울 기반 블라인드 SQLi 점검을 위한 워커 스레드"""
    finished = pyqtSignal(str)

    def __init__(self, target, method='GET', scheme='http', verify=True):
        super().__init__()
        self.target = target
        self.method = method
        self.scheme = scheme
        self.verify = verify

    def run(self):
        """백그라운드에서 블라인드 SQLi 점검"""
        baseline, results = blind.run_boolean(self.target, method=self.method,
                                              scheme=self.scheme, verify=self.verify)
        self.finished.emit(blind.format_results(baseline, results))


class FullScanWorker(QThread):
    """전체 점검 + HTML 보고서 생성을 위한 워커 스레드"""
    finished = pyqtSignal(str, str)  # (요약 텍스트, 보고서 경로)

    def __init__(self, url, verify=True):
        super().__init__()
        self.url = url
        self.verify = verify

    def run(self):
        """백그라운드에서 전체 점검 후 보고서 저장"""
        result = scan.run_full_scan(self.url, verify=self.verify)
        lines = [f'대상: {result["url"]}  종합: {result["overall"]}']
        for p in result['policies']:
            lines.append(f'  - {p["name"]}: {p["verdict"]} '
                         f'({p["counts"]["VULNERABLE"]}/{p["total"]})')
        path = report.save_report(result)
        self.finished.emit('\n'.join(lines), path)


class MainWindow(QMainWindow):
    """메인 윈도우 클래스"""
    
    def __init__(self):
        super().__init__()
        self.ping_worker = None
        self.httpget_worker = None
        self.pattern_worker = None
        self.blind_worker = None
        self.fullscan_worker = None
        self.init_ui()
    
    def init_ui(self):
        """UI 초기화"""
        self.setWindowTitle('EasyAttack')
        self.setGeometry(100, 100, 600, 400)
        
        # 중앙 위젯
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 메인 레이아웃
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # 입력 영역 레이아웃
        input_layout = QHBoxLayout()
        
        # 입력 라벨
        input_label = QLabel('도메인 또는 IP:')
        input_layout.addWidget(input_label)
        
        # 입력칸
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText('예: google.com 또는 8.8.8.8')
        input_layout.addWidget(self.input_field)
        
        # nslookup 버튼
        self.nslookup_button = QPushButton('nslookup')
        self.nslookup_button.clicked.connect(self.on_nslookup_clicked)
        input_layout.addWidget(self.nslookup_button)
        
        # ping 버튼
        self.ping_button = QPushButton('ping')
        self.ping_button.clicked.connect(self.on_ping_clicked)
        input_layout.addWidget(self.ping_button)
        
        main_layout.addLayout(input_layout)

        # 패킷 전송 영역 (스킴 선택은 HTTP GET·패턴·전체점검 공용)
        packet_layout = QHBoxLayout()
        packet_layout.addWidget(QLabel('패킷 전송:'))
        self.scheme_combo = QComboBox()
        self.scheme_combo.addItems(['http', 'https'])
        packet_layout.addWidget(self.scheme_combo)
        self.insecure_check = QCheckBox('인증서 검증 안 함')
        packet_layout.addWidget(self.insecure_check)
        self.httpget_button = QPushButton('HTTP GET')
        self.httpget_button.clicked.connect(self.on_httpget_clicked)
        packet_layout.addWidget(self.httpget_button)
        packet_layout.addStretch()
        main_layout.addLayout(packet_layout)

        # 패턴 공격 영역 (SQLi, XSS 등)
        attack_layout = QHBoxLayout()
        attack_layout.addWidget(QLabel('패턴 공격:'))
        self.category_combo = QComboBox()
        self.category_combo.addItems(list_categories())
        attack_layout.addWidget(self.category_combo)
        self.method_combo = QComboBox()
        self.method_combo.addItems(['GET', 'POST'])
        attack_layout.addWidget(self.method_combo)
        self.pattern_button = QPushButton('전송')
        self.pattern_button.clicked.connect(self.on_pattern_clicked)
        attack_layout.addWidget(self.pattern_button)
        self.blind_button = QPushButton('Blind SQLi')
        self.blind_button.clicked.connect(self.on_blind_clicked)
        attack_layout.addWidget(self.blind_button)
        attack_layout.addStretch()
        main_layout.addLayout(attack_layout)

        # 전체 점검 영역 (모든 정책 실행 후 HTML 보고서)
        full_layout = QHBoxLayout()
        full_layout.addWidget(QLabel('전체 점검:'))
        self.fullscan_button = QPushButton('전체 점검 + 보고서')
        self.fullscan_button.clicked.connect(self.on_fullscan_clicked)
        full_layout.addWidget(self.fullscan_button)
        full_layout.addStretch()
        main_layout.addLayout(full_layout)

        main_layout.addStretch()
        
        # 결과 출력 영역 (하단 고정)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setPlaceholderText('IP 주소가 여기에 표시됩니다.')
        self.result_text.setFixedHeight(300)  # 약 8줄 정도 높이
        main_layout.addWidget(self.result_text)
    
    def append_result(self, text):
        """결과를 추가하고 자동 스크롤"""
        self.result_text.append(text)
        # 자동 스크롤을 맨 아래로
        scrollbar = self.result_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def on_nslookup_clicked(self):
        """nslookup 버튼 클릭 이벤트 핸들러"""
        input_value = self.input_field.text().strip()
        
        if not input_value:
            self.append_result('오류: 입력값이 비어있습니다.')
            return
        
        # IP 조회
        self.append_result(f'=== nslookup: {input_value} ===')
        ip = resolve_to_ip(input_value)
        
        if ip:
            self.append_result(f'IP 주소: {ip}')
        else:
            self.append_result(f'오류: {input_value}의 IP 주소를 찾을 수 없습니다.')
        self.append_result('')  # 빈 줄 추가
    
    def on_ping_clicked(self):
        """ping 버튼 클릭 이벤트 핸들러"""
        input_value = self.input_field.text().strip()
        
        if not input_value:
            self.append_result('오류: 입력값이 비어있습니다.')
            return
        
        # 이미 실행 중인 ping이 있으면 중단
        if self.ping_worker and self.ping_worker.isRunning():
            self.ping_worker.terminate()
            self.ping_worker.wait()
        
        # ping 버튼 비활성화
        self.ping_button.setEnabled(False)
        self.append_result(f'=== ping: {input_value} ===')
        
        # 백그라운드 스레드에서 ping 실행
        self.ping_worker = PingWorker(input_value, count=4)
        self.ping_worker.finished.connect(self.on_ping_finished)
        self.ping_worker.start()
    
    def on_ping_finished(self, result):
        """ping 완료 시 호출되는 콜백"""
        # ping 결과 추가
        self.append_result(result)
        self.append_result('')  # 빈 줄 추가
        self.ping_button.setEnabled(True)

    def on_httpget_clicked(self):
        """HTTP GET 버튼 클릭 핸들러"""
        input_value = self.input_field.text().strip()
        if not input_value:
            self.append_result('오류: 입력값이 비어있습니다.')
            return

        if self.httpget_worker and self.httpget_worker.isRunning():
            self.httpget_worker.terminate()
            self.httpget_worker.wait()

        scheme = self.scheme_combo.currentText()
        self.httpget_button.setEnabled(False)
        self.append_result(f'=== HTTP GET [{scheme}]: {input_value} ===')

        self.httpget_worker = HttpGetWorker(input_value, scheme, not self.insecure_check.isChecked())
        self.httpget_worker.finished.connect(self.on_httpget_finished)
        self.httpget_worker.start()

    def on_httpget_finished(self, result):
        """HTTP GET 완료 콜백"""
        self.append_result(result)
        self.append_result('')
        self.httpget_button.setEnabled(True)

    def on_pattern_clicked(self):
        """패턴 공격 버튼 클릭 핸들러"""
        input_value = self.input_field.text().strip()
        if not input_value:
            self.append_result('오류: 입력값이 비어있습니다.')
            return

        category = self.category_combo.currentText()
        if not category:
            self.append_result('오류: 패턴 카테고리가 없습니다.')
            return

        if self.pattern_worker and self.pattern_worker.isRunning():
            self.pattern_worker.terminate()
            self.pattern_worker.wait()

        method = self.method_combo.currentText()
        scheme = self.scheme_combo.currentText()
        self.pattern_button.setEnabled(False)
        self.append_result(f'=== 패턴 공격 [{category}/{method}/{scheme}]: {input_value} ===')

        self.pattern_worker = PatternWorker(input_value, category, method, scheme,
                                            not self.insecure_check.isChecked())
        self.pattern_worker.finished.connect(self.on_pattern_finished)
        self.pattern_worker.start()

    def on_pattern_finished(self, result):
        """패턴 공격 완료 콜백"""
        self.append_result(result)
        self.append_result('')
        self.pattern_button.setEnabled(True)

    def on_blind_clicked(self):
        """블라인드 SQLi 버튼 클릭 핸들러"""
        input_value = self.input_field.text().strip()
        if not input_value:
            self.append_result('오류: 입력값이 비어있습니다.')
            return

        if self.blind_worker and self.blind_worker.isRunning():
            self.blind_worker.terminate()
            self.blind_worker.wait()

        method = self.method_combo.currentText()
        scheme = self.scheme_combo.currentText()
        self.blind_button.setEnabled(False)
        self.append_result(f'=== Blind SQLi [{method}/{scheme}]: {input_value} ===')

        self.blind_worker = BlindWorker(input_value, method, scheme,
                                        not self.insecure_check.isChecked())
        self.blind_worker.finished.connect(self.on_blind_finished)
        self.blind_worker.start()

    def on_blind_finished(self, result):
        """블라인드 SQLi 완료 콜백"""
        self.append_result(result)
        self.append_result('')
        self.blind_button.setEnabled(True)

    def on_fullscan_clicked(self):
        """전체 점검 버튼 클릭 핸들러 (URL + 스킴으로 모든 정책 점검)"""
        input_value = self.input_field.text().strip()
        if not input_value:
            self.append_result('오류: 입력값이 비어있습니다.')
            return

        if self.fullscan_worker and self.fullscan_worker.isRunning():
            return

        # 스킴이 없으면 드롭다운 값으로 URL 구성
        scheme = self.scheme_combo.currentText()
        url = input_value if '://' in input_value else f'{scheme}://{input_value}'
        self.fullscan_button.setEnabled(False)
        self.append_result(f'=== 전체 점검: {url} (진행 중...) ===')

        self.fullscan_worker = FullScanWorker(url, not self.insecure_check.isChecked())
        self.fullscan_worker.finished.connect(self.on_fullscan_finished)
        self.fullscan_worker.start()

    def on_fullscan_finished(self, summary, report_path):
        """전체 점검 완료 콜백: 요약 표시 후 보고서 열기"""
        self.append_result(summary)
        self.append_result(f'보고서 저장: {report_path}')
        self.append_result('')
        self.fullscan_button.setEnabled(True)
        webbrowser.open(report_path)

