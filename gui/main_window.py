"""PyQt GUI 메인 윈도우 모듈"""
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QLabel, QTextEdit)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from utils.network import resolve_to_ip, ping_host


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


class MainWindow(QMainWindow):
    """메인 윈도우 클래스"""
    
    def __init__(self):
        super().__init__()
        self.ping_worker = None
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
        
        # 중간 여백 (패킷 전송 메뉴를 넣을 공간)
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

