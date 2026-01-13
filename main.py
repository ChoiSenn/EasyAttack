"""EasyAttack 프로그램 진입점"""
import sys
import os

# PyQt5 플러그인 경로 설정 (Windows Store Python 환경 대응)
# QApplication 생성 전에 환경 변수 설정 필요
import PyQt5
pyqt5_path = os.path.dirname(PyQt5.__file__)
plugin_path = os.path.join(pyqt5_path, 'Qt5', 'plugins')
if os.path.exists(plugin_path):
    os.environ['QT_PLUGIN_PATH'] = plugin_path

from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow


def main():
    """메인 함수"""
    app = QApplication(sys.argv)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()

