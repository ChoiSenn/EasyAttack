"""EasyAttack 진입점. 인자 없으면 GUI, 있으면 CLI"""
import sys


def run_gui():
    """PyQt GUI 실행"""
    import os
    import PyQt5

    # PyQt5 플러그인 경로 설정 (Windows Store Python 환경 대응)
    pyqt5_path = os.path.dirname(PyQt5.__file__)
    plugin_path = os.path.join(pyqt5_path, 'Qt5', 'plugins')
    if os.path.exists(plugin_path):
        os.environ['QT_PLUGIN_PATH'] = plugin_path

    from PyQt5.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


def main():
    """인자 유무로 GUI/CLI 분기"""
    if len(sys.argv) > 1:
        from cli.main_cli import run
        sys.exit(run())
    else:
        run_gui()


if __name__ == '__main__':
    main()
