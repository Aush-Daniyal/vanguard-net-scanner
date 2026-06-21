import asyncio
import sys
import time

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSlider, QProgressBar, QScrollArea,
    QFrame, QGridLayout, QSizePolicy, QSpacerItem
)

from scanner_core import AsyncPortScanner, PortResult, parse_port_range
from analyzer import VulnerabilityAnalyzer, Severity, SEVERITY_COLOR


STYLE_SHEET = """
QWidget {
    background-color: #131314;
    color: #ffffff;
    font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', sans-serif;
}
#RootWindow {
    background-color: #131314;
}
#HeaderTitle {
    font-size: 22px;
    font-weight: 600;
    color: #ffffff;
}
#HeaderSubtitle {
    font-size: 13px;
    color: #b4b4b4;
}
#ConfigCard {
    background-color: #1e1e1f;
    border-radius: 16px;
    padding: 18px;
}
QLabel.fieldLabel {
    font-size: 12px;
    color: #b4b4b4;
    font-weight: 500;
    padding-bottom: 2px;
}
QLineEdit {
    background-color: #2a2a2c;
    border: 1px solid #3a3a3c;
    border-radius: 12px;
    padding: 10px 14px;
    font-size: 14px;
    color: #ffffff;
    selection-background-color: #1a73e8;
}
QLineEdit:focus {
    border: 1px solid #1a73e8;
}
QPushButton#ScanButton {
    background-color: #1a73e8;
    color: #ffffff;
    border: none;
    border-radius: 12px;
    padding: 12px 28px;
    font-size: 14px;
    font-weight: 600;
}
QPushButton#ScanButton:hover {
    background-color: #2b83f1;
}
QPushButton#ScanButton:pressed {
    background-color: #1664c9;
}
QPushButton#ScanButton:disabled {
    background-color: #2a2a2c;
    color: #6f6f70;
}
QPushButton#StopButton {
    background-color: #2a2a2c;
    color: #f28b82;
    border: 1px solid #3a3a3c;
    border-radius: 12px;
    padding: 12px 22px;
    font-size: 14px;
    font-weight: 600;
}
QPushButton#StopButton:hover {
    background-color: #353537;
}
QSlider::groove:horizontal {
    height: 4px;
    background: #3a3a3c;
    border-radius: 2px;
}
QSlider::sub-page:horizontal {
    background: #1a73e8;
    border-radius: 2px;
}
QSlider::handle:horizontal {
    background: #ffffff;
    width: 16px;
    height: 16px;
    margin: -6px 0;
    border-radius: 8px;
}
QProgressBar {
    background-color: #2a2a2c;
    border: none;
    border-radius: 2px;
    max-height: 4px;
    min-height: 4px;
}
QProgressBar::chunk {
    background-color: #1a73e8;
    border-radius: 2px;
}
QScrollArea {
    border: none;
    background-color: transparent;
}
QScrollBar:vertical {
    background: #131314;
    width: 8px;
    margin: 0px;
}
QScrollBar::handle:vertical {
    background: #3a3a3c;
    border-radius: 4px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background: #4a4a4c;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
#ResultCardHigh {
    background-color: #2a1f1f;
    border: 1px solid #4a2c2c;
    border-radius: 12px;
}
#ResultCardMedium {
    background-color: #2a271f;
    border: 1px solid #4a3f2c;
    border-radius: 12px;
}
#ResultCardSafe {
    background-color: #1f2a22;
    border: 1px solid #2c4a35;
    border-radius: 12px;
}
#PortLabel {
    font-size: 16px;
    font-weight: 700;
    color: #ffffff;
}
#ServiceLabel {
    font-size: 13px;
    color: #b4b4b4;
}
#BannerLabel {
    font-size: 12px;
    color: #9a9a9c;
}
#SeverityBadge {
    border-radius: 10px;
    padding: 4px 12px;
    font-size: 11px;
    font-weight: 700;
}
#StatusLabel {
    font-size: 13px;
    color: #b4b4b4;
}
#EmptyState {
    color: #6f6f70;
    font-size: 14px;
}
"""


class ScanWorker(QThread):
    result_ready = pyqtSignal(object, object)
    progress_updated = pyqtSignal(int, int)
    scan_finished = pyqtSignal(float, int)
    scan_error = pyqtSignal(str)

    def __init__(self, target: str, ports: list[int], concurrency: int, timeout: float):
        super().__init__()
        self.target = target
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self.analyzer = VulnerabilityAnalyzer()
        self._scanner: AsyncPortScanner | None = None
        self._open_count = 0

    def _on_result(self, result: PortResult):
        findings = self.analyzer.analyze(result.port, result.service, result.banner)
        self._open_count += 1
        self.result_ready.emit(result, findings)

    def _on_progress(self, done: int, total: int):
        self.progress_updated.emit(done, total)

    def run(self):
        start = time.perf_counter()
        try:
            self._scanner = AsyncPortScanner(
                target=self.target,
                ports=self.ports,
                concurrency=self.concurrency,
                timeout=self.timeout,
                on_result=self._on_result,
                on_progress=self._on_progress,
            )
            asyncio.run(self._scanner.run())
        except Exception as exc:
            self.scan_error.emit(str(exc))
        finally:
            elapsed = time.perf_counter() - start
            self.scan_finished.emit(elapsed, self._open_count)

    def stop(self):
        if self._scanner:
            self._scanner.stop()


class ResultCard(QFrame):
    def __init__(self, result: PortResult, findings, parent=None):
        super().__init__(parent)
        severity = max(findings, key=lambda f: f.severity.value) if findings else None
        top_severity = self._top_severity(findings)

        if top_severity == Severity.HIGH:
            self.setObjectName("ResultCardHigh")
        elif top_severity == Severity.MEDIUM:
            self.setObjectName("ResultCardMedium")
        else:
            self.setObjectName("ResultCardSafe")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        port_label = QLabel(f":{result.port}")
        port_label.setObjectName("PortLabel")
        port_label.setFixedWidth(70)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        service_label = QLabel(f"{result.service}  ·  {result.latency_ms:.0f} ms")
        service_label.setObjectName("ServiceLabel")
        info_layout.addWidget(service_label)

        banner_text = result.banner if result.banner else "Баннер не получен"
        banner_label = QLabel(banner_text)
        banner_label.setObjectName("BannerLabel")
        banner_label.setWordWrap(True)
        info_layout.addWidget(banner_label)

        title_text = findings[0].title if findings else ""
        if title_text:
            title_label = QLabel(title_text)
            title_label.setObjectName("BannerLabel")
            title_label.setStyleSheet("color: #d4d4d6; font-weight: 600;")
            info_layout.addWidget(title_label)

        badge = QLabel(top_severity.value.upper())
        badge.setObjectName("SeverityBadge")
        color = SEVERITY_COLOR[top_severity]
        badge.setStyleSheet(
            f"background-color: rgba({self._hex_to_rgb(color)}, 0.18); color: {color};"
        )
        badge.setFixedWidth(80)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(port_label)
        layout.addLayout(info_layout, stretch=1)
        layout.addWidget(badge, alignment=Qt.AlignmentFlag.AlignTop)

    @staticmethod
    def _top_severity(findings) -> Severity:
        if not findings:
            return Severity.INFO
        order = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
        return max(findings, key=lambda f: order[f.severity]).severity

    @staticmethod
    def _hex_to_rgb(hex_color: str) -> str:
        hex_color = hex_color.lstrip("#")
        r, g, b = tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
        return f"{r}, {g}, {b}"


class VanguardNetWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vanguard-Net — Network Audit Suite")
        self.setMinimumSize(880, 720)
        self.resize(980, 780)
        self.setObjectName("RootWindow")

        self.worker: ScanWorker | None = None
        self.open_count = 0
        self.high_count = 0
        self.medium_count = 0

        self._build_ui()
        self.setStyleSheet(STYLE_SHEET)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(20)

        header = QVBoxLayout()
        header.setSpacing(4)
        title = QLabel("Vanguard-Net")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Высокопроизводительный асинхронный аудит сети и сигнатурный анализ уязвимостей")
        subtitle.setObjectName("HeaderSubtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        root.addLayout(header)

        config_card = QFrame()
        config_card.setObjectName("ConfigCard")
        config_layout = QGridLayout(config_card)
        config_layout.setSpacing(14)
        config_layout.setContentsMargins(20, 20, 20, 20)

        target_label = QLabel("TARGET IP / HOSTNAME")
        target_label.setProperty("class", "fieldLabel")
        target_label.setStyleSheet("font-size: 12px; color: #b4b4b4; font-weight: 500;")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("например: 192.168.1.1 или scanme.local")
        self.target_input.setText("127.0.0.1")

        port_label = QLabel("PORT RANGE")
        port_label.setStyleSheet("font-size: 12px; color: #b4b4b4; font-weight: 500;")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("например: 1-1024 или 22,80,443,8080-8090")
        self.port_input.setText("1-1024")

        timeout_label = QLabel("ТАЙМАУТ СОЕДИНЕНИЯ: 1.5 сек")
        timeout_label.setStyleSheet("font-size: 12px; color: #b4b4b4; font-weight: 500;")
        self.timeout_value_label = timeout_label
        self.timeout_slider = QSlider(Qt.Orientation.Horizontal)
        self.timeout_slider.setMinimum(2)
        self.timeout_slider.setMaximum(50)
        self.timeout_slider.setValue(15)
        self.timeout_slider.valueChanged.connect(self._on_timeout_changed)

        concurrency_label = QLabel("ПАРАЛЛЕЛЬНЫЕ ПОТОКИ: 500")
        concurrency_label.setStyleSheet("font-size: 12px; color: #b4b4b4; font-weight: 500;")
        self.concurrency_value_label = concurrency_label
        self.concurrency_slider = QSlider(Qt.Orientation.Horizontal)
        self.concurrency_slider.setMinimum(50)
        self.concurrency_slider.setMaximum(2000)
        self.concurrency_slider.setValue(500)
        self.concurrency_slider.valueChanged.connect(self._on_concurrency_changed)

        config_layout.addWidget(target_label, 0, 0)
        config_layout.addWidget(self.target_input, 1, 0)
        config_layout.addWidget(port_label, 0, 1)
        config_layout.addWidget(self.port_input, 1, 1)
        config_layout.addWidget(timeout_label, 2, 0)
        config_layout.addWidget(self.timeout_slider, 3, 0)
        config_layout.addWidget(concurrency_label, 2, 1)
        config_layout.addWidget(self.concurrency_slider, 3, 1)
        config_layout.setColumnStretch(0, 1)
        config_layout.setColumnStretch(1, 1)

        root.addWidget(config_card)

        controls_row = QHBoxLayout()
        controls_row.setSpacing(12)
        self.scan_button = QPushButton("Начать сканирование")
        self.scan_button.setObjectName("ScanButton")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.clicked.connect(self._start_scan)

        self.stop_button = QPushButton("Остановить")
        self.stop_button.setObjectName("StopButton")
        self.stop_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_button.clicked.connect(self._stop_scan)
        self.stop_button.setEnabled(False)

        controls_row.addWidget(self.scan_button)
        controls_row.addWidget(self.stop_button)
        controls_row.addItem(QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        root.addLayout(controls_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        root.addWidget(self.progress_bar)

        self.status_label = QLabel("Готов к сканированию")
        self.status_label.setObjectName("StatusLabel")
        root.addWidget(self.status_label)

        self.results_scroll = QScrollArea()
        self.results_scroll.setWidgetResizable(True)
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setSpacing(10)
        self.results_layout.setContentsMargins(2, 2, 2, 2)
        self.results_layout.addItem(QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        self.empty_state = QLabel("Здесь появятся результаты сканирования портов в реальном времени")
        self.empty_state.setObjectName("EmptyState")
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_layout.insertWidget(0, self.empty_state)

        self.results_scroll.setWidget(self.results_container)
        root.addWidget(self.results_scroll, stretch=1)

    def _on_timeout_changed(self, value: int):
        seconds = value / 10
        self.timeout_value_label.setText(f"ТАЙМАУТ СОЕДИНЕНИЯ: {seconds:.1f} сек")

    def _on_concurrency_changed(self, value: int):
        self.concurrency_value_label.setText(f"ПАРАЛЛЕЛЬНЫЕ ПОТОКИ: {value}")

    def _clear_results(self):
        for i in reversed(range(self.results_layout.count())):
            item = self.results_layout.itemAt(i)
            widget = item.widget()
            if widget is not None and widget is not self.empty_state:
                self.results_layout.takeAt(i)
                widget.deleteLater()
        self.empty_state.setText("Здесь появятся результаты сканирования портов в реальном времени")
        self.empty_state.show()

    def _start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Укажите целевой IP или hostname")
            return

        try:
            ports = parse_port_range(self.port_input.text())
        except Exception:
            self.status_label.setText("Некорректный формат диапазона портов")
            return

        if not ports:
            self.status_label.setText("Список портов пуст")
            return

        self.open_count = 0
        self.high_count = 0
        self.medium_count = 0
        self._clear_results()
        self.empty_state.hide()

        timeout = self.timeout_slider.value() / 10
        concurrency = self.concurrency_slider.value()

        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.port_input.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Сканирование {target} — {len(ports)} портов...")

        self.worker = ScanWorker(target, ports, concurrency, timeout)
        self.worker.result_ready.connect(self._on_result_ready)
        self.worker.progress_updated.connect(self._on_progress_updated)
        self.worker.scan_finished.connect(self._on_scan_finished)
        self.worker.scan_error.connect(self._on_scan_error)
        self.worker.start()

    def _stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.status_label.setText("Остановка сканирования...")
            self.stop_button.setEnabled(False)

    def _on_result_ready(self, result: PortResult, findings):
        self.open_count += 1
        top = ResultCard._top_severity(findings)
        if top == Severity.HIGH:
            self.high_count += 1
        elif top == Severity.MEDIUM:
            self.medium_count += 1

        card = ResultCard(result, findings)
        self.results_layout.insertWidget(self.results_layout.count() - 1, card)

    def _on_progress_updated(self, done: int, total: int):
        percent = int((done / total) * 100) if total else 0
        self.progress_bar.setValue(percent)
        self.status_label.setText(
            f"Проверено {done}/{total} портов · Открыто: {self.open_count} · "
            f"Критично: {self.high_count} · Средне: {self.medium_count}"
        )

    def _on_scan_finished(self, elapsed: float, open_count: int):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.port_input.setEnabled(True)
        self.progress_bar.setValue(100)
        self.status_label.setText(
            f"Завершено за {elapsed:.2f} сек · Открыто портов: {open_count} · "
            f"Критично: {self.high_count} · Средне: {self.medium_count}"
        )
        if open_count == 0:
            self.empty_state.setText("Открытых портов не обнаружено")
            self.empty_state.show()

    def _on_scan_error(self, message: str):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.port_input.setEnabled(True)
        self.status_label.setText(f"Ошибка сканирования: {message}")


def launch_app():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = VanguardNetWindow()
    window.show()
    sys.exit(app.exec())