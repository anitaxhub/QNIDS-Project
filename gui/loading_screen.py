from PyQt5.QtWidgets import QSplashScreen
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QPainter, QColor, QFont


class LoadingScreen(QSplashScreen):

    def __init__(self):
        pixmap = QPixmap(500, 300)
        pixmap.fill(QColor('#0a0f1a'))
        super().__init__(pixmap)
        self.setWindowFlag(Qt.WindowStaysOnTopHint)
        self._draw()

    def _draw(self):
        painter = QPainter(self.pixmap())
        painter.setRenderHint(QPainter.Antialiasing)

        # Background
        painter.fillRect(
            0, 0, 500, 300,
            QColor('#0a0f1a')
        )

        # Border
        painter.setPen(QColor('#00d4ff'))
        painter.drawRect(1, 1, 498, 298)

        # Title
        painter.setFont(
            QFont('Arial', 32, QFont.Bold)
        )
        painter.setPen(QColor('#00d4ff'))
        painter.drawText(
            0, 80, 500, 60,
            Qt.AlignCenter, "QNIDS"
        )

        # Subtitle
        painter.setFont(QFont('Arial', 10))
        painter.setPen(QColor('#64748b'))
        painter.drawText(
            0, 150, 500, 30,
            Qt.AlignCenter,
            "Quantum-Inspired Network "
            "Intrusion Detection System"
        )

        # Loading text
        painter.setFont(QFont('Arial', 9))
        painter.setPen(QColor('#3b82f6'))
        painter.drawText(
            0, 220, 500, 30,
            Qt.AlignCenter,
            "Loading models and initializing..."
        )

        # Version
        painter.setFont(QFont('Arial', 8))
        painter.setPen(QColor('#1e3048'))
        painter.drawText(
            0, 275, 500, 20,
            Qt.AlignCenter,
            "v1.0  |  Final Year Project  |  BSCS 2021-2025"
        )

        painter.end()
        self.setPixmap(self.pixmap())