import winsound
import threading
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

# Colors
RED    = "#ef4444"
ORANGE = "#f59e0b"
GREEN  = "#10b981"
BG     = "#0a0f1a"
PANEL  = "#111827"
BORDER = "#1e3048"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"


def play_attack_sound():
    """Known attack sound — short beep"""
    def _play():
        try:
            winsound.Beep(1000, 200)
            winsound.Beep(800,  200)
        except Exception as e:
            print(f"Sound error: {e}")
    threading.Thread(target=_play, daemon=True).start()


def play_unknown_sound():
    """Unknown threat sound — urgent beeps"""
    def _play():
        try:
            for _ in range(3):
                winsound.Beep(1500, 150)
                winsound.Beep(500,  150)
        except Exception as e:
            print(f"Sound error: {e}")
    threading.Thread(target=_play, daemon=True).start()


class UnknownThreatPopup(QDialog):
    """
    Unknown threat detected hone pe
    yeh warning popup show hota hai
    """

    def __init__(self, parent=None,
                 attack_info="", ip="", ts=""):
        super().__init__(parent)
        self.setWindowTitle("⚠ Unknown Threat Detected!")
        self.setFixedSize(420, 280)
        self.setModal(False)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {BG};
                border: 2px solid {ORANGE};
                border-radius: 12px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setFixedHeight(56)
        header.setStyleSheet(f"""
            background: rgba(245,158,11,0.15);
            border-bottom: 1px solid {ORANGE};
            border-radius: 10px 10px 0 0;
        """)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 0, 16, 0)

        icon = QLabel("⚠")
        icon.setStyleSheet(f"""
            color: {ORANGE};
            font-size: 24px;
        """)

        title = QLabel("UNKNOWN THREAT DETECTED")
        title.setStyleSheet(f"""
            color: {ORANGE};
            font-size: 14px;
            font-weight: bold;
            letter-spacing: 1px;
        """)

        hl.addWidget(icon)
        hl.addSpacing(8)
        hl.addWidget(title)
        hl.addStretch()
        layout.addWidget(header)

        # Content
        content = QFrame()
        content.setStyleSheet(
            f"background: {PANEL}; padding: 0px;"
        )
        cl = QVBoxLayout(content)
        cl.setContentsMargins(20, 16, 20, 16)
        cl.setSpacing(10)

        desc = QLabel(
            "An anomalous network pattern was detected\n"
            "that does not match any known attack signature."
        )
        desc.setStyleSheet(
            f"color: {TEXT}; font-size: 12px;"
        )
        desc.setWordWrap(True)

        # Info box
        info_box = QFrame()
        info_box.setStyleSheet(f"""
            background: rgba(245,158,11,0.08);
            border: 1px solid rgba(245,158,11,0.3);
            border-radius: 6px;
            padding: 4px;
        """)
        il = QVBoxLayout(info_box)
        il.setContentsMargins(12, 8, 12, 8)
        il.setSpacing(4)

        for label, value in [
            ("Time:",        ts),
            ("Source IP:",   ip),
            ("Pattern:",     attack_info),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"color: {MUTED}; font-size: 11px;"
            )
            lbl.setFixedWidth(80)
            val = QLabel(value)
            val.setStyleSheet(
                f"color: {ORANGE}; font-size: 11px; font-weight: bold;"
            )
            row.addWidget(lbl)
            row.addWidget(val)
            row.addStretch()
            il.addLayout(row)

        cl.addWidget(desc)
        cl.addWidget(info_box)
        layout.addWidget(content)

        # Buttons
        btn_frame = QFrame()
        btn_frame.setFixedHeight(52)
        btn_frame.setStyleSheet(f"""
            background: {BG};
            border-top: 1px solid {BORDER};
            border-radius: 0 0 10px 10px;
        """)
        bl = QHBoxLayout(btn_frame)
        bl.setContentsMargins(16, 0, 16, 0)
        bl.setSpacing(10)

        # Countdown label
        self._countdown = 10
        self.timer_lbl = QLabel(
            f"Auto-close in {self._countdown}s"
        )
        self.timer_lbl.setStyleSheet(
            f"color: {MUTED}; font-size: 10px;"
        )

        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.setFixedWidth(90)
        dismiss_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: {MUTED};
                font-size: 11px;
                padding: 6px;
            }}
            QPushButton:hover {{
                border-color: {ORANGE};
                color: {ORANGE};
            }}
        """)
        dismiss_btn.clicked.connect(self.close)

        investigate_btn = QPushButton("Investigate")
        investigate_btn.setFixedWidth(100)
        investigate_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgba(245,158,11,0.2);
                border: 1px solid {ORANGE};
                border-radius: 6px;
                color: {ORANGE};
                font-size: 11px;
                font-weight: bold;
                padding: 6px;
            }}
            QPushButton:hover {{
                background: rgba(245,158,11,0.35);
            }}
        """)
        investigate_btn.clicked.connect(self.close)

        bl.addWidget(self.timer_lbl)
        bl.addStretch()
        bl.addWidget(dismiss_btn)
        bl.addWidget(investigate_btn)
        layout.addWidget(btn_frame)

        # Auto-close timer
        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._tick)
        self._auto_timer.start(1000)

    def _tick(self):
        self._countdown -= 1
        self.timer_lbl.setText(
            f"Auto-close in {self._countdown}s"
        )
        if self._countdown <= 0:
            self._auto_timer.stop()
            self.close()