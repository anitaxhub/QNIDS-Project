from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame
)
from PyQt5.QtCore import Qt

BG     = "#0a0f1a"
PANEL  = "#111827"
PANEL2 = "#1a2436"
BORDER = "#1e3048"
ACCENT = "#00d4ff"
GREEN  = "#10b981"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"


class AboutDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About QNIDS")
        self.setFixedSize(440, 380)
        self.setStyleSheet(f"""
            QDialog {{
                background: {BG};
                border: 1px solid {BORDER};
            }}
        """)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setFixedHeight(100)
        header.setStyleSheet(f"""
            background: linear-gradient(
                {PANEL}, {PANEL2}
            );
            border-bottom: 1px solid {BORDER};
        """)
        hl = QVBoxLayout(header)
        hl.setAlignment(Qt.AlignCenter)

        logo = QLabel("⬡  QNIDS")
        logo.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 26px;
            font-weight: bold;
            letter-spacing: 3px;
        """)
        logo.setAlignment(Qt.AlignCenter)

        sub = QLabel(
            "Quantum-Inspired Network "
            "Intrusion Detection System"
        )
        sub.setStyleSheet(
            f"color: {MUTED}; font-size: 10px;"
        )
        sub.setAlignment(Qt.AlignCenter)

        hl.addWidget(logo)
        hl.addWidget(sub)
        layout.addWidget(header)

        # Info section
        info = QFrame()
        info.setStyleSheet(f"background: {PANEL};")
        il = QVBoxLayout(info)
        il.setContentsMargins(28, 20, 28, 20)
        il.setSpacing(12)

        # ── Yahan apni info bharein
        fields = [
            ("Version",    "1.0.0"),
            ("Project",    "Final Year Project — BSCS"),
            ("Session",    "2021 – 2025"),
            ("Supervisor", "Prof. ___________"),
            ("Team",       "Person A  |  Person B"),
            ("Algorithm",  "QPSO + Random Forest"),
            ("Datasets",   "NSL-KDD  |  UNSW-NB15"),
        ]

        for label, value in fields:
            row = QHBoxLayout()

            lbl = QLabel(label)
            lbl.setFixedWidth(90)
            lbl.setStyleSheet(f"""
                color: {MUTED};
                font-size: 11px;
                font-weight: bold;
            """)

            val = QLabel(value)
            val.setStyleSheet(f"""
                color: {TEXT};
                font-size: 11px;
            """)

            row.addWidget(lbl)
            row.addWidget(val)
            row.addStretch()
            il.addLayout(row)

        layout.addWidget(info, stretch=1)

        # Footer
        footer = QFrame()
        footer.setFixedHeight(50)
        footer.setStyleSheet(f"""
            background: {PANEL2};
            border-top: 1px solid {BORDER};
        """)
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(16, 0, 16, 0)

        copy_lbl = QLabel(
            "© 2025 QNIDS Team — All Rights Reserved"
        )
        copy_lbl.setStyleSheet(
            f"color: {MUTED}; font-size: 10px;"
        )

        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(80)
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background: {ACCENT};
                color: #000;
                font-weight: bold;
                border-radius: 6px;
                padding: 6px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background: #33ddff;
            }}
        """)
        close_btn.clicked.connect(self.close)

        fl.addWidget(copy_lbl)
        fl.addStretch()
        fl.addWidget(close_btn)
        layout.addWidget(footer)