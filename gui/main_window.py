import sys
import random
import os
from datetime import datetime
from csv_simulator import CSVSimulator
from PyQt5.QtWidgets import QFileDialog
from export_manager import ExportManager
from PyQt5.QtWidgets import QMessageBox, QFileDialog
from loading_screen import LoadingScreen
from about_dialog import AboutDialog

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QColor, QFont

from capture_to_gui import PacketCapture

from alert_system import (
    play_attack_sound,
    play_unknown_sound,
    UnknownThreatPopup
)
from chart_widget import AttackPieChart

# ── Thread-safe signal class
class _Signaller(QObject):
    packet_received = pyqtSignal(str, str, str, str, str, int)


# ── Colors
BG     = "#0a0f1a"
PANEL  = "#111827"
PANEL2 = "#1a2436"
BORDER = "#1e3048"
ACCENT = "#00d4ff"
GREEN  = "#10b981"
RED    = "#ef4444"
ORANGE = "#f59e0b"
PURPLE = "#8b5cf6"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"
PA     = "#3b82f6"

# ── Sample data for Demo Mode
SAMPLE_ATTACKS = [
    ("DoS Attack",       "ATTACK",  RED,    92),
    ("Normal Traffic",   "NORMAL",  GREEN,  98),
    ("Probe",            "ATTACK",  RED,    87),
    ("DDoS",             "ATTACK",  RED,    95),
    ("Normal Traffic",   "NORMAL",  GREEN,  99),
    ("Unknown Threat",   "UNKNOWN", ORANGE, 74),
    ("R2L Attempt",      "ATTACK",  RED,    83),
    ("Normal Traffic",   "NORMAL",  GREEN,  97),
    ("Port Scan",        "ATTACK",  RED,    91),
]
SAMPLE_IPS = [
    "192.168.1.", "10.0.0.",
    "172.16.0.",  "203.0.113."
]


def rnd_ip():
    return random.choice(SAMPLE_IPS) + str(random.randint(1, 254))


def rnd_event():
    return random.choice(SAMPLE_ATTACKS)


# ════════════════════════════════════════
# METRIC CARD
# ════════════════════════════════════════
class MetricCard(QFrame):
    def __init__(self, label, value, subtitle,
                 color, trend="", trend_up=True):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {PANEL};
                border: 1px solid {BORDER};
                border-top: 2px solid {color};
                border-radius: 10px;
            }}
        """)
        self.setMinimumHeight(105)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)

        lbl = QLabel(label.upper())
        lbl.setStyleSheet(f"""
            color: {MUTED};
            font-size: 9px;
            font-weight: bold;
            letter-spacing: 1.5px;
        """)

        self.val = QLabel(value)
        self.val.setStyleSheet(f"""
            color: {color};
            font-size: 28px;
            font-weight: bold;
        """)

        sub = QLabel(subtitle)
        sub.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        lay.addWidget(lbl)
        lay.addWidget(self.val)
        lay.addWidget(sub)

        if trend:
            tc = GREEN if trend_up else RED
            ts = "▲" if trend_up else "▼"
            tw = QLabel(f"{ts} {trend}")
            tw.setStyleSheet(
                f"color: {tc}; font-size: 10px; font-weight: bold;"
            )
            lay.addWidget(tw)

    def update_value(self, new_val):
        self.val.setText(new_val)


# ════════════════════════════════════════
# MAIN WINDOW
# ════════════════════════════════════════
class QNIDSMainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle(
            "QNIDS — Quantum-Inspired Network Intrusion Detection System"
        )
        # App icon set karo
        icon_path = os.path.join(
            os.path.dirname(__file__),
            "qnids_icon.ico"
        )
        if os.path.exists(icon_path):
            from PyQt5.QtGui import QIcon
            self.setWindowIcon(QIcon(icon_path))
            
        self.setMinimumSize(1200, 720)
        self.setStyleSheet(f"background-color: {BG}; color: {TEXT};")
        

        # State variables
        self.is_paused    = False
        self.is_demo_mode = False
        self.row_count    = 0
        self.attack_count = 0
        self.packet_count = 0
        
        # Alert control
        self._last_unknown_time = 0
        self._popup_open        = False

        # Thread-safe signal setup
        self._sig = _Signaller()
        self._sig.packet_received.connect(self.add_row)

        # PacketCapture object
        self.capturer = PacketCapture(callback=self._on_packet)
        
        # CSV Simulator
        self.simulator = CSVSimulator(
            callback=self._on_packet
        )

        # Build UI
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_header())

        mid_widget = QWidget()
        mid = QHBoxLayout(mid_widget)
        mid.setContentsMargins(0, 0, 0, 0)
        mid.setSpacing(0)
        mid.addWidget(self._make_sidebar())
        mid.addWidget(self._make_content(), stretch=1)
        mid.addWidget(self._make_right_panel())
        root.addWidget(mid_widget, stretch=1)

        root.addWidget(self._make_statusbar())

        # Timers
        self.feed_timer = QTimer()
        self.feed_timer.timeout.connect(self._auto_add_row)
        self.feed_timer.start(1500)

        self.pkt_timer = QTimer()
        self.pkt_timer.timeout.connect(self._update_packets)
        self.pkt_timer.start(700)

        self.clock_timer = QTimer()
        self.clock_timer.timeout.connect(self._update_clock)
        self.clock_timer.start(1000)

    # ════════════════════════════════════
    # HEADER
    # ════════════════════════════════════
    def _make_header(self):
        hdr = QFrame()
        hdr.setFixedHeight(54)
        hdr.setStyleSheet(f"""
            QFrame {{
                background-color: {PANEL};
                border-bottom: 1px solid {BORDER};
            }}
        """)
        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(20, 0, 20, 0)

        logo = QLabel("⬡")
        logo.setStyleSheet(f"color: {ACCENT}; font-size: 22px;")

        title = QLabel("QNIDS")
        title.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 18px;
            font-weight: bold;
            letter-spacing: 2px;
        """)

        sub = QLabel("Quantum-Inspired Network Intrusion Detection System")
        sub.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        self.status_badge = QLabel("● SYSTEM ACTIVE")
        self.status_badge.setStyleSheet(f"""
            color: {GREEN};
            font-size: 11px;
            font-weight: bold;
            background: rgba(16,185,129,0.1);
            border: 1px solid rgba(16,185,129,0.3);
            border-radius: 10px;
            padding: 3px 12px;
        """)

        self.clock_lbl = QLabel("00:00:00")
        self.clock_lbl.setStyleSheet(
            f"color: {MUTED}; font-size: 12px; font-family: monospace;"
        )

        lay.addWidget(logo)
        lay.addSpacing(6)
        lay.addWidget(title)
        lay.addSpacing(10)
        lay.addWidget(sub)
        lay.addStretch()
        lay.addWidget(self.status_badge)
        lay.addSpacing(16)
        lay.addWidget(self.clock_lbl)
        return hdr

    # ════════════════════════════════════
    # SIDEBAR
    # ════════════════════════════════════
    def _make_sidebar(self):
        sb = QFrame()
        sb.setFixedWidth(200)
        sb.setStyleSheet(f"""
            QFrame {{
                background-color: {PANEL};
                border-right: 1px solid {BORDER};
            }}
        """)
        lay = QVBoxLayout(sb)
        lay.setContentsMargins(0, 12, 0, 12)
        lay.setSpacing(2)

        def sec_lbl(txt):
            l = QLabel(f"  {txt}")
            l.setStyleSheet(f"""
                color: {MUTED};
                font-size: 9px;
                font-weight: bold;
                letter-spacing: 2px;
                padding: 8px 0 3px 12px;
            """)
            return l

        def nav(icon, txt, active=False):
            b = QPushButton(f"  {icon}  {txt}")
            b.setStyleSheet(f"""
                QPushButton {{
                    text-align: left;
                    padding: 8px 12px;
                    border: none;
                    border-left: 2px solid {'%s' % ACCENT if active else 'transparent'};
                    background: {'rgba(0,212,255,0.1)' if active else 'transparent'};
                    color: {'%s' % ACCENT if active else MUTED};
                    font-size: 13px;
                }}
                QPushButton:hover {{
                    background: rgba(0,212,255,0.06);
                    color: {TEXT};
                }}
            """)
            return b

        lay.addWidget(sec_lbl("NAVIGATION"))
        lay.addWidget(nav("⬡", "Dashboard", True))
        lay.addWidget(nav("⚡", "Live Detection"))
        lay.addWidget(nav("◈", "QPSO Analysis"))
        lay.addWidget(nav("↓", "Reports"))

        lay.addWidget(sec_lbl("DATASETS"))
        lay.addWidget(nav("▣", "NSL-KDD  ✓"))
        lay.addWidget(nav("▣", "UNSW-NB15  ✓"))
        lay.addWidget(nav("+", "Load Custom"))
        lay.addWidget(sec_lbl("HELP"))
        about_btn = nav("ℹ", "About QNIDS")
        about_btn.clicked.connect(self._show_about)
        lay.addWidget(about_btn)

        lay.addStretch()

        box = QFrame()
        box.setStyleSheet(f"""
            QFrame {{
                background: {PANEL2};
                border: 1px solid {BORDER};
                border-radius: 8px;
                margin: 8px;
            }}
        """)
        bl = QVBoxLayout(box)
        bl.setContentsMargins(12, 10, 12, 10)
        bl.setSpacing(3)

        t = QLabel("QPSO STATUS")
        t.setStyleSheet(
            f"color: {MUTED}; font-size: 9px; font-weight: bold; letter-spacing: 1px;"
        )
        v = QLabel("41 → 19 Features")
        v.setStyleSheet(
            f"color: {ACCENT}; font-size: 16px; font-weight: bold;"
        )
        s = QLabel("53% dimensionality reduction")
        s.setStyleSheet(f"color: {MUTED}; font-size: 9px;")
        s.setWordWrap(True)

        bl.addWidget(t)
        bl.addWidget(v)
        bl.addWidget(s)
        lay.addWidget(box)
        return sb
    
    # About Function
    def _show_about(self):
        dialog = AboutDialog(parent=self)
        dialog.exec_()

    # ════════════════════════════════════
    # MAIN CONTENT
    # ════════════════════════════════════
    def _make_content(self):
        frame = QFrame()
        frame.setStyleSheet(f"background: {BG};")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)

        lay.addWidget(self._make_input_bar())
        lay.addWidget(self._make_toggle_bar())
        lay.addLayout(self._make_metric_cards())
        lay.addWidget(self._make_feed_panel(), stretch=1)
        return frame

    def _make_input_bar(self):
        bar = QFrame()
        bar.setFixedHeight(48)
        bar.setStyleSheet(f"""
            QFrame {{
                background: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}
        """)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 12, 0)

        # Dataset selector
        self.dataset_label = QLabel("Dataset:")
        self.dataset_label.setStyleSheet(
            f"color: {MUTED}; font-size: 11px;"
        )

        self.dataset_selector = QPushButton("NSL-KDD ▾")
        self.dataset_selector.setFixedWidth(130)
        self.dataset_selector.setStyleSheet(f"""
            QPushButton {{
                background: {PANEL2};
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: {ACCENT};
                font-size: 11px;
                font-weight: bold;
                padding: 5px 10px;
                text-align: left;
            }}
            QPushButton:hover {{
                border-color: {ACCENT};
            }}
        """)
        self.dataset_selector.clicked.connect(
            self._toggle_dataset
        )
        self.current_dataset = "NSL-KDD"

        # Speed selector
        self.speed_label = QLabel("Speed:")
        self.speed_label.setStyleSheet(
            f"color: {MUTED}; font-size: 11px;"
        )

        self.speed_btn = QPushButton("Normal ▾")
        self.speed_btn.setFixedWidth(100)
        self.speed_btn.setStyleSheet(f"""
            QPushButton {{
                background: {PANEL2};
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: {TEXT};
                font-size: 11px;
                padding: 5px 10px;
                text-align: left;
            }}
            QPushButton:hover {{
                border-color: {ACCENT};
            }}
        """)
        self.speed_btn.clicked.connect(self._toggle_speed)
        self.current_speed = "Normal"
        self.speed_values  = {
            "Slow":   1.5,
            "Normal": 0.5,
            "Fast":   0.15
        }

        # Run button
        run_btn = QPushButton("▶  RUN DETECTION")
        run_btn.setFixedWidth(155)
        run_btn.setStyleSheet(f"""
            QPushButton {{
                background: {ACCENT};
                color: #000;
                font-size: 12px;
                font-weight: bold;
                border-radius: 6px;
                padding: 7px;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{ background: #33ddff; }}
        """)
        run_btn.clicked.connect(self._on_run)

        lay.addWidget(self.dataset_label)
        lay.addSpacing(4)
        lay.addWidget(self.dataset_selector)
        lay.addSpacing(16)
        lay.addWidget(self.speed_label)
        lay.addSpacing(4)
        lay.addWidget(self.speed_btn)
        lay.addStretch()
        lay.addWidget(run_btn)
        return bar

    def _make_toggle_bar(self):
        bar = QFrame()
        bar.setFixedHeight(44)
        bar.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        self.live_btn = QPushButton("🔵  LIVE MODE  —  Real Network Packets")
        self.demo_btn = QPushButton("🔴  DEMO MODE  —  CSV Attack Simulation")

        self._set_toggle_styles(demo_active=False)

        self.live_btn.clicked.connect(lambda: self._switch_mode(demo=False))
        self.demo_btn.clicked.connect(lambda: self._switch_mode(demo=True))

        lay.addWidget(self.live_btn)
        lay.addWidget(self.demo_btn)
        return bar

    def _set_toggle_styles(self, demo_active):
        active_live = not demo_active
        active_demo = demo_active

        self.live_btn.setStyleSheet(f"""
            QPushButton {{
                background: {'rgba(59,130,246,0.2)' if active_live else 'transparent'};
                border: 1.5px solid {'%s' % PA if active_live else BORDER};
                border-radius: 8px;
                color: {'%s' % PA if active_live else MUTED};
                font-size: 12px;
                font-weight: {'bold' if active_live else 'normal'};
                padding: 8px;
            }}
            QPushButton:hover {{
                background: rgba(59,130,246,0.15);
                color: {PA};
            }}
        """)

        self.demo_btn.setStyleSheet(f"""
            QPushButton {{
                background: {'rgba(239,68,68,0.2)' if active_demo else 'transparent'};
                border: 1.5px solid {'%s' % RED if active_demo else BORDER};
                border-radius: 8px;
                color: {'%s' % RED if active_demo else MUTED};
                font-size: 12px;
                font-weight: {'bold' if active_demo else 'normal'};
                padding: 8px;
            }}
            QPushButton:hover {{
                background: rgba(239,68,68,0.15);
                color: {RED};
            }}
        """)

    def _switch_mode(self, demo):
        self.is_demo_mode = demo
        self._set_toggle_styles(demo_active=demo)

        if demo:
            # ── Demo Mode ON
            self.capturer.stop()
            self.feed_timer.stop()

            self.mode_lbl.setText("Mode: Demo/Simulation")
            self.mode_lbl.setStyleSheet(
                f"color: {RED}; font-size: 11px;"
            )
            self.status_badge.setText("● DEMO MODE")
            self.status_badge.setStyleSheet(f"""
                color: {RED};
                font-size: 11px;
                font-weight: bold;
                background: rgba(239,68,68,0.1);
                border: 1px solid rgba(239,68,68,0.3);
                border-radius: 10px;
                padding: 3px 12px;
            """)
            self.live_badge.setText("⏺ DEMO")
            self.live_badge.setStyleSheet(f"""
                color: {RED};
                font-size: 10px;
                font-weight: bold;
                background: rgba(239,68,68,0.12);
                border: 1px solid rgba(239,68,68,0.3);
                border-radius: 8px;
                padding: 2px 10px;
            """)

            # CSV file select karo
            self._load_and_start_csv()

        else:
            # ── Live Mode ON
            self.simulator.stop()
            self.feed_timer.stop()

            self.mode_lbl.setText("Mode: Live Network")
            self.mode_lbl.setStyleSheet(
                "color: #3b82f6; font-size: 11px;"
            )
            self.status_badge.setText("● LIVE CAPTURE")
            self.status_badge.setStyleSheet("""
                color: #3b82f6;
                font-size: 11px;
                font-weight: bold;
                background: rgba(59,130,246,0.1);
                border: 1px solid rgba(59,130,246,0.3);
                border-radius: 10px;
                padding: 3px 12px;
            """)

            # Live badge — Monitoring status
            self.live_badge.setText("● MONITORING")
            self.live_badge.setStyleSheet("""
                color: #3b82f6;
                font-size: 10px;
                font-weight: bold;
                background: rgba(59,130,246,0.12);
                border: 1px solid rgba(59,130,246,0.3);
                border-radius: 8px;
                padding: 2px 10px;
            """)

            # Monitoring status row add karo
            self._add_monitoring_row()

            # Real capture shuru karo
            self.capturer = PacketCapture(
                callback=self._on_packet
            )
            self.capturer.start()

    def _add_monitoring_row(self):
        """Live mode mein monitoring status show karo"""
        from datetime import datetime
        self.add_row(
            datetime.now().strftime("%H:%M:%S"),
            "---",
            "Network Monitoring Active...",
            "● MONITORING",
            "#3b82f6",
            100
        )
            
    def _make_metric_cards(self):
        row = QHBoxLayout()
        row.setSpacing(10)

        self.card_acc = MetricCard(
            "Detection Accuracy", "94.2%",
            "Hybrid QPSO+RF",
            ACCENT, "+6.1% vs baseline", True
        )
        self.card_fpr = MetricCard(
            "False Positive Rate", "4.8%",
            "vs 12.3% Classical RF",
            RED, "-7.5% improvement", True
        )
        self.card_attacks = MetricCard(
            "Attacks Detected", "0",
            "Current session",
            GREEN, "Live counting", True
        )
        self.card_packets = MetricCard(
            "Packets Analyzed", "0",
            "Processing speed",
            PURPLE, "Active", True
        )

        for c in [self.card_acc, self.card_fpr,
                  self.card_attacks, self.card_packets]:
            row.addWidget(c)
        return row

    def _make_feed_panel(self):
        wrapper = QFrame()
        wrapper.setStyleSheet(f"""
            QFrame {{
                background: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}
        """)
        lay = QVBoxLayout(wrapper)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Feed header bar
        hdr = QFrame()
        hdr.setFixedHeight(40)
        hdr.setStyleSheet(f"""
            background: {PANEL2};
            border-bottom: 1px solid {BORDER};
            border-radius: 10px 10px 0 0;
        """)
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(14, 0, 14, 0)

        feed_title = QLabel("LIVE DETECTION FEED")
        feed_title.setStyleSheet(
            f"color: {TEXT}; font-size: 12px; font-weight: bold; letter-spacing: 1px;"
        )

        self.live_badge = QLabel("● LIVE")
        self.live_badge.setStyleSheet(f"""
            color: {GREEN};
            font-size: 10px;
            font-weight: bold;
            background: rgba(16,185,129,0.12);
            border: 1px solid rgba(16,185,129,0.3);
            border-radius: 8px;
            padding: 2px 10px;
        """)

        self.event_count_lbl = QLabel("0 events")
        self.event_count_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")

        self.pause_btn = QPushButton("⏸ Pause")
        self.pause_btn.setFixedWidth(80)
        self.pause_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {BORDER};
                border-radius: 5px;
                color: {MUTED};
                font-size: 11px;
                padding: 3px 8px;
            }}
            QPushButton:hover {{
                border-color: {ACCENT};
                color: {ACCENT};
            }}
        """)
        self.pause_btn.clicked.connect(self._toggle_pause)

        clear_btn = QPushButton("✕ Clear")
        clear_btn.setFixedWidth(65)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {BORDER};
                border-radius: 5px;
                color: {MUTED};
                font-size: 11px;
                padding: 3px 8px;
            }}
            QPushButton:hover {{
                border-color: {RED};
                color: {RED};
            }}
        """)
        clear_btn.clicked.connect(self._clear_table)

        hl.addWidget(feed_title)
        hl.addSpacing(8)
        hl.addWidget(self.live_badge)
        hl.addStretch()
        hl.addWidget(self.event_count_lbl)
        hl.addSpacing(8)
        hl.addWidget(self.pause_btn)
        hl.addSpacing(4)
        hl.addWidget(clear_btn)
        lay.addWidget(hdr)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Attack Type", "Verdict", "Confidence"
        ])
        self.table.setColumnWidth(0, 85)
        self.table.setColumnWidth(1, 125)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(3, 105)
        self.table.setColumnWidth(4, 100)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background: {BG};
                border: none;
                color: {TEXT};
                font-size: 12px;
                gridline-color: rgba(30,48,72,0.5);
                outline: none;
            }}
            QHeaderView::section {{
                background: {PANEL2};
                color: {MUTED};
                font-size: 9px;
                font-weight: bold;
                letter-spacing: 1px;
                padding: 7px 8px;
                border: none;
                border-right: 1px solid {BORDER};
                border-bottom: 1px solid {BORDER};
            }}
            QTableWidget::item {{
                padding: 5px 8px;
                border-bottom: 1px solid rgba(30,48,72,0.4);
            }}
            QTableWidget::item:selected {{
                background: rgba(0,212,255,0.08);
                color: {TEXT};
            }}
            QScrollBar:vertical {{
                background: {BG};
                width: 5px;
                border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER};
                border-radius: 3px;
            }}
        """)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setDefaultSectionSize(34)

        lay.addWidget(self.table)
        return wrapper

    # ════════════════════════════════════
    # RIGHT PANEL
    # ════════════════════════════════════
    def _make_right_panel(self):
        rp = QFrame()
        rp.setFixedWidth(215)
        rp.setStyleSheet(f"""
            QFrame {{
                background: {PANEL};
                border-left: 1px solid {BORDER};
            }}
        """)
        lay = QVBoxLayout(rp)
        lay.setContentsMargins(12, 14, 12, 14)
        lay.setSpacing(12)

        # ── sec function pehle define karo
        def sec(txt):
            l = QLabel(txt)
            l.setStyleSheet(
                f"color: {MUTED}; font-size: 9px;"
                f"font-weight: bold; letter-spacing: 1.5px;"
            )
            return l

        # ── Active Models
        lay.addWidget(sec("ACTIVE MODELS"))
        for name, acc, color, active in [
            ("Hybrid RF+QPSO", "94.2%", ACCENT, True),
            ("Classical RF",   "88.1%", MUTED,  False),
            ("Decision Tree",  "85.7%", MUTED,  False),
        ]:
            row = QFrame()
            row.setStyleSheet(f"""
                background: {PANEL2};
                border: 1px solid {BORDER};
                border-radius: 6px;
            """)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(8, 5, 8, 5)
            dot = QLabel("●")
            dot.setStyleSheet(
                f"color: {color}; font-size: 10px;"
            )
            nm = QLabel(name)
            nm.setStyleSheet(
                f"color: {'%s' % TEXT if active else MUTED};"
                f"font-size: 11px;"
            )
            ac = QLabel(acc)
            ac.setStyleSheet(
                f"color: {color}; font-size: 11px;"
                f"font-weight: bold;"
            )
            rl.addWidget(dot)
            rl.addWidget(nm, stretch=1)
            rl.addWidget(ac)
            lay.addWidget(row)

        # ── Attack Distribution Chart
        lay.addWidget(sec("ATTACK DISTRIBUTION"))
        self.pie_chart = AttackPieChart()
        self.pie_chart.setFixedHeight(240)
        self.pie_chart.setStyleSheet(f"""
            background: {PANEL};
            border: 1px solid {BORDER};
            border-radius: 10px;
        """)
        lay.addWidget(self.pie_chart)

        # ── Export buttons
        # Export buttons
        lay.addStretch()
        lay.addWidget(sec("EXPORT"))

        pdf_btn = QPushButton("↓  Export PDF")
        pdf_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: {MUTED};
                font-size: 11px;
                padding: 6px;
            }}
            QPushButton:hover {{
                border-color: {ACCENT};
                color: {ACCENT};
            }}
        """)
        pdf_btn.clicked.connect(self._export_pdf)

        csv_btn = QPushButton("↓  Export CSV")
        csv_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: {MUTED};
                font-size: 11px;
                padding: 6px;
            }}
            QPushButton:hover {{
                border-color: {GREEN};
                color: {GREEN};
            }}
        """)
        csv_btn.clicked.connect(self._export_csv)

        lay.addWidget(pdf_btn)
        lay.addWidget(csv_btn)
        return rp
    
    # Export Functions
    
    def _get_exporter(self):
        """ExportManager object banao current data se"""
        return ExportManager(
            table_widget = self.table,
            accuracy     = self.card_acc.val.text(),
            fpr          = self.card_fpr.val.text(),
            attacks      = self.attack_count,
            packets      = self.packet_count,
            pie_counts   = self.pie_chart.counts
        )

    def _export_pdf(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "PDF Report Save Karo",
            os.path.join(
                os.path.expanduser("~"),
                "Desktop",
                f"QNIDS_Report_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                f".pdf"
            ),
            "PDF Files (*.pdf)"
        )
        if not filepath:
            return

        exporter = self._get_exporter()
        result   = exporter.export_pdf(filepath)

        if result:
            QMessageBox.information(
                self, "Export Complete",
                f"PDF saved successfully!\n\n{filepath}"
            )
        else:
            QMessageBox.warning(
                self, "Export Failed",
                "PDF export failed. Check console."
            )

    def _export_csv(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "CSV Report Save Karo",
            os.path.join(
                os.path.expanduser("~"),
                "Desktop",
                f"QNIDS_Report_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                f".csv"
            ),
            "CSV Files (*.csv)"
        )
        if not filepath:
            return

        exporter = self._get_exporter()
        result   = exporter.export_csv(filepath)

        if result:
            QMessageBox.information(
                self, "Export Complete",
                f"CSV saved successfully!\n\n{filepath}"
            )
        else:
            QMessageBox.warning(
                self, "Export Failed",
                "CSV export failed. Check console."
            )
            
    # ════════════════════════════════════
    # STATUS BAR
    # ════════════════════════════════════
    def _make_statusbar(self):
        bar = QFrame()
        bar.setFixedHeight(28)
        bar.setStyleSheet(f"""
            QFrame {{
                background: {PANEL};
                border-top: 1px solid {BORDER};
            }}
        """)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 0, 20, 0)
        lay.setSpacing(20)

        self.sys_lbl = QLabel("● System Ready")
        self.sys_lbl.setStyleSheet(f"color: {GREEN}; font-size: 11px;")

        self.mode_lbl = QLabel("Mode: Live Network")
        self.mode_lbl.setStyleSheet(f"color: {PA}; font-size: 11px;")

        self.pkt_lbl = QLabel("Packets: 0")
        self.pkt_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")

        dataset_lbl = QLabel("NSL-KDD Loaded")
        dataset_lbl.setStyleSheet(f"color: {ACCENT}; font-size: 11px;")

        ver = QLabel("QNIDS v1.0")
        ver.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        lay.addWidget(self.sys_lbl)
        lay.addWidget(self.mode_lbl)
        lay.addWidget(self.pkt_lbl)
        lay.addWidget(dataset_lbl)
        lay.addStretch()
        lay.addWidget(ver)
        return bar

    # ════════════════════════════════════
    # PACKET CALLBACK — thread safe
    # ════════════════════════════════════
    def _on_packet(self, ts, ip, info, verdict, color, conf):
        self._sig.packet_received.emit(ts, ip, info, verdict, color, conf)

    # ════════════════════════════════════
    # TABLE FUNCTIONS
    # ════════════════════════════════════
    def add_row(self, timestamp, ip, attack_type,
                verdict, verdict_color, confidence):
        self.table.insertRow(0)

        # Time
        t = QTableWidgetItem(timestamp)
        t.setForeground(QColor(MUTED))
        t.setFont(QFont("Courier New", 10))
        t.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(0, 0, t)

        # Source IP
        ip_i = QTableWidgetItem(ip)
        ip_i.setForeground(QColor(TEXT))
        ip_i.setFont(QFont("Courier New", 10))
        ip_i.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(0, 1, ip_i)

        # Attack Type
        at = QTableWidgetItem(f"  {attack_type}")
        if "Normal" in attack_type or "NORMAL" in attack_type:
            at.setForeground(QColor(GREEN))
        elif "Unknown" in attack_type or "UNKNOWN" in attack_type:
            at.setForeground(QColor(ORANGE))
        elif "MONITORING" in attack_type:
            at.setForeground(QColor(PA))
        else:
            at.setForeground(QColor(RED))
        self.table.setItem(0, 2, at)

        # Verdict
        vd = QTableWidgetItem(verdict)
        vd.setForeground(QColor(verdict_color))
        vd.setFont(QFont("Arial", 11, QFont.Bold))
        vd.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(0, 3, vd)

        # Confidence
        cf = QTableWidgetItem(f"{confidence}%")
        cf_color = (GREEN if confidence >= 90
                    else ORANGE if confidence >= 75
                    else RED)
        cf.setForeground(QColor(cf_color))
        cf.setFont(QFont("Courier New", 10, QFont.Bold))
        cf.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(0, 4, cf)

        # Row background alternate
        row_bg = QColor("#0d1520" if self.row_count % 2 == 0 else "#0a0f1a")
        for col in range(5):
            item = self.table.item(0, col)
            if item:
                item.setBackground(row_bg)

        # Max 100 rows
        if self.table.rowCount() > 100:
            self.table.removeRow(self.table.rowCount() - 1)

        # Update counters
        self.row_count += 1
        if verdict_color in (RED, ORANGE):
            self.attack_count += 1
            self.card_attacks.update_value(str(self.attack_count))

        self.event_count_lbl.setText(f"{self.row_count} events")
        
        # ── Alert system
        self._trigger_alert(
            attack_type, verdict,
            verdict_color, confidence,
            timestamp, ip
        )

        # ── Chart update karo
        self.pie_chart.update_counts(attack_type, verdict)

    def _trigger_alert(self, attack_type, verdict,
                       color, confidence,
                       ts, ip):
        """
        Attack type ke hisaab se alert trigger karo
        """
        import time

        if 'NORMAL' in verdict:
            return

        if 'UNKNOWN' in verdict:
            # Unknown threat — sound + popup
            play_unknown_sound()

            # Popup spam rokne ke liye — 5 sec gap
            now = time.time()
            if not self._popup_open and \
               (now - self._last_unknown_time) > 5:
                self._last_unknown_time = now
                self._popup_open        = True
                self._show_unknown_popup(
                    attack_type, ip, ts
                )

        elif 'ATTACK' in verdict:
            # Known attack — sirf sound
            if confidence >= 85:
                play_attack_sound()

    def _show_unknown_popup(self, attack_info, ip, ts):
        """Unknown threat popup show karo"""
        popup = UnknownThreatPopup(
            parent      = self,
            attack_info = attack_info,
            ip          = ip,
            ts          = ts
        )
        popup.finished.connect(
            lambda: setattr(self, '_popup_open', False)
        )

        # Center pe show karo
        popup.move(
            self.x() + (self.width()  - popup.width())  // 2,
            self.y() + (self.height() - popup.height()) // 2
        )
        popup.show()
        
    def _auto_add_row(self):
        if self.is_paused:
            return
        attack_type, verdict, color, conf = rnd_event()
        conf = max(60, min(99, conf + random.randint(-4, 4)))
        self.add_row(
            datetime.now().strftime("%H:%M:%S"),
            rnd_ip(), attack_type, verdict, color, conf
        )

    def _toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_btn.setText("▶ Resume")
            self.live_badge.setText("⏸ PAUSED")
            self.live_badge.setStyleSheet(f"""
                color: {ORANGE}; font-size: 10px; font-weight: bold;
                background: rgba(245,158,11,0.12);
                border: 1px solid rgba(245,158,11,0.3);
                border-radius: 8px; padding: 2px 10px;
            """)
        else:
            self.pause_btn.setText("⏸ Pause")
            self.live_badge.setText("● LIVE")
            self.live_badge.setStyleSheet(f"""
                color: {GREEN}; font-size: 10px; font-weight: bold;
                background: rgba(16,185,129,0.12);
                border: 1px solid rgba(16,185,129,0.3);
                border-radius: 8px; padding: 2px 10px;
            """)

    def _clear_table(self):
        self.table.setRowCount(0)
        self.row_count    = 0
        self.attack_count = 0
        self.event_count_lbl.setText("0 events")
        self.card_attacks.update_value("0")

    # ════════════════════════════════════
    # TIMERS
    # ════════════════════════════════════
    def _update_packets(self):
        self.packet_count += random.randint(6, 14)
        display = (f"{self.packet_count/1000:.1f}K"
                   if self.packet_count >= 1000
                   else str(self.packet_count))
        self.card_packets.update_value(display)
        self.pkt_lbl.setText(f"Packets: {display}")

    def _update_clock(self):
        self.clock_lbl.setText(datetime.now().strftime("%H:%M:%S"))

    def _on_run(self):
        self.is_paused = False
        self.pause_btn.setText("⏸ Pause")
        self.live_badge.setText("● LIVE")
        self.live_badge.setStyleSheet(f"""
            color: {GREEN}; font-size: 10px; font-weight: bold;
            background: rgba(16,185,129,0.12);
            border: 1px solid rgba(16,185,129,0.3);
            border-radius: 8px; padding: 2px 10px;
        """)
        
    def _toggle_dataset(self):
        """NSL-KDD aur UNSW-NB15 ke beech switch karo"""
        if self.current_dataset == "NSL-KDD":
            self.current_dataset = "UNSW-NB15"
            self.dataset_selector.setText("UNSW-NB15 ▾")
            self.dataset_selector.setStyleSheet(f"""
                QPushButton {{
                    background: {PANEL2};
                    border: 1px solid {PURPLE};
                    border-radius: 6px;
                    color: {PURPLE};
                    font-size: 11px;
                    font-weight: bold;
                    padding: 5px 10px;
                    text-align: left;
                }}
                QPushButton:hover {{
                    border-color: {PURPLE};
                }}
            """)
            # UNSW model load karo
            self._load_unsw_model()
        else:
            self.current_dataset = "NSL-KDD"
            self.dataset_selector.setText("NSL-KDD ▾")
            self.dataset_selector.setStyleSheet(f"""
                QPushButton {{
                    background: {PANEL2};
                    border: 1px solid {BORDER};
                    border-radius: 6px;
                    color: {ACCENT};
                    font-size: 11px;
                    font-weight: bold;
                    padding: 5px 10px;
                    text-align: left;
                }}
                QPushButton:hover {{
                    border-color: {ACCENT};
                }}
            """)
            # NSL-KDD model wapas load karo
            self._load_nslkdd_model()

        print(f"Dataset switched to: {self.current_dataset}")

    def _toggle_speed(self):
        """Speed cycle karo: Slow → Normal → Fast"""
        speeds = ["Slow", "Normal", "Fast"]
        idx    = speeds.index(self.current_speed)
        self.current_speed = speeds[(idx + 1) % len(speeds)]

        colors = {
            "Slow":   MUTED,
            "Normal": TEXT,
            "Fast":   GREEN
        }
        color = colors[self.current_speed]

        self.speed_btn.setText(f"{self.current_speed} ▾")
        self.speed_btn.setStyleSheet(f"""
            QPushButton {{
                background: {PANEL2};
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: {color};
                font-size: 11px;
                font-weight: bold;
                padding: 5px 10px;
                text-align: left;
            }}
            QPushButton:hover {{ border-color: {ACCENT}; }}
        """)

        # Simulator speed update karo
        new_speed = self.speed_values[self.current_speed]
        self.simulator.set_speed(new_speed)
        print(f"Speed: {self.current_speed} ({new_speed}s)")

    def _load_unsw_model(self):
        """Load UNSW-NB15 model"""
        try:
            self.simulator.predictor.load_unsw_model()
            self.sys_lbl.setText("● UNSW-NB15 Active")
            self.sys_lbl.setStyleSheet(
                f"color: {PURPLE}; font-size: 11px;"
            )
            print("UNSW model loaded")
        except Exception as e:
            print(f"UNSW model error: {e}")

    def _load_nslkdd_model(self):
        """NSL-KDD model load again"""
        try:
            self.simulator.predictor.load_nslkdd_model()
            self.sys_lbl.setText("● System Ready")
            self.sys_lbl.setStyleSheet(
                f"color: {GREEN}; font-size: 11px;"
            )
            print("NSL-KDD model loaded")
        except Exception as e:
            print(f"NSL-KDD model error: {e}")

    def closeEvent(self, event):
        self.capturer.stop()
        self.simulator.stop()
        event.accept()
        
    # Load CSV file
    def _load_and_start_csv(self):
        # File dialog kholo
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "NSL-KDD CSV File Select Karo",
            "D:\\QNIDS-Project\\data",
            "CSV/Text Files (*.csv *.txt);;All Files (*)"
        )

        if not filepath:
            # User ne cancel kiya
            print("No file selected")
            return

        # CSV load karo
        loaded = self.simulator.load_csv(filepath)

        if loaded:
            # Simulation shuru karo
            self.simulator.start()
            self.live_badge.setText("● SIMULATING")
            self.live_badge.setStyleSheet(f"""
                color: {RED};
                font-size: 10px;
                font-weight: bold;
                background: rgba(239,68,68,0.12);
                border: 1px solid rgba(239,68,68,0.3);
                border-radius: 8px;
                padding: 2px 10px;
            """)
            print("Simulation started!")
        else:
            print("CSV load failed")
            
    def _toggle_pause(self):
        self.is_paused = not self.is_paused

        if self.is_paused:
            self.pause_btn.setText("▶ Resume")
            self.live_badge.setText("⏸ PAUSED")
            self.live_badge.setStyleSheet(f"""
                color: {ORANGE};
                font-size: 10px;
                font-weight: bold;
                background: rgba(245,158,11,0.12);
                border: 1px solid rgba(245,158,11,0.3);
                border-radius: 8px;
                padding: 2px 10px;
            """)
            # CSV simulator bhi pause karo
            self.simulator.pause()

        else:
            self.pause_btn.setText("⏸ Pause")
            self.live_badge.setText("● LIVE")
            self.live_badge.setStyleSheet(f"""
                color: {GREEN};
                font-size: 10px;
                font-weight: bold;
                background: rgba(16,185,129,0.12);
                border: 1px solid rgba(16,185,129,0.3);
                border-radius: 8px;
                padding: 2px 10px;
            """)
            # CSV simulator resume karo
            self.simulator.resume()


# ── Run
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Loading screen show karo
    splash = LoadingScreen()
    splash.show()
    app.processEvents()

    # Window banao
    window = QNIDSMainWindow()

    # 2 second baad loading band karo
    QTimer.singleShot(2000, splash.close)
    QTimer.singleShot(2200, window.show)

    sys.exit(app.exec_())