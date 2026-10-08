"""
threat_panel.py — Persistent Threat Side Panel
=================================================
Replaces UnknownThreatPopup's per-event modal popups with a single
always-visible dock panel: a scrollable threat list + a detail/AI
analysis section for whichever threat is selected.
"""

import winsound
import threading
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTextEdit, QApplication, QProgressBar,
    QListWidget, QListWidgetItem, QSplitter, QScrollArea
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QColor

# ── Theme (same palette as alert_system.py)
BG     = "#0a0f1a"
PANEL  = "#111827"
PANEL2 = "#1a2436"
BORDER = "#1e3048"
ACCENT = "#00d4ff"
GREEN  = "#10b981"
RED    = "#ef4444"
ORANGE = "#f59e0b"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"


def play_attack_sound():
    def _play():
        try:
            winsound.Beep(1000, 200)
            winsound.Beep(800, 200)
        except Exception as e:
            print(f"[threat_panel] Sound error: {e}")
    threading.Thread(target=_play, daemon=True).start()


def play_unknown_sound():
    def _play():
        try:
            for _ in range(3):
                winsound.Beep(1500, 150)
                winsound.Beep(500, 150)
        except Exception as e:
            print(f"[threat_panel] Sound error: {e}")
    threading.Thread(target=_play, daemon=True).start()


class _AISignal(QObject):
    result_ready = pyqtSignal(str, str)  # (threat_id, result_text)


class _DualLayerPanel(QFrame):
    """Unchanged from alert_system.py — RF confidence + IF score display."""

    def __init__(self, rf_confidence: int, if_score: float, decision: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"QFrame {{ background: {PANEL2}; border: 1px solid {BORDER}; border-radius: 8px; }}")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(8)

        if decision == "KNOWN_ATTACK":
            d_color, d_text = RED, "▲  KNOWN ATTACK DETECTED"
        elif decision == "SUSPICIOUS":
            d_color, d_text = ORANGE, "◆  SUSPICIOUS / ZERO-DAY RISK"
        else:
            d_color, d_text = GREEN, "●  NORMAL TRAFFIC"

        badge = QLabel(d_text)
        badge.setStyleSheet(f"color: {d_color}; font-size: 12px; font-weight: bold; letter-spacing: 1px; padding: 4px 0;")
        badge.setAlignment(Qt.AlignCenter)
        lay.addWidget(badge)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {BORDER};")
        lay.addWidget(sep)

        l1_lbl = QLabel("Layer 1 — Random Forest Confidence")
        l1_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px; font-weight: bold;")
        lay.addWidget(l1_lbl)

        rf_row = QHBoxLayout()
        rf_bar = QProgressBar()
        rf_bar.setFixedHeight(10)
        rf_bar.setRange(0, 100)
        rf_bar.setValue(rf_confidence)
        rf_bar.setTextVisible(False)
        bar_color = GREEN if rf_confidence >= 85 else ORANGE if rf_confidence >= 70 else RED
        rf_bar.setStyleSheet(f"""
            QProgressBar {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 5px; }}
            QProgressBar::chunk {{ background: {bar_color}; border-radius: 5px; }}
        """)
        rf_val = QLabel(f"{rf_confidence}%")
        rf_val.setFixedWidth(38)
        rf_val.setStyleSheet(f"color: {bar_color}; font-size: 12px; font-weight: bold;")
        rf_val.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        rf_row.addWidget(rf_bar, stretch=1)
        rf_row.addSpacing(8)
        rf_row.addWidget(rf_val)
        lay.addLayout(rf_row)

        l2_lbl = QLabel("Layer 2 — Isolation Forest Anomaly Score")
        l2_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px; font-weight: bold;")
        lay.addWidget(l2_lbl)

        if_row = QHBoxLayout()
        if if_score < -0.20:
            if_color, if_desc = RED, "High Anomaly — Zero-Day Risk"
        elif if_score < 0:
            if_color, if_desc = ORANGE, "Borderline — Monitor Closely"
        else:
            if_color, if_desc = GREEN, "Normal Range"

        if_score_lbl = QLabel(f"{if_score:+.4f}")
        if_score_lbl.setStyleSheet(f"color: {if_color}; font-size: 14px; font-weight: bold; font-family: monospace;")
        if_desc_lbl = QLabel(if_desc)
        if_desc_lbl.setStyleSheet(f"color: {if_color}; font-size: 10px;")

        if_row.addWidget(if_score_lbl)
        if_row.addSpacing(10)
        if_row.addWidget(if_desc_lbl)
        if_row.addStretch()
        lay.addLayout(if_row)


class ThreatSidePanel(QWidget):
    """
    Persistent dashboard panel — always visible, never blocks.

    Top half: scrollable list of every SUSPICIOUS / KNOWN_ATTACK event
               (newest on top), color-coded.
    Bottom half: detail + dual-layer scores + AI analysis for whichever
                 threat is currently selected in the list.

    Usage from main_window.py:
        self.threat_panel = ThreatSidePanel()
        # instead of creating UnknownThreatPopup(...), call:
        self.threat_panel.add_threat(
            attack_info=..., ip=..., ts=..., confidence=...,
            protocol=..., if_score=..., decision=...
        )
    """

    MAX_THREATS = 500  # cap memory growth on long demo runs

    def __init__(self, parent=None):
        super().__init__(parent)
        self._threats = {}      # threat_id -> dict of its data
        self._next_id = 0
        self._ai_sig = _AISignal()
        self._ai_sig.result_ready.connect(self._show_ai_result)
        self._build_ui()

    # ────────────────────────────────────────────────────
    # UI
    # ────────────────────────────────────────────────────
    def _build_ui(self):
        self.setStyleSheet(f"background: {BG};")
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)

        header = QLabel("⚠  THREAT PANEL")
        header.setStyleSheet(f"color: {ORANGE}; font-size: 13px; font-weight: bold; letter-spacing: 1px;")
        root.addWidget(header)

        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet(f"QSplitter::handle {{ background: {BORDER}; }}")

        # ── Threat list (top)
        list_frame = QFrame()
        list_frame.setStyleSheet(f"background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px;")
        ll = QVBoxLayout(list_frame)
        ll.setContentsMargins(8, 8, 8, 8)

        list_hdr = QHBoxLayout()
        self.count_lbl = QLabel("0 threats")
        self.count_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px; font-weight: bold;")
        clear_btn = QPushButton("Clear")
        clear_btn.setFixedWidth(60)
        clear_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER};
                border-radius: 4px; color: {MUTED}; font-size: 10px; padding: 3px; }}
            QPushButton:hover {{ border-color: {RED}; color: {RED}; }}
        """)
        clear_btn.clicked.connect(self._clear_all)
        list_hdr.addWidget(self.count_lbl)
        list_hdr.addStretch()
        list_hdr.addWidget(clear_btn)
        ll.addLayout(list_hdr)

        self.threat_list = QListWidget()
        self.threat_list.setStyleSheet(f"""
            QListWidget {{ background: {PANEL}; border: none; color: {TEXT}; font-size: 11px; }}
            QListWidget::item {{ padding: 8px; border-bottom: 1px solid {BORDER}; }}
            QListWidget::item:selected {{ background: {PANEL2}; border-left: 3px solid {ACCENT}; }}
        """)
        self.threat_list.currentItemChanged.connect(self._on_select)
        ll.addWidget(self.threat_list)
        splitter.addWidget(list_frame)
        
        self.threat_list.setWordWrap(True)
        self.threat_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # ── Detail + AI panel (bottom)
        detail_frame = QFrame()
        detail_frame.setStyleSheet(f"background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px;")
        self.detail_layout = QVBoxLayout(detail_frame)
        self.detail_layout.setContentsMargins(12, 12, 12, 12)
        self.detail_layout.setSpacing(8)

        self.placeholder_lbl = QLabel("Select a threat from the list above to see details and run AI analysis.")
        self.placeholder_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        self.placeholder_lbl.setWordWrap(True)
        self.detail_layout.addWidget(self.placeholder_lbl)
        self.detail_layout.addStretch()

        scroll = QScrollArea()
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(detail_frame)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        splitter.addWidget(scroll)

        splitter.setSizes([260, 400])
        root.addWidget(splitter)

        self._detail_frame = detail_frame
        self._current_id = None

    # ────────────────────────────────────────────────────
    # Public API — call this instead of UnknownThreatPopup(...)
    # ────────────────────────────────────────────────────
    def add_threat(self, attack_info="", ip="", ts="", confidence=0,
                   protocol="TCP", if_score=0.0, decision="SUSPICIOUS"):
        threat_id = str(self._next_id)
        self._next_id += 1

        self._threats[threat_id] = {
            "attack_info": attack_info, "ip": ip, "ts": ts,
            "confidence": confidence, "protocol": protocol,
            "if_score": if_score, "decision": decision,
            "ai_result": None,
        }

        color = RED if decision == "KNOWN_ATTACK" else ORANGE
        icon = "▲" if decision == "KNOWN_ATTACK" else "◆"
        item = QListWidgetItem(f"{icon}  {ts}   {ip}\n{attack_info}")
        item.setForeground(QColor(color))
        item.setData(Qt.UserRole, threat_id)
        self.threat_list.insertItem(0, item)  # newest on top
        self.threat_list.setCurrentItem(item)  # auto-select newest

        # Trim oldest if over cap
        while self.threat_list.count() > self.MAX_THREATS:
            old_item = self.threat_list.takeItem(self.threat_list.count() - 1)
            old_id = old_item.data(Qt.UserRole)
            self._threats.pop(old_id, None)

        self.count_lbl.setText(f"{self.threat_list.count()} threats")

        # Sound — non-blocking, safe even during a burst
        if decision == "KNOWN_ATTACK":
            play_attack_sound()
        else:
            play_unknown_sound()

        return threat_id

    # ────────────────────────────────────────────────────
    # Selection → render detail panel
    # ────────────────────────────────────────────────────
    def _on_select(self, current, _previous):
        if current is None:
            return
        threat_id = current.data(Qt.UserRole)
        self._current_id = threat_id
        self._render_detail(threat_id)
        
    def _clear_layout(self, layout):
        """Recursively empty a layout — handles nested QHBoxLayout/
        QVBoxLayout rows (added via addLayout), not just plain widgets.
        A shallow clear (checking child.widget() only) leaves nested-
        layout widgets detached but still alive, causing stale overlapping
        labels to linger on screen."""
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
            else:
                child_layout = item.layout()
                if child_layout is not None:
                    self._clear_layout(child_layout)

    def _render_detail(self, threat_id):
        self._clear_layout(self.detail_layout)


        data = self._threats.get(threat_id)
        if not data:
            return

        for label, value, color in [
            ("Time:",      data["ts"],          TEXT),
            ("Source IP:", data["ip"],          ACCENT),
            ("Pattern:",   data["attack_info"], RED if data["decision"] == "KNOWN_ATTACK" else ORANGE),
            ("Protocol:",  data["protocol"],    TEXT),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(75)
            lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px; font-weight: bold;")
            val = QLabel(str(value))
            val.setWordWrap(True)
            val.setMaximumWidth(210)
            val.setStyleSheet(f"color: {color}; font-size: 11px;")
            row.addWidget(lbl)
            row.addWidget(val, stretch=1)
            self.detail_layout.addLayout(row)

        dl_panel = _DualLayerPanel(
            rf_confidence=data["confidence"],
            if_score=data["if_score"],
            decision=data["decision"],
        )
        self.detail_layout.addWidget(dl_panel)

        # ── AI section
        ai_hdr = QHBoxLayout()
        ai_lbl = QLabel("🤖 AI THREAT ANALYSIS")
        ai_lbl.setStyleSheet(f"color: {ACCENT}; font-size: 11px; font-weight: bold; letter-spacing: 1px;")
        analyze_btn = QPushButton("⚡ Analyze")
        analyze_btn.setFixedWidth(95)
        analyze_btn.setStyleSheet(f"""
            QPushButton {{ background: rgba(0,212,255,0.15); border: 1px solid {ACCENT};
                border-radius: 5px; color: {ACCENT}; font-size: 10px; font-weight: bold; padding: 4px 8px; }}
            QPushButton:hover {{ background: rgba(0,212,255,0.25); }}
            QPushButton:disabled {{ color: {MUTED}; border-color: {BORDER}; background: transparent; }}
        """)
        analyze_btn.clicked.connect(lambda: self._start_analysis(threat_id, analyze_btn))
        ai_hdr.addWidget(ai_lbl)
        ai_hdr.addStretch()
        ai_hdr.addWidget(analyze_btn)
        self.detail_layout.addLayout(ai_hdr)

        ai_result = QTextEdit()
        ai_result.setFixedHeight(110)
        ai_result.setReadOnly(True)
        ai_result.setStyleSheet(f"""
            QTextEdit {{ background: {PANEL2}; border: 1px solid {BORDER};
                border-radius: 6px; color: {TEXT}; font-size: 10px; padding: 6px; }}
        """)
        if data["ai_result"]:
            ai_result.setPlainText(data["ai_result"])
        else:
            ai_result.setPlaceholderText("Click '⚡ Analyze' for AI threat analysis...")
        self.detail_layout.addWidget(ai_result)
        self._current_ai_box = ai_result
        self._current_analyze_btn = analyze_btn

        copy_btn = QPushButton("📋 Copy details")
        copy_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: 1px solid {BORDER};
                border-radius: 5px; color: {MUTED}; font-size: 11px; padding: 5px; }}
            QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
        """)
        copy_btn.clicked.connect(lambda: self._copy_details(threat_id))
        self.detail_layout.addWidget(copy_btn)

        self.detail_layout.addStretch()

    # ────────────────────────────────────────────────────
    # AI analysis — identical call pattern to alert_system.py,
    # but result is routed to this threat's record + box, and
    # a NEW threat selected mid-analysis does not get blocked.
    # ────────────────────────────────────────────────────
    def _start_analysis(self, threat_id, btn):
        btn.setEnabled(False)
        btn.setText("Analyzing...")
        if threat_id == self._current_id:
            self._current_ai_box.setPlainText("🤖 Analyzing threat pattern...\nPlease wait...")

        data = self._threats.get(threat_id)
        if not data:
            return

        try:
            from ai_analyzer import AIAnalyzer
            analyzer = AIAnalyzer()
            analyzer.analyze(
                attack_info=data["attack_info"],
                ip=data["ip"],
                confidence=data["confidence"],
                protocol=data["protocol"],
                callback=lambda result: self._ai_sig.result_ready.emit(threat_id, result),
            )
        except Exception as e:
            err = f"Error: {str(e)}"
            self._threats[threat_id]["ai_result"] = err
            if threat_id == self._current_id:
                self._current_ai_box.setPlainText(err)
                btn.setEnabled(True)
                btn.setText("⚡ Analyze")

    def _show_ai_result(self, threat_id, result):
        if threat_id in self._threats:
            self._threats[threat_id]["ai_result"] = result
        # Only touch live widgets if that threat is still the one selected
        if threat_id == self._current_id and hasattr(self, "_current_ai_box"):
            self._current_ai_box.setPlainText(result)
            self._current_analyze_btn.setEnabled(True)
            self._current_analyze_btn.setText("🔄 Re-analyze")

    def _copy_details(self, threat_id):
        data = self._threats.get(threat_id)
        if not data:
            return
        details = (
            f"QNIDS Threat Report\n{'=' * 40}\n"
            f"Time:        {data['ts']}\n"
            f"Source IP:   {data['ip']}\n"
            f"Pattern:     {data['attack_info']}\n"
            f"Decision:    {data['decision']}\n"
            f"RF Conf:     {data['confidence']}%\n"
            f"IF Score:    {data['if_score']:+.4f}\n\n"
            f"AI Analysis:\n{data['ai_result'] or '(not analyzed yet)'}"
        )
        QApplication.clipboard().setText(details)

    def _clear_all(self):
        self.threat_list.clear()
        self._threats.clear()
        self.count_lbl.setText("0 threats")
        self._current_id = None

        self._clear_layout(self.detail_layout)

        placeholder = QLabel(
            "Select a threat from the list above to see details and run AI analysis."
        )
        placeholder.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        placeholder.setWordWrap(True)
        self.detail_layout.addWidget(placeholder)
        self.detail_layout.addStretch()