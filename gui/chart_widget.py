import numpy as np
import matplotlib
matplotlib.use('Agg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QImage

# ── Theme
BG     = "#0a0f1a"
PANEL  = "#111827"
PANEL2 = "#1a2436"
BORDER = "#1e3048"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"
GREEN  = "#10b981"
RED    = "#ef4444"
ORANGE = "#f59e0b"
YELLOW = "#eab308"
ACCENT = "#00d4ff"

# ── CIC-IDS2017 categories + colors (unchanged)
CATEGORIES = {
    "Normal":     "#10b981",
    "DoS":        "#ef4444",
    "DDoS":       "#f97316",
    "PortScan":   "#8b5cf6",
    "BruteForce": "#3b82f6",
    "WebAttack":  "#eab308",
    "Suspicious": "#f59e0b",
}

# ── Severity colors
SEVERITY_COLORS = {
    "Critical": RED,
    "High":     ORANGE,
    "Medium":   YELLOW,
    "Low":      GREEN,
}


def classify_severity(verdict: str, confidence: int, if_score: float):
    """
    Real severity bucketing — driven entirely by the model's own output.
    Returns None for Normal traffic (not a threat).
    """
    v = verdict.lower()
    if "normal" in v:
        return None

    if "attack" in v:
        # Known attack — graded by RF confidence
        if confidence >= 90:
            return "Critical"
        elif confidence >= 75:
            return "High"
        else:
            return "Medium"
    else:
        # Suspicious / Zero-day — graded by Isolation Forest anomaly score
        if if_score < -0.20:
            return "High"
        elif if_score < -0.05:
            return "Medium"
        else:
            return "Low"


class AttackPieChart(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)

        self.counts = {k: 0 for k in CATEGORIES}
        self.severity_counts = {k: 0 for k in SEVERITY_COLORS}
        self.total_events = 0
        self._update_counter = 0

        self.setStyleSheet(f"background: {PANEL};")
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(10)

        # ── Header
        hdr = QHBoxLayout()
        title = QLabel("ATTACK DISTRIBUTION")
        title.setStyleSheet(f"color: {MUTED}; font-size: 9px; font-weight: bold; letter-spacing: 1.5px;")
        self.live_badge = QLabel("● LIVE")
        self.live_badge.setStyleSheet(f"""
            color: {GREEN}; font-size: 9px; font-weight: bold;
            background: rgba(16,185,129,0.12); border: 1px solid rgba(16,185,129,0.3);
            border-radius: 8px; padding: 2px 8px;
        """)
        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self.live_badge)
        root.addLayout(hdr)

        # ── Donut chart
        self.chart_label = QLabel()
        self.chart_label.setStyleSheet(f"background: {PANEL};")
        self.chart_label.setAlignment(Qt.AlignCenter)
        self.chart_label.setFixedHeight(220)
        root.addWidget(self.chart_label)

        # ── Severity stat boxes (Critical / High / Medium / Low)
        self.stat_row = QHBoxLayout()
        self.stat_row.setSpacing(6)
        self._stat_boxes = {}
        for sev in ["Critical", "High", "Medium", "Low"]:
            box, val_lbl = self._make_stat_box(sev, SEVERITY_COLORS[sev])
            self._stat_boxes[sev] = val_lbl
            self.stat_row.addWidget(box)
        root.addLayout(self.stat_row)

        # ── Legend area
        self.legend_frame = QFrame()
        self.legend_frame.setStyleSheet(f"background: {PANEL}; border-top: 1px solid {PANEL2};")
        self.legend_layout = QVBoxLayout(self.legend_frame)
        self.legend_layout.setContentsMargins(0, 8, 0, 0)
        self.legend_layout.setSpacing(8)
        root.addWidget(self.legend_frame)

        self._draw_chart()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._draw_chart)
        self._timer.start(5000)

    # ── Stat box widget ───────────────────────────────────────────
    def _make_stat_box(self, label, color):
        box = QFrame()
        box.setStyleSheet(f"""
            QFrame {{ background: {PANEL2}; border: 1px solid {BORDER};
                border-radius: 8px; }}
        """)
        lay = QVBoxLayout(box)
        lay.setContentsMargins(6, 8, 6, 8)
        lay.setSpacing(2)

        val_lbl = QLabel("0")
        val_lbl.setAlignment(Qt.AlignCenter)
        val_lbl.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")

        name_lbl = QLabel(label.upper())
        name_lbl.setAlignment(Qt.AlignCenter)
        name_lbl.setStyleSheet(f"color: {MUTED}; font-size: 8px; font-weight: bold; letter-spacing: 1px;")

        lay.addWidget(val_lbl)
        lay.addWidget(name_lbl)
        return box, val_lbl

    # ── Draw donut chart ──────────────────────────────────────────
    def _draw_chart(self):
        try:
            active   = {k: v for k, v in self.counts.items() if v > 0}
            total    = sum(active.values())
            has_data = bool(active)

            threats = sum(v for k, v in active.items() if k != "Normal")
            threat_pct = (threats / total * 100) if total else 0.0

            fig = Figure(figsize=(2.6, 2.6), facecolor=PANEL)
            ax  = fig.add_axes([0.05, 0.05, 0.9, 0.9])
            ax.set_facecolor(PANEL)

            if not has_data:
                ax.pie([1], colors=["#1e3048"], startangle=90,
                       wedgeprops={"linewidth": 0, "width": 0.45})
                ax.text(0, 0, "Waiting\nfor data", ha="center", va="center",
                        color=MUTED, fontsize=8, fontfamily="monospace")
            else:
                labels = list(active.keys())
                sizes  = list(active.values())
                colors = [CATEGORIES[k] for k in labels]

                ax.pie(sizes, colors=colors, startangle=90,
                       wedgeprops={"linewidth": 2.0, "edgecolor": PANEL, "width": 0.42},
                       counterclock=False)

                ax.pie(sizes, colors=[c + "22" for c in colors], startangle=90,
                       wedgeprops={"linewidth": 0, "width": 0.50, "alpha": 0.4},
                       counterclock=False)

                ax.text(0, 0.14, str(total), ha="center", va="center",
                        color=TEXT, fontsize=17, fontweight="bold")
                ax.text(0, -0.04, "EVENTS", ha="center", va="center",
                        color=MUTED, fontsize=6.5, fontfamily="monospace")
                ax.text(0, -0.20, f"{threat_pct:.1f}% threats", ha="center", va="center",
                        color=RED, fontsize=7, fontweight="bold")

            ax.axis("equal")

            canvas = FigureCanvasAgg(fig)
            canvas.draw()
            buf = canvas.buffer_rgba()
            arr = np.frombuffer(buf, dtype=np.uint8)
            w, h = canvas.get_width_height()
            arr = arr.reshape(h, w, 4)
            img = QImage(arr.data, w, h, QImage.Format_RGBA8888)
            self.chart_label.setPixmap(
                QPixmap.fromImage(img).scaled(
                    self.chart_label.width() or 220, 210,
                    Qt.KeepAspectRatio, Qt.SmoothTransformation
                )
            )
            import matplotlib.pyplot as plt
            plt.close(fig)

            # Update severity stat boxes
            for sev, val_lbl in self._stat_boxes.items():
                val_lbl.setText(str(self.severity_counts.get(sev, 0)))

            self._rebuild_legend(active, total)

        except Exception as e:
            print(f"[chart_widget] Draw error: {e}")

    # ── Legend rows (dot + name + underline + count + %) ───────────
    def _rebuild_legend(self, active: dict, total: int):
        while self.legend_layout.count():
            child = self.legend_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        ordered = sorted(active.items(), key=lambda kv: (kv[0] != "Normal", -kv[1]))

        for label, count in ordered:
            color = CATEGORIES.get(label, MUTED)
            pct   = (count / total * 100) if total else 0

            wrapper = QFrame()
            wrapper.setFrameShape(QFrame.NoFrame)
            wrapper.setStyleSheet("background: transparent; border: none;")
            entry = QVBoxLayout(wrapper)
            entry.setContentsMargins(0, 0, 0, 0)
            entry.setSpacing(4)

            row = QHBoxLayout()
            row.setSpacing(6)

            dot = QLabel("●")
            dot.setStyleSheet(f"color: {color}; font-size: 10px; border: none; background: transparent;")
            dot.setFixedWidth(12)

            name_lbl = QLabel(label)
            name_lbl.setStyleSheet(f"color: {TEXT}; font-size: 11px; border: none; background: transparent;")

            count_lbl = QLabel(str(count))
            count_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px; border: none; background: transparent;")

            pct_lbl = QLabel(f"{pct:.1f}%")
            pct_lbl.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold; border: none; background: transparent;")
            pct_lbl.setFixedWidth(50)
            pct_lbl.setAlignment(Qt.AlignRight)

            row.addWidget(dot)
            row.addWidget(name_lbl, stretch=1)
            row.addWidget(count_lbl)
            row.addSpacing(6)
            row.addWidget(pct_lbl)
            entry.addLayout(row)

            # Underline bar — QLabel instead of QFrame (no native border to leak)
            bar_wrap = QHBoxLayout()
            bar_wrap.setContentsMargins(18, 0, 0, 0)
            bar_width = max(4, int(pct * 1.6))
            bar = QLabel()
            bar.setFixedSize(bar_width, 3)
            bar.setStyleSheet(f"background: {color}; border: none; border-radius: 1px;")
            bar_wrap.addWidget(bar)
            bar_wrap.addStretch()
            entry.addLayout(bar_wrap)

            self.legend_layout.addWidget(wrapper)

    # ── Count updater — now takes confidence + if_score for real severity ──
    def update_counts(self, attack_type: str, verdict: str,
                       confidence: int = 0, if_score: float = 0.0):
        v  = verdict.lower()
        at = attack_type.lower()

        if "normal" in v:
            self.counts["Normal"] += 1
        elif "unknown" in v or "suspicious" in v:
            self.counts["Suspicious"] += 1
        elif "ddos" in at:
            self.counts["DDoS"] += 1
        elif "dos" in at:
            self.counts["DoS"] += 1
        elif "portscan" in at or "port scan" in at or "scan" in at:
            self.counts["PortScan"] += 1
        elif "brute" in at:
            self.counts["BruteForce"] += 1
        elif "web" in at or "sql" in at or "xss" in at:
            self.counts["WebAttack"] += 1
        else:
            if "attack" in v:
                self.counts["DoS"] += 1
            else:
                self.counts["Normal"] += 1

        self.total_events += 1

        severity = classify_severity(verdict, confidence, if_score)
        if severity:
            self.severity_counts[severity] += 1

        self._update_counter += 1
        if self._update_counter % 10 == 0:
            self._draw_chart()

    def reset(self):
        self.counts = {k: 0 for k in CATEGORIES}
        self.severity_counts = {k: 0 for k in SEVERITY_COLORS}
        self.total_events = 0
        self._update_counter = 0
        self._draw_chart()