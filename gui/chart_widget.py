from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame
)
from PyQt5.QtCore import Qt
from matplotlib.backends.backend_qt5agg import (
    FigureCanvasQTAgg as FigureCanvas
)
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Qt5Agg')

# Colors
BG     = "#0a0f1a"
PANEL  = "#111827"
PANEL2 = "#1a2436"
BORDER = "#1e3048"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"
ACCENT = "#00d4ff"


class AttackPieChart(QWidget):
    """
    Real-time attack distribution pie chart
    Matplotlib embedded in PyQt5
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        # Attack counters
        self.counts = {
            'Normal': 0,
            'DoS':    0,
            'Probe':  0,
            'R2L':    0,
            'U2R':    0,
            'Unknown':0,
        }

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setFixedHeight(36)
        header.setStyleSheet(f"""
            background: {PANEL2};
            border-bottom: 1px solid {BORDER};
            border-radius: 10px 10px 0 0;
        """)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(14, 0, 14, 0)

        title = QLabel("ATTACK DISTRIBUTION")
        title.setStyleSheet(f"""
            color: {TEXT};
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1px;
        """)
        hl.addWidget(title)
        layout.addWidget(header)

        # Matplotlib figure
        self.fig = Figure(
            figsize=(3, 2.8),
            facecolor='#111827'
        )
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setStyleSheet(
            f"background-color: {PANEL};"
        )
        layout.addWidget(self.canvas)

        # Initial empty chart draw
        self._draw_chart()

    def _draw_chart(self):
        self.ax.clear()
        self.ax.set_facecolor('#111827')
        self.fig.patch.set_facecolor('#111827')

        # Zero counts filter karo
        labels = []
        sizes  = []
        colors = []

        color_map = {
            'Normal':  '#10b981',
            'DoS':     '#ef4444',
            'Probe':   '#8b5cf6',
            'R2L':     '#f59e0b',
            'U2R':     '#3b82f6',
            'Unknown': '#f97316',
        }

        for label, count in self.counts.items():
            if count > 0:
                labels.append(f"{label}\n{count}")
                sizes.append(count)
                colors.append(color_map[label])

        if not sizes:
            # Koi data nahi — placeholder
            self.ax.text(
                0.5, 0.5,
                'Waiting for\ndata...',
                ha='center', va='center',
                color='#64748b', fontsize=10,
                transform=self.ax.transAxes
            )
            self.ax.set_xlim(0, 1)
            self.ax.set_ylim(0, 1)
            self.ax.axis('off')
        else:
            wedges, texts, autotexts = self.ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct='%1.0f%%',
                startangle=90,
                pctdistance=0.75,
                wedgeprops={
                    'linewidth': 1.5,
                    'edgecolor': '#0a0f1a'
                }
            )

            # Text colors
            for text in texts:
                text.set_color('#c8dff0')
                text.set_fontsize(8)

            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontsize(8)
                autotext.set_fontweight('bold')

        self.canvas.draw()

    def update_counts(self, attack_type, verdict):
        """
        Naya packet aane pe chart update karo
        Main window se call hoga
        """
        verdict_lower = verdict.lower()

        if 'normal' in verdict_lower:
            self.counts['Normal'] += 1
        elif 'unknown' in verdict_lower:
            self.counts['Unknown'] += 1
        else:
            # Attack type se category determine karo
            at_lower = attack_type.lower()
            if 'dos' in at_lower or 'neptune' in at_lower \
               or 'smurf' in at_lower or 'back' in at_lower \
               or 'teardrop' in at_lower or 'pod' in at_lower:
                self.counts['DoS'] += 1
            elif 'probe' in at_lower or 'ipsweep' in at_lower \
                 or 'portsweep' in at_lower or 'nmap' in at_lower \
                 or 'satan' in at_lower:
                self.counts['Probe'] += 1
            elif 'r2l' in at_lower or 'warez' in at_lower \
                 or 'guess' in at_lower:
                self.counts['R2L'] += 1
            elif 'u2r' in at_lower or 'overflow' in at_lower \
                 or 'rootkit' in at_lower:
                self.counts['U2R'] += 1
            else:
                self.counts['DoS'] += 1

        # Har 10 packets pe chart update karo
        total = sum(self.counts.values())
        if total % 10 == 0:
            self._draw_chart()

    def reset(self):
        """Chart reset karo"""
        for key in self.counts:
            self.counts[key] = 0
        self._draw_chart()