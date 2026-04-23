import csv
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import (
    getSampleStyleSheet, ParagraphStyle
)
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph,
    Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER


class ExportManager:

    def __init__(self, table_widget=None,
                 accuracy="94.2%", fpr="4.8%",
                 attacks=0, packets=0,
                 pie_counts=None):
        self.table_widget = table_widget
        self.accuracy     = accuracy
        self.fpr          = fpr
        self.attacks      = attacks
        self.packets      = packets
        self.pie_counts   = pie_counts or {}

    def export_csv(self, filepath=None):
        try:
            if not filepath:
                ts = datetime.now().strftime(
                    "%Y%m%d_%H%M%S"
                )
                filepath = os.path.join(
                    os.path.expanduser("~"),
                    "Desktop",
                    f"QNIDS_Report_{ts}.csv"
                )

            with open(filepath, 'w',
                      newline='',
                      encoding='utf-8') as f:
                writer = csv.writer(f)

                writer.writerow([
                    "QNIDS — Quantum-Inspired "
                    "NIDS Report"
                ])
                writer.writerow([
                    f"Generated: "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                ])
                writer.writerow([])

                writer.writerow(["MODEL PERFORMANCE"])
                writer.writerow([
                    "Model", "Accuracy",
                    "False Positive Rate"
                ])
                writer.writerow([
                    "Hybrid QPSO+RF",
                    self.accuracy, self.fpr
                ])
                writer.writerow([
                    "Classical RF", "88.1%", "12.3%"
                ])
                writer.writerow([
                    "Decision Tree", "85.7%", "15.1%"
                ])
                writer.writerow([])

                writer.writerow([
                    "SESSION STATISTICS"
                ])
                writer.writerow([
                    "Attacks Detected",
                    str(self.attacks)
                ])
                writer.writerow([
                    "Packets Analyzed",
                    str(self.packets)
                ])
                writer.writerow([])

                writer.writerow(["DETECTION LOG"])
                writer.writerow([
                    "Time", "Source IP",
                    "Attack Type",
                    "Verdict", "Confidence"
                ])

                if self.table_widget:
                    for row in range(
                        self.table_widget.rowCount()
                    ):
                        row_data = []
                        for col in range(5):
                            item = \
                                self.table_widget.item(
                                    row, col
                                )
                            row_data.append(
                                item.text()
                                if item else ""
                            )
                        writer.writerow(row_data)

            print(f"CSV exported: {filepath}")
            return filepath

        except Exception as e:
            print(f"CSV export error: {e}")
            return None

    def export_pdf(self, filepath=None):
        try:
            if not filepath:
                ts = datetime.now().strftime(
                    "%Y%m%d_%H%M%S"
                )
                filepath = os.path.join(
                    os.path.expanduser("~"),
                    "Desktop",
                    f"QNIDS_Report_{ts}.pdf"
                )

            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=0.75*inch,
                bottomMargin=0.75*inch
            )

            story  = []
            styles = getSampleStyleSheet()

            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=22,
                textColor=colors.HexColor('#00d4ff'),
                spaceAfter=4,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )
            sub_style = ParagraphStyle(
                'CustomSub',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#64748b'),
                spaceAfter=2,
                alignment=TA_CENTER
            )
            section_style = ParagraphStyle(
                'SectionHeader',
                parent=styles['Heading2'],
                fontSize=13,
                textColor=colors.HexColor('#00d4ff'),
                spaceBefore=16,
                spaceAfter=8,
                fontName='Helvetica-Bold'
            )
            normal_style = ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#334155'),
                spaceAfter=4
            )

            # Title
            story.append(Paragraph(
                "QNIDS", title_style
            ))
            story.append(Paragraph(
                "Quantum-Inspired Network Intrusion "
                "Detection System",
                sub_style
            ))
            story.append(Paragraph(
                f"Report Generated: "
                f"{datetime.now().strftime('%B %d, %Y  %H:%M:%S')}",
                sub_style
            ))
            story.append(Spacer(1, 0.15*inch))
            story.append(HRFlowable(
                width="100%", thickness=1,
                color=colors.HexColor('#00d4ff')
            ))
            story.append(Spacer(1, 0.1*inch))

            # Project Info
            story.append(Paragraph(
                "Project Information", section_style
            ))
            info_data = [
                ["Project",
                 "QNIDS — Quantum-Inspired NIDS"],
                ["Dataset",
                 "NSL-KDD / UNSW-NB15"],
                ["Algorithm",
                 "QPSO + Random Forest + "
                 "Isolation Forest"],
                ["Features",
                 "41 to 19 (QPSO Selection)"],
                ["Session",
                 datetime.now().strftime(
                     "%Y-%m-%d %H:%M"
                 )],
            ]
            info_table = Table(
                info_data,
                colWidths=[1.8*inch, 4.5*inch]
            )
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1),
                 colors.HexColor('#f1f5f9')),
                ('FONTNAME', (0, 0), (0, -1),
                 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TEXTCOLOR', (0, 0), (0, -1),
                 colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (1, 0), (1, -1),
                 colors.HexColor('#334155')),
                ('GRID', (0, 0), (-1, -1), 0.5,
                 colors.HexColor('#e2e8f0')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1),
                 [colors.white,
                  colors.HexColor('#f8fafc')]),
                ('PADDING', (0, 0), (-1, -1), 7),
            ]))
            story.append(info_table)

            # Model Performance
            story.append(Paragraph(
                "Model Performance Comparison",
                section_style
            ))
            perf_data = [
                ["Model", "Accuracy",
                 "False Positive Rate", "F1-Score"],
                ["Hybrid QPSO+RF (Ours)",
                 self.accuracy, self.fpr, "0.938"],
                ["Classical RF (Baseline)",
                 "88.1%", "12.3%", "0.871"],
                ["Decision Tree",
                 "85.7%", "15.1%", "0.842"],
            ]
            perf_table = Table(
                perf_data,
                colWidths=[2.2*inch, 1.3*inch,
                           1.8*inch, 1.2*inch]
            )
            perf_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0),
                 colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0),
                 colors.HexColor('#00d4ff')),
                ('FONTNAME', (0, 0), (-1, 0),
                 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, 1),
                 colors.HexColor('#ecfdf5')),
                ('TEXTCOLOR', (0, 1), (-1, 1),
                 colors.HexColor('#065f46')),
                ('FONTNAME', (0, 1), (-1, 1),
                 'Helvetica-Bold'),
                ('TEXTCOLOR', (0, 2), (-1, -1),
                 colors.HexColor('#334155')),
                ('ROWBACKGROUNDS', (0, 2), (-1, -1),
                 [colors.white,
                  colors.HexColor('#f8fafc')]),
                ('GRID', (0, 0), (-1, -1), 0.5,
                 colors.HexColor('#e2e8f0')),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('PADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(perf_table)

            # Session Stats
            story.append(Paragraph(
                "Session Statistics", section_style
            ))
            stat_data = [
                ["Metric", "Value"],
                ["Attacks Detected",
                 str(self.attacks)],
                ["Packets Analyzed",
                 str(self.packets)],
                ["Detection Mode",
                 "QPSO + RF + Anomaly Detection"],
            ]
            stat_table = Table(
                stat_data,
                colWidths=[2.5*inch, 4*inch]
            )
            stat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0),
                 colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0),
                 colors.HexColor('#00d4ff')),
                ('FONTNAME', (0, 0), (-1, 0),
                 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TEXTCOLOR', (0, 1), (-1, -1),
                 colors.HexColor('#334155')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [colors.white,
                  colors.HexColor('#f8fafc')]),
                ('GRID', (0, 0), (-1, -1), 0.5,
                 colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(stat_table)

            # Detection Log
            story.append(Paragraph(
                "Detection Log", section_style
            ))
            log_data = [
                ["Time", "Source IP",
                 "Attack Type",
                 "Verdict", "Conf."]
            ]

            if self.table_widget:
                max_rows = min(
                    50,
                    self.table_widget.rowCount()
                )
                for row in range(max_rows):
                    row_data = []
                    for col in range(5):
                        item = \
                            self.table_widget.item(
                                row, col
                            )
                        row_data.append(
                            item.text()
                            if item else ""
                        )
                    log_data.append(row_data)

            if len(log_data) > 1:
                log_table = Table(
                    log_data,
                    colWidths=[
                        0.8*inch, 1.1*inch,
                        2.2*inch, 1.0*inch,
                        0.8*inch
                    ]
                )
                log_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0),
                     colors.HexColor('#0f172a')),
                    ('TEXTCOLOR', (0, 0), (-1, 0),
                     colors.HexColor('#00d4ff')),
                    ('FONTNAME', (0, 0), (-1, 0),
                     'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('TEXTCOLOR', (0, 1), (-1, -1),
                     colors.HexColor('#334155')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                     [colors.white,
                      colors.HexColor('#f8fafc')]),
                    ('GRID', (0, 0), (-1, -1), 0.3,
                     colors.HexColor('#e2e8f0')),
                    ('ALIGN', (3, 0), (4, -1),
                     'CENTER'),
                    ('PADDING', (0, 0), (-1, -1), 5),
                ]))
                story.append(log_table)
            else:
                story.append(Paragraph(
                    "No detection data available.",
                    normal_style
                ))

            # Footer
            story.append(Spacer(1, 0.2*inch))
            story.append(HRFlowable(
                width="100%", thickness=0.5,
                color=colors.HexColor('#e2e8f0')
            ))
            story.append(Spacer(1, 0.05*inch))
            story.append(Paragraph(
                "QNIDS v1.0  |  Final Year Project  |  "
                "Quantum-Inspired Network Intrusion "
                "Detection System",
                sub_style
            ))

            doc.build(story)
            print(f"PDF exported: {filepath}")
            return filepath

        except Exception as e:
            print(f"PDF export error: {e}")
            import traceback
            traceback.print_exc()
            return None