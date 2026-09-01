"""Publication-Grade Vectorized PDF Report Generator for ADAM.

Produces professional, multi-page Threat Intelligence & Malware Analysis PDFs
utilizing ReportLab with cyber-styled covers, KPI cards, vector severity graphs,
milestone timelines, MITRE matrices, mutation inspection, and forensic IOC tables.
"""

from __future__ import annotations
import io
import os
from datetime import datetime
from typing import List, Dict, Any, Tuple

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Group, Circle

from adam.reporting.model import ReportDataModel


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that computes total pages dynamically and adds running headers & footers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        # Don't draw header/footer on cover page (page 1)
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Top Header
        self.drawString(54, 750, "ADAM — ADAPTIVE DECEPTION THREAT ANALYSIS REPORT")
        self.drawRightString(558, 750, f"SESSION: {getattr(self, 'session_id', 'ANALYSIS')}")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 744, 558, 744)

        # Running Footer
        self.line(54, 45, 558, 45)
        self.setFont("Helvetica", 8)
        self.drawString(54, 32, "CONFIDENTIAL — CYBERSECURITY & THREAT INTELLIGENCE RESEARCH")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_text)
        self.restoreState()


class MalwareReportPDFGenerator:
    """Renders ReportDataModel into a high-density, professional PDF document."""

    # Color Palette: Deep Slate, Cyber Green, Cobalt Blue, Amber, Crimson
    PRIMARY_COLOR = colors.HexColor("#0f172a")      # Slate 900
    ACCENT_GREEN = colors.HexColor("#10b981")       # Emerald 500
    ACCENT_BLUE = colors.HexColor("#0284c7")        # Sky 600
    SEV_CRITICAL = colors.HexColor("#e11d48")       # Rose 600
    SEV_HIGH = colors.HexColor("#f97316")           # Orange 500
    SEV_MEDIUM = colors.HexColor("#eab308")         # Amber 500
    SEV_LOW = colors.HexColor("#10b981")            # Emerald 500
    BG_LIGHT = colors.HexColor("#f8fafc")           # Slate 50
    CARD_BORDER = colors.HexColor("#e2e8f0")        # Slate 200
    TEXT_MUTED = colors.HexColor("#64748b")         # Slate 500

    @classmethod
    def generate_pdf(cls, report: ReportDataModel) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        custom_styles = cls._build_styles(styles)

        story = []

        # 1. Cover Page
        story.extend(cls._build_cover_page(report, custom_styles))
        story.append(PageBreak())

        # 2. Executive Summary & KPIs + Threat Risk Assessment
        story.extend(cls._build_executive_summary_section(report, custom_styles))
        story.append(PageBreak())

        # 3. Threat Severity & Category Matrix
        story.extend(cls._build_severity_and_category_section(report, custom_styles))
        story.append(PageBreak())

        # 4. Attack Milestone Timeline & Campaign Progression
        story.extend(cls._build_timeline_and_campaign_section(report, custom_styles))
        story.append(PageBreak())

        # 5. Semantic Intent Catalog & ATT&CK Coverage
        story.extend(cls._build_semantic_intent_section(report, custom_styles))
        story.append(PageBreak())

        # 6. Adaptive Policy & Deception Activity
        story.extend(cls._build_deception_activity_section(report, custom_styles))
        story.append(PageBreak())

        # 7. Behavioral Yield & Post-Mutation Impact
        story.extend(cls._build_behavioral_yield_section(report, custom_styles))
        story.append(PageBreak())

        # 8. Network Intelligence, Process Hierarchy & IOCs
        story.extend(cls._build_forensics_and_iocs_section(report, custom_styles))

        # Build document with NumberedCanvas
        def make_canvas(*args, **kwargs):
            canv = NumberedCanvas(*args, **kwargs)
            canv.session_id = report.session_id
            return canv

        doc.build(story, canvasmaker=make_canvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @classmethod
    def _build_styles(cls, base_styles) -> Dict[str, ParagraphStyle]:
        s = {}
        s["CoverTitle"] = ParagraphStyle(
            "CoverTitle",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=cls.PRIMARY_COLOR
        )
        s["CoverSubtitle"] = ParagraphStyle(
            "CoverSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=18,
            textColor=cls.ACCENT_BLUE
        )
        s["SectionHeader"] = ParagraphStyle(
            "SectionHeader",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=cls.PRIMARY_COLOR,
            spaceAfter=6,
            keepWithNext=True
        )
        s["SubSectionHeader"] = ParagraphStyle(
            "SubSectionHeader",
            parent=base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=cls.PRIMARY_COLOR,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True
        )
        s["Body"] = ParagraphStyle(
            "Body",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#1e293b")
        )
        s["BodyBold"] = ParagraphStyle(
            "BodyBold",
            parent=s["Body"],
            fontName="Helvetica-Bold"
        )
        s["BodyMuted"] = ParagraphStyle(
            "BodyMuted",
            parent=s["Body"],
            textColor=cls.TEXT_MUTED,
            fontSize=8,
            leading=11
        )
        s["TableCell"] = ParagraphStyle(
            "TableCell",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#1e293b")
        )
        s["TableCellBold"] = ParagraphStyle(
            "TableCellBold",
            parent=s["TableCell"],
            fontName="Helvetica-Bold"
        )
        s["TableCellCode"] = ParagraphStyle(
            "TableCellCode",
            parent=s["TableCell"],
            fontName="Courier",
            fontSize=7,
            leading=9
        )
        s["KPILabel"] = ParagraphStyle(
            "KPILabel",
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=cls.TEXT_MUTED,
            alignment=1
        )
        s["KPIValue"] = ParagraphStyle(
            "KPIValue",
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=18,
            textColor=cls.PRIMARY_COLOR,
            alignment=1
        )
        return s

    @classmethod
    def _build_cover_page(cls, report: ReportDataModel, s: Dict[str, ParagraphStyle]) -> List[Any]:
        items = []
        items.append(Spacer(1, 40))

        # Cyber Grid Header Art (ReportLab Drawing)
        d = Drawing(504, 36)
        d.add(Rect(0, 0, 504, 36, fillColor=colors.HexColor("#0f172a"), strokeColor=None, rx=4, ry=4))
        d.add(String(16, 12, "ADAM", fontName="Helvetica-Bold", fontSize=16, fillColor=colors.HexColor("#10b981")))
        d.add(String(72, 13, "AUTONOMOUS DECEPTION & ADAPTIVE MUTATION SANDBOX", fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor("#94a3b8")))
        d.add(String(430, 13, "SECURITY REPORT", fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor("#38bdf8")))
        items.append(d)

        items.append(Spacer(1, 30))
        items.append(Paragraph("ADAPTIVE DECEPTION THREAT ANALYSIS REPORT", s["CoverSubtitle"]))
        items.append(Spacer(1, 6))
        items.append(Paragraph(f"Autonomous Malware Behavior & AMTD Yield Assessment", s["CoverTitle"]))
        items.append(Spacer(1, 14))

        # Risk Banner
        sev_color = cls._get_sev_color(report.risk_score.level)
        risk_table_data = [
            [
                Paragraph("<b>THREAT RISK LEVEL:</b>", s["Body"]),
                Paragraph(f"<b><font color='{sev_color.hexval()}'>{report.risk_score.level} (Score: {report.risk_score.score}/100)</font></b>", s["Body"]),
                Paragraph(f"<b>STATUS:</b> {report.status}", s["Body"])
            ]
        ]
        t_risk = Table(risk_table_data, colWidths=[130, 240, 134])
        t_risk.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        items.append(t_risk)

        items.append(Spacer(1, 24))

        # Metadata Panel
        meta_data = [
            [Paragraph("<b>Sample Filename:</b>", s["TableCellBold"]), Paragraph(report.sample_filename or "sample.exe", s["TableCell"]),
             Paragraph("<b>Analysis Arm:</b>", s["TableCellBold"]), Paragraph(f"<b>{report.arm}</b>", s["TableCell"])],
            [Paragraph("<b>SHA-256 Hash:</b>", s["TableCellBold"]), Paragraph(report.sample_sha256 or "Unknown", s["TableCellCode"]),
             Paragraph("<b>VM Profile:</b>", s["TableCellBold"]), Paragraph(report.vm_profile, s["TableCell"])],
            [Paragraph("<b>Session ID:</b>", s["TableCellBold"]), Paragraph(report.session_id, s["TableCellCode"]),
             Paragraph("<b>Network Mode:</b>", s["TableCellBold"]), Paragraph(report.network_mode, s["TableCell"])],
            [Paragraph("<b>Experiment ID:</b>", s["TableCellBold"]), Paragraph(report.experiment_id, s["TableCell"]),
             Paragraph("<b>Deception Status:</b>", s["TableCellBold"]), Paragraph("<b>ENABLED (Active AMTD)</b>" if report.deception_enabled else "Disabled", s["TableCell"])],
            [Paragraph("<b>Analysis Date:</b>", s["TableCellBold"]), Paragraph(report.started_at[:19].replace("T", " "), s["TableCell"]),
             Paragraph("<b>Detonation Duration:</b>", s["TableCellBold"]), Paragraph(f"{int(report.duration_seconds)} seconds", s["TableCell"])],
        ]
        t_meta = Table(meta_data, colWidths=[100, 180, 94, 130])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        items.append(t_meta)

        items.append(Spacer(1, 30))
        items.append(Paragraph("<b>Report Notice:</b> This automated threat intelligence report was generated by the ADAM Adaptive Deception Sandbox. It documents closed-loop attacker behaviors, MITRE ATT&CK tactic mappings, and post-mutation behavioral yield under active kernel deception.", s["BodyMuted"]))

        return items

    @classmethod
    def _build_executive_summary_section(cls, report: ReportDataModel, s: Dict[str, ParagraphStyle]) -> List[Any]:
        items = []
        items.append(Paragraph("1. Executive Summary & Core Metrics", s["SectionHeader"]))
        items.append(HRFlowable(width="100%", thickness=1, color=cls.PRIMARY_COLOR, spaceAfter=10))

        # KPI 2x4 Grid
        k = report.kpis
        kpi_data = [
            [
                cls._kpi_box("TOTAL RAW EVENTS", f"{k.total_raw_events:,}", s),
                cls._kpi_box("SEMANTIC INTENTS", f"{k.total_semantic_events:,}", s),
                cls._kpi_box("CRITICAL ATTACKS", f"{k.critical_events}", s, highlight=cls.SEV_CRITICAL if k.critical_events > 0 else None),
                cls._kpi_box("HIGH SEVERITY", f"{k.high_events}", s, highlight=cls.SEV_HIGH if k.high_events > 0 else None),
            ],
            [
                cls._kpi_box("POLICY DECISIONS", f"{k.total_decisions}", s),
                cls._kpi_box("MUTATIONS APPLIED", f"{k.total_mutations_applied}", s, highlight=cls.ACCENT_GREEN),
                cls._kpi_box("POST-MUTATION YIELD", f"+{k.post_mutation_events}", s, highlight=cls.ACCENT_BLUE),
                cls._kpi_box("BEHAVIORAL YIELD %", f"+{k.behavioral_yield_percentage}%", s, highlight=cls.ACCENT_BLUE),
            ]
        ]
        t_kpis = Table(kpi_data, colWidths=[126, 126, 126, 126])
        t_kpis.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 2),
            ('RIGHTPADDING', (0,0), (-1,-1), 2),
        ]))
        items.append(t_kpis)
        items.append(Spacer(1, 14))

        # Threat Assessment Card
        items.append(Paragraph("Threat Risk Assessment", s["SubSectionHeader"]))
        risk_box = [
            [
                Paragraph(f"<b>Threat Level: <font color='{cls._get_sev_color(report.risk_score.level).hexval()}'>{report.risk_score.level}</font> ({report.risk_score.score}/100)</b>", s["BodyBold"]),
                Paragraph(f"<b>Severity Weight:</b> {report.risk_score.breakdown.get('severity_weight', 0)}% | <b>Diversity:</b> {report.risk_score.breakdown.get('attack_diversity', 0)}% | <b>Threat Multiplier:</b> {report.risk_score.breakdown.get('threat_multiplier', 0)}%", s["TableCell"])
            ],
            [
                Paragraph(report.risk_score.rationale, s["TableCell"]),
                Paragraph(f"<b>Confidence Mean:</b> {report.confidence_metrics.mean} (Median: {report.confidence_metrics.median})", s["TableCell"])
            ]
        ]
        t_rbox = Table(risk_box, colWidths=[240, 264])
        t_rbox.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('BOX', (0,0), (-1,-1), 1, cls.CARD_BORDER),
            ('LINEBELOW', (0,0), (-1,0), 0.5, cls.CARD_BORDER),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        items.append(t_rbox)
        items.append(Spacer(1, 14))

        # Key Findings Narrative
        items.append(Paragraph("Key Analyst Findings", s["SubSectionHeader"]))
        for idx, finding in enumerate(report.key_findings, 1):
            items.append(Paragraph(f"<b>{idx}.</b> {finding}", s["Body"]))
            items.append(Spacer(1, 3))

        return items

    @classmethod
    def _build_severity_and_category_section(cls, report: ReportDataModel, s: Dict[str, ParagraphStyle]) -> List[Any]:
        items = []
        items.append(Paragraph("2. Attack Severity & Category Distribution", s["SectionHeader"]))
        items.append(HRFlowable(width="100%", thickness=1, color=cls.PRIMARY_COLOR, spaceAfter=10))

        # Severity Breakdown Table
        sd = report.severity_distribution
        sev_table_data = [
            [Paragraph("<b>Severity</b>", s["TableCellBold"]), Paragraph("<b>Event Count</b>", s["TableCellBold"]), Paragraph("<b>Percentage</b>", s["TableCellBold"]), Paragraph("<b>Visual Share</b>", s["TableCellBold"])],
            [Paragraph("<b><font color='#e11d48'>CRITICAL</font></b>", s["TableCellBold"]), Paragraph(str(sd.critical), s["TableCellBold"]), Paragraph(f"{sd.critical_pct}%", s["TableCell"]), cls._make_bar(sd.critical_pct, cls.SEV_CRITICAL)],
            [Paragraph("<b><font color='#f97316'>HIGH</font></b>", s["TableCellBold"]), Paragraph(str(sd.high), s["TableCellBold"]), Paragraph(f"{sd.high_pct}%", s["TableCell"]), cls._make_bar(sd.high_pct, cls.SEV_HIGH)],
            [Paragraph("<b><font color='#eab308'>MEDIUM</font></b>", s["TableCellBold"]), Paragraph(str(sd.medium), s["TableCellBold"]), Paragraph(f"{sd.medium_pct}%", s["TableCell"]), cls._make_bar(sd.medium_pct, cls.SEV_MEDIUM)],
            [Paragraph("<b><font color='#10b981'>LOW</font></b>", s["TableCellBold"]), Paragraph(str(sd.low), s["TableCellBold"]), Paragraph(f"{sd.low_pct}%", s["TableCell"]), cls._make_bar(sd.low_pct, cls.SEV_LOW)],
        ]
        t_sev = Table(sev_table_data, colWidths=[90, 80, 80, 254])
        t_sev.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        items.append(t_sev)
        items.append(Spacer(1, 14))

        # Severity × Category Matrix Heatmap
        items.append(Paragraph("Severity × Category Heatmap Matrix", s["SubSectionHeader"]))
        matrix_data = [
            [Paragraph("<b>MITRE Category</b>", s["TableCellBold"]),
             Paragraph("<b><font color='#e11d48'>CRIT</font></b>", s["TableCellBold"]),
             Paragraph("<b><font color='#f97316'>HIGH</font></b>", s["TableCellBold"]),
             Paragraph("<b><font color='#eab308'>MED</font></b>", s["TableCellBold"]),
             Paragraph("<b><font color='#10b981'>LOW</font></b>", s["TableCellBold"]),
             Paragraph("<b>Total</b>", s["TableCellBold"]),
             Paragraph("<b>Share %</b>", s["TableCellBold"])]
        ]
        for cat in report.category_summaries:
            matrix_data.append([
                Paragraph(f"<b>{cat.category}</b>", s["TableCell"]),
                Paragraph(str(cat.critical) if cat.critical > 0 else "-", s["TableCellBold"] if cat.critical > 0 else s["TableCell"]),
                Paragraph(str(cat.high) if cat.high > 0 else "-", s["TableCellBold"] if cat.high > 0 else s["TableCell"]),
                Paragraph(str(cat.medium) if cat.medium > 0 else "-", s["TableCellBold"] if cat.medium > 0 else s["TableCell"]),
                Paragraph(str(cat.low) if cat.low > 0 else "-", s["TableCellBold"] if cat.low > 0 else s["TableCell"]),
                Paragraph(f"<b>{cat.count}</b>", s["TableCellBold"]),
                Paragraph(f"{cat.percentage}%", s["TableCell"]),
            ])

        t_mat = Table(matrix_data, colWidths=[150, 46, 46, 46, 46, 60, 110])
        t_mat.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (1,0), (-1,-1), 'CENTER'),
        ]))
        items.append(t_mat)

        return items

    @classmethod
    def _build_timeline_and_campaign_section(cls, report: ReportDataModel, s: Dict[str, ParagraphStyle]) -> List[Any]:
        items = []
        items.append(Paragraph("3. Attack Timeline & Campaign Progression", s["SectionHeader"]))
        items.append(HRFlowable(width="100%", thickness=1, color=cls.PRIMARY_COLOR, spaceAfter=10))

        # Campaign Phases Flow
        items.append(Paragraph("Observed Campaign Progression Phases", s["SubSectionHeader"]))
        if report.campaign_phases:
            phase_flow_text = "  ➔  ".join([f"<b>{p['phase']}</b> ({p['count']})" for p in report.campaign_phases])
            items.append(Paragraph(f"<font color='#0284c7'>{phase_flow_text}</font>", s["BodyBold"]))
        else:
            items.append(Paragraph("Single execution phase observed.", s["BodyMuted"]))
        items.append(Spacer(1, 10))

        # Milestone Timeline Table
        items.append(Paragraph("Chronological Attack Milestones & Deception Triggers", s["SubSectionHeader"]))
        tl_data = [
            [Paragraph("<b>Time Offset</b>", s["TableCellBold"]), Paragraph("<b>Phase / Category</b>", s["TableCellBold"]), Paragraph("<b>Milestone Activity</b>", s["TableCellBold"]), Paragraph("<b>Severity</b>", s["TableCellBold"])]
        ]
        for m in report.timeline[:14]:  # Show top 14 notable milestones
            sev_col = cls._get_sev_color(m.severity)
            safe_desc = str(m.description).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            safe_title = str(m.title).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            tl_data.append([
                Paragraph(f"<code>{m.time_offset}</code>", s["TableCellCode"]),
                Paragraph(f"<b>{m.phase}</b>", s["TableCell"]),
                Paragraph(f"<b>{safe_title}</b><br/><font color='#64748b'>{safe_desc}</font>", s["TableCell"]),
                Paragraph(f"<b><font color='{sev_col.hexval()}'>{m.severity}</font></b>", s["TableCellBold"]),
            ])

        t_tl = Table(tl_data, colWidths=[70, 110, 244, 80])
        t_tl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        items.append(t_tl)

        return items

    @classmethod
    def _build_semantic_intent_section(cls, report: ReportDataModel, s: Dict[str, ParagraphStyle]) -> List[Any]:
        items = []
        items.append(Paragraph("4. Semantic Intent Catalog & ATT&CK Coverage", s["SectionHeader"]))
        items.append(HRFlowable(width="100%", thickness=1, color=cls.PRIMARY_COLOR, spaceAfter=10))

        # Semantic Intent Table
        items.append(Paragraph("Ranked Semantic Intent Detections", s["SubSectionHeader"]))
        si_data = [
            [Paragraph("<b>Detected Intent</b>", s["TableCellBold"]), Paragraph("<b>Category</b>", s["TableCellBold"]), Paragraph("<b>Severity</b>", s["TableCellBold"]), Paragraph("<b>Confidence</b>", s["TableCellBold"]), Paragraph("<b>ATT&CK</b>", s["TableCellBold"]), Paragraph("<b>Count</b>", s["TableCellBold"]), Paragraph("<b>Causal Deception</b>", s["TableCellBold"])]
        ]
        for intent in report.semantic_intents[:12]:
            sev_col = cls._get_sev_color(intent.severity)
            causal_text = f"<font color='#0284c7'>{intent.caused_by_mutation[:14]}...</font>" if intent.caused_by_mutation else "-"
            si_data.append([
                Paragraph(f"<code>{intent.intent}</code>", s["TableCellCode"]),
                Paragraph(intent.category, s["TableCell"]),
                Paragraph(f"<b><font color='{sev_col.hexval()}'>{intent.severity}</font></b>", s["TableCellBold"]),
                Paragraph(f"{int(intent.confidence * 100)}%", s["TableCell"]),
                Paragraph(f"<code>{intent.attck_technique}</code>", s["TableCellCode"]),
                Paragraph(str(intent.occurrences), s["TableCellBold"]),
                Paragraph(causal_text, s["TableCell"]),
            ])

        t_si = Table(si_data, colWidths=[140, 80, 56, 54, 54, 40, 80])
        t_si.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        items.append(t_si)
        items.append(Spacer(1, 14))

        # MITRE ATT&CK Matrix Summary
        items.append(Paragraph("MITRE ATT&CK Technique Mapping", s["SubSectionHeader"]))
        attck_data = [
            [Paragraph("<b>Tactic</b>", s["TableCellBold"]), Paragraph("<b>Technique ID</b>", s["TableCellBold"]), Paragraph("<b>Technique Name</b>", s["TableCellBold"]), Paragraph("<b>Occurrences</b>", s["TableCellBold"]), Paragraph("<b>Severity</b>", s["TableCellBold"])]
        ]
        for att in report.attck_coverage[:8]:
            sev_col = cls._get_sev_color(att.severity)
            attck_data.append([
                Paragraph(att.tactic, s["TableCellBold"]),
                Paragraph(f"<code>{att.technique}</code>", s["TableCellCode"]),
                Paragraph(att.technique_name, s["TableCell"]),
                Paragraph(str(att.count), s["TableCellBold"]),
                Paragraph(f"<b><font color='{sev_col.hexval()}'>{att.severity}</font></b>", s["TableCellBold"]),
            ])
        t_att = Table(attck_data, colWidths=[100, 70, 214, 50, 70])
        t_att.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        items.append(t_att)

        return items

    @classmethod
    def _build_deception_activity_section(cls, report: ReportDataModel, s: Dict[str, ParagraphStyle]) -> List[Any]:
        items = []
        items.append(Paragraph("5. Adaptive Policy & Deception Activity", s["SectionHeader"]))
        items.append(HRFlowable(width="100%", thickness=1, color=cls.PRIMARY_COLOR, spaceAfter=10))

        # Policy Decisions Summary
        pa = report.policy_analysis
        pol_data = [
            [Paragraph("<b>Decisions Evaluated:</b>", s["TableCellBold"]), Paragraph(str(pa.total_evaluated), s["TableCellBold"]),
             Paragraph("<b>Mutations Executed:</b>", s["TableCellBold"]), Paragraph(f"<b><font color='#10b981'>{pa.executed}</font></b>", s["TableCellBold"])],
            [Paragraph("<b>Suppressed (Budget):</b>", s["TableCellBold"]), Paragraph(str(pa.suppressed_budget), s["TableCell"]),
             Paragraph("<b>Suppressed (Confidence):</b>", s["TableCellBold"]), Paragraph(str(pa.suppressed_confidence), s["TableCell"])],
            [Paragraph("<b>Suppressed (Cooldown):</b>", s["TableCellBold"]), Paragraph(str(pa.suppressed_cooldown), s["TableCell"]),
             Paragraph("<b>Mutation Rate:</b>", s["TableCellBold"]), Paragraph(f"<b>{int(pa.mutation_rate * 100)}%</b>", s["TableCellBold"])],
        ]
        t_pol = Table(pol_data, colWidths=[140, 112, 140, 112])
        t_pol.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('BOX', (0,0), (-1,-1), 1, cls.CARD_BORDER),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        items.append(t_pol)
        items.append(Spacer(1, 14))

        # Applied Deception Mutations Cards
        items.append(Paragraph("Applied Deception Mutations & Environmental Changes", s["SubSectionHeader"]))
        if report.mutations:
            for mut in report.mutations[:4]:
                m_card = [
                    [
                        Paragraph(f"<b>MUTATION: {mut.primitive}</b>", s["BodyBold"]),
                        Paragraph(f"Status: <b>{mut.status}</b> | Latency: <b>{round(mut.latency_ms, 1)}ms</b> | Plausibility: <b>{mut.plausibility_score}</b>", s["TableCell"])
                    ],
                    [
                        Paragraph(f"<b>Trigger:</b> <code>{mut.triggering_intent}</code> (Rule: {mut.policy_rule})<br/><b>Yield:</b> {mut.subsequent_events_count} subsequent attributed behaviors", s["TableCell"]),
                        Paragraph(f"<b>Artifacts Generated:</b> {mut.explanation.get('summary', 'Synthetic deception environment generated.')}", s["TableCell"])
                    ]
                ]
                t_mcard = Table(m_card, colWidths=[240, 264])
                t_mcard.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
                    ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#86efac")),
                    ('LINEBELOW', (0,0), (-1,0), 0.5, colors.HexColor("#bbf7d0")),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('LEFTPADDING', (0,0), (-1,-1), 6),
                    ('RIGHTPADDING', (0,0), (-1,-1), 6),
                ]))
                items.append(t_mcard)
                items.append(Spacer(1, 6))
        else:
            items.append(Paragraph("No active deception mutations were triggered during this session.", s["BodyMuted"]))

        return items

    @classmethod
    def _build_behavioral_yield_section(cls, report: ReportDataModel, s: Dict[str, ParagraphStyle]) -> List[Any]:
        items = []
        items.append(Paragraph("6. Behavioral Yield & AMTD Research Impact", s["SectionHeader"]))
        items.append(HRFlowable(width="100%", thickness=1, color=cls.PRIMARY_COLOR, spaceAfter=10))

        items.append(Paragraph(
            "<b>Behavioral Yield Assessment:</b> Behavioral yield quantifies the gain in threat visibility achieved by dynamically mutating the sandbox environment. "
            "When attacker probes trigger active deception (e.g. fake domain controllers, crypto wallets, or shares), subsequent attacker actions causally attributed to those lures represent new forensic yield.",
            s["Body"]
        ))
        items.append(Spacer(1, 10))

        # Comparison Table
        yield_data = [
            [Paragraph("<b>Intent / Dimension</b>", s["TableCellBold"]), Paragraph("<b>Control (Baseline)</b>", s["TableCellBold"]), Paragraph("<b>Treatment (Deception)</b>", s["TableCellBold"]), Paragraph("<b>Behavioral Delta</b>", s["TableCellBold"]), Paragraph("<b>Attributed to Mutation</b>", s["TableCellBold"])]
        ]
        for y in report.yield_comparisons[:10]:
            delta_color = "#10b981" if y.delta > 0 else ("#e11d48" if y.delta < 0 else "#64748b")
            attr_text = "<b><font color='#10b981'>YES (Causally Attributed)</font></b>" if y.attributed_to_mutation else "Baseline"
            yield_data.append([
                Paragraph(f"<code>{y.intent_or_dimension}</code>", s["TableCellCode"]),
                Paragraph(str(y.control_count), s["TableCell"]),
                Paragraph(str(y.treatment_count), s["TableCellBold"]),
                Paragraph(f"<b><font color='{delta_color}'>{'+' if y.delta > 0 else ''}{y.delta}</font></b>", s["TableCellBold"]),
                Paragraph(attr_text, s["TableCell"]),
            ])

        t_yd = Table(yield_data, colWidths=[160, 84, 84, 76, 100])
        t_yd.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        items.append(t_yd)

        return items

    @classmethod
    def _build_forensics_and_iocs_section(cls, report: ReportDataModel, s: Dict[str, ParagraphStyle]) -> List[Any]:
        items = []
        items.append(Paragraph("7. Network Intelligence, Process Hierarchy & IOCs", s["SectionHeader"]))
        items.append(HRFlowable(width="100%", thickness=1, color=cls.PRIMARY_COLOR, spaceAfter=10))

        # Forensic Indicators of Compromise
        items.append(Paragraph("Extracted Indicators of Compromise (IOCs)", s["SubSectionHeader"]))
        ioc_data = [
            [Paragraph("<b>Type</b>", s["TableCellBold"]), Paragraph("<b>Indicator Value</b>", s["TableCellBold"]), Paragraph("<b>Confidence</b>", s["TableCellBold"]), Paragraph("<b>Forensic Context</b>", s["TableCellBold"])]
        ]
        if report.iocs:
            for ioc in report.iocs[:12]:
                ioc_data.append([
                    Paragraph(f"<b>{ioc.ioc_type}</b>", s["TableCellBold"]),
                    Paragraph(f"<code>{ioc.value}</code>", s["TableCellCode"]),
                    Paragraph(f"{int(ioc.confidence * 100)}%", s["TableCell"]),
                    Paragraph(ioc.context, s["TableCell"]),
                ])
        else:
            ioc_data.append([Paragraph("None", s["TableCell"]), Paragraph("No network/file IOCs extracted.", s["TableCell"]), Paragraph("-", s["TableCell"]), Paragraph("-", s["TableCell"])])

        t_ioc = Table(ioc_data, colWidths=[90, 190, 54, 170])
        t_ioc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('GRID', (0,0), (-1,-1), 0.5, cls.CARD_BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        items.append(t_ioc)
        items.append(Spacer(1, 14))

        # Process Tree Summary
        items.append(Paragraph("Process Execution Hierarchy", s["SubSectionHeader"]))
        if report.process_tree:
            proc_lines = []
            for p in report.process_tree[:6]:
                proc_lines.append(Paragraph(f"• <b>PID {p.pid}:</b> <code>{p.name}</code> {f'({p.command_line})' if p.command_line != p.name else ''}", s["TableCell"]))
                for child in p.children:
                    proc_lines.append(Paragraph(f"&nbsp;&nbsp;&nbsp;&nbsp;└── <b>PID {child.pid}:</b> <code>{child.name}</code>", s["TableCellCode"]))
            items.extend(proc_lines)
        else:
            items.append(Paragraph("Single parent process execution monitored.", s["BodyMuted"]))

        return items

    @classmethod
    def _kpi_box(cls, label: str, val: str, s: Dict[str, ParagraphStyle], highlight: Optional[colors.Color] = None) -> Table:
        val_style = s["KPIValue"]
        if highlight:
            val_style = ParagraphStyle(
                "KPIHighlight",
                parent=val_style,
                textColor=highlight
            )
        data = [
            [Paragraph(label, s["KPILabel"])],
            [Paragraph(val, val_style)]
        ]
        t = Table(data, colWidths=[120])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('BOX', (0,0), (-1,-1), 1, cls.CARD_BORDER),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ]))
        return t

    @classmethod
    def _make_bar(cls, pct: float, color: colors.Color) -> Drawing:
        d = Drawing(240, 10)
        d.add(Rect(0, 1, 240, 8, fillColor=colors.HexColor("#e2e8f0"), strokeColor=None, rx=3, ry=3))
        fill_w = max(4.0, min(240.0, (pct / 100.0) * 240.0))
        d.add(Rect(0, 1, fill_w, 8, fillColor=color, strokeColor=None, rx=3, ry=3))
        return d

    @classmethod
    def _get_sev_color(cls, sev: str) -> colors.Color:
        u = sev.upper()
        if u == "CRITICAL": return cls.SEV_CRITICAL
        if u == "HIGH": return cls.SEV_HIGH
        if u == "MEDIUM": return cls.SEV_MEDIUM
        return cls.SEV_LOW
