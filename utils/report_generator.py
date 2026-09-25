from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

VERDICT_COLORS = {
    "Phishing": colors.HexColor("#c62828"),
    "Suspicious": colors.HexColor("#e08600"),
    "Safe": colors.HexColor("#2e7d32"),
}


def _p(text, style):
    return Paragraph(escape(str(text)), style)


def build_report(result):
    """Return a PDF report for one scan as bytes."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Phishing Analysis Report #{result.get('id', '')}",
    )

    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11)
    verdict_style = ParagraphStyle(
        "verdict", parent=styles["Heading1"],
        textColor=VERDICT_COLORS.get(result["verdict"], colors.black),
    )

    story = [
        Paragraph("AI Phishing Email Detector - Analysis Report", styles["Title"]),
        _p(f"Scan #{result.get('id', '-')}  |  {result.get('created_at', '')}", small),
        Spacer(1, 6 * mm),
        Paragraph(f"Verdict: {escape(result['verdict'])} ({result['risk_score']}/100 risk)", verdict_style),
    ]

    summary = [
        ["Subject", _p(result["subject"], body)],
        ["Sender", _p(result["sender"], body)],
        ["ML phishing probability", f"{result['ml_probability'] * 100:.1f}%  ({result['model_name']})"],
        ["Phishing type", result["phishing_type"] or "-"],
        ["Trigger words", _p(", ".join(result["keywords"]) or "-", body)],
    ]
    table = Table(summary, colWidths=[48 * mm, 122 * mm])
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8dc")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eceff1")),
    ]))
    story += [table, Spacer(1, 6 * mm)]

    story.append(Paragraph("Links found", styles["Heading2"]))
    if result["urls"]:
        rows = [["Risk", "URL", "Reasons"]]
        for url in result["urls"]:
            rows.append([
                f"{url['level']} ({url['score']})",
                _p(url["url"], small),
                _p("; ".join(url["reasons"]) or "No issues found", small),
            ])
        url_table = Table(rows, colWidths=[24 * mm, 70 * mm, 76 * mm], repeatRows=1)
        url_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff1")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8dc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 1), (0, -1), 8.5),
        ]))
        story.append(url_table)
    else:
        story.append(_p("No links found in this email.", body))

    story += [Spacer(1, 4 * mm), Paragraph("Sender checks", styles["Heading2"])]
    if result["header_findings"]:
        for finding in result["header_findings"]:
            story.append(_p("- " + finding, body))
    else:
        story.append(_p("No header problems found (or no headers were provided).", body))

    story += [Spacer(1, 4 * mm), Paragraph("Email content", styles["Heading2"])]
    content = result["body"][:3000] + ("..." if len(result["body"]) > 3000 else "")
    story.append(Paragraph(escape(content).replace("\n", "<br/>"), small))

    story += [
        Spacer(1, 8 * mm),
        _p("This report is produced automatically and can be wrong. "
           "Do not click links or open attachments in an email you are unsure about.", small),
    ]

    doc.build(story)
    return buffer.getvalue()
