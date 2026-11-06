"""Portable PDF report generation for completed VAPT assessments."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def generate_pdf(assessment: dict[str, Any], output_dir: str | Path) -> str:
    """Write a compact, dependency-light PDF from a serialized assessment."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as error:
        raise RuntimeError("PDF generation requires reportlab; install it with: pip install reportlab") from error

    target = assessment.get("target", {})
    target_text = target.get("url") if isinstance(target, dict) else str(target)
    assessment_id = str(assessment.get("assessment_id", "assessment"))
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    pdf_path = output_path / f"{assessment_id}.pdf"

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="Finding", parent=styles["BodyText"], fontSize=9, leading=12, spaceAfter=5))
    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm)
    story = [Paragraph("VAPT Assessment Report", styles["Title"]),
             Paragraph(f"Assessment: {assessment_id}", styles["Small"]),
             Paragraph(f"Target: {target_text}", styles["Small"]),
             Paragraph(f"Status: {assessment.get('status', 'unknown')}", styles["Small"]), Spacer(1, 8)]

    summary = assessment.get("summary", {})
    counts = summary.get("by_severity", {})
    summary_rows = [["Finding count", "Critical", "High", "Medium", "Low", "Info", "Errors"],
                    [str(summary.get("finding_count", 0)), str(counts.get("critical", 0)),
                     str(counts.get("high", 0)), str(counts.get("medium", 0)),
                     str(counts.get("low", 0)), str(counts.get("info", 0)),
                     str(summary.get("error_count", len(assessment.get("errors", []))))]]
    table = Table(summary_rows, repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                               ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                               ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                               ("FONTSIZE", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story += [Paragraph("Summary", styles["Heading2"]), table, Spacer(1, 8), Paragraph("Findings", styles["Heading2"])]

    findings = assessment.get("findings", [])
    if not findings:
        story.append(Paragraph("No findings were recorded.", styles["Finding"]))
    for finding in findings:
        title = finding.get("title", finding.get("finding_id", "Finding"))
        severity = finding.get("severity", "unknown").upper()
        description = finding.get("description", "")
        remediation = finding.get("remediation", "")
        story.append(Paragraph(f"<b>{title}</b> [{severity}]", styles["Finding"]))
        story.append(Paragraph(description, styles["Finding"]))
        if remediation:
            story.append(Paragraph(f"<b>Remediation:</b> {remediation}", styles["Finding"]))

    errors = assessment.get("errors", [])
    if errors:
        story += [Paragraph("Errors", styles["Heading2"])]
        story.extend(Paragraph(str(error), styles["Small"]) for error in errors)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc.build(story, onFirstPage=lambda canvas, _: canvas.drawRightString(A4[0] - 16 * mm, 8 * mm, generated))
    return str(pdf_path)
