<<<<<<< Updated upstream
"""Portable PDF report generation for completed VAPT assessments."""
=======
>>>>>>> Stashed changes
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
<<<<<<< Updated upstream


def generate_pdf(assessment: dict[str, Any], output_dir: str | Path) -> str:
    """Write a compact, dependency-light PDF from a serialized assessment."""
=======
import json


# Vulnerability class descriptions for the report
VULN_CLASS_DETAILS = {
    "injection": {
        "name": "Injection Vulnerabilities",
        "description": (
            "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. "
            "The attacker's hostile data can trick the interpreter into executing unintended commands or accessing "
            "data without proper authorization. This category includes SQL Injection, Command Injection, LDAP Injection, "
            "NoSQL Injection, and XML External Entity (XXE) Injection."
        ),
        "tests_performed": [
            "SQL Injection: Tested authentication and search endpoints with SQL meta-characters (', \", OR 1=1, UNION SELECT) "
            "to detect improper input sanitization in database queries.",
            "Command Injection: Tested ping, exec, shell, and diagnostic endpoints with command separators (;, |, &, &&, $()) "
            "to detect OS command execution via user input.",
            "LDAP Injection: Tested login and search filters with LDAP meta-characters (*, (), |) "
            "to detect improper LDAP query construction.",
            "NoSQL Injection: Tested MongoDB/NoSQL endpoints with operator injection ($ne, $gt, $regex, $where) "
            "to detect query logic bypass.",
            "XXE Injection: Tested XML parsers with external entity references to detect file read and SSRF via XML processing.",
        ],
        "impact": "Critical - Can lead to full database compromise, remote code execution, authentication bypass, and data exfiltration.",
        "references": ["OWASP Top 10: A03:2021 - Injection", "CWE-89, CWE-78, CWE-74"]
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "description": (
            "XSS flaws occur when an application includes untrusted data in a web page without proper validation "
            "or escaping. An attacker can execute malicious scripts in the victim's browser, leading to session "
            "hijacking, credential theft, defacement, or malware distribution."
        ),
        "tests_performed": [
            "Reflected XSS: Injected JavaScript payloads (<script>alert(1)</script>, <img src=x onerror=alert(1)>, "
            "svg/onload, javascript: URIs) into search, query, and reflection endpoints to verify output encoding.",
            "DOM-based XSS Indicators: Checked for unsafe JavaScript sinks (innerHTML, document.write, eval) "
            "via static analysis of returned scripts.",
        ],
        "impact": "Medium to Critical - Session hijacking, credential theft, defacement, malware delivery.",
        "references": ["OWASP Top 10: A03:2021 - Injection (XSS)", "CWE-79"]
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": (
            "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL. "
            "An attacker can force the application to make requests to internal services, cloud metadata endpoints, "
            "or arbitrary external systems, potentially bypassing firewalls and accessing sensitive data."
        ),
        "tests_performed": [
            "Cloud Metadata Access: Tested fetch/proxy/import endpoints with cloud metadata URLs "
            "(http://169.254.169.254/latest/meta-data/, http://metadata.google.internal/, "
            "http://metadata.azure.com/) to detect internal service exposure.",
            "Internal Network Scanning: Tested with private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
            "127.0.0.1) and alternative protocols (file://, dict://, gopher://, ldap://) to detect internal reachability.",
        ],
        "impact": "Critical - Internal network access, cloud credential theft, service enumeration, potential RCE.",
        "references": ["OWASP Top 10: A10:2021 - SSRF", "CWE-918"]
    },
    "path_traversal": {
        "name": "Path Traversal / Directory Traversal",
        "description": (
            "Path traversal vulnerabilities allow attackers to access files and directories outside the web root "
            "by manipulating file path inputs with sequences like ../ or ..\\. This can lead to disclosure of "
            "system files, source code, configuration files, and credentials."
        ),
        "tests_performed": [
            "Standard Traversal: Tested file/download/read/view endpoints with payloads "
            "(../../../etc/passwd, ..\\..\\..\\windows\\win.ini) to detect directory escape.",
            "Encoded Traversal: Tested URL-encoded variants (%2e%2e%2f, ..%2f, ..%5c) and double-encoding "
            "to bypass basic filters.",
            "Null Byte Injection: Tested payloads with null bytes (%00) to bypass file extension checks "
            "(where applicable to legacy PHP/Java).",
        ],
        "impact": "High - Sensitive file disclosure, source code exposure, credential theft, system compromise.",
        "references": ["OWASP: Path Traversal", "CWE-22"]
    },
    "redirect": {
        "name": "Open Redirect",
        "description": (
            "Open redirects occur when an application redirects users to a user-supplied URL without validation. "
            "While often considered low severity, they enable phishing campaigns by making malicious links "
            "appear to originate from the trusted domain."
        ),
        "tests_performed": [
            "Parameter Testing: Tested redirect/login/logout/next/return/url/goto parameters with "
            "external URLs (https://evil.com) to detect unrestricted redirection.",
            "Header-Based Redirects: Checked for Location header manipulation via Host, X-Forwarded-Host, "
            "and Referer headers.",
        ],
        "impact": "Low to Medium - Phishing facilitation, credential harvesting, OAuth/SAML flow hijacking.",
        "references": ["OWASP: Unvalidated Redirects and Forwards", "CWE-601"]
    },
    "config": {
        "name": "Security Misconfiguration",
        "description": (
            "Security misconfigurations are the most common issue seen in web applications. They include "
            "missing security headers, overly permissive CORS policies, insecure cookie settings, "
            "default credentials, and unnecessary feature exposure."
        ),
        "tests_performed": [
            "Security Headers: Verified presence of Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, "
            "Strict-Transport-Security, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, "
            "Cross-Origin-Resource-Policy.",
            "CORS Configuration: Tested with Origin: https://evil.com to detect over-permissive policies "
            "(wildcard *, reflected origin with credentials).",
            "Cookie Security: Verified Secure, HttpOnly, and SameSite attributes on session cookies.",
            "JWT Algorithm Confusion: Tested acceptance of \'alg:none\' and \'alg:HS256\' with public key "
            "to detect algorithm confusion vulnerabilities.",
            "IDOR Testing: Tested authenticated access to object references (/api/users/1, /api/orders/2, etc.) "
            "to detect missing authorization checks.",
            "Weak Credentials: Tested common default credentials (admin/admin, admin/password, test/test) "
            "against login endpoints.",
        ],
        "impact": "Varies (Low to Critical) - Information disclosure, session hijacking, account takeover, compliance violations.",
        "references": ["OWASP Top 10: A05:2021 - Security Misconfiguration", "CWE-16"]
    }
}

# Severity ordering for reports
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#2563eb"
}


def generate_pdf(assessment: dict[str, Any], output_dir: str | Path) -> str:
>>>>>>> Stashed changes
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
<<<<<<< Updated upstream
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
=======
        from reportlab.lib.units import mm, inch
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
            PageBreak, KeepTogether, ListFlowable, ListItem
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
=======


def _get_scan_type(assessment: dict[str, Any]) -> str:
    active = assessment.get("active", {})
    phases = active.get("phases", {})
    if phases.get("exploit"):
        return "Active Scan with Exploitation"
    elif phases.get("crawl"):
        return "Active Scan with Deep Crawl"
    elif phases.get("detect"):
        return "Active Scan (Detection Only)"
    return "Passive Scan"


def _severity_risk_text(severity: str) -> str:
    mapping = {
        "critical": "Immediate action required — Complete compromise likely",
        "high": "Urgent remediation — Significant impact likely",
        "medium": "Short-term fix — Moderate impact possible",
        "low": "Long-term improvement — Limited impact",
        "info": "Informational — No direct risk"
    }
    return mapping.get(severity.lower(), "Unknown")


def _group_findings_by_class(findings: list[dict]) -> dict[str, list]:
    groups = {k: [] for k in VULN_CLASS_DETAILS.keys()}
    for f in findings:
        fid = f.get("finding_id", "").lower()
        matched = False
        for cls in VULN_CLASS_DETAILS.keys():
            if cls in fid or any(kw in fid for kw in _class_keywords(cls)):
                groups[cls].append(f)
                matched = True
                break
        if not matched:
            # Default to config for unclassified
            groups.setdefault("config", []).append(f)
    return {k: v for k, v in groups.items() if v}


def _class_keywords(cls: str) -> list[str]:
    mapping = {
        "injection": ["sqli", "sql", "cmd", "command", "ldap", "nosql", "xxe", "injection"],
        "xss": ["xss", "reflected", "script"],
        "ssrf": ["ssrf", "metadata", "fetch"],
        "path_traversal": ["path", "traversal", "directory"],
        "redirect": ["redirect", "open_redirect"],
        "config": ["cors", "cookie", "header", "jwt", "idor", "weak", "cred", "missing", "config"],
    }
    return mapping.get(cls, [])


def _add_finding_detail(story, finding: dict, num: int, styles, severity_colors):
    title = finding.get("title", finding.get("finding_id", f"Finding {num}"))
    severity = finding.get("severity", "info").upper()
    sev_color = severity_colors.get(finding.get("severity", "info").lower(), "#6b7280")
    description = finding.get("description", "")
    remediation = finding.get("remediation", "")
    confidence = finding.get("confidence", "high")

    # Finding header
    story.append(Paragraph(
        f"Finding {num}: <font color='{sev_color}'><b>{title}</b></font> "
        f"[<font color='{sev_color}'><b>{severity}</b></font>] "
        f"(Confidence: {confidence.capitalize()})",
        styles["FindingTitle"]
    ))

    # Description
    if description:
        story.append(Paragraph(f"<b>Description:</b> {description}", styles["FindingDesc"]))

    # Evidence
    evidence = finding.get("evidence", [])
    if evidence:
        story.append(Paragraph("<b>Evidence:</b>", styles["FindingDesc"]))
        for ev in evidence:
            ev_type = ev.get("type", "evidence")
            ev_data = ev.get("data", {})
            story.append(Paragraph(f"  • <b>{ev_type}:</b>", styles["Evidence"]))
            if isinstance(ev_data, dict):
                for k, v in ev_data.items():
                    story.append(Paragraph(f"    <b>{k}:</b> {v}", styles["Evidence"]))
            else:
                story.append(Paragraph(f"    {ev_data}", styles["Evidence"]))

    # Remediation
    if remediation:
        story.append(Paragraph(f"<b>Remediation:</b> {remediation}", styles["Remediation"]))

    story.append(Spacer(1, 4 * mm))
>>>>>>> Stashed changes
