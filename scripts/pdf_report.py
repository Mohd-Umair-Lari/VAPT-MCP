<<<<<<< Updated upstream
=======
"""Professional PDF report generation for VAPT assessments.

Generates detailed, cybersecurity-specialist quality reports with:
- Cover page with engagement details
- Executive summary
- Methodology & scope
- Detailed findings per vulnerability class
- Evidence & remediation
- Appendices with raw data
"""
>>>>>>> Stashed changes
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json

# ReportLab imports at module level for helper functions
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, inch
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        PageBreak, KeepTogether, ListFlowable, ListItem
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


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
            "SQL Injection: Tested authentication and search endpoints with SQL meta-characters (\', \", OR 1=1, UNION SELECT) "
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
            "JWT Algorithm Confusion: Tested acceptance of 'alg:none' and 'alg:HS256' with public key "
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
<<<<<<< Updated upstream
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm, inch
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
            PageBreak, KeepTogether, ListFlowable, ListItem
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    except ImportError as error:
        raise RuntimeError("PDF generation requires reportlab; install it with: pip install reportlab") from error
=======
import json

# ReportLab imports at module level for helper functions
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, inch
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        PageBreak, KeepTogether, ListFlowable, ListItem
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


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
=======
>>>>>>> Stashed changes
    """Generate a professional, comprehensive PDF report from assessment data."""
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("PDF generation requires reportlab; install it with: pip install reportlab")

    target = assessment.get("target", {})
    target_text = target.get("url") if isinstance(target, dict) else str(target)
    assessment_id = str(assessment.get("assessment_id", "assessment"))
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    pdf_path = output_path / f"{assessment_id}.pdf"

    styles = getSampleStyleSheet()
    # Custom styles
    styles.add(ParagraphStyle(
        name="CoverTitle", parent=styles["Title"],
        fontSize=28, leading=34, spaceAfter=12, alignment=TA_CENTER,
        textColor=colors.HexColor("#1e3a5f")
    ))
    styles.add(ParagraphStyle(
        name="CoverSubtitle", parent=styles["Normal"],
        fontSize=14, leading=18, spaceAfter=6, alignment=TA_CENTER,
        textColor=colors.HexColor("#4a5568")
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader", parent=styles["Heading1"],
        fontSize=16, leading=20, spaceBefore=16, spaceAfter=8,
        textColor=colors.HexColor("#1e3a5f"), borderWidth=0, borderPadding=0,
        backColor=colors.HexColor("#f7fafc")
    ))
    styles.add(ParagraphStyle(
        name="SubSectionHeader", parent=styles["Heading2"],
        fontSize=13, leading=16, spaceBefore=10, spaceAfter=6,
        textColor=colors.HexColor("#2d3748")
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle", parent=styles["Normal"],
        fontSize=11, leading=14, spaceBefore=8, spaceAfter=4,
        textColor=colors.HexColor("#1a202c")
    ))
    styles.add(ParagraphStyle(
        name="BodyJustified", parent=styles["Normal"],
        fontSize=10, leading=13, alignment=TA_JUSTIFY, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="SmallText", parent=styles["Normal"],
        fontSize=8, leading=10, textColor=colors.HexColor("#718096")
    ))
    styles.add(ParagraphStyle(
        name="TableHeader", parent=styles["Normal"],
        fontSize=9, leading=11, textColor=colors.white, alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name="TableCell", parent=styles["Normal"],
        fontSize=9, leading=11, alignment=TA_LEFT
    ))
    styles.add(ParagraphStyle(
        name="TableCellCenter", parent=styles["Normal"],
        fontSize=9, leading=11, alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name="FindingDesc", parent=styles["Normal"],
        fontSize=10, leading=13, spaceAfter=4, alignment=TA_JUSTIFY
    ))
    styles.add(ParagraphStyle(
        name="Remediation", parent=styles["Normal"],
        fontSize=10, leading=13, spaceAfter=8,
        backColor=colors.HexColor("#fef3c7"), borderPadding=6,
        borderWidth=1, borderColor=colors.HexColor("#f59e0b")
    ))
    styles.add(ParagraphStyle(
        name="Evidence", parent=styles["Normal"],
        fontSize=8, leading=10, spaceAfter=4,
        backColor=colors.HexColor("#f3f4f6"), borderPadding=4,
        fontName="Courier"
    ))

    doc = SimpleDocTemplate(
        str(pdf_path), pagesize=A4,
        rightMargin=20 * mm, leftMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=20 * mm
    )

    story = []
    A4_WIDTH = A4[0] - 40 * mm

<<<<<<< Updated upstream
=======
    # ============================================================
    # COVER PAGE
    # ============================================================
>>>>>>> Stashed changes
    story.append(Spacer(1, 50 * mm))
    story.append(Paragraph("VULNERABILITY ASSESSMENT<br/>& PENETRATION TESTING REPORT", styles["CoverTitle"]))
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph("Comprehensive Security Assessment", styles["CoverSubtitle"]))
    story.append(Spacer(1, 20 * mm))

    # Cover info table
    cover_data = [
        [Paragraph("<b>Target</b>", styles["TableHeader"]), Paragraph(target_text or "N/A", styles["TableCell"])],
        [Paragraph("<b>Assessment ID</b>", styles["TableHeader"]), Paragraph(assessment_id, styles["TableCell"])],
        [Paragraph("<b>Status</b>", styles["TableHeader"]), Paragraph(assessment.get("status", "unknown").upper(), styles["TableCell"])],
        [Paragraph("<b>Scan Type</b>", styles["TableHeader"]), Paragraph(_get_scan_type(assessment), styles["TableCell"])],
        [Paragraph("<b>Date</b>", styles["TableHeader"]), Paragraph(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), styles["TableCell"])],
        [Paragraph("<b>Classification</b>", styles["TableHeader"]), Paragraph("CONFIDENTIAL", styles["TableCell"])],
    ]
    cover_table = Table(cover_data, colWidths=[50 * mm, A4_WIDTH - 50 * mm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

<<<<<<< Updated upstream
=======
    # ============================================================
    # TABLE OF CONTENTS
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("TABLE OF CONTENTS", styles["SectionHeader"]))
    story.append(Spacer(1, 4 * mm))
    toc_items = [
        "1. Executive Summary",
        "2. Scope & Methodology",
        "3. Findings Summary",
        "4. Detailed Findings",
        "5. Evidence & Technical Details",
        "6. Remediation Guidance",
        "7. Appendix A: Scan Configuration",
        "8. Appendix B: Reconnaissance Data",
        "9. Appendix C: Tool Outputs",
    ]
    for item in toc_items:
        story.append(Paragraph(item, ParagraphStyle(
            "TOCItem", parent=styles["Normal"], fontSize=11, leading=18,
            leftIndent=10 * mm, textColor=colors.HexColor("#2d3748")
        )))
    story.append(PageBreak())

<<<<<<< Updated upstream
=======
    # ============================================================
    # 1. EXECUTIVE SUMMARY
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("1. EXECUTIVE SUMMARY", styles["SectionHeader"]))
    story.append(Spacer(1, 2 * mm))

    summary = assessment.get("summary", {})
    findings = assessment.get("findings", [])
    finding_count = summary.get("finding_count", len(findings))
    by_severity = summary.get("by_severity", {})

    exec_text = (
        f"This report presents the results of a {_get_scan_type(assessment).lower()} "
        f"conducted against <b>{target_text}</b> on "
        f"{datetime.now(timezone.utc).strftime('%B %d, %Y')}. "
        f"The assessment identified a total of <b>{finding_count}</b> findings across "
        f"<b>{len(by_severity)}</b> severity levels."
    )
    story.append(Paragraph(exec_text, styles["BodyJustified"]))
    story.append(Spacer(1, 4 * mm))

    # Severity breakdown table
    sev_data = [
        [Paragraph("<b>Severity</b>", styles["TableHeader"]),
         Paragraph("<b>Count</b>", styles["TableHeader"]),
         Paragraph("<b>Percentage</b>", styles["TableHeader"]),
         Paragraph("<b>Risk Level</b>", styles["TableHeader"])],
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = by_severity.get(sev, 0)
        pct = f"{(count/finding_count*100):.1f}%" if finding_count > 0 else "0%"
        risk = _severity_risk_text(sev)
        sev_color = SEVERITY_COLORS.get(sev, "#6b7280")
        sev_data.append([
            Paragraph(f'<font color="{sev_color}"><b>{sev.upper()}</b></font>', styles["TableCell"]),
            Paragraph(str(count), styles["TableCellCenter"]),
            Paragraph(pct, styles["TableCellCenter"]),
            Paragraph(risk, styles["TableCellCenter"]),
        ])

    sev_table = Table(sev_data, colWidths=[30 * mm, 20 * mm, 30 * mm, A4_WIDTH - 80 * mm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 6 * mm))

    # Key findings highlight
    critical_high = [f for f in findings if f.get("severity", "").lower() in ("critical", "high")]
    if critical_high:
        story.append(Paragraph("<b>Key Risk Areas Requiring Immediate Attention:</b>", styles["BodyJustified"]))
        for f in critical_high[:5]:
            title = f.get("title", f.get("finding_id", "Finding"))
            sev = f.get("severity", "").upper()
            sev_color = SEVERITY_COLORS.get(f.get("severity", "").lower(), "#6b7280")
            story.append(Paragraph(
                f"• <font color='{sev_color}'><b>{sev}</b></font> — {title}",
                styles["FindingDesc"]
            ))
    story.append(PageBreak())

<<<<<<< Updated upstream
=======
    # ============================================================
    # 2. SCOPE & METHODOLOGY
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("2. SCOPE & METHODOLOGY", styles["SectionHeader"]))
    story.append(Spacer(1, 2 * mm))

    story.append(Paragraph("2.1 Engagement Scope", styles["SubSectionHeader"]))
    scope_text = (
        f"The assessment was performed against the target <b>{target_text}</b>. "
        f"The scope included all accessible web endpoints, APIs, and services reachable "
        f"from the public internet. The following activities were explicitly authorized:"
    )
    story.append(Paragraph(scope_text, styles["BodyJustified"]))

    scope_items = [
        "Passive reconnaissance (header analysis, SSL/TLS configuration, DNS enumeration)",
        "Content discovery (directory brute-forcing, API endpoint identification, technology fingerprinting)",
        "Vulnerability detection (injection, XSS, SSRF, path traversal, open redirect, misconfiguration)",
        "Active exploitation (where approved) to validate finding impact",
        "Security configuration review (headers, cookies, CORS, JWT, authentication mechanisms)",
    ]
    for item in scope_items:
        story.append(Paragraph(f"• {item}", styles["FindingDesc"], bulletText="•"))

    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("2.2 Testing Methodology", styles["SubSectionHeader"]))
    method_text = (
        "The assessment follows industry-standard methodologies including OWASP Testing Guide v4, "
        "OWASP ASVS 4.0, NIST SP 800-115, and PTES. The approach combines automated scanning "
        "with manual validation to minimize false positives and maximize coverage."
    )
    story.append(Paragraph(method_text, styles["BodyJustified"]))

    method_items = [
        "<b>Reconnaissance Phase:</b> Automated discovery of endpoints, technologies, and attack surface using "
        "80+ universal paths, 15+ technology-specific paths, and pattern-based discovery.",
        "<b>Detection Phase:</b> Low-impact probes for SQL injection (error-based), reflected XSS, SSRF, "
        "and configuration issues (headers, cookies, CORS).",
        "<b>Exploitation Phase:</b> Controlled proof-of-concept exploitation to validate findings "
        "(requires explicit approval). Includes SQLi auth bypass, JWT alg:none, IDOR, weak credentials.",
        "<b>Validation:</b> All findings manually verified; false positives removed. Evidence captured "
        "including request/response pairs, payloads, and impact demonstrations.",
    ]
    for item in method_items:
        story.append(Paragraph(item, styles["FindingDesc"], bulletText="•"))

    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("2.3 Tooling", styles["SubSectionHeader"]))
    story.append(Paragraph(
        "Custom VAPT framework with integrated modules: HTTP client (rate-limited, scope-enforced), "
        "reconnaissance engine (80+ paths, tech fingerprinting), exploit modules (12 modules across 6 categories), "
        "deep crawler (forms, parameters, tech detection), approval-gated exploitation, and internet-wide CIDR scanner.",
        styles["BodyJustified"]
    ))
    story.append(PageBreak())

<<<<<<< Updated upstream
=======
    # ============================================================
    # 3. FINDINGS SUMMARY
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("3. FINDINGS SUMMARY", styles["SectionHeader"]))
    story.append(Spacer(1, 2 * mm))

    # Group findings by vulnerability class
    findings_by_class = _group_findings_by_class(findings)

    for vuln_class, class_findings in sorted(findings_by_class.items()):
        class_details = VULN_CLASS_DETAILS.get(vuln_class, {"name": vuln_class.title()})
        story.append(Paragraph(f"3.{list(VULN_CLASS_DETAILS.keys()).index(vuln_class)+1} {class_details['name']}", styles["SubSectionHeader"]))
        story.append(Paragraph(f"<b>Findings:</b> {len(class_findings)}", styles["BodyJustified"]))

        # Summary table for this class
        class_sev = {}
        for f in class_findings:
            sev = f.get("severity", "info").lower()
            class_sev[sev] = class_sev.get(sev, 0) + 1

        class_table_data = [
            [Paragraph("<b>Severity</b>", styles["TableHeader"]), Paragraph("<b>Count</b>", styles["TableHeader"])],
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if class_sev.get(sev, 0) > 0:
                sev_color = SEVERITY_COLORS.get(sev, "#6b7280")
                class_table_data.append([
                    Paragraph(f'<font color="{sev_color}"><b>{sev.upper()}</b></font>', styles["TableCell"]),
                    Paragraph(str(class_sev[sev]), styles["TableCellCenter"]),
                ])

        if len(class_table_data) > 1:
            ct = Table(class_table_data, colWidths=[60 * mm, A4_WIDTH - 60 * mm])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(ct)

    story.append(PageBreak())

<<<<<<< Updated upstream
=======
    # ============================================================
    # 4. DETAILED FINDINGS
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("4. DETAILED FINDINGS", styles["SectionHeader"]))
    story.append(Spacer(1, 2 * mm))

    intro_text = (
        "Each finding below includes: vulnerability description, technical details, evidence, "
        "impact assessment, and specific remediation guidance. Findings are grouped by vulnerability "
        "class and ordered by severity (Critical → Info)."
    )
    story.append(Paragraph(intro_text, styles["BodyJustified"]))
    story.append(Spacer(1, 4 * mm))

    finding_num = 0
    for vuln_class in VULN_CLASS_DETAILS.keys():
        class_findings = findings_by_class.get(vuln_class, [])
        if not class_findings:
            continue

        class_details = VULN_CLASS_DETAILS[vuln_class]
        story.append(Paragraph(f"4.{list(VULN_CLASS_DETAILS.keys()).index(vuln_class)+1} {class_details['name']}", styles["SubSectionHeader"]))

        # Class description
        story.append(Paragraph(class_details["description"], styles["BodyJustified"]))
        story.append(Spacer(1, 2 * mm))

        # Tests performed
        story.append(Paragraph("<b>Tests Performed:</b>", styles["BodyJustified"]))
        for test in class_details["tests_performed"]:
            story.append(Paragraph(f"• {test}", styles["FindingDesc"], bulletText="•"))
        story.append(Spacer(1, 4 * mm))

        # Individual findings
        for finding in sorted(class_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info").lower(), 5)):
            finding_num += 1
            _add_finding_detail(story, finding, finding_num, styles, SEVERITY_COLORS)

    story.append(PageBreak())

    # ============================================================
    # 5. EVIDENCE & TECHNICAL DETAILS
    # ============================================================
<<<<<<< Updated upstream
    story.append(Paragraph("5. EVIMDENCE & TECHNICAL DETAILS", styles["SectionHeader"]))
=======
    story.append(Paragraph("5. EVIDENCE & TECHNICAL DETAILS", styles["SectionHeader"]))
>>>>>>> Stashed changes
    story.append(Spacer(1, 2 * mm))

    for finding in findings:
        evidence = finding.get("evidence", [])
        if evidence:
            title = finding.get("title", finding.get("finding_id", "Finding"))
            story.append(Paragraph(f"Finding: {title} [{finding.get('severity', '').upper()}]", styles["SubSectionHeader"]))
            for ev in evidence:
                ev_type = ev.get("type", "evidence")
                ev_data = ev.get("data", {})
                story.append(Paragraph(f"<b>Evidence Type:</b> {ev_type}", styles["FindingDesc"]))
                if isinstance(ev_data, dict):
                    for k, v in ev_data.items():
                        story.append(Paragraph(f"  <b>{k}:</b> {v}", styles["Evidence"]))
                else:
                    story.append(Paragraph(f"  {ev_data}", styles["Evidence"]))
            story.append(Spacer(1, 3 * mm))

    story.append(PageBreak())

<<<<<<< Updated upstream
=======
    # ============================================================
    # 6. REMEDIATION GUIDANCE
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("6. REMEDIATION GUIDANCE", styles["SectionHeader"]))
    story.append(Spacer(1, 2 * mm))

    remediation_text = (
        "The following prioritized remediation guidance addresses the root causes of identified "
        "vulnerabilities. Recommendations are ordered by risk reduction potential."
    )
    story.append(Paragraph(remediation_text, styles["BodyJustified"]))
    story.append(Spacer(1, 4 * mm))

    # Priority 1: Critical/High
    critical_high = [f for f in findings if f.get("severity", "").lower() in ("critical", "high")]
    if critical_high:
        story.append(Paragraph("Priority 1 — Immediate (Critical & High Severity)", styles["SubSectionHeader"]))
        for f in critical_high:
            title = f.get("title", f.get("finding_id", "Finding"))
            rem = f.get("remediation", "No specific remediation provided.")
            story.append(Paragraph(f"<b>{title} [{f.get('severity', '').upper()}]</b>", styles["FindingDesc"]))
            story.append(Paragraph(rem, styles["Remediation"]))

    # Priority 2: Medium
    medium_findings = [f for f in findings if f.get("severity", "").lower() == "medium"]
    if medium_findings:
        story.append(Paragraph("Priority 2 — Short-term (Medium Severity)", styles["SubSectionHeader"]))
        for f in medium_findings:
            title = f.get("title", f.get("finding_id", "Finding"))
            rem = f.get("remediation", "No specific remediation provided.")
            story.append(Paragraph(f"<b>{title} [MEDIUM]</b>", styles["FindingDesc"]))
            story.append(Paragraph(rem, styles["Remediation"]))

    # Priority 3: Low/Info
    low_info = [f for f in findings if f.get("severity", "").lower() in ("low", "info")]
    if low_info:
        story.append(Paragraph("Priority 3 — Long-term (Low & Informational)", styles["SubSectionHeader"]))
        for f in low_info:
            title = f.get("title", f.get("finding_id", "Finding"))
            rem = f.get("remediation", "No specific remediation provided.")
            story.append(Paragraph(f"<b>{title} [{f.get('severity', '').upper()}]</b>", styles["FindingDesc"]))
            story.append(Paragraph(rem, styles["Remediation"]))

    story.append(PageBreak())

<<<<<<< Updated upstream

=======
    # ============================================================
    # APPENDIX A: SCAN CONFIGURATION
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("APPENDIX A: SCAN CONFIGURATION", styles["SectionHeader"]))
    story.append(Spacer(1, 2 * mm))

    active_cfg = assessment.get("active", {})
    config_data = [
        [Paragraph("<b>Parameter</b>", styles["TableHeader"]), Paragraph("<b>Value</b>", styles["TableHeader"])],
        ["Scan Type", _get_scan_type(assessment)],
        ["Rate Limit", f"{active_cfg.get('rate_limit_per_second', 'N/A')} req/s"],
        ["Max Concurrent", str(active_cfg.get('max_concurrent_per_host', 'N/A'))],
        ["Max Redirects", str(active_cfg.get('max_redirects', 'N/A'))],
        ["Response Size Limit", f"{active_cfg.get('max_response_bytes', 'N/A')} bytes"],
        ["Request Budget", str(active_cfg.get('global_request_budget', 'N/A'))],
        ["Private IPs Allowed", str(active_cfg.get('allow_private_ips', 'N/A'))],
        ["DNS Rebinding Protection", str(active_cfg.get('enable_dns_rebinding_protection', 'N/A'))],
        ["Scope Enforcement", str(active_cfg.get('enforce_scope', 'N/A'))],
        ["Exploit Categories", ", ".join(active_cfg.get('exploit_categories', ['all']))],
        ["Crawl Enabled", str(active_cfg.get('phases', {}).get('crawl', False))],
    ]
    config_table = Table(config_data, colWidths=[60 * mm, A4_WIDTH - 60 * mm])
    config_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
    ]))
    story.append(config_table)
    story.append(PageBreak())

<<<<<<< Updated upstream
=======
    # ============================================================
    # APPENDIX B: RECONNAISSANCE DATA
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("APPENDIX B: RECONNAISSANCE DATA", styles["SectionHeader"]))
    story.append(Spacer(1, 2 * mm))

    recon = assessment.get("recon", [])
    if recon:
        story.append(Paragraph(f"Total paths checked: {len(recon)}", styles["BodyJustified"]))
        story.append(Spacer(1, 2 * mm))

        # Show discovered endpoints
        discovered = [r for r in recon if r.get("status") and 200 <= r.get("status", 0) < 400]
        if discovered:
            story.append(Paragraph(f"Discovered endpoints ({len(discovered)}):", styles["SubSectionHeader"]))
            for item in discovered[:50]:
                path = item.get("path", "")
                status = item.get("status", "")
                ctype = item.get("content_type", "")
                story.append(Paragraph(f"  <b>{path}</b> — HTTP {status} — {ctype}", styles["FindingDesc"]))
            if len(discovered) > 50:
                story.append(Paragraph(f"  ... and {len(discovered) - 50} more", styles["SmallText"]))

    # Technology fingerprinting
    obs = assessment.get("observations", {})
    techs = obs.get("technologies", {})
    if techs:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("Detected Technologies:", styles["SubSectionHeader"]))
        for cat, items in techs.items():
            if items:
                story.append(Paragraph(f"  <b>{cat}:</b> {', '.join(items)}", styles["FindingDesc"]))

    story.append(PageBreak())

<<<<<<< Updated upstream
=======
    # ============================================================
    # APPENDIX C: TOOL OUTPUTS & ERRORS
    # ============================================================
>>>>>>> Stashed changes
    story.append(Paragraph("APPENDIX C: TOOL OUTPUTS & ERRORS", styles["SectionHeader"]))
    story.append(Spacer(1, 2 * mm))

    errors = assessment.get("errors", [])
    if errors:
        story.append(Paragraph(f"Errors encountered ({len(errors)}):", styles["SubSectionHeader"]))
        for err in errors:
            story.append(Paragraph(f"  • {err}", styles["FindingDesc"]))
    else:
        story.append(Paragraph("No errors recorded during assessment.", styles["BodyJustified"]))

<<<<<<< Updated upstream
=======
    # ============================================================
    # FOOTER / GENERATED INFO
    # ============================================================
>>>>>>> Stashed changes
    story.append(Spacer(1, 15 * mm))
    story.append(Paragraph(
        f"<i>Report generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</i>",
        styles["SmallText"]
    ))
    story.append(Paragraph(
        "<i>This report contains confidential security information. Distribution should be limited to authorized personnel only.</i>",
        styles["SmallText"]
    ))

    # Build PDF
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc.build(story, onFirstPage=lambda canvas, _: canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, generated))
    return str(pdf_path)


def _get_scan_type(assessment: dict[str, Any]) -> str:
<<<<<<< Updated upstream


def _get_scan_type(assessment: dict[str, Any]) -> str:
=======
>>>>>>> Stashed changes
    """Determine scan type from assessment data."""
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
    """Group findings by vulnerability class based on finding_id."""
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
    """Add a detailed finding entry to the story."""
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
