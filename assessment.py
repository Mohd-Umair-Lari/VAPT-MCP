#!/usr/bin/env python3
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ALLOWED_TARGETS = {"192.168.56.102:3000"}
REPORTS = Path.home() / "vapt-mvp" / "reports"

def blocked(target, reason):
    print(json.dumps({"status": "DENIED", "target": target, "reason": reason}, indent=2))
    sys.exit(1)

target = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.102:3000"

if target not in ALLOWED_TARGETS:
    blocked(target, "Target is outside the authorized lab scope.")

url = f"http://{target}/"
timestamp = datetime.now(timezone.utc).isoformat()
evidence = {"url": url, "timestamp_utc": timestamp, "headers": {}, "status_code": None}
findings = []

try:
    request = Request(url, headers={"User-Agent": "VAPT-MVP-Lab/0.1"})
    with urlopen(request, timeout=10) as response:
        evidence["status_code"] = response.status
        evidence["headers"] = dict(response.headers.items())
except (URLError, HTTPError, TimeoutError) as error:
    print(json.dumps({"status": "FAILED", "target": target, "error": str(error)}, indent=2))
    sys.exit(2)

headers = {key.lower(): value for key, value in evidence["headers"].items()}
for header, title, severity in [
    ("content-security-policy", "Content Security Policy header not observed", "Low"),
    ("x-frame-options", "Clickjacking protection header not observed", "Low"),
    ("x-content-type-options", "MIME-sniffing protection header not observed", "Low"),
]:
    if header not in headers:
        findings.append({
            "title": title,
            "severity": severity,
            "confidence": "Observed",
            "evidence": f"Response from {url} did not include {header}."
        })

result = {
    "assessment_id": datetime.now().strftime("lab-%Y%m%d-%H%M%S"),
    "status": "COMPLETED",
    "scope": target,
    "policy": "Passive HTTP inspection only",
    "evidence": evidence,
    "findings": findings
}

REPORTS.mkdir(parents=True, exist_ok=True)
report_json = REPORTS / f"{result['assessment_id']}.json"
report_json.write_text(json.dumps(result, indent=2))

lines = [
    "# VAPT MVP Assessment Report",
    f"- Assessment: `{result['assessment_id']}`",
    f"- Authorized target: `{target}`",
    f"- Policy: `{result['policy']}`",
    f"- HTTP status: `{evidence['status_code']}`",
    "",
    "## Findings",
]
lines += ["- No observations recorded."] if not findings else [
    f"- **{f['severity']}** — {f['title']}\n  - Evidence: {f['evidence']}"
    for f in findings
]
report_md.write_text("\n".join(lines) + "\n")

print(json.dumps({
    "status": "COMPLETED",
    "target": target,
    "http_status": evidence["status_code"],
    "findings": len(findings),
    "report": str(report_md)
}, indent=2))
