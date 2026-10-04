#!/usr/bin/env python3
"""Non-intrusive Phase 1/2 VAPT assessment for the authorized lab target."""
from __future__ import annotations
import argparse, json, sys, urllib.error, urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_CONFIG = Path(__file__).with_name("config.json")
DEFAULT_REPORT_DIR = Path(__file__).resolve().parent / "reports"
SAFE_RECON_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
REQUIRED_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy header", "medium"),
    "x-frame-options": ("Missing X-Frame-Options header", "low"),
    "x-content-type-options": ("Missing X-Content-Type-Options header", "low"),
}

@dataclass
class Evidence:
    kind: str
    value: Any

@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    confidence: str = "high"
    remediation: str = "Review this behavior and apply the recommended security configuration for the application."

@dataclass
class Assessment:
    assessment_id: str
    started_at_utc: str
    completed_at_utc: str | None
    target: dict[str, Any]
    status: str
    checks: list[str] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    recon: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def load_config(path: Path) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    target = config.get("target", {})
    if not {"scheme", "host", "port", "base_path"}.issubset(target):
        raise ValueError("config target must include scheme, host, port, and base_path")
    if target["scheme"] != "http" or target["host"] != "192.168.56.101" or int(target["port"]) != 3000:
        raise ValueError("allowlist violation: only http://192.168.56.101:3000 is authorized")
    return config

def target_url(target: dict[str, Any]) -> str:
    path = str(target.get("base_path", "/")); path = path if path.startswith("/") else "/" + path
    return f"{target['scheme']}://{target['host']}:{int(target['port'])}{path}"

def assess_headers(headers: dict[str, str]) -> list[Finding]:
    normalized = {k.lower(): v for k, v in headers.items()}; findings = []
    for header, (title, severity) in REQUIRED_HEADERS.items():
        if not normalized.get(header):
            findings.append(Finding(f"missing-{header.replace('-', '_')}", title, severity,
                f"The response did not include the recommended {header} response header.",
                [Evidence("response_header", {"header": header, "present": False})]))
    return findings

def assess_phase3(headers: dict[str, str], recon: list[dict[str, Any]]) -> list[Finding]:
    """Perform passive checks using only the already collected response data."""
    findings: list[Finding] = []
    if headers.get("Access-Control-Allow-Origin", "").strip() == "*":
        findings.append(Finding(
            "wildcard-cors", "Wildcard CORS policy", "low",
            "The response allows cross-origin requests from any origin. Confirm this is intended for the application.",
            [Evidence("response_header", {"header": "Access-Control-Allow-Origin", "value": "*"})],
        ))
    if headers.get("X-Recruiting"):
        findings.append(Finding(
            "recruiting-header-disclosure", "Recruiting path disclosed in response header", "info",
            "The response exposes an application route through the X-Recruiting header. This is usually low risk but should be intentional.",
            [Evidence("response_header", {"header": "X-Recruiting", "value": headers["X-Recruiting"]})],
        ))
    for item in recon:
        if item.get("status") == 200 and item.get("path") == "/sitemap.xml" and "html" in (item.get("content_type") or "").lower():
            findings.append(Finding(
                "sitemap-fallback", "Sitemap path returns HTML", "info",
                "The sitemap path returned HTML rather than an XML content type; it may be the application shell fallback, not a real sitemap.",
                [Evidence("recon_response", item)],
            ))
    return findings

def assess_phase4(headers: dict[str, str], final_url: str, requested_url: str) -> list[Finding]:
    """Passive checks for cookies, redirects, and advertised HTTP methods."""
    findings: list[Finding] = []
    cookie = headers.get("Set-Cookie", "")
    if cookie and "secure" not in cookie.lower():
        findings.append(Finding("cookie-without-secure", "Cookie missing Secure attribute", "low",
            "A cookie was set without the Secure attribute.", [Evidence("set_cookie", cookie)],
            remediation="Set Secure on cookies when the application is served over HTTPS."))
    if cookie and "httponly" not in cookie.lower():
        findings.append(Finding("cookie-without-httponly", "Cookie missing HttpOnly attribute", "low",
            "A cookie was set without the HttpOnly attribute.", [Evidence("set_cookie", cookie)],
            remediation="Set HttpOnly on cookies that do not need browser JavaScript access."))
    if cookie and "samesite" not in cookie.lower():
        findings.append(Finding("cookie-without-samesite", "Cookie missing SameSite attribute", "low",
            "A cookie was set without a SameSite attribute.", [Evidence("set_cookie", cookie)],
            remediation="Set an appropriate SameSite policy, usually Lax or Strict."))
    if final_url != requested_url:
        findings.append(Finding("unexpected-redirect", "Request redirected", "info",
            "The target redirected the assessment request to another URL; confirm this is expected.",
            [Evidence("redirect", {"requested": requested_url, "final": final_url})]))
    allow = headers.get("Allow")
    if allow:
        findings.append(Finding("advertised-http-methods", "HTTP methods advertised", "info",
            "The response advertises supported HTTP methods. Review the list for methods not required by the application.",
            [Evidence("allow_header", allow)]))
    return findings

def finish_summary(assessment: Assessment) -> None:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in assessment.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    assessment.summary = {"finding_count": len(assessment.findings), "by_severity": counts,
        "recon_paths_checked": len(assessment.recon), "error_count": len(assessment.errors)}

def safe_recon(target: dict[str, Any], user_agent: str, timeout: float) -> list[dict[str, Any]]:
    base = f"{target['scheme']}://{target['host']}:{int(target['port'])}"; results = []
    for path in SAFE_RECON_PATHS:
        item: dict[str, Any] = {"path": path}; request = urllib.request.Request(base + path, headers={"User-Agent": user_agent})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                item.update(status=response.status, content_type=response.headers.get("Content-Type"))
        except urllib.error.HTTPError as error:
            item.update(status=error.code, content_type=error.headers.get("Content-Type") if error.headers else None)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            item.update(status=None, error=str(error))
        results.append(item)
    return results

def run_assessment(config: dict[str, Any]) -> Assessment:
    started = utc_now(); target = config["target"]; agent = config.get("user_agent", "VAPT-MVP-Lab/0.1")
    assessment = Assessment(datetime.now(timezone.utc).strftime("assessment-%Y%m%dT%H%M%SZ"), started, None,
        {**target, "url": target_url(target)}, "running",
        ["scope_allowlist", "http_get", "security_headers", "safe_recon"])
    request = urllib.request.Request(assessment.target["url"], headers={"User-Agent": agent})
    try:
        with urllib.request.urlopen(request, timeout=float(config.get("timeout_seconds", 10))) as response:
            headers = dict(response.headers.items())
            assessment.observations = {"http_status": response.status, "headers": headers,
                "content_type": response.headers.get("Content-Type"), "content_length": response.headers.get("Content-Length"),
                "server": response.headers.get("Server"), "powered_by": response.headers.get("X-Powered-By")}
            assessment.recon = safe_recon(target, agent, float(config.get("timeout_seconds", 10)))
            assessment.findings = assess_headers(headers) + assess_phase3(headers, assessment.recon) + assess_phase4(headers, response.geturl(), assessment.target["url"])
            assessment.status = "completed"
    except urllib.error.HTTPError as error:
        headers = dict(error.headers.items()) if error.headers else {}; assessment.observations = {"http_status": error.code, "headers": headers}
        assessment.recon = safe_recon(target, agent, float(config.get("timeout_seconds", 10)))
        assessment.findings = assess_headers(headers) + assess_phase3(headers, assessment.recon) + assess_phase4(headers, error.geturl() if hasattr(error, "geturl") else assessment.target["url"], assessment.target["url"])
        assessment.errors.append(f"HTTP error {error.code}: {error.reason}"); assessment.status = "completed_with_errors"
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        assessment.errors.append(f"Request failed: {error}"); assessment.status = "failed"
    finish_summary(assessment); assessment.completed_at_utc = utc_now(); return assessment

def write_reports(assessment: Assessment, report_dir: Path) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True); data = asdict(assessment)
    json_path = report_dir / f"{assessment.assessment_id}.json"; md_path = report_dir / f"{assessment.assessment_id}.md"
    json_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lines = [f"# VAPT MVP Assessment {assessment.assessment_id}", "", f"- Status: **{assessment.status}**",
        f"- Target: `{assessment.target['url']}`", f"- Started (UTC): `{assessment.started_at_utc}`", "",
        "## Summary", "", f"- Findings: **{assessment.summary.get('finding_count', 0)}**",
        f"- Errors: **{assessment.summary.get('error_count', 0)}**", "",
        "## Safe recon", "", "| Path | Status | Content type |", "|---|---:|---|"]
    lines += [f"| `{x['path']}` | `{x.get('status', 'error')}` | `{x.get('content_type') or '—'}` |" for x in assessment.recon]
    lines += ["", "## Findings", ""]
    if assessment.findings:
        for f in assessment.findings: lines += [f"### {f.finding_id} — {f.title}", "", f"Severity: **{f.severity}** | Confidence: **{f.confidence}**", "", f.description, "", f"Remediation: {f.remediation}", ""]
    else: lines += ["No missing security headers were detected.", ""]
    if assessment.errors: lines += ["## Errors", ""] + [f"- {e}" for e in assessment.errors]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8"); return json_path, md_path

def main() -> int:
    parser = argparse.ArgumentParser(description="Run the non-intrusive VAPT MVP assessment")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG); parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    args = parser.parse_args()
    try: assessment = run_assessment(load_config(args.config)); paths = write_reports(assessment, args.report_dir)
    except (OSError, ValueError, json.JSONDecodeError) as error: print(f"Assessment could not start: {error}", file=sys.stderr); return 2
    print(json.dumps({"status": assessment.status, "json_report": str(paths[0]), "markdown_report": str(paths[1])}, indent=2)); return 0 if assessment.status != "failed" else 1

if __name__ == "__main__": raise SystemExit(main())
