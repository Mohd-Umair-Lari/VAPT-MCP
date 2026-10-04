#!/usr/bin/env python3
"""Small, non-intrusive Phase 1 VAPT assessment for an authorized lab target."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_CONFIG = Path(__file__).with_name("config.json")
DEFAULT_REPORT_DIR = Path.home() / "vapt-mvp" / "reports"
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


@dataclass
class Assessment:
    assessment_id: str
    started_at_utc: str
    completed_at_utc: str | None
    target: dict[str, Any]
    status: str
    checks: list[str] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        config = json.load(handle)
    target = config.get("target", {})
    required = {"scheme", "host", "port", "base_path"}
    if not required.issubset(target):
        raise ValueError("config target must include scheme, host, port, and base_path")
    if target["scheme"] != "http" or target["host"] != "192.168.56.102" or int(target["port"]) != 3000:
        raise ValueError("allowlist violation: only http://192.168.56.102:3000 is authorized")
    return config


def target_url(target: dict[str, Any]) -> str:
    path = str(target.get("base_path", "/"))
    if not path.startswith("/"):
        path = "/" + path
    return f"{target['scheme']}://{target['host']}:{int(target['port'])}{path}"


def assess_headers(headers: dict[str, str]) -> list[Finding]:
    normalized = {key.lower(): value for key, value in headers.items()}
    findings: list[Finding] = []
    for header, (title, severity) in REQUIRED_HEADERS.items():
        if not normalized.get(header):
            findings.append(Finding(
                finding_id=f"missing-{header.replace('-', '_')}",
                title=title,
                severity=severity,
                description=f"The response did not include the recommended {header} response header.",
                evidence=[Evidence("response_header", {"header": header, "present": False})],
            ))
    return findings


def run_assessment(config: dict[str, Any]) -> Assessment:
    started = utc_now()
    target = config["target"]
    assessment = Assessment(
        assessment_id=datetime.now(timezone.utc).strftime("assessment-%Y%m%dT%H%M%SZ"),
        started_at_utc=started,
        completed_at_utc=None,
        target={**target, "url": target_url(target)},
        status="running",
        checks=["scope_allowlist", "http_get", "security_headers"],
    )
    request = urllib.request.Request(
        assessment.target["url"],
        headers={"User-Agent": config.get("user_agent", "VAPT-MVP-Lab/0.1")},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=float(config.get("timeout_seconds", 10))) as response:
            headers = dict(response.headers.items())
            assessment.observations = {
                "http_status": response.status,
                "headers": headers,
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
            }
            assessment.findings = assess_headers(headers)
            assessment.status = "completed"
    except urllib.error.HTTPError as error:
        headers = dict(error.headers.items()) if error.headers else {}
        assessment.observations = {"http_status": error.code, "headers": headers}
        assessment.findings = assess_headers(headers)
        assessment.errors.append(f"HTTP error {error.code}: {error.reason}")
        assessment.status = "completed_with_errors"
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        assessment.errors.append(f"Request failed: {error}")
        assessment.status = "failed"
    assessment.completed_at_utc = utc_now()
    return assessment


def assessment_dict(assessment: Assessment) -> dict[str, Any]:
    return asdict(assessment)


def write_reports(assessment: Assessment, report_dir: Path) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    data = assessment_dict(assessment)
    json_path = report_dir / f"{assessment.assessment_id}.json"
    md_path = report_dir / f"{assessment.assessment_id}.md"
    json_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"# VAPT MVP Assessment {assessment.assessment_id}", "",
        f"- Status: **{assessment.status}**",
        f"- Started (UTC): `{assessment.started_at_utc}`",
        f"- Completed (UTC): `{assessment.completed_at_utc}`",
        f"- Target: `{assessment.target['url']}`", "",
        "## Observations", "",
        f"- HTTP status: `{assessment.observations.get('http_status', 'unavailable')}`",
        f"- Response headers recorded: `{len(assessment.observations.get('headers', {}))}`", "",
        "## Findings", "",
    ]
    if assessment.findings:
        for finding in assessment.findings:
            lines += [f"### {finding.finding_id} — {finding.title}", "", f"Severity: **{finding.severity}**", "", finding.description, ""]
            for evidence in finding.evidence:
                lines.append(f"- Evidence (`{evidence.kind}`): `{json.dumps(evidence.value)}`")
            lines.append("")
    else:
        lines += ["No missing security headers were detected.", ""]
    if assessment.errors:
        lines += ["## Errors", ""] + [f"- {error}" for error in assessment.errors] + [""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the non-intrusive Phase 1 VAPT MVP assessment")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    args = parser.parse_args()
    try:
        assessment = run_assessment(load_config(args.config))
        json_path, md_path = write_reports(assessment, args.report_dir)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Assessment could not start: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": assessment.status, "json_report": str(json_path), "markdown_report": str(md_path)}, indent=2))
    return 0 if assessment.status != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
