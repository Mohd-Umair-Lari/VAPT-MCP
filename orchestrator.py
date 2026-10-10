"""Full VAPT pipeline: recon -> detect -> (approved) exploit -> report.

Honors the 'auto-recon, approve attacks' posture: recon and detection run
automatically; exploitation runs only when a valid approval token is supplied.
Reuses vapt_mvp's Assessment/report writer and history for a consistent record.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import active_vapt
import approval
import audit
import history
import vapt_mvp
from http_client import HttpClient
from scope import Scope

EXPLOIT_IDS = ["sqli-auth-bypass", "weak-credentials", "jwt-none-accepted", "idor-basket"]


def build_client(scope: Scope, config: dict[str, Any]) -> HttpClient:
    active = config.get("active", {})
    return HttpClient(
        scope,
        user_agent=config.get("user_agent", "VAPT-Lab/0.2"),
        timeout=float(config.get("timeout_seconds", 10)),
        rate_limit_per_second=float(active.get("rate_limit_per_second", 3)),
        max_bytes=int(active.get("max_response_bytes", 1_048_576)),
    )


def run(config: dict[str, Any], scope: Scope | None = None, client: HttpClient | None = None,
        approval_token: str | None = None, report_dir: str | Path | None = None) -> dict[str, Any]:
    scope = scope or Scope.authorized_lab()
    client = client or build_client(scope, config)
    active = config.get("active", {})
    phases = active.get("phases", {})
    report_dir = Path(report_dir) if report_dir else vapt_mvp.DEFAULT_REPORT_DIR

    assessment = vapt_mvp.Assessment(
        datetime.now(timezone.utc).strftime("active-%Y%m%dT%H%M%SZ"), vapt_mvp.utc_now(), None,
        {"url": scope.base_url()}, "running", checks=["scope_lock", "recon", "detect", "exploit_gate"])
    findings: list[vapt_mvp.Finding] = []
    pending: list[str] = []

    try:
        root = client.get("/")
        assessment.observations = {"http_status": root.status, "server": root.headers.get("Server"),
                                   "powered_by": root.headers.get("X-Powered-By")}
        findings += vapt_mvp.assess_headers(root.headers)
        findings += vapt_mvp.assess_phase4(root.headers, root.url, scope.base_url() + "/")
    except Exception as error:
        assessment.errors.append(f"root fetch failed: {error}")

    if phases.get("recon", True):
        assessment.recon = active_vapt.recon(client)
        audit.record("phase_recon", {"target": scope.base_url(), "paths": len(assessment.recon)})

    if phases.get("detect", True):
        for fn in (active_vapt.detect_sql_injection, active_vapt.detect_reflected_input):
            try:
                finding = fn(client)
                if finding:
                    findings.append(finding)
            except Exception as error:
                assessment.errors.append(f"{fn.__name__} failed: {error}")
        audit.record("phase_detect", {"target": scope.base_url(), "findings": len(findings)})

    want_exploit = bool(phases.get("exploit", False) or approval_token)
    approved, reason = False, "skipped"
    if want_exploit:
        if active.get("require_exploit_approval", True):
            approved, reason = approval.validate(approval_token, scope.base_url())
        else:
            approved, reason = True, "approval not required by config"

    if want_exploit and not approved:
        pending = list(EXPLOIT_IDS)
        audit.record("exploit_blocked", {"target": scope.base_url(), "reason": reason})
    elif want_exploit and approved:
        audit.record("phase_exploit_start", {"target": scope.base_url()})
        try:
            sqli, token = active_vapt.exploit_sql_login_bypass(client, True)
            if sqli:
                findings.append(sqli)
            if not token:
                weak, token = active_vapt.exploit_weak_login(client, True, active.get("weak_login_candidates", []))
                if weak:
                    findings.append(weak)
            for finding in (active_vapt.exploit_jwt_none(client, True),
                            active_vapt.exploit_idor_basket(client, True, token)):
                if finding:
                    findings.append(finding)
        except Exception as error:
            assessment.errors.append(f"exploit phase error: {error}")
        if approval_token:
            approval.consume(approval_token)
        audit.record("phase_exploit_done", {"target": scope.base_url(), "findings": len(findings)})

    assessment.findings = findings
    assessment.status = "completed" if not assessment.errors else "completed_with_errors"
    vapt_mvp.finish_summary(assessment)
    assessment.summary["pending_exploits"] = pending
    assessment.summary["exploit_status"] = reason
    assessment.completed_at_utc = vapt_mvp.utc_now()

    data = vapt_mvp.asdict(assessment)
    json_path, md_path = vapt_mvp.write_reports(assessment, report_dir)
    hist = history.record_assessment(data, report_dir / "history.json")
    return {"assessment": data, "reports": {"json": str(json_path), "markdown": str(md_path)},
            "history": hist, "pending_exploits": pending, "exploit_status": reason}


def _cli_run(exploit: bool) -> dict[str, Any]:
    config = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))
    token = None
    if exploit:
        config.setdefault("active", {}).setdefault("phases", {})["exploit"] = True
        token = approval.request_approval(Scope.authorized_lab().base_url())["token"]
    return run(config, approval_token=token)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the scope-locked VAPT pipeline against the authorized lab")
    parser.add_argument("--exploit", action="store_true", help="deliberately include the gated exploitation phase")
    args = parser.parse_args()
    result = _cli_run(args.exploit)
    print(json.dumps({"status": result["assessment"]["status"], "exploit_status": result["exploit_status"],
                      "summary": result["assessment"]["summary"], "reports": result["reports"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
