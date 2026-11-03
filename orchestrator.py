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
        user_agent=config.get("user_agent", "VAPT-Agent/1.0"),
        timeout=float(config.get("timeout_seconds", 10)),
        rate_limit_per_second=float(active.get("rate_limit_per_second", 3)),
        max_bytes=int(active.get("max_response_bytes", 1_048_576)),
        max_redirects=int(active.get("max_redirects", 5)),
        allow_private_ips=bool(active.get("allow_private_ips", False)),
        max_concurrent_per_host=int(active.get("max_concurrent_per_host", 2)),
        global_request_budget=int(active.get("global_request_budget", 1000)),
    )


def run(config: dict[str, Any], scope: Scope | None = None, client: HttpClient | None = None,
        approval_token: str | None = None, report_dir: str | Path | None = None) -> dict[str, Any]:
    if scope is None:
        target = config.get("target", {})
        scope = Scope.from_config(target)
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
        for fn in (active_vapt.detect_sql_injection, active_vapt.detect_reflected_input, active_vapt.detect_ssrf):
            try:
                finding = fn(client)
                if finding:
                    findings.append(finding)
            except Exception as error:
                assessment.errors.append(f"{fn.__name__} failed: {error}")
        audit.record("phase_detect", {"target": scope.base_url(), "findings": len(findings)})

    # Deep crawl if requested
    if phases.get("crawl", False):
        try:
            crawl_result = active_vapt.deep_crawl(client, max_depth=3, max_pages=50)
            assessment.recon.extend([{"url": e.url, "method": e.method, "parameters": e.parameters,
                                     "forms": len(e.forms), "status": e.status_code} for e in crawl_result.endpoints])
            assessment.observations["technologies"] = crawl_result.technologies
            audit.record("phase_crawl", {"target": scope.base_url(), "endpoints": len(crawl_result.endpoints)})
        except Exception as error:
            assessment.errors.append(f"crawl failed: {error}")

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
            # Run generic exploits
            exploit_categories = active.get("exploit_categories", ["injection", "xss", "ssrf", "path_traversal", "redirect", "config"])
            endpoints = active.get("exploit_endpoints", None)
            generic_findings = active_vapt.exploit_generic(client, True, categories=exploit_categories, endpoints=endpoints)
            findings.extend(generic_findings)

            # Legacy Juice Shop specific exploits (kept for compatibility)
            sqli, token = active_vapt.exploit_sql_login_bypass(client, True)
            if sqli:
                findings.append(sqli)
            if not token:
                weak, token = active_vapt.exploit_weak_login(client, True, active.get("weak_login_candidates", []))
                if weak:
                    findings.append(weak)
            for finding in (active_vapt.exploit_jwt_none(client, True),
                            active_vapt.exploit_idor(client, True, token)):
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
    if assessment.errors and want_exploit and approved:
        assessment.summary["exploit_status"] = "completed_with_errors"
    else:
        assessment.summary["exploit_status"] = reason
    assessment.completed_at_utc = vapt_mvp.utc_now()

    data = vapt_mvp.asdict(assessment)
    json_path, md_path = vapt_mvp.write_reports(assessment, report_dir)
    hist = history.record_assessment(data, report_dir / "history.json")
    exploit_status = assessment.summary["exploit_status"]
    return {"assessment": data, "reports": {"json": str(json_path), "markdown": str(md_path)},
            "history": hist, "pending_exploits": pending, "exploit_status": exploit_status}


def _cli_run(exploit: bool, target_url: str | None = None, crawl: bool = False,
             exploit_categories: str | None = None) -> dict[str, Any]:
    config = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))
    if target_url:
        config["target"] = json.loads(json.dumps(Scope.from_url(target_url).__dict__))
        config["target"]["base_path"] = "/"
    token = None
    if exploit:
        config.setdefault("active", {}).setdefault("phases", {})["exploit"] = True
        token = approval.request_approval(target_url or Scope.from_config(config["target"]).base_url())["token"]
    if crawl:
        config.setdefault("active", {}).setdefault("phases", {})["crawl"] = True
    if exploit_categories:
        config.setdefault("active", {})["exploit_categories"] = exploit_categories.split(",")
    return run(config, approval_token=token)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the VAPT pipeline against a target")
    parser.add_argument("--exploit", action="store_true", help="deliberately include the gated exploitation phase")
    parser.add_argument("--target", type=str, help="target URL (scheme://host:port)")
    parser.add_argument("--crawl", action="store_true", help="enable deep crawling for attack surface discovery")
    parser.add_argument("--exploit-categories", type=str, help="comma-separated exploit categories (injection,xss,ssrf,path_traversal,redirect,config)")
    parser.add_argument("--allow-private", action="store_true", help="allow private IP targets (for internal testing)")
    args = parser.parse_args()
    if args.allow_private:
        # This would need config modification - for now just pass it through
        pass
    result = _cli_run(args.exploit, args.target, args.crawl, args.exploit_categories)
    print(json.dumps({"status": result["assessment"]["status"], "exploit_status": result["exploit_status"],
                      "summary": result["assessment"]["summary"], "reports": result["reports"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
