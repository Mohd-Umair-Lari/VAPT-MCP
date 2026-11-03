"""Real stdio MCP server for the VAPT project.

The server implements the MCP JSON-RPC tool surface needed by Hermes. It uses
only the existing allowlisted assessment engine and keeps logs on stderr so
stdout remains a clean MCP transport.
"""
from __future__ import annotations

import json
import sys
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

import history
import harness
import mcp_tools
import vapt_mvp
import approval
import orchestrator
from scope import Scope

PROTOCOL_VERSION = "2024-11-05"
JOBS: dict[str, dict[str, Any]] = {}
LOCK = threading.Lock()

TOOLS = [
    {"name": "vapt_get_scope", "description": "Return the configured target and allowed checks.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "vapt_start_assessment", "description": "Start an assessment against a target URL supplied for this run.",
     "inputSchema": {"type": "object", "properties": {"mode": {"type": "string", "enum": ["passive", "active"]}, "target_url": {"type": "string"}, "exploit_categories": {"type": "string"}, "crawl": {"type": "boolean"}}, "additionalProperties": False}},
    {"name": "vapt_get_status", "description": "Get the status of an assessment job.",
     "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_get_report", "description": "Return the completed assessment and report paths for a job.",
     "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_get_history", "description": "Return compact local assessment history and change alerts.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "vapt_exec_command", "description": "Run an allowlisted command against the configured target.",
     "inputSchema": {"type": "object", "required": ["argv"], "properties": {
         "argv": {"type": "array", "items": {"type": "string"}},
         "mode": {"type": "string", "enum": ["passive", "active"]},
         "approval_token": {"type": "string"},
         "target_url": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_get_command_output", "description": "Read status and output for a command job.",
     "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_detect", "description": "Run recon and detection without exploitation.",
     "inputSchema": {"type": "object", "properties": {"target_url": {"type": "string"}}, "additionalProperties": False}},
    {"name": "request_exploit_approval", "description": "Create a human approval token for active verification.",
     "inputSchema": {"type": "object", "required": ["confirmation", "target_url"], "properties": {"confirmation": {"type": "string"}, "target_url": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_exploit", "description": "Run active verification with a valid approval token.",
     "inputSchema": {"type": "object", "required": ["approval_token", "confirmation", "target_url"], "properties": {"approval_token": {"type": "string"}, "confirmation": {"type": "string"}, "target_url": {"type": "string"}, "exploit_categories": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_list_active_actions", "description": "List active verification actions without executing them.",
     "inputSchema": {"type": "object", "properties": {"target_url": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_crawl", "description": "Run deep crawling for attack surface discovery.",
     "inputSchema": {"type": "object", "properties": {"target_url": {"type": "string"}, "max_depth": {"type": "integer"}, "max_pages": {"type": "integer"}}, "additionalProperties": False}},
]


def result_text(value: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(value, indent=2)}], "structuredContent": value}


def _load_scope() -> Scope:
    """Load the Scope from config.json."""
    config = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))
    return Scope.from_config(config["target"])


def scope() -> dict[str, Any]:
    sc = _load_scope()
    return {"target": sc.base_url(), "phases": ["recon", "detect", "exploit"],
            "exploit_requires_approval": True}


def vapt_scope() -> dict[str, Any]:
    return scope()


def vapt_detect(target_url: str = "") -> dict[str, Any]:
    if not target_url:
        target_url = scope()["target"]
    sc = Scope.from_url(target_url)
    config = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))
    config.setdefault("active", {})["phases"] = {"recon": True, "detect": True, "exploit": False}
    return orchestrator.run(config, scope=sc)


def request_exploit_approval(confirmation: str = "", target_url: str = "") -> dict[str, Any]:
    if not target_url:
        return {"status": "error", "message": "target_url is required"}
    if confirmation.strip() != f"APPROVE ACTIVE TEST {target_url}":
        return {"status": "pending", "message": f"Human confirmation required. Repeat exactly: APPROVE ACTIVE TEST {target_url}"}
    return approval.request_approval(target_url)


def vapt_list_active_actions(target_url: str = "") -> dict[str, Any]:
    if not target_url:
        target_url = scope()["target"]
    return {"target": target_url, "actions": [
        {"id": "sqli", "description": "Test for SQL injection across common endpoints", "requires_approval": True},
        {"id": "xss", "description": "Test for reflected XSS across common endpoints", "requires_approval": True},
        {"id": "ssrf", "description": "Test for Server-Side Request Forgery", "requires_approval": True},
        {"id": "path_traversal", "description": "Test for path/directory traversal", "requires_approval": True},
        {"id": "cmd_injection", "description": "Test for command injection", "requires_approval": True},
        {"id": "xxe", "description": "Test for XML External Entity injection", "requires_approval": True},
        {"id": "ldap_injection", "description": "Test for LDAP injection", "requires_approval": True},
        {"id": "nosql_injection", "description": "Test for NoSQL injection", "requires_approval": True},
        {"id": "open_redirect", "description": "Test for open redirect vulnerabilities", "requires_approval": True},
        {"id": "cors", "description": "Test for CORS misconfiguration", "requires_approval": True},
        {"id": "security_headers", "description": "Test for missing security headers", "requires_approval": False},
        {"id": "cookie_security", "description": "Test for cookie security attributes", "requires_approval": False},
        {"id": "jwt_none", "description": "Test for JWT none algorithm acceptance", "requires_approval": True},
        {"id": "idor", "description": "Test for Insecure Direct Object References", "requires_approval": True},
        {"id": "weak_login", "description": "Test for weak/default credentials", "requires_approval": True},
    ], "executed": False}


def vapt_exploit(approval_token: str, confirmation: str = "", target_url: str = "", exploit_categories: str = "") -> dict[str, Any]:
    if not target_url:
        return {"status": "error", "message": "target_url is required"}
    if confirmation.strip() != f"APPROVE ACTIVE TEST {target_url}":
        return {"status": "refused", "reason": "Explicit execution confirmation is required.",
                "hint": f"Repeat exactly only when ready: APPROVE ACTIVE TEST {target_url}"}
    ok, reason = approval.validate(approval_token, target_url)
    if not ok:
        return {"status": "refused", "reason": reason, "hint": "Call request_exploit_approval first."}
    config = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))
    config.setdefault("active", {})["phases"] = {"recon": True, "detect": True, "exploit": True}
    if exploit_categories:
        config["active"]["exploit_categories"] = exploit_categories.split(",")
    sc = Scope.from_url(target_url)
    return orchestrator.run(config, scope=sc, approval_token=approval_token)


def vapt_crawl(target_url: str = "", max_depth: int = 3, max_pages: int = 100) -> dict[str, Any]:
    if not target_url:
        target_url = scope()["target"]
    sc = Scope.from_url(target_url)
    config = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))
    config.setdefault("active", {})["phases"] = {"recon": True, "detect": True, "exploit": False, "crawl": True}
    return orchestrator.run(config, scope=sc)


def run_job(job_id: str, target_url: str | None = None, mode: str = "passive", exploit_categories: str = "", crawl: bool = False) -> None:
    try:
        with LOCK:
            JOBS[job_id]["status"] = "running"
        if mode == "active":
            output = vapt_exploit("", "", target_url or "", exploit_categories)
        elif crawl:
            output = vapt_crawl(target_url or "")
        else:
            output = mcp_tools.vapt_assess(target_url=target_url)
        with LOCK:
            assessment_status = output.get("assessment", {}).get("status", "completed")
            JOBS[job_id].update(status=assessment_status, result=output)
    except Exception as error:
        with LOCK:
            JOBS[job_id].update(status="failed", error=str(error))


def start_assessment(arguments: dict[str, Any]) -> dict[str, Any]:
    mode = arguments.get("mode", "passive")
    if mode not in {"passive", "active"}:
        raise ValueError("Mode must be passive or active")
    target = arguments.get("target_url") or scope()["target"]
    job_id = "job-" + uuid.uuid4().hex[:12]
    with LOCK:
        JOBS[job_id] = {"job_id": job_id, "status": "queued", "target": target, "mode": mode}
    threading.Thread(target=run_job, args=(job_id, arguments.get("target_url"), mode,
                                           arguments.get("exploit_categories", ""), arguments.get("crawl", False)), daemon=True).start()
    return {"job_id": job_id, "status": "queued", "target": target, "mode": mode}


def get_job(job_id: str) -> dict[str, Any]:
    with LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise ValueError("Unknown job_id")
        return dict(job)


def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "vapt_get_scope":
        return scope()
    if name == "vapt_start_assessment":
        return start_assessment(arguments)
    if name == "vapt_get_status":
        job = get_job(arguments["job_id"])
        return {key: value for key, value in job.items() if key not in {"result"}}
    if name == "vapt_get_report":
        job = get_job(arguments["job_id"])
        if job["status"] not in {"completed", "completed_with_errors", "failed"}:
            return {"job_id": arguments["job_id"], "status": job["status"], "message": "Report is not ready."}
        return job["result"]
    if name == "vapt_get_history":
        return {"history": history.load_history()}
    if name == "vapt_exec_command":
        mode = arguments.get("mode", "passive")
        target_url = arguments.get("target_url") or scope()["target"]
        approved = mode == "passive"
        if mode == "active":
            token = arguments.get("approval_token", "")
            approved, _ = approval.validate(token, target_url)
        # Create a harness for the specific target
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.hostname or "example.com"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        h = harness.Harness(host, port)
        return h.start(arguments["argv"], mode, approved)
    if name == "vapt_get_command_output":
        return harness.DEFAULT_HARNESS.status(arguments["job_id"])
    if name == "vapt_detect":
        return vapt_detect(arguments.get("target_url", ""))
    if name == "request_exploit_approval":
        return request_exploit_approval(arguments.get("confirmation", ""), arguments.get("target_url", ""))
    if name == "vapt_exploit":
        return vapt_exploit(arguments["approval_token"], arguments.get("confirmation", ""),
                           arguments.get("target_url", ""), arguments.get("exploit_categories", ""))
    if name == "vapt_list_active_actions":
        return vapt_list_active_actions(arguments.get("target_url", ""))
    if name == "vapt_crawl":
        return vapt_crawl(arguments.get("target_url", ""), arguments.get("max_depth", 3), arguments.get("max_pages", 100))
    raise ValueError(f"Unknown tool: {name}")


def handle(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    request_id = request.get("id")
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "vapt-mcp", "version": "1.0.0"},
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    try:
        if method == "tools/list":
            value = {"tools": TOOLS}
        elif method == "tools/call":
            params = request.get("params", {}); value = result_text(call_tool(params["name"], params.get("arguments", {})))
        else:
            raise ValueError(f"Unsupported method: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": value}
    except Exception as error:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(error)}}


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            response = handle(json.loads(line))
            if response is not None:
                print(json.dumps(response), flush=True)
        except Exception as error:
            print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(error)}}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
