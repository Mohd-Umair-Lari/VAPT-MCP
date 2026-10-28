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
    {"name": "vapt_get_scope", "description": "Return the fixed authorized target and allowed checks.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "vapt_start_assessment", "description": "Start a safe VAPT assessment job against the fixed target.",
     "inputSchema": {"type": "object", "properties": {"mode": {"type": "string", "enum": ["passive"]}}, "additionalProperties": False}},
    {"name": "vapt_get_status", "description": "Get the status of an assessment job.",
     "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_get_report", "description": "Return the completed assessment and report paths for a job.",
     "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_get_history", "description": "Return compact local assessment history and change alerts.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "vapt_exec_command", "description": "Run an allowlisted command against the authorized target.",
     "inputSchema": {"type": "object", "required": ["argv"], "properties": {
         "argv": {"type": "array", "items": {"type": "string"}},
         "mode": {"type": "string", "enum": ["passive", "active"]},
         "approval_token": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_get_command_output", "description": "Read status and output for a command job.",
     "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_detect", "description": "Run recon and detection without exploitation.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "request_exploit_approval", "description": "Create a human approval token for active verification.",
     "inputSchema": {"type": "object", "required": ["confirmation"], "properties": {"confirmation": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_exploit", "description": "Run active verification with a valid approval token.",
     "inputSchema": {"type": "object", "required": ["approval_token", "confirmation"], "properties": {"approval_token": {"type": "string"}, "confirmation": {"type": "string"}}, "additionalProperties": False}},
    {"name": "vapt_list_active_actions", "description": "List active verification actions without executing them.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
]


def result_text(value: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(value, indent=2)}], "structuredContent": value}


def scope() -> dict[str, Any]:
    value = mcp_tools.vapt_scope()
    return {"target": value["target"]["url"].rstrip("/"), "phases": ["recon", "detect", "exploit"],
            "exploit_requires_approval": True}


def vapt_scope() -> dict[str, Any]:
    return scope()


def vapt_detect() -> dict[str, Any]:
    config = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))
    config.setdefault("active", {})["phases"] = {"recon": True, "detect": True, "exploit": False}
    return orchestrator.run(config, scope=Scope.authorized_lab())


APPROVAL_PHRASE = "APPROVE ACTIVE TEST 192.168.56.102:3000"


def request_exploit_approval(confirmation: str = "") -> dict[str, Any]:
    if confirmation.strip() != APPROVAL_PHRASE:
        return {"status": "pending", "message": f"Human confirmation required. Repeat exactly: {APPROVAL_PHRASE}"}
    return approval.request_approval(Scope.authorized_lab().base_url())


def vapt_list_active_actions() -> dict[str, Any]:
    return {"target": Scope.authorized_lab().base_url(), "actions": [
        {"id": "sqli-login-bypass", "description": "Verify whether a crafted login value returns a session token.", "requires_approval": True},
        {"id": "jwt-none", "description": "Verify whether an unsigned JWT is accepted by a protected endpoint.", "requires_approval": True},
        {"id": "idor-basket", "description": "Verify whether one session can access another basket identifier.", "requires_approval": True},
        {"id": "weak-login", "description": "Verify configured lab-only weak credential candidates.", "requires_approval": True},
    ], "executed": False}


def vapt_exploit(approval_token: str, confirmation: str = "") -> dict[str, Any]:
    if confirmation.strip() != APPROVAL_PHRASE:
        return {"status": "refused", "reason": "Explicit execution confirmation is required.",
                "hint": f"Repeat exactly only when ready: {APPROVAL_PHRASE}"}
    ok, reason = approval.validate(approval_token, Scope.authorized_lab().base_url())
    if not ok:
        return {"status": "refused", "reason": reason, "hint": "Call request_exploit_approval first."}
    config = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))
    config.setdefault("active", {})["phases"] = {"recon": True, "detect": True, "exploit": True}
    return orchestrator.run(config, scope=Scope.authorized_lab(), approval_token=approval_token)


def run_job(job_id: str) -> None:
    try:
        with LOCK:
            JOBS[job_id]["status"] = "running"
        output = mcp_tools.vapt_assess()
        with LOCK:
            JOBS[job_id].update(status="completed", result=output)
    except Exception as error:
        with LOCK:
            JOBS[job_id].update(status="failed", error=str(error))


def start_assessment(arguments: dict[str, Any]) -> dict[str, Any]:
    if arguments.get("mode", "passive") != "passive":
        raise ValueError("Only passive mode is available through this MCP server")
    target = scope()["target"]
    job_id = "job-" + uuid.uuid4().hex[:12]
    with LOCK:
        JOBS[job_id] = {"job_id": job_id, "status": "queued", "target": target}
    threading.Thread(target=run_job, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "queued", "target": target, "mode": "passive"}


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
        if job["status"] != "completed":
            return {"job_id": arguments["job_id"], "status": job["status"], "message": "Report is not ready."}
        return job["result"]
    if name == "vapt_get_history":
        return {"history": history.load_history()}
    if name == "vapt_exec_command":
        mode = arguments.get("mode", "passive")
        approved = mode == "passive"
        if mode == "active":
            token = arguments.get("approval_token", "")
            approved, _ = approval.validate(token, Scope.authorized_lab().base_url())
        return harness.DEFAULT_HARNESS.start(arguments["argv"], mode, approved)
    if name == "vapt_get_command_output":
        return harness.DEFAULT_HARNESS.status(arguments["job_id"])
    if name == "vapt_detect":
        return vapt_detect()
    if name == "request_exploit_approval":
        return request_exploit_approval(arguments.get("confirmation", ""))
    if name == "vapt_exploit":
        return vapt_exploit(arguments["approval_token"], arguments.get("confirmation", ""))
    if name == "vapt_list_active_actions":
        return vapt_list_active_actions()
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
            "serverInfo": {"name": "vapt-mcp", "version": "0.1.0"},
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
