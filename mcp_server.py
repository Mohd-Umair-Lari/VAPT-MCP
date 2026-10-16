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
         "approved": {"type": "boolean"}}, "additionalProperties": False}},
    {"name": "vapt_get_command_output", "description": "Read status and output for a command job.",
     "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}, "additionalProperties": False}},
]


def result_text(value: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(value, indent=2)}], "structuredContent": value}


def scope() -> dict[str, Any]:
    return mcp_tools.vapt_scope()


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
    target = scope()["target"]["url"]
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
        return harness.DEFAULT_HARNESS.start(arguments["argv"], arguments.get("mode", "passive"), bool(arguments.get("approved", False)))
    if name == "vapt_get_command_output":
        return harness.DEFAULT_HARNESS.status(arguments["job_id"])
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
