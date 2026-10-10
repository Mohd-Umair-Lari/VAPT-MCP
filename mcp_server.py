"""MCP server plugin exposing the scope-locked VAPT tools to an LLM/agent.

Load this as an MCP server over stdio. Recon/detection are safe to call freely;
exploitation requires an approval token obtained via request_exploit_approval,
which confirms a human/operator intends the active attack before it runs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

import approval
import orchestrator
import vapt_mvp
from scope import Scope

server = MCPServer("vapt-lab")
CONFIG = Path(__file__).with_name("config.json")


def _config() -> dict[str, Any]:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


@server.tool(description="Return the single authorized lab target and available capabilities.")
def vapt_scope() -> dict[str, Any]:
    return {"target": Scope.authorized_lab().base_url(), "phases": ["recon", "detect", "exploit"],
            "exploit_requires_approval": True}


@server.tool(description="Run recon + detection (safe, no exploitation) against the authorized lab.")
def vapt_detect() -> dict[str, Any]:
    config = _config()
    config.setdefault("active", {})["phases"] = {"recon": True, "detect": True, "exploit": False}
    return orchestrator.run(config, scope=Scope.authorized_lab())


@server.tool(description="Request an approval token for exploitation; a human must intend this before attacks run.")
def request_exploit_approval() -> dict[str, Any]:
    return approval.request_approval(Scope.authorized_lab().base_url())


@server.tool(description="Run active exploitation against the authorized lab. Requires a valid approval_token.")
def vapt_exploit(approval_token: str) -> dict[str, Any]:
    ok, reason = approval.validate(approval_token, Scope.authorized_lab().base_url())
    if not ok:
        return {"status": "refused", "reason": reason, "hint": "Call request_exploit_approval first."}
    config = _config()
    config.setdefault("active", {})["phases"] = {"recon": True, "detect": True, "exploit": True}
    return orchestrator.run(config, scope=Scope.authorized_lab(), approval_token=approval_token)


@server.tool(description="Return the recorded assessment history for the lab.")
def vapt_history() -> list[dict[str, Any]]:
    import history
    return history.load_history(vapt_mvp.DEFAULT_REPORT_DIR / "history.json")


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
