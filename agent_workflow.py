"""Small approval-gated workflow for an agent or chat interface."""
from __future__ import annotations

from typing import Any

import mcp_tools


def make_plan(request: str) -> dict[str, Any]:
    text = request.lower().strip()
    if not text:
        return {"status": "needs_input", "message": "Describe the authorized lab assessment you want to run."}
    if any(word in text for word in ("exploit", "payload", "bruteforce", "brute force", "shell")):
        return {"status": "rejected", "message": "This project only supports non-intrusive lab assessment checks."}
    scope = mcp_tools.vapt_scope()
    return {
        "status": "awaiting_approval",
        "action": "vapt_assess",
        "target": scope["target"]["url"],
        "checks": scope["checks"],
        "message": "Assessment is ready. Confirm the target and approve execution.",
    }


def execute_approved(plan: dict[str, Any], approved: bool) -> dict[str, Any]:
    if plan.get("status") != "awaiting_approval":
        return {"status": "not_executable", "message": "Only an awaiting-approval plan can be executed."}
    if not approved:
        return {"status": "cancelled", "message": "Assessment was not approved."}
    result = mcp_tools.call_tool("vapt_assess")
    return {"status": "completed", "result": result}
