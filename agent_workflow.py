"""Small approval-gated workflow for an agent or chat interface."""
from __future__ import annotations

from typing import Any

import mcp_tools


def make_plan(request: str, target_url: str | None = None) -> dict[str, Any]:
    text = request.lower().strip()
    if not text:
        return {"status": "needs_input", "message": "Describe the assessment you want to run."}

    scope = mcp_tools.vapt_scope()
    target = target_url or scope["target"]["url"]

    # Check for active/exploit requests
    wants_exploit = any(word in text for word in ("exploit", "payload", "bruteforce", "brute force", "shell", "attack", "penetrat"))
    wants_active = wants_exploit or any(word in text for word in ("active", "intrusive", "sql", "xss", "ssrf", "rce", "idor"))

    if wants_active:
        return {
            "status": "awaiting_approval",
            "action": "vapt_exploit",
            "target": target,
            "checks": ["recon", "detect", "exploit"],
            "exploit_categories": ["injection", "xss", "ssrf", "path_traversal", "redirect", "config"],
            "message": f"Active exploitation requested for {target}. This requires explicit approval. Confirm target and approve.",
        }

    return {
        "status": "awaiting_approval",
        "action": "vapt_assess",
        "target": target,
        "checks": scope["checks"],
        "message": f"Passive assessment is ready for {target}. Confirm the target and approve execution.",
    }


def execute_approved(plan: dict[str, Any], approved: bool) -> dict[str, Any]:
    if plan.get("status") != "awaiting_approval":
        return {"status": "not_executable", "message": "Only an awaiting-approval plan can be executed."}
    if not approved:
        return {"status": "cancelled", "message": "Assessment was not approved."}

    action = plan.get("action", "vapt_assess")
    if action == "vapt_exploit":
        # For exploit, we need to go through the approval flow
        result = mcp_tools.call_tool("vapt_assess", {"target_url": plan["target"]})
        return {"status": "completed", "result": result, "note": "Exploit phase requires separate approval via request_exploit_approval/vapt_exploit"}
    else:
        result = mcp_tools.call_tool("vapt_assess", {"target_url": plan["target"]})
        return {"status": "completed", "result": result}
