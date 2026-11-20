"""Provider-neutral interactive workflow for an LLM-controlled VAPT session.

The model supplies intent and receives structured state. This module enforces
the workflow rules; it does not execute arbitrary model-generated code.

Supports both gated (with approval) and unrestricted (auto-approve) modes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import agent_workflow
import mcp_tools


@dataclass
class Session:
    session_id: str
    state: str = "new"
    plan: dict[str, Any] | None = None
    messages: list[dict[str, str]] = field(default_factory=list)
    last_result: dict[str, Any] | None = None


class VaptSession:
    """State machine used by a chat/LLM host."""

    def __init__(self, session_id: str = "local-session") -> None:
        self.session = Session(session_id)

    def start(self, request: str, target_url: str | None = None, auto_approve: bool = False) -> dict[str, Any]:
        plan = agent_workflow.make_plan(request, target_url, auto_approve)
        self.session.plan = plan
        self.session.messages.append({"role": "user", "content": request})
        if plan["status"] == "awaiting_approval":
            self.session.state = "awaiting_approval"
        elif plan["status"] == "executing":
            self.session.state = "running"
            # Auto-execute the plan
            return self.approve(True)
        else:
            self.session.state = plan["status"]
        return plan

    def approve(self, approved: bool) -> dict[str, Any]:
        if self.session.state not in ("awaiting_approval", "running") or not self.session.plan:
            return {"status": "not_ready", "message": "There is no assessment waiting for approval."}
        if not approved:
            self.session.state = "cancelled"
            return agent_workflow.execute_approved(self.session.plan, False)
        self.session.state = "running"
        plan = self.session.plan
        action = plan.get("action", "vapt_assess")
        if action == "vapt_exploit":
            # Run exploit with auto_approve if set
            result = mcp_tools.call_tool("vapt_exploit", {
                "target_url": plan["target"],
                "exploit_categories": ",".join(plan.get("exploit_categories", [])),
                "auto_approve": plan.get("auto_approve", False)
            })
            self.session.last_result = result
            self.session.state = "completed"
            return {"status": "completed", "result": result}
        else:
            result = mcp_tools.call_tool("vapt_assess", {"target_url": plan["target"]})
            self.session.last_result = result
            self.session.state = "completed"
            return {"status": "completed", "result": result}

    def snapshot(self) -> dict[str, Any]:
        return {
            "session_id": self.session.session_id,
            "state": self.session.state,
            "plan": self.session.plan,
            "has_result": self.session.last_result is not None,
        }
