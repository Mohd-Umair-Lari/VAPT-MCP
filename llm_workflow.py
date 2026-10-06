"""Provider-neutral interactive workflow for an LLM-controlled VAPT session.
The model supplies intent and receives structured state. This module enforces
the workflow rules; it does not execute arbitrary model-generated code.
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

    def start(self, request: str) -> dict[str, Any]:
        plan = agent_workflow.make_plan(request)
        self.session.plan = plan
        self.session.messages.append({"role": "user", "content": request})
        if plan["status"] == "awaiting_approval":
            self.session.state = "awaiting_approval"
        else:
            self.session.state = plan["status"]
        return plan

    def approve(self, approved: bool) -> dict[str, Any]:
        if self.session.state != "awaiting_approval" or not self.session.plan:
            return {"status": "not_ready", "message": "There is no assessment waiting for approval."}
        if not approved:
            self.session.state = "cancelled"
            return agent_workflow.execute_approved(self.session.plan, False)
        self.session.state = "running"
        result = mcp_tools.call_tool("vapt_assess")
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
