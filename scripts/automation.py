"""Local, opt-in assessment comparison helpers for Phase 11."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import mcp_tools


def load_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def compare_reports(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    previous_ids = {item["finding_id"] for item in previous.get("findings", [])}
    current_ids = {item["finding_id"] for item in current.get("findings", [])}
    return {"new_findings": sorted(current_ids - previous_ids),
            "resolved_findings": sorted(previous_ids - current_ids),
            "unchanged_findings": sorted(previous_ids & current_ids),
            "meaningful_change": current_ids != previous_ids}


def run_automation(previous_report: str | Path | None = None) -> dict[str, Any]:
    result = mcp_tools.vapt_assess(); comparison = None
    current = result["assessment"]
    if previous_report:
        comparison = compare_reports(load_report(previous_report), current)
    elif result.get("history"):
        comparison = result["history"].get("entry", {}).get("comparison")
    return {"assessment": result, "comparison": comparison}
