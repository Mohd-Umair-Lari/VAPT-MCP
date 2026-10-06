"""Persistent local assessment history and change-alert generation."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import automation

DEFAULT_HISTORY = Path(__file__).resolve().parent / "reports" / "history.json"

def load_history(path: Path = DEFAULT_HISTORY) -> list[dict[str, Any]]:
    if not path.exists(): return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list): raise ValueError("history must contain a JSON list")
    return data

def record_assessment(assessment: dict[str, Any], path: Path = DEFAULT_HISTORY) -> dict[str, Any]:
    history = load_history(path); previous = history[-1] if history else None
    previous_for_compare = {"findings": [{"finding_id": value} for value in previous.get("finding_ids", [])]} if previous else None
    comparison = automation.compare_reports(previous_for_compare, assessment) if previous else {
        "new_findings": sorted(x["finding_id"] for x in assessment.get("findings", [])),
        "resolved_findings": [], "unchanged_findings": [], "meaningful_change": bool(assessment.get("findings")),
    }
    entry = {"assessment_id": assessment.get("assessment_id"), "completed_at_utc": assessment.get("completed_at_utc"),
             "status": assessment.get("status"), "summary": assessment.get("summary", {}), "comparison": comparison}
    entry["finding_ids"] = sorted(x["finding_id"] for x in assessment.get("findings", []))
    history.append(entry); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    return {"entry": entry, "alert": make_alert(comparison)}

def make_alert(comparison: dict[str, Any]) -> dict[str, Any]:
    if not comparison.get("meaningful_change"): return {"notify": False, "reason": "No finding changes detected."}
    return {"notify": True, "reason": "Finding set changed.", "new_findings": comparison.get("new_findings", []),
            "resolved_findings": comparison.get("resolved_findings", [])}
