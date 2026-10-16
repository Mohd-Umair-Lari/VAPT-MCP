"""MCP-facing adapter for the safe VAPT MVP operations.

This module keeps the tool boundary separate from the assessment engine. An MCP
server or host integration can call these functions without gaining arbitrary
command execution or arbitrary-target access.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import vapt_mvp

TOOL_DEFINITIONS = [
    {
        "name": "vapt_scope",
        "description": "Return the single authorized lab target and safe checks available.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vapt_assess",
        "description": "Run the non-intrusive VAPT assessment against the configured authorized lab target.",
        "inputSchema": {
            "type": "object",
            "properties": {"config_path": {"type": "string"}, "report_dir": {"type": "string"}},
            "additionalProperties": False,
        },
    },
]


def vapt_scope() -> dict[str, Any]:
    config = vapt_mvp.load_config(vapt_mvp.DEFAULT_CONFIG)
    return {
        "target": {**config["target"], "url": vapt_mvp.target_url(config["target"])},
        "checks": ["http_get", "security_headers", "safe_recon", "passive_verification", "configuration_checks"],
        "intrusive_testing": False,
    }


def vapt_assess(config_path: str | None = None, report_dir: str | None = None) -> dict[str, Any]:
    config = vapt_mvp.load_config(Path(config_path) if config_path else vapt_mvp.DEFAULT_CONFIG)
    assessment = vapt_mvp.run_assessment(config)
    json_path, markdown_path = vapt_mvp.write_reports(
        assessment, Path(report_dir) if report_dir else vapt_mvp.DEFAULT_REPORT_DIR
    )
    assessment_data = vapt_mvp.asdict(assessment)
    # Lazy import avoids coupling the assessment engine to persistence while
    # ensuring every tool-triggered run is recorded automatically.
    import history
    history_result = history.record_assessment(assessment_data, Path(report_dir or vapt_mvp.DEFAULT_REPORT_DIR) / "history.json")
    return {"assessment": assessment_data,
            "reports": {"json": str(json_path), "markdown": str(markdown_path)},
            "history": history_result}


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    if name == "vapt_scope":
        return vapt_scope()
    if name == "vapt_assess":
        return vapt_assess(arguments.get("config_path"), arguments.get("report_dir"))
    raise ValueError(f"Unknown tool: {name}")


def main() -> int:
    """Simple JSON-in/JSON-out helper for local MCP bridge experiments."""
    import sys
    for line in sys.stdin:
        if line.strip():
            try:
                request = json.loads(line)
                result = call_tool(request["name"], request.get("arguments"))
                print(json.dumps({"ok": True, "result": result}), flush=True)
            except Exception as error:  # boundary must return a machine-readable error
                print(json.dumps({"ok": False, "error": str(error)}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
