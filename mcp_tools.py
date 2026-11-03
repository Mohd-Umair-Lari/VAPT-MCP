"""MCP-facing adapter for the VAPT operations.

This module keeps the tool boundary separate from the assessment engine. An MCP
server or host integration can call these functions without gaining arbitrary
command execution or arbitrary-target access.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import vapt_mvp
from scope import Scope

TOOL_DEFINITIONS = [
    {
        "name": "vapt_scope",
        "description": "Return the configured target and safe checks available.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "vapt_assess",
        "description": "Run the non-intrusive VAPT assessment against a target URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"config_path": {"type": "string"}, "report_dir": {"type": "string"}, "target_url": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "vapt_exploit",
        "description": "Run active exploitation against a target URL (requires approval).",
        "inputSchema": {
            "type": "object",
            "properties": {"approval_token": {"type": "string"}, "confirmation": {"type": "string"}, "target_url": {"type": "string"}, "exploit_categories": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "vapt_crawl",
        "description": "Run deep crawling for attack surface discovery.",
        "inputSchema": {
            "type": "object",
            "properties": {"target_url": {"type": "string"}, "max_depth": {"type": "integer"}, "max_pages": {"type": "integer"}},
            "additionalProperties": False,
        },
    },
]


def vapt_scope() -> dict[str, Any]:
    config = vapt_mvp.load_config(vapt_mvp.DEFAULT_CONFIG)
    sc = Scope.from_config(config["target"])
    return {
        "target": {**config["target"], "url": vapt_mvp.target_url(config["target"])},
        "checks": ["http_get", "security_headers", "safe_recon", "passive_verification", "configuration_checks"],
        "intrusive_testing": False,
    }


def vapt_assess(config_path: str | None = None, report_dir: str | None = None,
                target_url: str | None = None) -> dict[str, Any]:
    config = (vapt_mvp.config_for_passive_url(target_url) if target_url else
              vapt_mvp.load_config(Path(config_path) if config_path else vapt_mvp.DEFAULT_CONFIG))
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


def vapt_exploit(approval_token: str, confirmation: str, target_url: str, exploit_categories: str = "") -> dict[str, Any]:
    # Delegate to mcp_server for exploit functionality
    import mcp_server
    return mcp_server.vapt_exploit(approval_token, confirmation, target_url, exploit_categories)


def vapt_crawl(target_url: str, max_depth: int = 3, max_pages: int = 100) -> dict[str, Any]:
    # Delegate to mcp_server for crawl functionality
    import mcp_server
    return mcp_server.vapt_crawl(target_url, max_depth, max_pages)


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    if name == "vapt_scope":
        return vapt_scope()
    if name == "vapt_assess":
        return vapt_assess(arguments.get("config_path"), arguments.get("report_dir"), arguments.get("target_url"))
    if name == "vapt_exploit":
        return vapt_exploit(arguments["approval_token"], arguments["confirmation"], arguments["target_url"], arguments.get("exploit_categories", ""))
    if name == "vapt_crawl":
        return vapt_crawl(arguments["target_url"], arguments.get("max_depth", 3), arguments.get("max_pages", 100))
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
