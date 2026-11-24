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
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": True},
    },
    {
        "name": "vapt_assess",
        "description": "Run the non-intrusive VAPT assessment against a target URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"config_path": {"type": "string"}, "report_dir": {"type": "string"}, "target_url": {"type": "string"}, "enforce_scope": {"type": "boolean"}},
            "additionalProperties": True,
        },
    },
    {
        "name": "vapt_exploit",
        "description": "Run active exploitation against a target URL (approval optional).",
        "inputSchema": {
            "type": "object",
            "properties": {"approval_token": {"type": "string"}, "confirmation": {"type": "string"}, "target_url": {"type": "string"}, "exploit_categories": {"type": "string"}, "exploit_action": {"type": "string"}, "auto_approve": {"type": "boolean"}},
            "additionalProperties": True,
        },
    },
    {
        "name": "vapt_crawl",
        "description": "Run deep crawling for attack surface discovery.",
        "inputSchema": {
            "type": "object",
            "properties": {"target_url": {"type": "string"}, "max_depth": {"type": "integer"}, "max_pages": {"type": "integer"}, "enforce_scope": {"type": "boolean"}},
            "additionalProperties": True,
        },
    },
    {
        "name": "vapt_scan_cidr",
        "description": "Run internet-wide CIDR/ASN scanning with multiple modules.",
        "inputSchema": {
            "type": "object",
            "properties": {"cidr": {"type": "string"}, "ports": {"type": "string"}, "modules": {"type": "string"}, "rate": {"type": "integer"}, "concurrent": {"type": "integer"}, "output_format": {"type": "string"}},
            "additionalProperties": True,
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
                target_url: str | None = None, enforce_scope: bool = False) -> dict[str, Any]:
    config = (vapt_mvp.config_for_passive_url(target_url) if target_url else
              vapt_mvp.load_config(Path(config_path) if config_path else vapt_mvp.DEFAULT_CONFIG))
    if target_url:
        config["target"] = {"scheme": "https" if "https" in target_url else "http", 
                           "host": target_url.replace("https://", "").replace("http://", "").split(":")[0].split("/")[0],
                           "port": 443 if "https" in target_url else 80}
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


def vapt_exploit(approval_token: str = "", confirmation: str = "", target_url: str = "", exploit_categories: str = "", exploit_action: str = "", auto_approve: bool = False) -> dict[str, Any]:
    # Delegate to mcp_server for exploit functionality
    import mcp_server
    return mcp_server.vapt_exploit(approval_token, confirmation, target_url, exploit_categories, exploit_action, auto_approve)


def vapt_crawl(target_url: str = "", max_depth: int = 3, max_pages: int = 100, enforce_scope: bool = False) -> dict[str, Any]:
    # Delegate to mcp_server for crawl functionality
    import mcp_server
    return mcp_server.vapt_crawl(target_url, max_depth, max_pages, enforce_scope)


def vapt_scan_cidr(cidr: str = "", ports: str = "80,443,8080,8443", modules: str = "http,tls,ssh", 
                   rate: int = 100, concurrent: int = 50, output_format: str = "json") -> dict[str, Any]:
    # Delegate to mcp_server for CIDR scanning
    import mcp_server
    return mcp_server.vapt_scan_cidr(cidr, ports, modules, rate, concurrent, output_format)


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    if name == "vapt_scope":
        return vapt_scope()
    if name == "vapt_assess":
        return vapt_assess(arguments.get("config_path"), arguments.get("report_dir"), arguments.get("target_url"), arguments.get("enforce_scope", False))
    if name == "vapt_exploit":
        return vapt_exploit(arguments.get("approval_token", ""), arguments.get("confirmation", ""), arguments.get("target_url", ""), arguments.get("exploit_categories", ""), arguments.get("exploit_action", ""), arguments.get("auto_approve", False))
    if name == "vapt_crawl":
        return vapt_crawl(arguments.get("target_url", ""), arguments.get("max_depth", 3), arguments.get("max_pages", 100), arguments.get("enforce_scope", False))
    if name == "vapt_scan_cidr":
        return vapt_scan_cidr(arguments.get("cidr", ""), arguments.get("ports", "80,443,8080,8443"),
                             arguments.get("modules", "http,tls,ssh"), arguments.get("rate", 100),
                             arguments.get("concurrent", 50), arguments.get("output_format", "json"))
    raise ValueError(f"Unknown tool: {name}")


def main() -> int:
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
