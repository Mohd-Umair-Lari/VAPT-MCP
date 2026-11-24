from __future__ import annotations

import json
import sys
from pathlib import Path

import orchestrator
from scope import Scope, ScopeViolation


def main() -> int:
    config = json.loads((Path(__file__).resolve().parent.parent / "config.json").read_text(encoding="utf-8"))
    active = {**config.get("active", {})}
    active["phases"] = {**active.get("phases", {}), "exploit": False}
    config = {**config, "active": active}
    try:
        result = orchestrator.run(config, scope=Scope.authorized_lab(), approval_token=None)
    except ScopeViolation as error:
        print(json.dumps({"status": "refused", "error": str(error)}), file=sys.stderr)
        return 2
    alert = result.get("history", {}).get("alert", {})
    print(json.dumps({
        "status": result["assessment"]["status"],
        "summary": result["assessment"]["summary"],
        "reports": result["reports"],
        "alert": alert,
        "pending_exploits": result["pending_exploits"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
