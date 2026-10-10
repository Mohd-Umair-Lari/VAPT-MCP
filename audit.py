"""Append-only local audit log of active actions (JSON lines)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_AUDIT = Path(__file__).resolve().parent / "reports" / "audit.log"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def record(event: str, detail: dict[str, Any], path: Path = DEFAULT_AUDIT) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"ts": _utc(), "event": event, **detail}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    return entry
