"""Intent-gate for exploitation.

Recon and detection run automatically. Active exploitation requires an explicit
approval token that a human (or an LLM acting under human oversight) must request
and then pass in. An unattended scheduled run never requests a token, so it can
never fire exploitation on its own. This is an intent/audit gate, not a
cryptographic boundary against the operator of the machine.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import audit

DEFAULT_PENDING = Path(__file__).resolve().parent / "reports" / "pending_approval.json"
TTL_MINUTES = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def request_approval(target_url: str, path: Path = DEFAULT_PENDING) -> dict[str, Any]:
    token = "exploit-" + secrets.token_hex(8)
    record = {
        "token": token,
        "target": target_url,
        "issued_at": _stamp(_now()),
        "expires_at": _stamp(_now() + timedelta(minutes=TTL_MINUTES)),
        "consumed": False,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    audit.record("exploit_approval_requested", {"token": token, "target": target_url})
    return record


def validate(token: str | None, target_url: str, path: Path = DEFAULT_PENDING) -> tuple[bool, str]:
    if not token:
        return False, "no approval token supplied"
    if not path.exists():
        return False, "no pending approval on record"
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("token") != token:
        return False, "approval token does not match"
    if record.get("consumed"):
        return False, "approval token already used"
    if record.get("target") != target_url:
        return False, "approval token issued for a different target"
    if _now() > datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00")):
        return False, "approval token expired"
    return True, "approved"


def consume(token: str, path: Path = DEFAULT_PENDING) -> None:
    record = json.loads(path.read_text(encoding="utf-8"))
    record["consumed"] = True
    record["consumed_at"] = _stamp(_now())
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    audit.record("exploit_approval_consumed", {"token": token})
