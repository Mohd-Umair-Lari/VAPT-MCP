"""Intent-gate for exploitation with cryptographic approval tokens.

Recon and detection run automatically. Active exploitation requires an explicit
approval token that a human (or an LLM acting under human oversight) must request
and then pass in. An unattended scheduled run never requests a token, so it can
never fire exploitation on its own.

Approval tokens are HMAC-SHA256 signed with a secret key, providing:
- Integrity: tokens cannot be forged without the secret
- Binding: tokens are bound to a specific target URL
- Expiration: tokens have configurable TTL
- Single-use: tokens are consumed after use
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import audit


DEFAULT_PENDING = Path(__file__).resolve().parent / "reports" / "pending_approval.json"
TTL_MINUTES = 30
# Secret key for HMAC signing - in production, load from secure config/env
# This should be a long random string, ideally from a key management system
SECRET_KEY_FILE = Path(__file__).resolve().parent / "reports" / ".approval_secret"


def _get_secret_key() -> bytes:
    """Get or create the HMAC secret key."""
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_bytes()
    # Generate new key
    key = secrets.token_bytes(32)
    SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_KEY_FILE.write_bytes(key)
    # Restrict permissions (Unix-like systems)
    try:
        SECRET_KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return key


def _sign_token(token: str, target_url: str, issued_at: str, expires_at: str) -> str:
    """Create HMAC signature for approval token."""
    key = _get_secret_key()
    message = f"{token}|{target_url}|{issued_at}|{expires_at}".encode()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    return signature


def _verify_token(token: str, target_url: str, issued_at: str, expires_at: str, signature: str) -> bool:
    """Verify HMAC signature for approval token."""
    expected = _sign_token(token, target_url, issued_at, expires_at)
    return hmac.compare_digest(expected, signature)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def request_approval(target_url: str, path: Path = DEFAULT_PENDING) -> dict[str, Any]:
    token = "exploit-" + secrets.token_hex(16)
    issued_at = _stamp(_now())
    expires_at = _stamp(_now() + timedelta(minutes=TTL_MINUTES))
    signature = _sign_token(token, target_url, issued_at, expires_at)
    record = {
        "token": token,
        "target": target_url,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "signature": signature,
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
    # Verify cryptographic signature
    issued_at = record.get("issued_at", "")
    expires_at = record.get("expires_at", "")
    signature = record.get("signature", "")
    if not _verify_token(token, target_url, issued_at, expires_at, signature):
        return False, "approval token signature verification failed (tampered or wrong key)"
    if _now() > datetime.fromisoformat(expires_at.replace("Z", "+00:00")):
        return False, "approval token expired"
    return True, "approved"


def consume(token: str, path: Path = DEFAULT_PENDING) -> None:
    record = json.loads(path.read_text(encoding="utf-8"))
    record["consumed"] = True
    record["consumed_at"] = _stamp(_now())
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    audit.record("exploit_approval_consumed", {"token": token})
