"""Scope definition for VAPT assessments.

A Scope defines the scheme/host/port boundary for a target.
For unrestricted scanning, scope enforcement can be disabled.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a request would leave the authorized scope (when enforced)."""


@dataclass(frozen=True)
class Scope:
    scheme: str
    host: str
    port: int
    enforce: bool = False  # When False, scope checks are warnings only

    @classmethod
    def from_config(cls, target: dict) -> "Scope":
        """Create a Scope from a target config dict with scheme, host, port."""
        return cls(target["scheme"], target["host"], int(target["port"]), 
                   target.get("enforce_scope", False))

    @classmethod
    def from_url(cls, url: str, enforce: bool = False) -> "Scope":
        """Parse a Scope from a base URL (scheme://host:port)."""
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Invalid target URL: {url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return cls(parsed.scheme, parsed.hostname, port, enforce)

    @classmethod
    def for_testing(cls, host: str, port: int, scheme: str = "http") -> "Scope":
        """Only for offline unit tests against a local mock server."""
        return cls(scheme, host, port, enforce=False)

    def base_url(self) -> str:
            # Don't include default ports (80 for http, 443 for https) to match user input
            if (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443):
                return f"{self.scheme}://{self.host}"
            return f"{self.scheme}://{self.host}:{self.port}"

    def contains(self, url: str) -> bool:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme == self.scheme and parsed.hostname == self.host and port == self.port

    def require(self, url: str) -> str:
        if self.enforce and not self.contains(url):
            raise ScopeViolation(
                f"Refusing out-of-scope request to {url!r}; authorized target is {self.base_url()}"
            )
        # When not enforcing, just log/warn but allow
        return url


def assert_config_authorized(target: dict) -> None:
    """Validate that a target config has required fields (no hardcoded allowlist)."""
    required = {"scheme", "host", "port"}
    missing = required - set(target.keys())
    if missing:
        raise ScopeViolation(f"Target config missing required fields: {missing}")
    if target["scheme"] not in {"http", "https"}:
        raise ScopeViolation(f"Invalid scheme: {target['scheme']} (must be http or https)")
    if not target["host"]:
        raise ScopeViolation("Target host cannot be empty")
    try:
        port = int(target["port"])
        if not (1 <= port <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        raise ScopeViolation(f"Invalid port: {target['port']}")
