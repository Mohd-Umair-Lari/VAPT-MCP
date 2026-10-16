"""Single source of truth for what this tool is authorized to touch.

Every active request MUST pass through a Scope. Production code only ever
constructs Scope.authorized_lab(), which is hard-locked to the one approved
OWASP Juice Shop lab target. Tests may construct a Scope bound to a local mock
server via Scope.for_testing(); there is no production code path that builds a
scope for any other host. This is the control that keeps the engine authorized.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

# The one and only authorized engagement target.
AUTHORIZED = {"scheme": "http", "host": "192.168.56.101", "port": 3000}


class ScopeViolation(Exception):
    """Raised when a request would leave the authorized scope."""


@dataclass(frozen=True)
class Scope:
    scheme: str
    host: str
    port: int

    @classmethod
    def authorized_lab(cls) -> "Scope":
        return cls(AUTHORIZED["scheme"], AUTHORIZED["host"], AUTHORIZED["port"])

    @classmethod
    def for_testing(cls, host: str, port: int, scheme: str = "http") -> "Scope":
        """Only for offline unit tests against a local mock server."""
        return cls(scheme, host, port)

    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def contains(self, url: str) -> bool:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme == self.scheme and parsed.hostname == self.host and port == self.port

    def require(self, url: str) -> str:
        if not self.contains(url):
            raise ScopeViolation(
                f"Refusing out-of-scope request to {url!r}; authorized target is {self.base_url()}"
            )
        return url


def assert_config_authorized(target: dict) -> None:
    """Fail closed if a config file points anywhere but the authorized lab."""
    if (
        target.get("scheme") != AUTHORIZED["scheme"]
        or target.get("host") != AUTHORIZED["host"]
        or int(target.get("port", 0)) != AUTHORIZED["port"]
    ):
        raise ScopeViolation("allowlist violation: only http://192.168.56.101:3000 is authorized")
