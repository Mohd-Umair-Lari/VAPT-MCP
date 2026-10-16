"""Scope-enforcing, rate-limited HTTP client for active checks.

All active modules send requests through HttpClient so the authorized scope,
redirect handling, and rate limits cannot be bypassed by an individual check.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests

from scope import Scope


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    text: str
    url: str
    elapsed_ms: int


@dataclass
class HttpClient:
    scope: Scope
    user_agent: str = "VAPT-Lab/0.2"
    timeout: float = 10.0
    rate_limit_per_second: float = 3.0
    max_bytes: int = 1_048_576
    _session: requests.Session = field(default_factory=requests.Session, init=False, repr=False)
    _last_request: float = field(default=0.0, init=False, repr=False)

    def _throttle(self) -> None:
        if self.rate_limit_per_second <= 0:
            return
        min_gap = 1.0 / self.rate_limit_per_second
        wait = min_gap - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def request(self, method: str, path_or_url: str, **kwargs: Any) -> Response:
        if "://" in path_or_url:
            url = path_or_url
        else:
            tail = path_or_url if path_or_url.startswith("/") else "/" + path_or_url
            url = self.scope.base_url() + tail
        # Fail closed before a single byte leaves the process.
        self.scope.require(url)
        self._throttle()
        headers = {"User-Agent": self.user_agent, **kwargs.pop("headers", {})}
        allow_redirects = kwargs.pop("allow_redirects", False)
        start = time.monotonic()
        resp = self._session.request(
            method, url, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects, **kwargs
        )
        # If a redirect was followed, re-validate the final hop stayed in scope.
        self.scope.require(resp.url)
        text = resp.content[: self.max_bytes].decode(resp.encoding or "utf-8", errors="replace")
        return Response(resp.status_code, dict(resp.headers), text, resp.url, int((time.monotonic() - start) * 1000))

    def get(self, path: str, **kw: Any) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> Response:
        return self.request("POST", path, **kw)
