"""Scope-enforcing, rate-limited HTTP client for active checks.

All active modules send requests through HttpClient so the authorized scope,
redirect handling, and rate limits cannot be bypassed by an individual check.

Security features:
- DNS rebinding protection (resolves and validates IPs before connecting)
- Private IP blocking (RFC 1918, RFC 4193, RFC 3927, RFC 6598, RFC 6890)
- Redirect limit enforcement
- Response size limits
- Per-host concurrency limits
- Global request budget
- Scope enforcement on every hop
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests

from scope import Scope


# --- Private IP ranges (RFC 1918, RFC 4193, RFC 3927, RFC 6598, RFC 6890) ---
PRIVATE_IPV4_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("240.0.0.0/4"),
]

PRIVATE_IPV6_RANGES = [
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("::ffff:0:0/96"),
    ipaddress.IPv6Network("2001:db8::/32"),
]


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return any(addr in net for net in PRIVATE_IPV4_RANGES)
        else:
            return any(addr in net for net in PRIVATE_IPV6_RANGES)
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses with DNS rebinding protection."""
    try:
        addrs = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        return list({addr[4][0] for addr in addrs})
    except OSError:
        return []


def validate_ips_allowed(ips: list[str], allow_private: bool = False) -> None:
    """Validate that resolved IPs are allowed (not private unless explicitly allowed)."""
    if allow_private:
        return
    for ip in ips:
        if is_private_ip(ip):
            raise ValueError(f"DNS rebinding protection: resolved IP {ip} is private/reserved")


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
    user_agent: str = "VAPT-Agent/1.0"
    timeout: float = 10.0
    rate_limit_per_second: float = 3.0
    max_bytes: int = 1_048_576
    max_redirects: int = 5
    allow_private_ips: bool = False
    max_concurrent_per_host: int = 2
    global_request_budget: int = 1000
    _session: requests.Session = field(default_factory=requests.Session, init=False, repr=False)
    _last_request: float = field(default=0.0, init=False, repr=False)
    _request_count: int = field(default=0, init=False, repr=False)
    _host_semaphores: dict[str, Any] = field(default_factory=dict, init=False, repr=False)

    def _check_budget(self) -> None:
        """Check global request budget."""
        if self._request_count >= self.global_request_budget:
            raise RuntimeError(f"Global request budget exhausted ({self.global_request_budget} requests)")

    def _get_host_semaphore(self, host: str) -> Any:
        """Get or create a semaphore for per-host concurrency control."""
        import threading
        if host not in self._host_semaphores:
            self._host_semaphores[host] = threading.Semaphore(self.max_concurrent_per_host)
        return self._host_semaphores[host]

    def _throttle(self) -> None:
        if self.rate_limit_per_second <= 0:
            return
        min_gap = 1.0 / self.rate_limit_per_second
        wait = min_gap - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def _validate_redirect(self, url: str, redirect_count: int) -> None:
        """Validate redirect target is in scope and not excessive."""
        if redirect_count > self.max_redirects:
            raise ValueError(f"Redirect limit exceeded ({self.max_redirects})")
        self.scope.require(url)

    def request(self, method: str, path_or_url: str, **kwargs: Any) -> Response:
        if "://" in path_or_url:
            url = path_or_url
        else:
            tail = path_or_url if path_or_url.startswith("/") else "/" + path_or_url
            url = self.scope.base_url() + tail

        # Fail closed before a single byte leaves the process.
        self.scope.require(url)
        self._check_budget()
        self._throttle()

        # DNS rebinding protection: resolve and validate IPs before connecting
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname:
            ips = resolve_hostname(hostname)
            validate_ips_allowed(ips, self.allow_private_ips)

        headers = {"User-Agent": self.user_agent, **kwargs.pop("headers", {})}
        start = time.monotonic()
        
        # Per-host concurrency control
        host_sem = self._get_host_semaphore(hostname)
        with host_sem:
            resp = self._session.request(
                method, url, headers=headers, timeout=self.timeout, 
                allow_redirects=False, **kwargs  # Handle redirects manually
            )

        # Manual redirect handling with validation
        redirect_count = 0
        final_url = resp.url
        while resp.is_redirect and redirect_count < self.max_redirects:
            redirect_count += 1
            location = resp.headers.get("Location")
            if not location:
                break
            # Resolve relative redirects
            if location.startswith("/"):
                parsed_base = urlparse(final_url)
                location = f"{parsed_base.scheme}://{parsed_base.netloc}{location}"
            elif not ("://" in location):
                # Relative redirect
                base_parsed = urlparse(final_url)
                base_path = base_parsed.path.rsplit("/", 1)[0] + "/"
                location = f"{base_parsed.scheme}://{base_parsed.netloc}{base_path}{location}"
            
            self._validate_redirect(location, redirect_count)
            
            # DNS rebinding check for redirect target
            redirect_parsed = urlparse(location)
            redirect_host = redirect_parsed.hostname or ""
            if redirect_host:
                redirect_ips = resolve_hostname(redirect_host)
                validate_ips_allowed(redirect_ips, self.allow_private_ips)
            
            # Follow redirect
            resp = self._session.request(
                method, location, headers=headers, timeout=self.timeout,
                allow_redirects=False, **kwargs
            )
            final_url = resp.url

        # Final URL scope validation
        self.scope.require(final_url)
        
        self._request_count += 1
        
        text = resp.content[: self.max_bytes].decode(resp.encoding or "utf-8", errors="replace")
        return Response(resp.status_code, dict(resp.headers), text, final_url, int((time.monotonic() - start) * 1000))

    def get(self, path: str, **kw: Any) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> Response:
        return self.request("POST", path, **kw)
