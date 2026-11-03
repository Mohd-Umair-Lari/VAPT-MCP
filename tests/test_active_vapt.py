import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import active_vapt
import approval
import mcp_server
import orchestrator
from http_client import HttpClient
from scope import Scope, ScopeViolation

WEAK = {"email": "test@test.com", "password": "test"}


class JuiceShopMock(BaseHTTPRequestHandler):
    """Minimal stand-in for the lab app so active checks can be tested offline."""

    def log_message(self, *args):  # keep test output quiet
        pass

    def _send(self, status, payload, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, {"app": "mock-juice"}, {"X-Powered-By": "Express"})
        elif parsed.path == "/rest/products/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            self._send(200, {"status": "success", "query": query, "data": []})
        elif parsed.path.startswith("/rest/basket/"):
            if self.headers.get("Authorization", "").startswith("Bearer "):
                self._send(200, {"data": {"id": parsed.path.rsplit("/", 1)[-1]}})
            else:
                self._send(401, {"error": "unauthenticated"})
        elif parsed.path.startswith("/api/users/") or parsed.path.startswith("/api/orders/") or parsed.path.startswith("/api/documents/") or parsed.path.startswith("/api/accounts/") or parsed.path.startswith("/api/baskets/"):
            if self.headers.get("Authorization", "").startswith("Bearer "):
                self._send(200, {"data": {"id": parsed.path.rsplit("/", 1)[-1]}})
            else:
                self._send(401, {"error": "unauthenticated"})
        elif parsed.path == "/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            self._send(200, {"results": [], "query": query})
        elif parsed.path == "/login":
            self._send(401, {"error": "invalid credentials"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/rest/user/login":
            email = body.get("email", "")
            if email == "'":
                self._send(500, {"error": "SQLITE_ERROR: near syntax error"})
            elif "' OR 1=1" in email:
                self._send(200, {"authentication": {"token": "eyJmYW...oken"}})
            elif email == WEAK["email"] and body.get("password") == WEAK["password"]:
                self._send(200, {"authentication": {"token": "***"}})
            else:
                self._send(401, {"error": "invalid credentials"})
        elif self.path == "/login":
            email = body.get("username", body.get("email", ""))
            if email == "'":
                self._send(500, {"error": "SQL syntax error near '"})
            elif "' OR 1=1" in email:
                self._send(200, {"authentication": {"token": "eyJmYW...oken"}})
            elif email == WEAK["email"] and body.get("password") == WEAK["password"]:
                self._send(200, {"authentication": {"token": "***"}})
            else:
                self._send(401, {"error": "invalid credentials"})
        elif self.path == "/fetch":
            url = body.get("url", "")
            if "169.254.169.254" in url:
                self._send(200, {"ami-id": "ami-123", "instance-id": "i-123"})
            else:
                self._send(200, {"fetched": url})
        else:
            self._send(404, {"error": "not found"})


class ActiveVaptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), JuiceShopMock)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def client(self):
        return HttpClient(Scope.for_testing("127.0.0.1", self.port), rate_limit_per_second=0, timeout=5)

    def test_scope_blocks_out_of_scope(self):
        with self.assertRaises(ScopeViolation):
            Scope.from_url("http://example.com/").require("http://other-host.com/")

    def test_http_client_refuses_out_of_scope(self):
        client = HttpClient(Scope.for_testing("127.0.0.1", self.port), rate_limit_per_second=0)
        with self.assertRaises(ScopeViolation):
            client.get("http://127.0.0.1:1/")

    def test_recon_returns_entries(self):
        notes = active_vapt.recon(self.client())
        self.assertTrue(any(note["path"] == "/robots.txt" for note in notes))

    def test_detect_sql_injection(self):
        finding = active_vapt.detect_sql_injection(self.client())
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding_id, "sqli-login-error")

    def test_detect_reflected_input(self):
        finding = active_vapt.detect_reflected_input(self.client())
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding_id, "reflected-search-input")

    def test_detect_ssrf(self):
        finding = active_vapt.detect_ssrf(self.client())
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding_id, "ssrf-metadata")

    def test_exploit_requires_approval_flag(self):
        with self.assertRaises(PermissionError):
            active_vapt.exploit_sql_login_bypass(self.client(), False)

    def test_exploit_sql_login_bypass(self):
        finding, token = active_vapt.exploit_sql_login_bypass(self.client(), True)
        self.assertEqual(finding.finding_id, "sqli-auth-bypass")
        self.assertTrue(token)

    def test_exploit_weak_login(self):
        finding, token = active_vapt.exploit_weak_login(self.client(), True, [WEAK])
        self.assertEqual(finding.finding_id, "weak-credentials")
        self.assertTrue(token)

    def test_exploit_jwt_none(self):
        finding = active_vapt.exploit_jwt_none(self.client(), True, probe_path="/rest/basket/1")
        self.assertEqual(finding.finding_id, "jwt-none-accepted")

    def test_exploit_idor(self):
        finding = active_vapt.exploit_idor(self.client(), True, token="any")
        self.assertIsNotNone(finding)
        self.assertIn("idor", finding.finding_id)

    def test_approval_lifecycle(self):
        target = "http://127.0.0.1:%d" % self.port
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "pending.json"
            record = approval.request_approval(target, path)
            ok, _ = approval.validate(record["token"], target, path)
            self.assertTrue(ok)
            approval.consume(record["token"], path)
            used, _ = approval.validate(record["token"], target, path)
            self.assertFalse(used)

    def _config(self, exploit=False, require_approval=True):
        return {"user_agent": "test", "timeout_seconds": 5,
                "active": {"rate_limit_per_second": 0, "max_response_bytes": 1048576,
                           "phases": {"recon": True, "detect": True, "exploit": exploit},
                           "require_exploit_approval": require_approval,
                           "weak_login_candidates": [WEAK]}}

    def test_orchestrator_auto_does_not_exploit(self):
        with TemporaryDirectory() as tmp:
            result = orchestrator.run(self._config(exploit=False),
                                      scope=Scope.for_testing("127.0.0.1", self.port),
                                      client=self.client(), report_dir=tmp)
        ids = {f["finding_id"] for f in result["assessment"]["findings"]}
        self.assertIn("sqli-login-error", ids)
        self.assertNotIn("sqli-auth-bypass", ids)
        self.assertEqual(result["exploit_status"], "skipped")

    def test_orchestrator_blocks_exploit_without_token(self):
        with TemporaryDirectory() as tmp:
            result = orchestrator.run(self._config(exploit=True),
                                      scope=Scope.for_testing("127.0.0.1", self.port),
                                      client=self.client(), report_dir=tmp)
        ids = {f["finding_id"] for f in result["assessment"]["findings"]}
        self.assertNotIn("sqli-auth-bypass", ids)
        self.assertTrue(result["pending_exploits"])

    def test_orchestrator_marks_approved_timeout_as_error(self):
        class FailingClient:
            def get(self, path):
                raise TimeoutError("target timed out")

            def post(self, path, **kwargs):
                raise TimeoutError("target timed out")

        config = self._config(exploit=True)
        target_url = "http://127.0.0.1:%d" % self.port
        token = approval.request_approval(target_url)["token"]
        with TemporaryDirectory() as tmp:
            result = orchestrator.run(config, scope=Scope.from_url(target_url), client=FailingClient(),
                                      approval_token=token, report_dir=tmp)
        self.assertEqual(result["assessment"]["status"], "completed_with_errors")
        self.assertEqual(result["exploit_status"], "completed_with_errors")

    def test_orchestrator_exploits_when_approval_not_required(self):
        with TemporaryDirectory() as tmp:
            result = orchestrator.run(self._config(exploit=True, require_approval=False),
                                      scope=Scope.for_testing("127.0.0.1", self.port),
                                      client=self.client(), report_dir=tmp)
        ids = {f["finding_id"] for f in result["assessment"]["findings"]}
        self.assertIn("sqli-auth-bypass", ids)

    def test_mcp_scope_tool(self):
        scope = mcp_server.vapt_scope()
        self.assertEqual(scope["target"], "http://example.com:80")
        self.assertTrue(scope["exploit_requires_approval"])

    def test_mcp_exploit_refuses_without_token(self):
        result = mcp_server.vapt_exploit("not-a-real-token", "", "http://example.com:80")
        self.assertEqual(result["status"], "refused")

    def test_mcp_exploit_requires_execution_confirmation(self):
        result = mcp_server.vapt_exploit("not-a-real-token", "", "http://example.com:80")
        self.assertEqual(result["status"], "refused")

    def test_mcp_lists_active_actions_without_executing(self):
        result = mcp_server.vapt_list_active_actions("http://example.com:80")
        self.assertFalse(result["executed"])
        self.assertTrue(result["actions"])

    def test_mcp_approval_requires_explicit_phrase(self):
        result = mcp_server.request_exploit_approval("", "http://example.com:80")
        self.assertEqual(result["status"], "pending")


if __name__ == "__main__":
    unittest.main()
