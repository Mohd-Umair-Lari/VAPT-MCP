import json
import sys
import tempfile
import unittest
from pathlib import Path

# Allow direct execution with: python tests/test_vapt_mvp.py
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vapt_mvp
import mcp_tools


class VaptMvpTests(unittest.TestCase):
    def test_authorized_config_loads(self):
        config = vapt_mvp.load_config(Path(__file__).parents[1] / "config.json")
        self.assertEqual(config["target"]["host"], "192.168.56.101")
        self.assertEqual(vapt_mvp.target_url(config["target"]), "http://192.168.56.101:3000/")

    def test_allowlist_rejects_wrong_host(self):
        config = {"target": {"scheme": "http", "host": "192.168.56.102", "port": 3000, "base_path": "/"}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(ValueError):
                vapt_mvp.load_config(path)

    def test_missing_security_header_is_found(self):
        findings = vapt_mvp.assess_headers({"X-Frame-Options": "SAMEORIGIN"})
        finding_ids = {finding.finding_id for finding in findings}
        self.assertIn("missing-content_security_policy", finding_ids)
        self.assertIn("missing-x_content_type_options", finding_ids)

    def test_phase3_detects_wildcard_cors_and_sitemap_fallback(self):
        findings = vapt_mvp.assess_phase3(
            {"Access-Control-Allow-Origin": "*"},
            [{"path": "/sitemap.xml", "status": 200, "content_type": "text/html"}],
        )
        finding_ids = {finding.finding_id for finding in findings}
        self.assertEqual(finding_ids, {"wildcard-cors", "sitemap-fallback"})

    def test_phase4_detects_cookie_attributes(self):
        findings = vapt_mvp.assess_phase4(
            {"Set-Cookie": "session=abc; Path=/"},
            "http://192.168.56.101:3000/",
            "http://192.168.56.101:3000/",
        )
        finding_ids = {finding.finding_id for finding in findings}
        self.assertEqual(finding_ids, {"cookie-without-secure", "cookie-without-httponly", "cookie-without-samesite"})

    def test_summary_counts_findings(self):
        assessment = vapt_mvp.Assessment("test", "now", None, {}, "completed", findings=[
            vapt_mvp.Finding("one", "One", "medium", "test"),
            vapt_mvp.Finding("two", "Two", "info", "test"),
        ])
        vapt_mvp.finish_summary(assessment)
        self.assertEqual(assessment.summary["finding_count"], 2)
        self.assertEqual(assessment.summary["by_severity"]["medium"], 1)

    def test_reports_write_to_requested_directory(self):
        assessment = vapt_mvp.Assessment("assessment-test", "now", "later", {"url": "http://example/"}, "completed")
        with tempfile.TemporaryDirectory() as directory:
            json_path, markdown_path = vapt_mvp.write_reports(assessment, Path(directory) / "reports")
            self.assertTrue(json_path.exists())
            self.assertTrue(markdown_path.exists())
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["assessment_id"], "assessment-test")

    def test_mcp_scope_is_restricted(self):
        scope = mcp_tools.vapt_scope()
        self.assertEqual(scope["target"]["host"], "192.168.56.101")
        self.assertFalse(scope["intrusive_testing"])

    def test_mcp_rejects_unknown_tool(self):
        with self.assertRaises(ValueError):
            mcp_tools.call_tool("shell_command")


if __name__ == "__main__":
    unittest.main()
