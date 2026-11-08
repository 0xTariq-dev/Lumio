import logging
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from guest.scan_url import (
    _bounded_browser_timeout_seconds,
    _browser_url,
    _build_report,
    _redact_browser_request_url,
    _static_fetch,
    _static_evidence,
)
from scrapling.core.utils import log as scrapling_log
from scrapling.engines.static import FetcherSession
from worker.microsandbox_runner import public_web_network


PAGE = b"""<!doctype html>
<html><head>
  <title>private-title-should-not-be-retained</title>
  <script src="https://cdn.example.com/static.js?key=private"></script>
</head><body>
  <form action="https://accounts.example.com/submit?email=private">
    <input type="password">
  </form>
  <a href="https://links.example.net/path/secret?token=private">link</a>
</body></html>"""


class _FixtureHandler(BaseHTTPRequestHandler):
    user_agent = None
    referer = None

    def do_GET(self):
        type(self).user_agent = self.headers.get("User-Agent")
        type(self).referer = self.headers.get("Referer")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *_args):
        return


class GuestPolicyTests(unittest.TestCase):
    def test_browser_timeout_is_bounded(self):
        self.assertEqual(_bounded_browser_timeout_seconds(90), 90)
        self.assertEqual(_bounded_browser_timeout_seconds(240), 90)
        self.assertEqual(_bounded_browser_timeout_seconds(0), 1)

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        scrapling_log.setLevel(logging.CRITICAL + 1)

    def test_browser_url_strips_query_and_fragment_but_keeps_path(self):
        self.assertEqual(
            _browser_url("https://example.com/deep/path?token=private#fragment"),
            "https://example.com/deep/path",
        )

    def test_all_browser_requests_strip_query_and_fragment(self):
        self.assertEqual(
            _redact_browser_request_url(
                "https://example.com/api/status?token=secret#fragment"
            ),
            ("https://example.com/api/status", True),
        )

    def test_static_evidence_and_report_do_not_retain_private_url_content(self):
        local_url = f"http://127.0.0.1:{self.server.server_port}/fixture"
        with FetcherSession(
            impersonate=None,
            stealthy_headers=False,
            retries=0,
            timeout=5,
            follow_redirects=False,
            headers={"User-Agent": "Veridict URL Scanner/0.1"},
        ) as fetcher:
            response = fetcher.get(local_url, follow_redirects=False)
        self.assertEqual(
            _FixtureHandler.user_agent, "Veridict URL Scanner/0.1"
        )
        self.assertIsNone(_FixtureHandler.referer)

        input_url = "https://example.com/path-secret?customer=private#section"
        static = _static_evidence(response, input_url)
        report = _build_report(
            "f3b3ae2d-9f71-4ae1-9060-384d71281da6",
            input_url,
            static,
            [input_url],
            False,
            None,
            False,
            False,
            query_redacted_for_browser=False,
            static_final_url=input_url,
        )
        serialized = str(report)

        self.assertTrue(static["isHtml"])
        self.assertTrue(static["titlePresent"])
        self.assertEqual(
            static["forms"][0]["actionHost"], "accounts.example.com"
        )
        self.assertIn("password-form-cross-origin", serialized)
        for secret in (
            "path-secret",
            "customer=private",
            "private-title-should-not-be-retained",
            "submit?email=private",
            "token=private",
        ):
            self.assertNotIn(secret, serialized)

    def test_static_fetcher_does_not_follow_a_private_redirect(self):
        class RedirectResponse:
            status = 302
            headers = {"location": "http://127.0.0.1/private"}

        class FakeSession:
            calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def get(self, *_args, **_kwargs):
                self.calls += 1
                return RedirectResponse()

        fake = FakeSession()
        with patch("guest.scan_url.FetcherSession", return_value=fake):
            response, redirects, blocked, _final_url = _static_fetch(
                "https://example.com/start?secret=value"
            )
        self.assertIsNotNone(response)
        self.assertEqual(fake.calls, 1)
        self.assertTrue(blocked)
        self.assertEqual(redirects, ["https://example.com/start?secret=value"])

    def test_guest_egress_policy_is_public_web_only(self):
        network = public_web_network()
        policy = network.policy
        self.assertEqual(str(policy.default_egress), "deny")
        self.assertEqual(str(policy.default_ingress), "deny")
        rules = {
            (str(rule.destination.value), str(rule.protocol), rule.port)
            for rule in policy.rules
        }
        self.assertIn(("public", "tcp", 80), rules)
        self.assertIn(("public", "tcp", 443), rules)
        self.assertNotIn(("public", "tcp", 22), rules)

    def test_query_redaction_with_scripts_makes_report_inconclusive(self):
        input_url = "https://example.com/path?token=private#fragment"
        static = {
            "status": 200,
            "isHtml": True,
            "oversized": False,
            "scriptCount": 1,
            "scriptHosts": [],
            "forms": [],
        }
        browser = {
            "finalHost": "example.com",
            "finalScheme": "https",
            "forms": [],
            "blockedRequestCount": 0,
            "skippedResourceCount": 0,
            "strippedBrowserQuery": False,
        }
        report = _build_report(
            "f3b3ae2d-9f71-4ae1-9060-384d71281da6",
            input_url,
            static,
            [input_url],
            False,
            browser,
            False,
            False,
            query_redacted_for_browser=True,
            static_final_url=input_url,
        )
        self.assertEqual(report["riskBand"], "inconclusive")
        self.assertFalse(report["coverage"]["sufficient"])
        self.assertNotIn("token=private", str(report))
        self.assertNotIn("#fragment", str(report))

    def test_stripped_query_on_a_browser_request_limits_coverage(self):
        input_url = "https://example.com/path"
        static = {
            "status": 200,
            "isHtml": True,
            "oversized": False,
            "scriptCount": 1,
            "scriptHosts": [],
            "forms": [],
        }
        browser = {
            "finalHost": "example.com",
            "finalScheme": "https",
            "forms": [],
            "blockedRequestCount": 0,
            "skippedResourceCount": 0,
            "strippedBrowserQuery": True,
        }
        report = _build_report(
            "f3b3ae2d-9f71-4ae1-9060-384d71281da6",
            input_url,
            static,
            [input_url],
            False,
            browser,
            False,
            False,
            query_redacted_for_browser=False,
            static_final_url=input_url,
        )
        self.assertEqual(report["riskBand"], "inconclusive")
        self.assertFalse(report["coverage"]["sufficient"])

    def test_https_downgrade_is_high_risk_when_coverage_is_complete(self):
        input_url = "https://secure.example.com/"
        static = {
            "status": 200,
            "isHtml": True,
            "oversized": False,
            "scriptCount": 0,
            "scriptHosts": [],
            "forms": [],
        }
        report = _build_report(
            "f3b3ae2d-9f71-4ae1-9060-384d71281da6",
            input_url,
            static,
            [input_url, "http://destination.example.net/"],
            False,
            None,
            False,
            False,
            query_redacted_for_browser=False,
            static_final_url="http://destination.example.net/",
        )
        self.assertEqual(report["riskBand"], "high")
        self.assertIn(
            "https-downgrade",
            {finding["id"] for finding in report["findings"]},
        )
        downgrade = next(
            finding
            for finding in report["findings"]
            if finding["id"] == "https-downgrade"
        )
        self.assertIn(
            "https://secure.example.com", downgrade["sanitizedObservedValue"]
        )
        self.assertIn(
            "http://destination.example.net", downgrade["sanitizedObservedValue"]
        )


if __name__ == "__main__":
    unittest.main()
