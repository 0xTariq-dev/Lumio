import asyncio
import base64
import json
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from worker.app import create_app
from worker.contracts import EmailScanRequest, URLScanRequest
from worker.settings import WorkerSettings


TOKEN = "test-worker-token-" + "x" * 32
IMAGE = "registry.example/veridict-guest@sha256:" + "a" * 64


class FakeAnalyzer:
    def __init__(self, *, block=False, redirect_blocked=False):
        self.block = block
        self.redirect_blocked = redirect_blocked
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.email_link_id = uuid4()
        self.seen_urls = []

    async def prepare(self):
        return None

    async def analyze(self, scan_id, request, _task_plan, progress):
        self.started.set()
        if self.block:
            await self.release.wait()
        if isinstance(request, EmailScanRequest):
            await progress("analyzing_email")
            await progress("building_report")
            return {
                "scanId": scan_id,
                "type": "email",
                "riskBand": "inconclusive",
                "completedAt": datetime.now(timezone.utc).isoformat(),
                "ruleSetVersion": "test-email-rules",
                "findings": [],
                "coverage": {
                    "sufficient": False,
                    "checks": [
                        {"name": "email_headers", "status": "completed"},
                        {"name": "email_body", "status": "completed"},
                        {"name": "email_links", "status": "completed"},
                        {"name": "attachment_metadata", "status": "completed"},
                        {"name": "selected_link_scan", "status": "skipped"},
                    ],
                },
                "links": [
                    {
                        "linkId": str(self.email_link_id),
                        "anchorText": "Email link 1",
                        "displayUrl": "https://example.com/",
                        "targetHost": "example.com",
                        "scanAvailable": True,
                    }
                ],
                "_privateLinks": {
                    str(self.email_link_id): "https://example.com/path?private=do-not-return"
                },
            }

        if isinstance(request, URLScanRequest):
            self.seen_urls.append(request.url)
        await progress("navigating")
        await progress("collecting_evidence")
        await progress("browser_skipped", "no_browser_required")
        await progress("building_report")
        return {
            "scanId": scan_id,
            "type": "url",
            "riskBand": "low",
            "completedAt": datetime.now(timezone.utc).isoformat(),
            "ruleSetVersion": "test-rules",
            "findings": [],
            "coverage": {
                "sufficient": True,
                "checks": [
                    {"name": "http_response", "status": "completed"},
                    {
                        "name": "redirect_chain",
                        "status": "blocked" if self.redirect_blocked else "completed",
                    },
                    {"name": "static_html", "status": "completed"},
                    {"name": "browser_observation", "status": "skipped"},
                ],
            },
        }


async def asgi_request(app, method, path, *, headers=None, body=b""):
    raw_headers = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    messages = []
    body_sent = False
    hold_connection = asyncio.Event()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 54321),
        "server": ("testserver", 80),
        "root_path": "",
    }

    async def receive():
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await hold_connection.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    response_start = next(message for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    response_headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in response_start["headers"]
    }
    return (
        response_start["status"],
        response_headers,
        response_body,
    )


def request_headers():
    return {
        "authorization": f"Bearer {TOKEN}",
        "content-type": "application/json",
    }


def scan_payload(scan_id=None, scan_type="url", url="https://example.com/"):
    return {
        "scanId": str(scan_id or uuid4()),
        "type": scan_type,
        "url": url,
        "consent": True,
    }


def email_payload(scan_id=None):
    content = b"From: sender@example.com\r\nSubject: private subject\r\n\r\nprivate body"
    return {
        "scanId": str(scan_id or uuid4()),
        "type": "email",
        "emailBase64": base64.b64encode(content).decode("ascii"),
        "consent": True,
    }


def completed_report(event_body):
    current_event = None
    for line in event_body.decode().splitlines():
        if line.startswith("event: "):
            current_event = line[7:]
        elif line.startswith("data: ") and current_event == "completed":
            return json.loads(line[6:])
    raise AssertionError("Completed report event was not present")


class WorkerApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.settings = WorkerSettings(token=TOKEN, guest_image=IMAGE)
        self.analyzer = FakeAnalyzer()
        self.app = create_app(self.settings, self.analyzer)

    async def test_authentication_and_safe_request_id(self):
        async with self.app.router.lifespan_context(self.app):
            status, headers, body = await asgi_request(
                self.app, "GET", "/healthz", headers={}
            )
            self.assertEqual(status, 401)
            self.assertIn("x-request-id", headers)
            self.assertEqual(json.loads(body)["error"]["code"], "UNAUTHORIZED")

    async def test_accepts_email_and_rejects_unsupported_or_private_targets(self):
        async with self.app.router.lifespan_context(self.app):
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(scan_payload(scan_type="qr")).encode(),
            )
            self.assertEqual(status, 422)
            self.assertEqual(
                json.loads(body)["error"]["code"], "UNSUPPORTED_SCAN_TYPE"
            )

            email_id = uuid4()
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(email_payload(email_id)).encode(),
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["accepted"], True)
            await self.analyzer.started.wait()
            _, _, event_body = await asgi_request(
                self.app,
                "GET",
                f"/v1/scans/{email_id}/events",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
            self.assertIn(b'"type":"email"', event_body)
            self.assertNotIn(b"_privateLinks", event_body)
            self.assertNotIn(b"private=do-not-return", event_body)
            email_report = completed_report(event_body)
            plan = {step["id"]: step["status"] for step in email_report["executionPlan"]}
            self.assertEqual(
                plan,
                {
                    "consent_target": "completed",
                    "sandbox": "completed",
                    "email_parse": "completed",
                    "report": "completed",
                },
            )
            self.assertNotIn("pending", plan.values())

            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(
                    scan_payload(url="http://127.0.0.1/internal")
                ).encode(),
            )
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body)["error"]["code"], "INVALID_URL")

    async def test_selected_email_link_requires_completed_source_and_uses_private_target(self):
        email_id = uuid4()
        selected_scan_id = uuid4()
        async with self.app.router.lifespan_context(self.app):
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(email_payload(email_id)).encode(),
            )
            self.assertEqual(status, 200)
            await self.analyzer.started.wait()
            _, _, email_events = await asgi_request(
                self.app,
                "GET",
                f"/v1/scans/{email_id}/events",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
            self.assertIn(b'"type":"email"', email_events)

            link_payload = {
                "scanId": str(selected_scan_id),
                "type": "email_link",
                "originalScanId": str(email_id),
                "linkId": str(self.analyzer.email_link_id),
                "consent": True,
            }
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(link_payload).encode(),
            )
            self.assertEqual(status, 200)
            _, _, link_events = await asgi_request(
                self.app,
                "GET",
                f"/v1/scans/{selected_scan_id}/events",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
            self.assertIn(b'"type":"email_link"', link_events)
            self.assertEqual(completed_report(link_events)["type"], "email_link")
            self.assertEqual(
                self.analyzer.seen_urls[-1],
                "https://example.com/path?private=do-not-return",
            )
            self.assertNotIn(b"private=do-not-return", link_events)

    async def test_rejects_oversized_request_before_parsing(self):
        async with self.app.router.lifespan_context(self.app):
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers={
                    **request_headers(),
                    "content-length": str(self.settings.request_body_limit_bytes + 1),
                },
                body=b"",
            )
            self.assertEqual(status, 413)
            self.assertEqual(
                json.loads(body)["error"]["code"], "REQUEST_TOO_LARGE"
            )

    async def test_streams_progress_and_terminal_report(self):
        scan_id = uuid4()
        async with self.app.router.lifespan_context(self.app):
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(scan_payload(scan_id)).encode(),
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["accepted"], True)
            await self.analyzer.started.wait()

            event_status, event_headers, event_body = await asgi_request(
                self.app,
                "GET",
                f"/v1/scans/{scan_id}/events",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
            self.assertEqual(event_status, 200)
            self.assertEqual(event_headers["content-type"], "text/event-stream; charset=utf-8")
            self.assertIn(b"event: progress", event_body)
            self.assertIn(b"event: completed", event_body)
            self.assertIn(b'"riskBand":"low"', event_body)
            self.assertIn(b'"id":"browser","status":"skipped"', event_body)
            self.assertIn(b'"executionPlan":[', event_body)
            report = completed_report(event_body)
            for step in report["executionPlan"]:
                if step["id"] != "consent_target" and step["status"] == "completed":
                    self.assertNotIn("reasonCode", step)

            scan_status, _, scan_body = await asgi_request(
                self.app,
                "GET",
                f"/v1/scans/{scan_id}",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
            parsed = json.loads(scan_body)
            self.assertEqual(scan_status, 200)
            self.assertEqual(parsed["status"], "completed")
            self.assertNotIn("report", parsed)

    async def test_private_redirect_is_marked_blocked_in_execution_plan(self):
        self.analyzer.redirect_blocked = True
        scan_id = uuid4()
        async with self.app.router.lifespan_context(self.app):
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(scan_payload(scan_id)).encode(),
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["accepted"], True)
            await self.analyzer.started.wait()

            _, _, event_body = await asgi_request(
                self.app,
                "GET",
                f"/v1/scans/{scan_id}/events",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
            report = completed_report(event_body)
            http_step = next(
                step for step in report["executionPlan"] if step["id"] == "http"
            )
            self.assertEqual(http_step["status"], "blocked")
            self.assertEqual(http_step["reasonCode"], "redirect_blocked")

    async def test_queue_capacity_rejects_new_work(self):
        self.analyzer.block = True
        async with self.app.router.lifespan_context(self.app):
            first = scan_payload()
            status, _, _ = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(first).encode(),
            )
            self.assertEqual(status, 200)
            await self.analyzer.started.wait()

            for _ in range(10):
                status, _, _ = await asgi_request(
                    self.app,
                    "POST",
                    "/v1/scans",
                    headers=request_headers(),
                    body=json.dumps(scan_payload()).encode(),
                )
                self.assertEqual(status, 200)

            status, headers, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(scan_payload()).encode(),
            )
            self.assertEqual(status, 429)
            self.assertEqual(headers["retry-after"], "30")
            self.assertEqual(json.loads(body)["error"]["code"], "SCAN_QUEUE_FULL")

            self.analyzer.release.set()


if __name__ == "__main__":
    unittest.main()
