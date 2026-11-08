import asyncio
import json
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from worker.app import create_app
from worker.settings import WorkerSettings


TOKEN = "test-worker-token-" + "x" * 32
IMAGE = "registry.example/veridict-guest@sha256:" + "a" * 64


class FakeAnalyzer:
    def __init__(self, *, block=False):
        self.block = block
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def prepare(self):
        return None

    async def analyze(self, scan_id, _url, progress):
        self.started.set()
        if self.block:
            await self.release.wait()
        await progress("navigating")
        await progress("collecting_evidence")
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
                    {"name": "redirect_chain", "status": "completed"},
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

    async def test_rejects_unsupported_types_and_private_urls(self):
        async with self.app.router.lifespan_context(self.app):
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers=request_headers(),
                body=json.dumps(scan_payload(scan_type="email")).encode(),
            )
            self.assertEqual(status, 422)
            self.assertEqual(
                json.loads(body)["error"]["code"], "UNSUPPORTED_SCAN_TYPE"
            )

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

    async def test_rejects_oversized_request_before_parsing(self):
        async with self.app.router.lifespan_context(self.app):
            status, _, body = await asgi_request(
                self.app,
                "POST",
                "/v1/scans",
                headers={
                    **request_headers(),
                    "content-length": "9000",
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
