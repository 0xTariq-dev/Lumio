import asyncio
import json
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from worker.app import create_app
from worker.contracts import EmailScanRequest, URLScanRequest
from worker.settings import WorkerSettings

from tests.test_worker_api import (
    IMAGE,
    TOKEN,
    FakeAnalyzer,
    asgi_request,
    completed_report,
    email_payload,
    request_headers,
    scan_payload,
)


AUTH = {"authorization": f"Bearer {TOKEN}"}


class ReviewAnalyzer(FakeAnalyzer):
    """Fake sandbox that records follow-up requests and can stall them."""

    def __init__(self):
        super().__init__()
        self.follow_up_requests = []
        self.stall_follow_up = False
        self.email_snapshots = []

    async def analyze(self, scan_id, request, task_plan, progress):
        if isinstance(request, EmailScanRequest):
            return await super().analyze(scan_id, request, task_plan, progress)
        is_follow_up = isinstance(request, URLScanRequest) and (
            request.browserRequested or "private=" in request.url
        )
        if not is_follow_up:
            return await super().analyze(scan_id, request, task_plan, progress)
        self.follow_up_requests.append(request)
        if self.stall_follow_up:
            await asyncio.Event().wait()
        checks = [
            {"name": "http_response", "status": "completed"},
            {"name": "redirect_chain", "status": "completed"},
            {"name": "static_html", "status": "completed"},
            {
                "name": "browser_observation",
                "status": "completed" if request.browserRequested else "skipped",
            },
        ]
        return {
            "scanId": scan_id,
            "type": "url",
            "riskBand": "high",
            "completedAt": datetime.now(timezone.utc).isoformat(),
            "ruleSetVersion": "test-rules",
            "findings": [
                {
                    "id": "password-form",
                    "title": "Password form posts off-site",
                    "explanation": "A password field submits to another host.",
                    "severity": "high",
                    "strength": "direct",
                    "source": "browser" if request.browserRequested else "url_navigation",
                },
                {
                    "id": "bad-finding",
                    "title": "x" * 500,
                    "explanation": "Oversized title must be dropped.",
                    "severity": "low",
                    "strength": "direct",
                    "source": "browser",
                },
            ],
            "coverage": {"sufficient": True, "checks": checks},
        }


async def submit(app, payload):
    return await asgi_request(
        app,
        "POST",
        "/v1/scans",
        headers=request_headers(),
        body=json.dumps(payload).encode(),
    )


async def command(app, scan_id, body):
    status, _, raw = await asgi_request(
        app,
        "POST",
        f"/v1/scans/{scan_id}/review/commands",
        headers=request_headers(),
        body=json.dumps(body).encode(),
    )
    return status, json.loads(raw)


async def review(app, scan_id):
    status, _, raw = await asgi_request(
        app, "GET", f"/v1/scans/{scan_id}/review", headers=AUTH
    )
    return status, json.loads(raw)


async def wait_for_status(app, scan_id, wanted, attempts=400):
    for _ in range(attempts):
        _, _, raw = await asgi_request(app, "GET", f"/v1/scans/{scan_id}", headers=AUTH)
        status = json.loads(raw).get("status")
        if status == wanted:
            return
        await asyncio.sleep(0.005)
    raise AssertionError(f"Scan never reached {wanted}")


async def wait_for_action(app, scan_id, action_id, wanted, attempts=400):
    for _ in range(attempts):
        status, body = await review(app, scan_id)
        if status == 200:
            for action in body["actions"]:
                if action["actionId"] == action_id and action["status"] == wanted:
                    return action
        await asyncio.sleep(0.005)
    raise AssertionError(f"Action never reached {wanted}")


async def events(app, scan_id):
    _, _, body = await asgi_request(app, "GET", f"/v1/scans/{scan_id}/events", headers=AUTH)
    return body


class AgentReviewTests(unittest.IsolatedAsyncioTestCase):
    def make_app(self, **settings):
        self.settings = WorkerSettings(token=TOKEN, guest_image=IMAGE, **settings)
        self.analyzer = ReviewAnalyzer()
        self.app = create_app(self.settings, self.analyzer)
        return self.app

    async def start_email_review(self):
        scan_id = uuid4()
        status, _, _ = await submit(self.app, {**email_payload(scan_id), "agentReview": True})
        self.assertEqual(status, 200)
        await wait_for_status(self.app, scan_id, "awaiting_review")
        return scan_id

    async def test_email_scan_pauses_before_report_and_keeps_input_only_in_memory(self):
        self.make_app()
        async with self.app.router.lifespan_context(self.app):
            scan_id = await self.start_email_review()
            # No report is published while the review is pending.
            status, _, _ = await asgi_request(
                self.app, "GET", f"/v1/scans/{scan_id}/report", headers=AUTH
            )
            self.assertEqual(status, 404)
            # The original email stays in volatile memory during the review.
            self.assertTrue(self.analyzer.last_request.emailBase64)

            status, view = await review(self.app, scan_id)
            self.assertEqual(status, 200)
            self.assertEqual(
                view["linkCandidates"],
                [{"linkId": str(self.analyzer.email_link_id), "host": "example.com"}],
            )
            # Link path/anchor context is withheld until sharing is approved.
            self.assertNotIn("linkContext", view)
            self.assertNotIn("private=do-not-return", json.dumps(view))

            status, body = await command(self.app, scan_id, {"command": "finalize"})
            self.assertEqual((status, body), (202, {"accepted": True}))
            await wait_for_status(self.app, scan_id, "completed")
            report = completed_report(await events(self.app, scan_id))
            check = report["coverage"]["checks"][-1]
            self.assertEqual(check["name"], "agent_follow_up")
            self.assertEqual(check["status"], "skipped")
            self.assertEqual(self.analyzer.last_request.emailBase64, "")

    async def test_reconnected_event_stream_replays_review_state_after_last_event_id(self):
        self.make_app()
        async with self.app.router.lifespan_context(self.app):
            scan_id = await self.start_email_review()
            record = self.app.state.scan_manager.get_record(str(scan_id))
            review_ready = next(event for event in record.events if event.name == "review_ready")
            reconnect_from = review_ready.event_id - 1

            stream = asyncio.create_task(
                asgi_request(
                    self.app,
                    "GET",
                    f"/v1/scans/{scan_id}/events",
                    headers={
                        **AUTH,
                        "last-event-id": str(reconnect_from),
                    },
                )
            )
            await asyncio.sleep(0.02)
            status, body = await command(self.app, scan_id, {"command": "finalize"})
            self.assertEqual(status, 202)
            stream_status, _, events_body = await stream

            self.assertEqual(stream_status, 200)
            rendered = events_body.decode()
            self.assertIn(
                f"id: {review_ready.event_id}\nevent: review_ready\n",
                rendered,
            )
            self.assertIn("event: completed\n", rendered)

    async def test_approved_link_share_and_visit_run_in_worker_with_redacted_context(self):
        self.make_app()
        async with self.app.router.lifespan_context(self.app):
            scan_id = await self.start_email_review()
            share_id = str(uuid4())
            status, _ = await command(
                self.app,
                scan_id,
                {"command": "run", "actionId": share_id, "tool": "link_metadata_share"},
            )
            self.assertEqual(status, 202)
            await wait_for_action(self.app, scan_id, share_id, "completed")
            _, view = await review(self.app, scan_id)
            self.assertEqual(
                view["linkContext"],
                [
                    {
                        "linkId": str(self.analyzer.email_link_id),
                        "host": "example.com",
                        "path": "/path",
                        "anchor": "Email link 1",
                    }
                ],
            )
            self.assertNotIn("private=do-not-return", json.dumps(view))

            visit_id = str(uuid4())
            status, _ = await command(
                self.app,
                scan_id,
                {
                    "command": "run",
                    "actionId": visit_id,
                    "tool": "email_link_visit",
                    "linkId": str(self.analyzer.email_link_id),
                },
            )
            self.assertEqual(status, 202)
            action = await wait_for_action(self.app, scan_id, visit_id, "completed")
            self.assertEqual(action["targetHost"], "example.com")
            self.assertEqual(action["riskBand"], "high")
            # Malformed findings from the sandbox are dropped, not forwarded.
            self.assertEqual([f["id"] for f in action["findings"]], ["password-form"])
            self.assertEqual(
                self.analyzer.follow_up_requests[-1].url,
                "https://example.com/path?private=do-not-return",
            )

            await command(self.app, scan_id, {"command": "finalize"})
            await wait_for_status(self.app, scan_id, "completed")
            stream = await events(self.app, scan_id)
            self.assertIn(b"event: review_ready", stream)
            self.assertIn(b"event: agent_action", stream)
            self.assertNotIn(b"private=do-not-return", stream)
            report = completed_report(stream)
            # Follow-up results never change the deterministic risk band.
            self.assertEqual(report["riskBand"], "inconclusive")
            self.assertEqual(
                [a["tool"] for a in report["agentActions"]],
                ["link_metadata_share", "email_link_visit"],
            )
            self.assertEqual(report["coverage"]["checks"][-1]["status"], "completed")

    async def test_decline_records_limitation_and_blocks_replay_or_retry(self):
        self.make_app()
        async with self.app.router.lifespan_context(self.app):
            scan_id = await self.start_email_review()
            action_id = str(uuid4())
            status, _ = await command(
                self.app,
                scan_id,
                {
                    "command": "skip",
                    "actionId": action_id,
                    "tool": "email_link_visit",
                    "reason": "declined",
                },
            )
            self.assertEqual(status, 202)
            await wait_for_status(self.app, scan_id, "completed")
            report = completed_report(await events(self.app, scan_id))
            self.assertEqual(report["agentActions"][0]["status"], "skipped")
            self.assertEqual(report["agentActions"][0]["reasonCode"], "declined")
            limitation = report["coverage"]["checks"][-1]
            self.assertEqual(limitation["status"], "skipped")
            self.assertIn("not approved", limitation["reason"])
            # The declined request cannot be retried through another tool.
            status, body = await command(
                self.app,
                scan_id,
                {
                    "command": "run",
                    "actionId": str(uuid4()),
                    "tool": "email_link_visit",
                    "linkId": str(self.analyzer.email_link_id),
                },
            )
            self.assertEqual(status, 409)
            self.assertEqual(body["error"]["code"], "REVIEW_NOT_ACTIVE")
            self.assertEqual(self.analyzer.follow_up_requests, [])

    async def test_rejects_replay_unknown_tools_unknown_links_and_internal_flags(self):
        self.make_app()
        async with self.app.router.lifespan_context(self.app):
            scan_id = await self.start_email_review()
            share_id = str(uuid4())
            share = {"command": "run", "actionId": share_id, "tool": "link_metadata_share"}
            self.assertEqual((await command(self.app, scan_id, share))[0], 202)
            await wait_for_action(self.app, scan_id, share_id, "completed")

            status, body = await command(self.app, scan_id, share)
            self.assertEqual((status, body["error"]["code"]), (409, "AGENT_ACTION_REPLAYED"))

            status, body = await command(
                self.app,
                scan_id,
                {"command": "run", "actionId": str(uuid4()), "tool": "url_browser_observation"},
            )
            self.assertEqual((status, body["error"]["code"]), (422, "AGENT_TOOL_NOT_ALLOWED"))

            status, body = await command(
                self.app,
                scan_id,
                {"command": "run", "actionId": str(uuid4()), "tool": "shell_exec"},
            )
            self.assertEqual((status, body["error"]["code"]), (400, "INVALID_REVIEW_COMMAND"))

            status, body = await command(
                self.app,
                scan_id,
                {
                    "command": "run",
                    "actionId": str(uuid4()),
                    "tool": "email_link_visit",
                    "linkId": str(uuid4()),
                },
            )
            self.assertEqual((status, body["error"]["code"]), (404, "EMAIL_LINK_NOT_AVAILABLE"))

            status, body = await command(
                self.app,
                scan_id,
                {
                    "command": "run",
                    "actionId": str(uuid4()),
                    "tool": "email_link_visit",
                    "linkId": str(self.analyzer.email_link_id),
                    "url": "https://attacker.example/",
                },
            )
            self.assertEqual((status, body["error"]["code"]), (400, "INVALID_REVIEW_COMMAND"))

            status, _, body = await submit(
                self.app, {**scan_payload(), "browserRequested": True}
            )
            self.assertEqual(status, 400)
            await command(self.app, scan_id, {"command": "finalize"})

    async def test_pending_review_cannot_exceed_hard_cap(self):
        self.make_app(agent_review_cap_seconds=1)
        async with self.app.router.lifespan_context(self.app):
            scan_id = await self.start_email_review()
            await wait_for_status(self.app, scan_id, "completed", attempts=600)
            report = completed_report(await events(self.app, scan_id))
            limitation = report["coverage"]["checks"][-1]
            self.assertEqual(limitation["status"], "skipped")
            self.assertIn("time limit", limitation["reason"])
            self.assertEqual(self.analyzer.last_request.emailBase64, "")

    async def test_follow_up_refused_without_enough_time_left(self):
        self.make_app(agent_review_cap_seconds=10)
        async with self.app.router.lifespan_context(self.app):
            scan_id = await self.start_email_review()
            action_id = str(uuid4())
            await command(
                self.app,
                scan_id,
                {
                    "command": "run",
                    "actionId": action_id,
                    "tool": "email_link_visit",
                    "linkId": str(self.analyzer.email_link_id),
                },
            )
            action = await wait_for_action(self.app, scan_id, action_id, "blocked")
            self.assertEqual(action["reasonCode"], "insufficient_time")
            self.assertEqual(self.analyzer.follow_up_requests, [])
            await command(self.app, scan_id, {"command": "finalize"})

    async def test_cancel_during_follow_up_stops_sandbox_and_returns_partial_report(self):
        self.make_app()
        self.analyzer.stall_follow_up = True
        async with self.app.router.lifespan_context(self.app):
            scan_id = await self.start_email_review()
            visit_id = str(uuid4())
            await command(
                self.app,
                scan_id,
                {
                    "command": "run",
                    "actionId": visit_id,
                    "tool": "email_link_visit",
                    "linkId": str(self.analyzer.email_link_id),
                },
            )
            await wait_for_action(self.app, scan_id, visit_id, "running")
            status, _, raw = await asgi_request(
                self.app, "POST", f"/v1/scans/{scan_id}/cancel", headers=request_headers()
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw)["status"], "cancelled")

            status, _, raw = await asgi_request(
                self.app, "GET", f"/v1/scans/{scan_id}/report", headers=AUTH
            )
            self.assertEqual(status, 200)
            partial = json.loads(raw)
            self.assertTrue(partial["partial"])
            self.assertIn("follow-up review", partial["partialReason"])
            self.assertEqual(partial["agentActions"][0]["status"], "failed")
            self.assertEqual(partial["agentActions"][0]["reasonCode"], "cancelled")
            self.assertEqual(self.analyzer.last_request.emailBase64, "")
            # Commands after cancellation are rejected.
            status, body = await command(self.app, scan_id, {"command": "finalize"})
            self.assertEqual((status, body["error"]["code"]), (409, "REVIEW_NOT_ACTIVE"))

    async def test_url_browser_follow_up_requires_eligible_baseline(self):
        self.make_app()
        async with self.app.router.lifespan_context(self.app):
            scan_id = uuid4()
            status, _, _ = await submit(
                self.app, {**scan_payload(scan_id), "agentReview": True}
            )
            self.assertEqual(status, 200)
            await wait_for_status(self.app, scan_id, "awaiting_review")
            _, view = await review(self.app, scan_id)
            self.assertTrue(view["browserEligible"])
            self.assertEqual(view["linkCandidates"], [])

            action_id = str(uuid4())
            status, _ = await command(
                self.app,
                scan_id,
                {"command": "run", "actionId": action_id, "tool": "url_browser_observation"},
            )
            self.assertEqual(status, 202)
            action = await wait_for_action(self.app, scan_id, action_id, "completed")
            self.assertTrue(self.analyzer.follow_up_requests[-1].browserRequested)
            # Only browser-sourced findings are attributed to this step.
            self.assertEqual([f["source"] for f in action["findings"]], ["browser"])

            status, body = await command(
                self.app,
                scan_id,
                {"command": "run", "actionId": str(uuid4()), "tool": "url_browser_observation"},
            )
            self.assertEqual((status, body["error"]["code"]), (409, "AGENT_ACTION_LIMIT"))
            await command(self.app, scan_id, {"command": "finalize"})
            await wait_for_status(self.app, scan_id, "completed")

    async def test_scans_without_review_consent_never_pause(self):
        self.make_app()
        async with self.app.router.lifespan_context(self.app):
            scan_id = uuid4()
            await submit(self.app, email_payload(scan_id))
            await wait_for_status(self.app, scan_id, "completed")
            report = completed_report(await events(self.app, scan_id))
            self.assertNotIn("agentActions", report)
            self.assertNotIn(
                "agent_follow_up", [check["name"] for check in report["coverage"]["checks"]]
            )
            status, body = await command(self.app, scan_id, {"command": "finalize"})
            self.assertEqual((status, body["error"]["code"]), (409, "REVIEW_NOT_ACTIVE"))


if __name__ == "__main__":
    unittest.main()
