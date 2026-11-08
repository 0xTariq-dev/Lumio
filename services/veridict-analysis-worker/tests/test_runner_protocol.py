import json
import unittest
from unittest.mock import AsyncMock, patch

from microsandbox.types import ExecEventType, PullPolicy

from worker.microsandbox_runner import MicrosandboxRunner
from worker.settings import WorkerSettings


SCAN_ID = "f3b3ae2d-9f71-4ae1-9060-384d71281da6"
IMAGE = "registry.example/guest@sha256:" + "a" * 64
REPORT = {
    "scanId": SCAN_ID,
    "type": "url",
    "riskBand": "low",
    "completedAt": "2026-11-06T10:00:00+00:00",
    "ruleSetVersion": "test-rules",
    "findings": [],
    "coverage": {
        "sufficient": True,
        "checks": [
            {"name": "http_response", "status": "completed"},
            {"name": "redirect_chain", "status": "completed"},
            {"name": "static_html", "status": "completed"},
        ],
    },
}


class FakeExecHandle:
    def __init__(self, output):
        self.output = output

    def __aiter__(self):
        async def events():
            for item in self.output:
                yield item

        return events()

    async def wait(self):
        return 0, True

    async def kill(self):
        return None


class FakeSandbox:
    def __init__(self, handle):
        self.handle = handle
        self.command = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def exec_stream(self, command, args, **kwargs):
        self.command = (command, args, kwargs)
        return self.handle


class RunnerProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_runner_streams_progress_and_reads_bounded_report_protocol(self):
        encoded = (
            json.dumps({"kind": "progress", "stage": "navigating"}).encode()
            + b"\n"
            + json.dumps({"kind": "progress", "stage": "collecting_evidence"}).encode()
            + b"\n"
            + json.dumps(
                {
                    "kind": "progress",
                    "stage": "browser_skipped",
                    "reasonCode": "no_browser_required",
                }
            ).encode()
            + b"\n"
            + json.dumps({"kind": "report", "report": REPORT}).encode()
            + b"\n"
        )
        handle = FakeExecHandle(
            [
                type(
                    "Event",
                    (),
                    {"event_type": ExecEventType.STDOUT, "data": encoded},
                )()
            ]
        )
        sandbox = FakeSandbox(handle)
        create = AsyncMock(return_value=sandbox)
        settings = WorkerSettings(token="x" * 40, guest_image=IMAGE)
        progress_events = []

        async def progress(stage, reason_code=None):
            progress_events.append((stage, reason_code))

        with patch("worker.microsandbox_runner.Sandbox.create", create):
            report = await MicrosandboxRunner(settings).analyze(
                SCAN_ID,
                "https://example.com/path?private=value",
                ["http", "static", "browser", "report"],
                progress,
            )

        self.assertEqual(report, REPORT)
        self.assertEqual(
            progress_events,
            [
                ("navigating", None),
                ("collecting_evidence", None),
                ("browser_skipped", "no_browser_required"),
            ],
        )
        command, args, kwargs = sandbox.command
        job = json.loads(kwargs["stdin"])
        self.assertEqual(job["url"], "https://example.com/path?private=value")
        self.assertEqual(job["taskPlan"], ["http", "static", "browser", "report"])
        self.assertEqual(command, "/usr/local/bin/python")
        self.assertEqual(args, ["/opt/veridict/guest/scan_url.py"])
        self.assertEqual(kwargs["user"], "veridict")
        self.assertEqual(kwargs["timeout"], 180)

        options = create.await_args.kwargs
        self.assertEqual(options["image"], IMAGE)
        self.assertEqual(options["pull_policy"], PullPolicy.NEVER)
        self.assertEqual(options["cpus"], 1)
        self.assertEqual(options["max_cpus"], 1)
        self.assertEqual(options["memory"], 2048)
        self.assertEqual(options["max_memory"], 2048)
        self.assertEqual(options["max_duration"], 180)
        self.assertTrue(options["ephemeral"])
        self.assertEqual(
            options["labels"]["app"], "veridict-analysis-worker"
        )


if __name__ == "__main__":
    unittest.main()
