import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from guest.rea_observer import (
    _inspection_summary,
    _origin_url,
    _run_rea_cli,
    observe_browser,
)
from guest.scan_url import _build_report


class _FakeStream:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    async def read(self, _size):
        return next(self.chunks, b"")


class _FakeProcess:
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = None
        self.killed = False

    def kill(self):
        self.killed = True
        self.returncode = -9

    async def wait(self):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class ReaObserverTests(unittest.IsolatedAsyncioTestCase):
    def test_origin_is_public_and_drops_path_query_and_fragment(self):
        self.assertEqual(
            _origin_url("https://example.com/path?token=private#fragment"),
            "https://example.com",
        )
        self.assertEqual(
            _origin_url("https://example.com:443/path"),
            "https://example.com",
        )

    def test_inspection_summary_keeps_only_allowlisted_counts(self):
        summary = _inspection_summary(
            {
                "normalized_result": {
                    "target": {
                        "url": "https://example.com/path?token=private",
                        "title": "private page title",
                    },
                    "completeness": {"status": "complete_within_window"},
                    "dom": {"total_nodes": 42},
                    "accessibility": {"total_nodes": 12},
                    "scripts": {"total": 4, "items": [{"source": "private.js"}]},
                    "resources": {"total": 7},
                    "network": {"requests": [{"url": "https://example.com/?token=private"}]},
                    "console": {"events": [{"text": "private console message"}]},
                }
            }
        )

        self.assertEqual(
            summary,
            {
                "status": "completed",
                "completeness": "complete_within_window",
                "counts": {
                    "domNodes": 42,
                    "accessibilityNodes": 12,
                    "scripts": 4,
                    "resources": 7,
                    "networkRequests": 1,
                    "consoleEvents": 1,
                },
            },
        )
        serialized = str(summary)
        for private_value in ("token=private", "private page title", "private.js", "private console message"):
            self.assertNotIn(private_value, serialized)

    async def test_observation_uses_same_origin_target_and_discards_raw_capture(self):
        target_result = {
            "normalized_result": {
                "targets": [
                    {
                        "target_id": "target-123",
                        "type": "page",
                        "origin": "https://example.com",
                        "url": "https://example.com/path?token=private",
                        "title": "private page title",
                    }
                ]
            }
        }
        inspection_result = {
            "normalized_result": {
                "target": {"url": "https://example.com/path?token=private"},
                "completeness": {"status": "policy_filtered"},
                "dom": {"total_nodes": 20},
                "scripts": {"total": 3},
            }
        }
        with patch(
            "guest.rea_observer._run_rea_cli",
            new=AsyncMock(side_effect=[(target_result, None), (inspection_result, None)]),
        ) as run_cli:
            result = await observe_browser(
                "https://example.com/path?token=private#fragment"
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["completeness"], "policy_filtered")
        self.assertEqual(result["counts"]["domNodes"], 20)
        self.assertNotIn("token=private", str(result))
        self.assertNotIn("private page title", str(result))
        self.assertEqual(run_cli.await_count, 2)
        self.assertIn("https://example.com", run_cli.await_args_list[0].args[0])

    async def test_invalid_or_ambiguous_targets_fail_closed(self):
        targets = {
            "normalized_result": {
                "targets": [
                    {
                        "target_id": "target-1",
                        "type": "page",
                        "origin": "https://example.com",
                    },
                    {
                        "target_id": "target-2",
                        "type": "page",
                        "origin": "https://example.com",
                    },
                ]
            }
        }
        with patch(
            "guest.rea_observer._run_rea_cli",
            new=AsyncMock(return_value=(targets, None)),
        ) as run_cli:
            result = await observe_browser("https://example.com/")

        self.assertEqual(result, {"status": "unavailable", "reasonCode": "rea_target_not_unique"})
        self.assertEqual(run_cli.await_count, 1)

    async def test_cli_output_limit_kills_the_child_process(self):
        process = _FakeProcess(_FakeStream([b"x" * 9]))
        with (
            patch("guest.rea_observer.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)),
            patch("guest.rea_observer.REA_STDOUT_LIMIT_BYTES", 8),
        ):
            result, error = await _run_rea_cli(["list-browser-targets"])

        self.assertIsNone(result)
        self.assertEqual(error, "rea_output_limit")
        self.assertTrue(process.killed)

    async def test_cli_timeout_kills_the_child_process(self):
        class BlockingStream:
            async def read(self, _size):
                await asyncio.Future()

        process = _FakeProcess(BlockingStream())
        with (
            patch("guest.rea_observer.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)),
            patch("guest.rea_observer.REA_PROCESS_TIMEOUT_SECONDS", 0.01),
        ):
            result, error = await _run_rea_cli(["inspect-web-page"])

        self.assertIsNone(result)
        self.assertEqual(error, "rea_timeout")
        self.assertTrue(process.killed)

    async def test_cli_cancellation_kills_the_child_process(self):
        class BlockingStream:
            def __init__(self):
                self.started = asyncio.Event()

            async def read(self, _size):
                self.started.set()
                await asyncio.Future()

        stream = BlockingStream()
        process = _FakeProcess(stream)
        with patch(
            "guest.rea_observer.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=process),
        ):
            task = asyncio.create_task(_run_rea_cli(["inspect-web-page"]))
            await stream.started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertTrue(process.killed)

    def test_report_adds_safe_rea_coverage_without_changing_risk(self):
        url = "https://example.com/path?token=private#fragment"
        report = _build_report(
            "f3b3ae2d-9f71-4ae1-9060-384d71281da6",
            url,
            {
                "status": 200,
                "isHtml": True,
                "oversized": False,
                "scriptCount": 1,
                "scriptHosts": [],
                "forms": [],
            },
            [url],
            False,
            {
                "finalHost": "example.com",
                "finalScheme": "https",
                "forms": [],
                "blockedRequestCount": 0,
                "skippedResourceCount": 0,
                "strippedBrowserQuery": False,
                "reaObservation": {
                    "status": "completed",
                    "completeness": "complete_within_window",
                    "counts": {"domNodes": 20, "scripts": 3},
                },
            },
            False,
            False,
            query_redacted_for_browser=False,
            static_final_url=url,
        )

        rea_check = next(
            check
            for check in report["coverage"]["checks"]
            if check["name"] == "rea_passive_observation"
        )
        self.assertEqual(rea_check["status"], "completed")
        self.assertIn("DOM nodes: 20", rea_check["reason"])
        self.assertEqual(report["riskBand"], "low")
        self.assertNotIn("token=private", str(report))
