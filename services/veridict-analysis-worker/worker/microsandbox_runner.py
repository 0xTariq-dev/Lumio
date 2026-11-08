from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from microsandbox import PullPolicy, Sandbox
from microsandbox.types import (
    Action,
    Destination,
    DestGroup,
    ExecEventType,
    Network,
    NetworkPolicy,
    Protocol,
    Rule,
    SecurityProfile,
)

from .manager import ProgressCallback
from .settings import WorkerSettings


_PINNED_IMAGE = re.compile(r"^.+@sha256:[0-9a-fA-F]{64}$")
_REPORT_OUTPUT_LIMIT = 256 * 1024
_ALLOWED_GUEST_STAGES = {
    "navigating",
    "collecting_evidence",
    "building_report",
}


def public_web_network() -> Network:
    """Allow DNS plus public HTTP(S), denying other destinations and ports."""
    public = Destination.group(DestGroup.PUBLIC)
    policy = NetworkPolicy(
        default_egress=Action.DENY,
        default_ingress=Action.DENY,
        rules=(
            *Rule.allow_dns(),
            Rule.allow(destination=public, protocol=Protocol.TCP, port=80),
            Rule.allow(destination=public, protocol=Protocol.TCP, port=443),
        ),
    )
    return Network(
        policy=policy,
        max_tcp_connections=48,
        max_udp_connections=16,
        strict=True,
    )


class MicrosandboxRunner:
    def __init__(self, settings: WorkerSettings):
        self.settings = settings

    async def prepare(self) -> None:
        image = self.settings.guest_image
        if not self.settings.is_configured or not image or not _PINNED_IMAGE.fullmatch(image):
            raise RuntimeError("Worker configuration is incomplete")
        if not Path("/dev/kvm").exists() or not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise RuntimeError("KVM is unavailable to the worker service")

        local_msb = Path(sys.executable).with_name("msb")
        msb = (
            str(local_msb)
            if local_msb.is_file() and os.access(local_msb, os.X_OK)
            else shutil.which("msb")
        )
        if not msb:
            raise RuntimeError("Microsandbox CLI is unavailable")

        process = await asyncio.create_subprocess_exec(
            msb,
            "pull",
            image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(300):
                exit_code = await process.wait()
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise RuntimeError("Guest image preparation timed out") from exc
        if exit_code != 0:
            raise RuntimeError("Guest image preparation failed")
        await self._remove_orphaned_sandboxes()

    async def _remove_orphaned_sandboxes(self) -> None:
        page = await Sandbox.list_with(
            labels={"app": "veridict-analysis-worker"},
            limit=100,
        )
        for handle in page.sandboxes:
            name = await handle.name()
            await Sandbox.remove(name)

    async def analyze(
        self, scan_id: str, url: str, progress: ProgressCallback
    ) -> dict[str, Any]:
        image = self.settings.guest_image
        if not image:
            raise RuntimeError("Guest image is not configured")

        job = json.dumps(
            {
                "scanId": scan_id,
                "url": url,
                "browserTimeoutSeconds": self.settings.browser_timeout_seconds,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        report: dict[str, Any] | None = None
        output_bytes = 0
        line_buffer = bytearray()

        async def read_guest_line(raw_line: bytes) -> None:
            nonlocal report
            if not raw_line:
                return
            try:
                message = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return
            if not isinstance(message, dict):
                return
            kind = message.get("kind")
            if kind == "progress":
                stage = message.get("stage")
                if stage in _ALLOWED_GUEST_STAGES:
                    await progress(stage)
            elif kind == "report" and isinstance(message.get("report"), dict):
                report = message["report"]
            elif kind == "error":
                raise RuntimeError("Guest analysis failed")

        async with asyncio.timeout(self.settings.sandbox_kill_seconds):
            async with await Sandbox.create(
                f"veridict-{scan_id}",
                image=image,
                cpus=self.settings.sandbox_cpus,
                max_cpus=self.settings.sandbox_cpus,
                memory=self.settings.sandbox_memory_mib,
                max_memory=self.settings.sandbox_memory_mib,
                max_duration=self.settings.sandbox_kill_seconds,
                security=SecurityProfile.RESTRICTED,
                user="veridict",
                ephemeral=True,
                labels={"app": "veridict-analysis-worker", "scan": scan_id},
                network=public_web_network(),
                pull_policy=PullPolicy.NEVER,
                replace=True,
            ) as sandbox:
                handle = await sandbox.exec_stream(
                    "/usr/local/bin/python",
                    ["/opt/veridict/guest/scan_url.py"],
                    user="veridict",
                    stdin=job,
                    timeout=self.settings.sandbox_kill_seconds,
                )
                async for event in handle:
                    if event.event_type == ExecEventType.FAILED:
                        raise RuntimeError("Guest process failed")
                    if event.event_type != ExecEventType.STDOUT or not event.data:
                        continue
                    output_bytes += len(event.data)
                    if output_bytes > _REPORT_OUTPUT_LIMIT:
                        await handle.kill()
                        raise RuntimeError("Guest output exceeded its limit")
                    line_buffer.extend(event.data)
                    if len(line_buffer) > _REPORT_OUTPUT_LIMIT:
                        await handle.kill()
                        raise RuntimeError("Guest output line exceeded its limit")
                    while True:
                        boundary = line_buffer.find(b"\n")
                        if boundary < 0:
                            break
                        line = bytes(line_buffer[:boundary])
                        del line_buffer[: boundary + 1]
                        await read_guest_line(line)

                if line_buffer:
                    await read_guest_line(bytes(line_buffer))
                exit_code, success = await handle.wait()
                if not success or exit_code != 0 or report is None:
                    raise RuntimeError("Guest process did not produce a report")
                return report
