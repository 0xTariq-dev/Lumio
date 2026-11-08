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

from .contracts import AnalysisRequest, EmailScanRequest
from .manager import EMAIL_PLAN_ACTIONS, ProgressCallback, URL_PLAN_ACTIONS
from .settings import WorkerSettings


_PINNED_IMAGE = re.compile(r"^.+@sha256:[0-9a-fA-F]{64}$")
_REPORT_OUTPUT_LIMIT = 256 * 1024
_ALLOWED_GUEST_STAGES = {
    "navigating",
    "collecting_evidence",
    "http_failed",
    "browser_inspection",
    "browser_completed",
    "browser_skipped",
    "browser_blocked",
    "browser_failed",
    "analyzing_email",
    "building_report",
}
_ALLOWED_REASON_CODES = {
    "no_browser_required",
    "redirect_blocked",
    "not_html",
    "static_body_limit",
    "http_unavailable",
    "http_fetch_failed",
    "browser_error",
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


def no_network() -> Network:
    policy = NetworkPolicy(
        default_egress=Action.DENY,
        default_ingress=Action.DENY,
        rules=(),
    )
    return Network(
        policy=policy,
        max_tcp_connections=1,
        max_udp_connections=1,
        strict=True,
    )


class MicrosandboxRunner:
    def __init__(self, settings: WorkerSettings):
        self.settings = settings

    def _msb_binary(self) -> str:
        local_msb = Path(sys.executable).with_name("msb")
        msb = (
            str(local_msb)
            if local_msb.is_file() and os.access(local_msb, os.X_OK)
            else shutil.which("msb")
        )
        if not msb:
            raise RuntimeError("Microsandbox CLI is unavailable")
        return msb

    async def _verify_local_image(self, msb: str | None = None) -> None:
        image = self.settings.guest_image
        local_image = self.settings.guest_image_local
        if not image or not local_image:
            raise RuntimeError("Local guest image configuration is incomplete")
        expected_digest = image.rsplit("@", 1)[1].lower()
        process = await asyncio.create_subprocess_exec(
            msb or self._msb_binary(),
            "image",
            "inspect",
            "--format",
            "json",
            local_image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(30):
                stdout, _ = await process.communicate()
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise RuntimeError("Local guest image verification timed out") from exc
        if process.returncode != 0:
            raise RuntimeError("Local guest image is unavailable")
        try:
            image_info = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Local guest image metadata is invalid") from exc
        if not isinstance(image_info, dict) or not isinstance(
            image_info.get("digest"), str
        ):
            raise RuntimeError("Local guest image metadata is invalid")
        if image_info["digest"].lower() != expected_digest:
            raise RuntimeError("Local guest image digest does not match configuration")

    async def prepare(self) -> None:
        image = self.settings.guest_image
        if not self.settings.is_configured or not image or not _PINNED_IMAGE.fullmatch(image):
            raise RuntimeError("Worker configuration is incomplete")
        if not Path("/dev/kvm").exists() or not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise RuntimeError("KVM is unavailable to the worker service")

        msb = self._msb_binary()
        if self.settings.guest_image_local:
            await self._verify_local_image(msb)
        else:
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
        self,
        scan_id: str,
        request: AnalysisRequest,
        task_plan: list[str],
        progress: ProgressCallback,
    ) -> dict[str, Any]:
        image = self.settings.guest_image_local or self.settings.guest_image
        if not image:
            raise RuntimeError("Guest image is not configured")
        if self.settings.guest_image_local:
            await self._verify_local_image()
        is_email = isinstance(request, EmailScanRequest)
        expected_plan = EMAIL_PLAN_ACTIONS if is_email else URL_PLAN_ACTIONS
        if tuple(task_plan) != expected_plan:
            raise ValueError("Unsupported analysis task plan")

        job_data: dict[str, Any] = {
            "scanId": scan_id,
            "type": "email" if is_email else "url",
            "taskPlan": task_plan,
        }
        script_path = "/opt/veridict/guest/scan_url.py"
        if is_email:
            job_data["emailBase64"] = request.emailBase64
            script_path = "/opt/veridict/guest/scan_email.py"
        else:
            job_data["url"] = request.url
            job_data["browserTimeoutSeconds"] = self.settings.browser_timeout_seconds
        job = json.dumps(
            job_data,
            separators=(",", ":"),
        ).encode("utf-8")
        report: dict[str, Any] | None = None
        exit_code: int | None = None
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
                    reason_code = message.get("reasonCode")
                    if reason_code not in _ALLOWED_REASON_CODES:
                        reason_code = None
                    await progress(stage, reason_code)
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
                network=no_network() if is_email else public_web_network(),
                pull_policy=PullPolicy.NEVER,
                replace=True,
            ) as sandbox:
                handle = await sandbox.exec_stream(
                    "/usr/local/bin/python",
                    [script_path],
                    user="veridict",
                    stdin=job,
                    timeout=self.settings.sandbox_kill_seconds,
                )
                async for event in handle:
                    if event.event_type == ExecEventType.FAILED:
                        raise RuntimeError("Guest process failed")
                    if event.event_type == ExecEventType.EXITED:
                        exit_code = event.code
                        continue
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
                if exit_code != 0 or report is None:
                    raise RuntimeError("Guest process did not produce a report")
                return report
