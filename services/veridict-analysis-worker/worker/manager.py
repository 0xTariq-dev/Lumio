from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Protocol
from uuid import UUID

from .contracts import ProgressPayload, ScanReport, ScanSnapshot, URLScanRequest, to_jsonable
from .settings import WorkerSettings


ProgressCallback = Callable[[str, str | None], Awaitable[None]]
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
PROGRESS_MESSAGES = {
    "queued": ("queued", "Waiting for an isolated scan slot.", 0),
    "starting_sandbox": ("starting_sandbox", "Starting a temporary analysis sandbox.", 1),
    "navigating": ("navigating", "Inspecting the public page.", 2),
    "collecting_evidence": ("collecting_evidence", "Collecting technical evidence.", 3),
    "http_failed": ("http_failed", "HTTP inspection did not complete; coverage may be reduced.", 3),
    "browser_inspection": ("browser_inspection", "Checking the page in a browser based on observed signals.", 4),
    "browser_completed": ("browser_completed", "Browser inspection completed.", 4),
    "browser_skipped": ("browser_skipped", "Browser inspection was skipped based on observed signals.", 4),
    "browser_blocked": ("browser_blocked", "Browser inspection was blocked by the scan policy.", 4),
    "browser_failed": ("browser_failed", "Browser inspection did not complete; coverage may be reduced.", 4),
    "building_report": ("building_report", "Preparing the evidence report.", 4),
    "completed": ("completed", "The execution plan completed and the report is ready.", 6),
    "failed": ("failed", "Analysis ended before all planned steps completed.", 0),
}
PLAN_TEMPLATE = (
    {"id": "consent_target", "status": "completed", "reasonCode": "consent_checked"},
    {"id": "sandbox", "status": "pending"},
    {"id": "http", "status": "pending"},
    {"id": "static", "status": "pending"},
    {"id": "browser", "status": "pending"},
    {"id": "report", "status": "pending"},
)
URL_PLAN_ACTIONS = ("http", "static", "browser", "report")
RESOLVED_PLAN_STATUSES = {"completed", "skipped", "failed", "blocked"}


class URLAnalyzer(Protocol):
    async def prepare(self) -> None: ...

    async def analyze(
        self,
        scan_id: str,
        url: str,
        task_plan: list[str],
        progress: ProgressCallback,
    ) -> dict[str, Any]: ...


@dataclass
class ScanEvent:
    event_id: int
    name: str
    data: dict[str, Any]


@dataclass
class ScanRecord:
    scan_id: str
    status: str
    created_at: datetime
    expires_at: datetime
    latest_progress: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    events: list[ScanEvent] = field(default_factory=list)
    condition: asyncio.Condition = field(default_factory=asyncio.Condition, repr=False)


class ScanManager:
    def __init__(
        self,
        settings: WorkerSettings,
        analyzer: URLAnalyzer,
        logger: logging.Logger,
    ) -> None:
        self.settings = settings
        self.analyzer = analyzer
        self.logger = logger
        self._queue: asyncio.Queue[tuple[str, URLScanRequest]] = asyncio.Queue(
            maxsize=settings.queue_limit
        )
        self._records: dict[str, ScanRecord] = {}
        self._accept_lock = asyncio.Lock()
        self._worker_task: asyncio.Task[None] | None = None
        self._active_scan_id: str | None = None
        self.ready = False

    async def start(self) -> None:
        if not self.settings.is_configured:
            return
        try:
            await self.analyzer.prepare()
        except Exception as exc:
            self.logger.error(
                "Worker initialization failed",
                extra={"operation": "startup", "error_type": type(exc).__name__},
            )
            return
        self.ready = True
        self._worker_task = asyncio.create_task(self._serve(), name="scan-worker")

    async def stop(self) -> None:
        self.ready = False
        if self._worker_task is not None:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

    @property
    def active_count(self) -> int:
        return 1 if self._active_scan_id is not None else 0

    @property
    def queued_count(self) -> int:
        return self._queue.qsize()

    async def enqueue(
        self, request: URLScanRequest
    ) -> tuple[str | None, str | None]:
        scan_id = str(request.scanId)
        async with self._accept_lock:
            self._prune_expired()
            existing = self._records.get(scan_id)
            if existing is not None:
                return ("queued" if existing.status == "queued" else "running"), None
            if not self.ready:
                return None, "unavailable"
            if self._queue.full():
                return None, "full"

            now = datetime.now(timezone.utc)
            record = ScanRecord(
                scan_id=scan_id,
                status="queued",
                created_at=now,
                expires_at=now + timedelta(seconds=self.settings.report_ttl_seconds),
            )
            self._records[scan_id] = record
            await self._publish_progress(record, "queued")
            self._queue.put_nowait((scan_id, request))
            return record.status, None

    def snapshot(self, scan_id: str) -> dict[str, Any] | None:
        self._prune_expired()
        record = self._records.get(scan_id)
        if record is None:
            return None
        snapshot = ScanSnapshot(
            scanId=UUID(record.scan_id),
            type="url",
            status=record.status,  # type: ignore[arg-type]
            createdAt=record.created_at,
            expiresAt=record.expires_at,
            latestProgress=(
                ProgressPayload.model_validate(record.latest_progress)
                if record.latest_progress
                else None
            ),
        )
        return to_jsonable(snapshot)

    def get_record(self, scan_id: str) -> ScanRecord | None:
        self._prune_expired()
        return self._records.get(scan_id)

    def _prune_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [
            scan_id
            for scan_id, record in self._records.items()
            if record.status in TERMINAL_STATUSES and record.expires_at <= now
        ]
        for scan_id in expired:
            self._records.pop(scan_id, None)

    async def _publish_progress(
        self,
        record: ScanRecord,
        stage: str,
        *,
        reason_code: str | None = None,
        status: str | None = None,
    ) -> None:
        progress_stage, message, _ = PROGRESS_MESSAGES[stage]
        plan = self._plan_for_stage(
            stage,
            record.latest_progress,
            reason_code=reason_code,
        )
        completed_steps = sum(
            step["status"] in RESOLVED_PLAN_STATUSES for step in plan
        )
        progress = ProgressPayload(
            stage=progress_stage,  # type: ignore[arg-type]
            message=message,
            completedSteps=completed_steps,
            totalSteps=len(plan),
            plan=plan,
        )
        record.latest_progress = to_jsonable(progress)
        await self._publish(
            record, "progress", record.latest_progress, status=status
        )

    @staticmethod
    def _plan_for_stage(
        stage: str,
        previous_progress: dict[str, Any] | None,
        *,
        reason_code: str | None,
    ) -> list[dict[str, Any]]:
        plan = [dict(step) for step in PLAN_TEMPLATE]
        steps = {step["id"]: step for step in plan}

        def set_step(step_id: str, state: str, reason: str | None = None) -> None:
            step = steps[step_id]
            step["status"] = state
            step.pop("reasonCode", None)
            if reason:
                step["reasonCode"] = reason

        if stage == "failed":
            previous_plan = (
                previous_progress.get("plan")
                if isinstance(previous_progress, dict)
                else None
            )
            if isinstance(previous_plan, list) and len(previous_plan) == len(plan):
                plan = [dict(step) for step in previous_plan]
                steps = {step["id"]: step for step in plan}
            running = [step for step in plan if step["status"] == "running"]
            if running:
                running[0]["status"] = "failed"
                running[0]["reasonCode"] = "analysis_failed"
            else:
                set_step("report", "failed", "analysis_failed")
            for step in plan:
                if step["status"] == "pending":
                    step["status"] = "skipped"
                    step["reasonCode"] = "earlier_step_failed"
            return plan

        if stage == "starting_sandbox":
            set_step("sandbox", "running")
        elif stage == "navigating":
            set_step("sandbox", "completed")
            set_step("http", "running")
        elif stage == "http_failed":
            set_step("http", "failed", reason_code or "http_fetch_failed")
            set_step("static", "skipped", "http_unavailable")
            set_step("browser", "skipped", "http_unavailable")
        elif stage == "collecting_evidence":
            set_step("sandbox", "completed")
            set_step("http", "completed")
            set_step("static", "running")
        elif stage == "browser_inspection":
            set_step("sandbox", "completed")
            set_step("http", "completed")
            set_step("static", "completed")
            set_step("browser", "running")
        elif stage == "browser_completed":
            set_step("sandbox", "completed")
            set_step("http", "completed")
            set_step("static", "completed")
            set_step("browser", "completed")
        elif stage == "browser_skipped":
            set_step("sandbox", "completed")
            if steps["http"]["status"] not in {"failed", "skipped"}:
                set_step("http", "completed")
            if steps["static"]["status"] not in {"failed", "skipped"}:
                set_step("static", "completed")
            set_step("browser", "skipped", reason_code or "no_browser_required")
        elif stage == "browser_blocked":
            set_step("sandbox", "completed")
            set_step("http", "completed")
            set_step("static", "completed")
            set_step("browser", "blocked", reason_code or "redirect_blocked")
        elif stage == "browser_failed":
            set_step("sandbox", "completed")
            set_step("http", "completed")
            set_step("static", "completed")
            set_step("browser", "failed", reason_code or "browser_error")
        elif stage == "building_report":
            for step_id in ("sandbox", "http", "static"):
                if steps[step_id]["status"] in {"pending", "running"}:
                    set_step(step_id, "completed")
            if steps["browser"]["status"] in {"pending", "running"}:
                set_step("browser", "skipped", "no_browser_required")
            set_step("report", "running")
        elif stage == "completed":
            if steps["browser"]["status"] == "pending":
                set_step("browser", "skipped", "no_browser_required")
            set_step("report", "completed")
        return plan

    async def _publish(
        self,
        record: ScanRecord,
        name: str,
        data: dict[str, Any],
        *,
        status: str | None = None,
    ) -> None:
        async with record.condition:
            if status is not None:
                record.status = status
            record.events.append(
                ScanEvent(
                    event_id=len(record.events) + 1,
                    name=name,
                    data=data,
                )
            )
            record.condition.notify_all()

    async def _serve(self) -> None:
        while True:
            scan_id, request = await self._queue.get()
            record = self._records.get(scan_id)
            if record is None:
                self._queue.task_done()
                continue
            if record.expires_at <= datetime.now(timezone.utc):
                await self._publish(
                    record,
                    "failed",
                    {
                        "code": "ANALYSIS_FAILED",
                        "message": "This analysis expired before a worker was available.",
                        "retryable": True,
                    },
                    status="failed",
                )
                self._queue.task_done()
                self._prune_expired()
                continue
            self._active_scan_id = scan_id

            async def progress(
                stage: str, reason_code: str | None = None
            ) -> None:
                await self._publish_progress(
                    record, stage, reason_code=reason_code
                )

            try:
                await self._publish_progress(
                    record, "starting_sandbox", status="running"
                )
                report_data = await self.analyzer.analyze(
                    scan_id,
                    request.url,
                    list(URL_PLAN_ACTIONS),
                    progress,
                )
                await self._publish_progress(record, "completed")
                report_data = {
                    **report_data,
                    "executionPlan": record.latest_progress["plan"],
                }
                report = ScanReport.model_validate(report_data)
                if str(report.scanId) != scan_id or report.type != "url":
                    raise ValueError("Worker report identity mismatch")
                record.report = to_jsonable(report)
                await self._publish(
                    record, "completed", record.report, status="completed"
                )
            except asyncio.CancelledError:
                await self._publish_progress(
                    record, "failed", status="cancelled"
                )
                await self._publish(
                    record,
                    "failed",
                    {
                        "code": "ANALYSIS_FAILED",
                        "message": "This analysis could not be completed. No report is available.",
                        "retryable": True,
                    },
                    status="cancelled",
                )
                raise
            except Exception as exc:
                self.logger.error(
                    "URL analysis failed",
                    extra={
                        "scan_id": scan_id,
                        "operation": "analyze_url",
                        "error_type": type(exc).__name__,
                    },
                )
                await self._publish_progress(record, "failed", status="failed")
                await self._publish(
                    record,
                    "failed",
                    {
                        "code": "ANALYSIS_FAILED",
                        "message": "This analysis could not be completed. No report is available.",
                        "retryable": True,
                    },
                    status="failed",
                )
            finally:
                self._active_scan_id = None
                self._queue.task_done()
                self._prune_expired()
