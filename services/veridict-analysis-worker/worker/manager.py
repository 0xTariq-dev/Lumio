from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Protocol
from uuid import UUID

from .contracts import ProgressPayload, ScanReport, ScanSnapshot, URLScanRequest, to_jsonable
from .settings import WorkerSettings


ProgressCallback = Callable[[str], Awaitable[None]]
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
PROGRESS_MESSAGES = {
    "queued": ("queued", "Waiting for an isolated scan slot.", 0),
    "starting_sandbox": ("starting_sandbox", "Starting a temporary analysis sandbox.", 1),
    "navigating": ("navigating", "Inspecting the public page.", 2),
    "collecting_evidence": ("collecting_evidence", "Collecting technical evidence.", 3),
    "building_report": ("building_report", "Preparing the evidence report.", 4),
}


class URLAnalyzer(Protocol):
    async def prepare(self) -> None: ...

    async def analyze(
        self, scan_id: str, url: str, progress: ProgressCallback
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
        self, record: ScanRecord, stage: str, *, status: str | None = None
    ) -> None:
        progress_stage, message, completed_steps = PROGRESS_MESSAGES[stage]
        progress = ProgressPayload(
            stage=progress_stage,  # type: ignore[arg-type]
            message=message,
            completedSteps=completed_steps,
            totalSteps=4,
        )
        record.latest_progress = to_jsonable(progress)
        await self._publish(
            record, "progress", record.latest_progress, status=status
        )

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

            async def progress(stage: str) -> None:
                await self._publish_progress(record, stage)

            try:
                await self._publish_progress(
                    record, "starting_sandbox", status="running"
                )
                report_data = await self.analyzer.analyze(
                    scan_id, request.url, progress
                )
                report = ScanReport.model_validate(report_data)
                if str(report.scanId) != scan_id or report.type != "url":
                    raise ValueError("Worker report identity mismatch")
                record.report = to_jsonable(report)
                await self._publish(
                    record, "completed", record.report, status="completed"
                )
            except asyncio.CancelledError:
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
