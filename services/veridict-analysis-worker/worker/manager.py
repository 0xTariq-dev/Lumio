from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Protocol
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import ValidationError

from shared.url_policy import URLPolicyError, normalize_public_http_url

from .contracts import (
    MAX_AGENT_ACTIONS,
    AgentActionResult,
    AgentFinalizeCommand,
    AgentReviewCommand,
    AgentRunCommand,
    AgentSkipCommand,
    AnalysisRequest,
    EmailLinkScanRequest,
    EmailScanRequest,
    Finding,
    ProgressPayload,
    ScanReport,
    ScanRequest,
    ScanSnapshot,
    URLScanRequest,
    to_jsonable,
)
from .link_context import build_link_context
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
    "analyzing_email": ("analyzing_email", "Extracting email indicators and links.", 3),
    "building_report": ("building_report", "Preparing the evidence report.", 4),
    "awaiting_review": ("awaiting_review", "Waiting for your decision on a follow-up step.", 5),
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
EMAIL_PLAN_TEMPLATE = (
    {"id": "consent_target", "status": "completed", "reasonCode": "consent_checked"},
    {"id": "sandbox", "status": "pending"},
    {"id": "email_parse", "status": "pending"},
    {"id": "report", "status": "pending"},
)
URL_PLAN_ACTIONS = ("http", "static", "browser", "report")
EMAIL_PLAN_ACTIONS = ("email_headers", "email_body", "email_links", "report")
RESOLVED_PLAN_STATUSES = {"completed", "skipped", "failed", "blocked"}
EMAIL_AGENT_TOOLS = frozenset({"link_metadata_share", "email_link_visit"})
URL_AGENT_TOOLS = frozenset({"url_browser_observation"})
SANDBOX_AGENT_TOOLS = frozenset({"email_link_visit", "url_browser_observation"})
# A follow-up sandbox run is refused when less than this much of the hard cap
# remains, so an approved action never starts without time to finish.
MIN_ACTION_SECONDS = 20
RISK_BANDS = {"low", "moderate", "high", "critical", "inconclusive"}


class URLAnalyzer(Protocol):
    async def prepare(self) -> None: ...

    async def analyze(
        self,
        scan_id: str,
        request: AnalysisRequest,
        task_plan: list[str],
        progress: ProgressCallback,
    ) -> dict[str, Any]: ...


@dataclass
class ScanEvent:
    event_id: int
    name: str
    data: dict[str, Any]


@dataclass
class ReviewSession:
    """Volatile state for a scan paused before its report is published.

    Lives only in worker memory while the scan holds its worker slot and is
    discarded when the review finalizes, times out, or is cancelled.
    """

    draft_report: dict[str, Any] = field(repr=False)
    deadline: float
    deadline_at: datetime
    target_url: str | None = field(default=None, repr=False)
    commands: asyncio.Queue[AgentReviewCommand] = field(
        default_factory=asyncio.Queue, repr=False
    )
    used_action_ids: set[str] = field(default_factory=set)
    actions: list[dict[str, Any]] = field(default_factory=list)
    link_shared: bool = False
    running: bool = False
    pending_commands: int = 0


@dataclass
class ScanRecord:
    scan_id: str
    scan_type: str
    status: str
    created_at: datetime
    expires_at: datetime
    latest_progress: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    private_links: dict[str, str] = field(default_factory=dict, repr=False)
    events: list[ScanEvent] = field(default_factory=list)
    condition: asyncio.Condition = field(default_factory=asyncio.Condition, repr=False)
    review: ReviewSession | None = field(default=None, repr=False)


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
        self._queue: asyncio.Queue[tuple[str, AnalysisRequest]] = asyncio.Queue(
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

    async def cancel(self, scan_id: str) -> tuple[bool, str]:
        """Cancel one queued or running scan without stopping the worker service."""
        async with self._accept_lock:
            self._prune_expired()
            record = self._records.get(scan_id)
            if record is None:
                return False, "not_found"
            if record.status in TERMINAL_STATUSES:
                return False, record.status

            if record.status == "queued":
                retained: list[tuple[str, AnalysisRequest]] = []
                removed_request: AnalysisRequest | None = None
                while True:
                    try:
                        queued_scan_id, request = self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    self._queue.task_done()
                    if queued_scan_id == scan_id:
                        removed_request = request
                    else:
                        retained.append((queued_scan_id, request))
                for item in retained:
                    self._queue.put_nowait(item)
                if removed_request is not None:
                    self._clear_email_request(removed_request)
                    await self._publish_cancellation(record)
                    return True, "cancelled"

            if self._active_scan_id != scan_id or self._worker_task is None:
                return False, record.status

            worker_task = self._worker_task
            worker_task.cancel()
            try:
                await worker_task
            except asyncio.CancelledError:
                pass
            if self.ready:
                self._worker_task = asyncio.create_task(
                    self._serve(), name="scan-worker"
                )
            return True, "cancelled"

    @staticmethod
    def _clear_email_request(request: AnalysisRequest) -> None:
        if isinstance(request, EmailScanRequest):
            request.emailBase64 = ""

    async def _publish_cancellation(self, record: ScanRecord) -> None:
        record.private_links.clear()
        await self._publish_progress(record, "failed", status="cancelled")
        await self._publish(
            record,
            "cancelled",
            {
                "code": "SCAN_CANCELLED",
                "message": "This scan was cancelled. Any completed batch results remain available.",
                "retryable": True,
            },
            status="cancelled",
        )

    @property
    def active_count(self) -> int:
        return 1 if self._active_scan_id is not None else 0

    @property
    def queued_count(self) -> int:
        return self._queue.qsize()

    async def enqueue(
        self, request: ScanRequest
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

            scan_type = request.type
            analysis_request: AnalysisRequest
            if isinstance(request, EmailLinkScanRequest):
                source = self._records.get(str(request.originalScanId))
                if (
                    source is None
                    or source.status != "completed"
                    or source.scan_type != "email"
                ):
                    return None, "link_unavailable"
                target = source.private_links.get(str(request.linkId))
                if not target:
                    return None, "link_unavailable"
                try:
                    target = normalize_public_http_url(target)
                except URLPolicyError:
                    return None, "link_unavailable"
                analysis_request = URLScanRequest(
                    scanId=request.scanId,
                    type="url",
                    url=target,
                    consent=True,
                )
            else:
                analysis_request = request

            now = datetime.now(timezone.utc)
            record = ScanRecord(
                scan_id=scan_id,
                scan_type=scan_type,
                status="queued",
                created_at=now,
                expires_at=now + timedelta(seconds=self.settings.report_ttl_seconds),
            )
            self._records[scan_id] = record
            await self._publish_progress(record, "queued")
            self._queue.put_nowait((scan_id, analysis_request))
            return record.status, None

    def snapshot(self, scan_id: str) -> dict[str, Any] | None:
        self._prune_expired()
        record = self._records.get(scan_id)
        if record is None:
            return None
        snapshot = ScanSnapshot(
            scanId=UUID(record.scan_id),
            type=record.scan_type,  # type: ignore[arg-type]
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

    def report(self, scan_id: str) -> dict[str, Any] | None:
        self._prune_expired()
        record = self._records.get(scan_id)
        if record is None or record.status not in {"completed", "cancelled"}:
            return None
        return record.report

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
        report_data: dict[str, Any] | None = None,
    ) -> None:
        progress_stage, message, _ = PROGRESS_MESSAGES[stage]
        plan = self._plan_for_stage(
            stage,
            record.latest_progress,
            reason_code=reason_code,
            report_data=report_data,
            scan_type=record.scan_type,
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
        report_data: dict[str, Any] | None = None,
        scan_type: str = "url",
    ) -> list[dict[str, Any]]:
        if stage == "awaiting_review":
            # Evidence steps are final; only report publication is outstanding.
            plan = ScanManager._plan_for_stage(
                "completed",
                None,
                reason_code=None,
                report_data=report_data,
                scan_type=scan_type,
            )
            for step in plan:
                if step["id"] == "report":
                    step["status"] = "running"
                    step.pop("reasonCode", None)
            return plan

        template = EMAIL_PLAN_TEMPLATE if scan_type == "email" else PLAN_TEMPLATE
        plan = [dict(step) for step in template]
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

        if scan_type == "email":
            if stage == "starting_sandbox":
                set_step("sandbox", "running")
            elif stage == "analyzing_email":
                set_step("sandbox", "completed")
                set_step("email_parse", "running")
            elif stage == "building_report":
                set_step("sandbox", "completed")
                set_step("email_parse", "completed")
                set_step("report", "running")
            elif stage == "completed":
                set_step("sandbox", "completed")
                set_step("email_parse", "completed")
                set_step("report", "completed")
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
        elif stage == "analyzing_email":
            set_step("sandbox", "completed")
            set_step("http", "running")
        elif stage == "building_report":
            for step_id in ("sandbox", "http", "static"):
                if steps[step_id]["status"] in {"pending", "running"}:
                    set_step(step_id, "completed")
            if steps["browser"]["status"] in {"pending", "running"}:
                set_step("browser", "skipped", "no_browser_required")
            set_step("report", "running")
        elif stage == "completed":
            if report_data:
                report_type = report_data.get("type")
                coverage = report_data.get("coverage")
                checks = {
                    check.get("name"): check
                    for check in coverage.get("checks", [])
                    if isinstance(check, dict) and isinstance(check.get("name"), str)
                } if isinstance(coverage, dict) else {}

                def apply_check(
                    step_id: str,
                    check_name: str,
                    fallback_status: str,
                    fallback_reason: str | None = None,
                ) -> str:
                    check = checks.get(check_name)
                    status_value = check.get("status") if isinstance(check, dict) else None
                    if status_value not in {"completed", "skipped", "failed", "blocked"}:
                        status_value = fallback_status
                    mapped_reason = None
                    if status_value == "failed":
                        mapped_reason = fallback_reason
                        if mapped_reason is None:
                            mapped_reason = (
                                "http_fetch_failed" if step_id == "http"
                                else "browser_error" if step_id == "browser"
                                else "analysis_failed"
                            )
                    elif status_value == "blocked":
                        mapped_reason = (
                            "redirect_blocked" if step_id in {"http", "browser"}
                            else "static_body_limit"
                        )
                    elif status_value == "skipped":
                        mapped_reason = (
                            "http_unavailable" if step_id == "http"
                            else "not_html" if step_id == "static"
                            else "no_browser_required"
                        )
                    else:
                        mapped_reason = None
                    set_step(step_id, status_value, mapped_reason)
                    return status_value

                set_step("sandbox", "completed")
                if report_type == "email":
                    apply_check("http", "email_headers", "failed", "analysis_failed")
                    apply_check("static", "email_body", "failed", "analysis_failed")
                    set_step("browser", "skipped", "no_browser_required")
                else:
                    http_status = apply_check("http", "http_response", "failed", "http_fetch_failed")
                    redirect_check = checks.get("redirect_chain")
                    if (
                        http_status == "completed"
                        and isinstance(redirect_check, dict)
                        and redirect_check.get("status") == "blocked"
                    ):
                        set_step("http", "blocked", "redirect_blocked")
                    apply_check("static", "static_html", "skipped", "not_html")
                    apply_check("browser", "browser_observation", "skipped", "no_browser_required")
            elif steps["browser"]["status"] == "pending":
                set_step("browser", "skipped", "no_browser_required")
            set_step("report", "completed")
        return plan

    @staticmethod
    def _private_link_targets(
        public_links: Any,
        private_links: Any,
    ) -> dict[str, str]:
        if not isinstance(public_links, list) or not isinstance(private_links, dict):
            return {}
        allowed_ids = {
            str(link.get("linkId"))
            for link in public_links
            if isinstance(link, dict)
            and link.get("scanAvailable") is True
            and isinstance(link.get("linkId"), str)
        }
        resolved: dict[str, str] = {}
        for link_id, raw_url in private_links.items():
            if link_id not in allowed_ids or not isinstance(raw_url, str):
                continue
            try:
                resolved[link_id] = normalize_public_http_url(raw_url)
            except URLPolicyError:
                continue
        return resolved

    # ----- Approval-gated agent review --------------------------------------

    def review_view(self, scan_id: str) -> dict[str, Any] | str:
        """Return the redacted review state for the API, or an error code."""
        self._prune_expired()
        record = self._records.get(scan_id)
        if record is None:
            return "not_found"
        session = record.review
        if session is None or record.status != "awaiting_review":
            return "not_reviewing"
        public_links = session.draft_report.get("links") or []
        candidates = [
            {"linkId": str(link["linkId"]), "host": str(link["targetHost"])}
            for link in public_links
            if isinstance(link, dict)
            and link.get("scanAvailable") is True
            and str(link.get("linkId")) in record.private_links
        ][:50]
        view: dict[str, Any] = {
            "scanId": record.scan_id,
            "type": record.scan_type,
            "deadline": session.deadline_at.isoformat(),
            "report": session.draft_report,
            "actions": list(session.actions),
            "linkCandidates": candidates,
            "linkMetadataShared": session.link_shared,
            "browserEligible": self._browser_follow_up_eligible(session),
            "busy": session.running or session.pending_commands > 0,
        }
        if session.link_shared:
            # Host/path/anchor only, after the user approved sharing it.
            view["linkContext"] = build_link_context(public_links, record.private_links)
        return view

    async def submit_review_command(
        self, scan_id: str, command: AgentReviewCommand
    ) -> str | None:
        """Validate and queue one review command. Returns an error code or None."""
        self._prune_expired()
        record = self._records.get(scan_id)
        if record is None:
            return "not_found"
        session = record.review
        if session is None or record.status != "awaiting_review":
            return "not_reviewing"
        if isinstance(command, AgentFinalizeCommand):
            session.commands.put_nowait(command)
            return None

        action_id = str(command.actionId)
        if action_id in session.used_action_ids:
            return "replayed"
        allowed = EMAIL_AGENT_TOOLS if record.scan_type == "email" else URL_AGENT_TOOLS
        if command.tool not in allowed:
            return "tool_not_allowed"

        if isinstance(command, AgentRunCommand):
            if session.running or session.pending_commands:
                return "busy"
            if len(session.actions) >= MAX_AGENT_ACTIONS:
                return "limit"
            if any(action["tool"] == command.tool for action in session.actions):
                return "tool_already_used"
            if command.tool == "email_link_visit":
                if command.linkId is None or str(command.linkId) not in record.private_links:
                    return "link_unavailable"
            elif command.linkId is not None:
                return "tool_not_allowed"
            if command.tool == "url_browser_observation" and not self._browser_follow_up_eligible(session):
                return "browser_not_eligible"

        session.used_action_ids.add(action_id)
        session.pending_commands += 1
        session.commands.put_nowait(command)
        return None

    @staticmethod
    def _browser_follow_up_eligible(session: ReviewSession) -> bool:
        """A browser follow-up is offered only when the baseline skipped it
        because no browser was required (not when policy blocked it)."""
        if not session.target_url:
            return False
        for step in session.draft_report.get("executionPlan") or []:
            if isinstance(step, dict) and step.get("id") == "browser":
                return (
                    step.get("status") == "skipped"
                    and step.get("reasonCode") == "no_browser_required"
                )
        return False

    async def _run_agent_review(
        self,
        record: ScanRecord,
        draft_report: dict[str, Any],
        deadline: float,
        *,
        target_url: str | None,
    ) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        remaining = max(0.0, deadline - loop.time())
        session = ReviewSession(
            draft_report=draft_report,
            deadline=deadline,
            deadline_at=datetime.now(timezone.utc) + timedelta(seconds=remaining),
            target_url=target_url,
        )
        record.review = session
        await self._publish_progress(
            record,
            "awaiting_review",
            status="awaiting_review",
            report_data=draft_report,
        )
        await self._publish(
            record,
            "review_ready",
            {
                "scanId": record.scan_id,
                "deadline": session.deadline_at.isoformat(),
                "linkCount": len(record.private_links) if record.scan_type == "email" else 0,
            },
        )

        outcome = "finalized"
        while True:
            remaining = session.deadline - loop.time()
            if remaining <= 0:
                outcome = "timed_out"
                break
            try:
                command = await asyncio.wait_for(session.commands.get(), timeout=remaining)
            except TimeoutError:
                outcome = "timed_out"
                break
            if isinstance(command, AgentFinalizeCommand):
                break
            session.pending_commands = max(0, session.pending_commands - 1)
            if isinstance(command, AgentSkipCommand):
                await self._record_action(
                    record,
                    session,
                    {
                        "actionId": str(command.actionId),
                        "tool": command.tool,
                        "status": "skipped",
                        "reasonCode": command.reason,
                    },
                )
                # A declined request is not retried through another tool.
                outcome = command.reason
                break
            await self._run_agent_action(record, session, command)

        final_report = self._final_review_report(session, outcome)
        record.review = None
        return final_report

    async def _run_agent_action(
        self,
        record: ScanRecord,
        session: ReviewSession,
        command: AgentRunCommand,
    ) -> None:
        base: dict[str, Any] = {"actionId": str(command.actionId), "tool": command.tool}
        if command.tool == "link_metadata_share":
            session.link_shared = True
            await self._record_action(record, session, {**base, "status": "completed"})
            return

        target_url: str | None = None
        if command.tool == "email_link_visit":
            raw_target = record.private_links.get(str(command.linkId))
            try:
                target_url = normalize_public_http_url(raw_target) if raw_target else None
            except URLPolicyError:
                target_url = None
            if not target_url:
                await self._record_action(
                    record,
                    session,
                    {**base, "status": "blocked", "reasonCode": "link_unavailable"},
                )
                return
        else:
            target_url = session.target_url
            if not target_url or not self._browser_follow_up_eligible(session):
                await self._record_action(
                    record,
                    session,
                    {**base, "status": "blocked", "reasonCode": "browser_not_eligible"},
                )
                return

        host = (urlsplit(target_url).hostname or "")[:253] or None
        loop = asyncio.get_running_loop()
        remaining = session.deadline - loop.time()
        if remaining < MIN_ACTION_SECONDS:
            await self._record_action(
                record,
                session,
                {**base, "status": "blocked", "reasonCode": "insufficient_time", "targetHost": host},
            )
            return

        running = {**base, "status": "running", "targetHost": host}
        await self._record_action(record, session, running)
        child_id = uuid5(NAMESPACE_URL, f"veridict-agent:{record.scan_id}:{command.actionId}")
        child_request = URLScanRequest(
            scanId=child_id,
            type="url",
            url=target_url,
            consent=True,
            browserRequested=command.tool == "url_browser_observation",
        )

        async def ignore_progress(_stage: str, _reason: str | None = None) -> None:
            return None

        session.running = True
        try:
            data = await asyncio.wait_for(
                self.analyzer.analyze(
                    str(child_id),
                    child_request,
                    list(URL_PLAN_ACTIONS),
                    ignore_progress,
                ),
                timeout=remaining,
            )
            result = self._summarize_action_report(running, data, command.tool)
        except TimeoutError:
            result = {**running, "status": "failed", "reasonCode": "timed_out"}
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.error(
                "Agent follow-up failed",
                extra={
                    "scan_id": record.scan_id,
                    "operation": f"agent_{command.tool}",
                    "error_type": type(exc).__name__,
                },
            )
            result = {**running, "status": "failed", "reasonCode": "analysis_failed"}
        finally:
            session.running = False
        await self._record_action(record, session, result)

    @staticmethod
    def _summarize_action_report(
        running: dict[str, Any], data: Any, tool: str
    ) -> dict[str, Any]:
        if not isinstance(data, dict):
            return {**running, "status": "failed", "reasonCode": "analysis_failed"}
        findings: list[dict[str, Any]] = []
        raw_findings = data.get("findings")
        for raw in raw_findings[:100] if isinstance(raw_findings, list) else []:
            if not isinstance(raw, dict):
                continue
            if tool == "url_browser_observation" and raw.get("source") != "browser":
                continue
            try:
                findings.append(to_jsonable(Finding.model_validate(raw)))
            except ValidationError:
                continue
            if len(findings) >= 25:
                break
        coverage = data.get("coverage") if isinstance(data.get("coverage"), dict) else {}
        if tool == "url_browser_observation":
            checks = coverage.get("checks") if isinstance(coverage.get("checks"), list) else []
            browser_status = next(
                (
                    check.get("status")
                    for check in checks
                    if isinstance(check, dict) and check.get("name") == "browser_observation"
                ),
                None,
            )
            if browser_status == "failed":
                return {**running, "status": "failed", "reasonCode": "analysis_failed"}
            if browser_status != "completed":
                return {**running, "status": "blocked", "reasonCode": "browser_not_eligible"}
        risk_band = data.get("riskBand")
        return {
            **running,
            "status": "completed",
            "riskBand": risk_band if risk_band in RISK_BANDS else "inconclusive",
            "findings": findings,
            "coverageSufficient": coverage.get("sufficient") is True,
        }

    async def _record_action(
        self,
        record: ScanRecord,
        session: ReviewSession,
        action: dict[str, Any],
    ) -> None:
        validated = to_jsonable(AgentActionResult.model_validate(action))
        for index, existing in enumerate(session.actions):
            if existing["actionId"] == validated["actionId"]:
                session.actions[index] = validated
                break
        else:
            session.actions.append(validated)
        await self._publish(record, "agent_action", validated)

    @staticmethod
    def _review_coverage_check(
        actions: list[dict[str, Any]], outcome: str
    ) -> dict[str, str]:
        ran_sandbox_action = any(
            action["tool"] in SANDBOX_AGENT_TOOLS and action["status"] == "completed"
            for action in actions
        )
        if outcome == "timed_out":
            return {
                "name": "agent_follow_up",
                "status": "skipped",
                "reason": "Follow-up review reached the time limit. The report uses the completed checks.",
            }
        if outcome in {"declined", "expired", "cancelled"}:
            return {
                "name": "agent_follow_up",
                "status": "skipped",
                "reason": "A proposed follow-up step was not approved. Coverage is limited to the completed checks.",
            }
        if ran_sandbox_action:
            return {
                "name": "agent_follow_up",
                "status": "completed",
                "reason": "Approved follow-up steps ran in the isolated worker. Their results are listed separately.",
            }
        return {
            "name": "agent_follow_up",
            "status": "skipped",
            "reason": "No follow-up step ran. The report uses the completed checks.",
        }

    def _final_review_report(
        self, session: ReviewSession, outcome: str
    ) -> dict[str, Any]:
        actions = [
            {**action, "status": "failed", "reasonCode": "cancelled"}
            if action["status"] == "running"
            else action
            for action in session.actions
        ]
        final = dict(session.draft_report)
        coverage = dict(final["coverage"])
        coverage["checks"] = [
            *coverage.get("checks", []),
            self._review_coverage_check(actions, outcome),
        ][:30]
        final["coverage"] = coverage
        if actions:
            final["agentActions"] = actions
        return to_jsonable(ScanReport.model_validate(final))

    def _partial_review_report(self, session: ReviewSession) -> dict[str, Any] | None:
        try:
            final = self._final_review_report(session, "cancelled")
        except ValidationError:
            return None
        checks = final["coverage"]["checks"]
        checks[-1] = {
            "name": "agent_follow_up",
            "status": "skipped",
            "reason": "Follow-up review was stopped. Unfinished follow-up steps are excluded.",
        }
        final["partial"] = True
        final["partialReason"] = (
            "Stopped during follow-up review. Completed baseline checks are shown; "
            "unfinished follow-up steps are excluded."
        )
        return to_jsonable(ScanReport.model_validate(final))

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
                if isinstance(request, EmailScanRequest):
                    request.emailBase64 = ""
                self._queue.task_done()
                self._prune_expired()
                continue
            self._active_scan_id = scan_id
            # The hard cap for review-enabled scans starts when the worker
            # begins this scan; baseline, approvals, and follow-ups share it.
            review_deadline = (
                asyncio.get_running_loop().time()
                + self.settings.agent_review_cap_seconds
            )

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
                task_plan = (
                    EMAIL_PLAN_ACTIONS
                    if record.scan_type == "email"
                    else URL_PLAN_ACTIONS
                )
                report_data = await self.analyzer.analyze(
                    scan_id,
                    request,
                    list(task_plan),
                    progress,
                )
                private_links = report_data.pop("_privateLinks", None)
                if record.scan_type == "email":
                    record.private_links = self._private_link_targets(
                        report_data.get("links"),
                        private_links,
                    )
                report_data = {**report_data, "type": record.scan_type}
                execution_plan = self._plan_for_stage(
                    "completed",
                    record.latest_progress,
                    reason_code=None,
                    report_data=report_data,
                    scan_type=record.scan_type,
                )
                report = ScanReport.model_validate(
                    {**report_data, "executionPlan": execution_plan}
                )
                if str(report.scanId) != scan_id or report.type != record.scan_type:
                    raise ValueError("Worker report identity mismatch")
                report_json = to_jsonable(report)
                if (
                    isinstance(request, (URLScanRequest, EmailScanRequest))
                    and request.agentReview
                    and record.scan_type in {"url", "email"}
                ):
                    # The original input stays referenced by `request` only for
                    # the duration of the review; `finally` erases email bytes.
                    report_json = await self._run_agent_review(
                        record,
                        report_json,
                        review_deadline,
                        target_url=(
                            request.url if isinstance(request, URLScanRequest) else None
                        ),
                    )
                await self._publish_progress(
                    record,
                    "completed",
                    report_data=report_json,
                )
                record.report = report_json
                await self._publish(
                    record, "completed", record.report, status="completed"
                )
            except asyncio.CancelledError:
                session = record.review
                if session is not None:
                    record.report = self._partial_review_report(session)
                    record.review = None
                await self._publish_cancellation(record)
                raise
            except Exception as exc:
                self.logger.error(
                    "Analysis failed",
                    extra={
                        "scan_id": scan_id,
                        "operation": f"analyze_{record.scan_type}",
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
                record.review = None
                self._clear_email_request(request)
                self._active_scan_id = None
                self._queue.task_done()
                self._prune_expired()
