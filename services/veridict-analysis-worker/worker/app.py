from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from shared.url_policy import URLPolicyError, normalize_public_http_url

from .contracts import EmailLinkScanRequest, EmailScanRequest, URLScanRequest
from .logging_config import configure_logging
from .manager import ScanManager
from .microsandbox_runner import MicrosandboxRunner
from .settings import WorkerSettings

_logger = configure_logging()


def _error(status: int, code: str, message: str, *, retryable: bool = False):
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                "retryable": retryable,
            }
        },
    )


def _operation_for_path(path: str) -> str:
    if path == "/healthz":
        return "health"
    if path == "/v1/scans":
        return "submit_scan"
    if re.fullmatch(r"/v1/scans/[0-9a-fA-F-]{36}/events", path):
        return "scan_events"
    if re.fullmatch(r"/v1/scans/[0-9a-fA-F-]{36}/cancel", path):
        return "cancel_scan"
    if re.fullmatch(r"/v1/scans/[0-9a-fA-F-]{36}", path):
        return "get_scan"
    return "not_found"


def create_app(
    settings: WorkerSettings | None = None,
    analyzer=None,
) -> FastAPI:
    worker_settings = settings or WorkerSettings.from_env()
    runner = analyzer or MicrosandboxRunner(worker_settings)
    manager = ScanManager(worker_settings, runner, _logger)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await manager.start()
        try:
            yield
        finally:
            await manager.stop()

    app = FastAPI(
        title="Veridict Analysis Worker",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.scan_manager = manager
    app.state.worker_settings = worker_settings

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        request_id = uuid4().hex
        started_at = time.monotonic()
        operation = _operation_for_path(request.url.path)
        _logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "operation": operation,
                "method": request.method,
            },
        )
        expected = worker_settings.token
        if not expected or len(expected) < 32 or not expected.isascii():
            response = _error(
                503,
                "WORKER_UNAVAILABLE",
                "The isolated analysis worker is not configured.",
                retryable=True,
            )
        else:
            authorization = request.headers.get("authorization", "")
            provided = (
                authorization[7:] if authorization.startswith("Bearer ") else ""
            )
            if not hmac.compare_digest(expected, provided):
                response = _error(
                    401, "UNAUTHORIZED", "Authentication is required."
                )
            else:
                try:
                    response = await call_next(request)
                except Exception as exc:
                    _logger.error(
                        "Request failed",
                        extra={
                            "request_id": request_id,
                            "operation": operation,
                            "method": request.method,
                            "error_type": type(exc).__name__,
                        },
                    )
                    response = _error(
                        500,
                        "INTERNAL_ERROR",
                        "The request could not be completed.",
                        retryable=True,
                    )

        response.headers["X-Request-ID"] = request_id
        _logger.info(
            "Request completed",
            extra={
                "request_id": request_id,
                "operation": operation,
                "method": request.method,
                "status_code": response.status_code,
                "elapsed_ms": round((time.monotonic() - started_at) * 1000),
            },
        )
        return response

    @app.get("/healthz")
    async def health():
        if not manager.ready:
            return _error(
                503,
                "WORKER_UNAVAILABLE",
                "The isolated analysis worker is not ready.",
                retryable=True,
            )
        return {
            "status": "ready",
            "queue": {
                "active": manager.active_count,
                "queued": manager.queued_count,
            },
        }

    @app.post("/v1/scans")
    async def create_scan(request: Request):
        if request.headers.get("content-encoding", "identity").lower() not in {
            "",
            "identity",
        }:
            return _error(415, "UNSUPPORTED_ENCODING", "Only plain JSON is supported.")
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return _error(415, "UNSUPPORTED_MEDIA_TYPE", "A JSON request is required.")

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > worker_settings.request_body_limit_bytes:
                    return _error(413, "REQUEST_TOO_LARGE", "The request is too large.")
            except ValueError:
                return _error(400, "INVALID_REQUEST", "The request is invalid.")

        body = bytearray()
        try:
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > worker_settings.request_body_limit_bytes:
                    return _error(413, "REQUEST_TOO_LARGE", "The request is too large.")
        except Exception:
            return _error(400, "INVALID_REQUEST", "The request is invalid.")

        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _error(400, "INVALID_REQUEST", "The request is invalid.")
        if not isinstance(payload, dict):
            return _error(400, "INVALID_REQUEST", "The request is invalid.")
        scan_type = payload.get("type")
        if scan_type not in {"url", "email", "email_link"}:
            return _error(
                422,
                "UNSUPPORTED_SCAN_TYPE",
                "This scan type is not supported.",
            )

        try:
            if scan_type == "url":
                scan_request = URLScanRequest.model_validate(payload)
                scan_request = scan_request.model_copy(
                    update={"url": normalize_public_http_url(scan_request.url)}
                )
            elif scan_type == "email":
                scan_request = EmailScanRequest.model_validate(payload)
            else:
                scan_request = EmailLinkScanRequest.model_validate(payload)
        except ValidationError:
            return _error(
                400,
                "INVALID_SCAN_REQUEST",
                "The scan request is invalid.",
            )
        except URLPolicyError:
            return _error(400, "INVALID_URL", "The URL is not eligible for analysis.")

        status, rejection = await manager.enqueue(scan_request)
        if rejection == "full":
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": "30"},
                content={
                    "error": {
                        "code": "SCAN_QUEUE_FULL",
                        "message": "The analysis queue is full. Try again later.",
                        "retryable": True,
                    }
                },
            )
        if status is None:
            if rejection == "link_unavailable":
                return _error(
                    404,
                    "EMAIL_LINK_NOT_AVAILABLE",
                    "This email link is no longer available for scanning.",
                )
            return _error(
                503,
                "WORKER_UNAVAILABLE",
                "The isolated analysis worker is not ready.",
                retryable=True,
            )
        return {"accepted": True, "status": status}

    @app.get("/v1/scans/{scan_id}")
    async def get_scan(scan_id: str):
        try:
            normalized_id = str(UUID(scan_id))
        except ValueError:
            return _error(404, "SCAN_NOT_FOUND", "The analysis was not found.")
        snapshot = manager.snapshot(normalized_id)
        if snapshot is None:
            return _error(404, "SCAN_NOT_FOUND", "The analysis was not found.")
        return snapshot

    @app.get("/v1/scans/{scan_id}/report")
    async def get_report(scan_id: str):
        try:
            normalized_id = str(UUID(scan_id))
        except ValueError:
            return _error(404, "SCAN_NOT_FOUND", "The analysis was not found.")
        report = manager.report(normalized_id)
        if report is None:
            return _error(404, "REPORT_NOT_FOUND", "The completed report is not available.")
        return report

    @app.post("/v1/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: str):
        try:
            normalized_id = str(UUID(scan_id))
        except ValueError:
            return _error(404, "SCAN_NOT_FOUND", "The analysis was not found.")
        status = await manager.cancel_scan(normalized_id)
        if status is None:
            return _error(404, "SCAN_NOT_FOUND", "The analysis was not found.")
        return {
            "scanId": normalized_id,
            "status": status,
            "cancelled": status in {"cancelling", "cancelled"},
        }

    @app.get("/v1/scans/{scan_id}/events")
    async def scan_events(scan_id: str, request: Request):
        try:
            normalized_id = str(UUID(scan_id))
        except ValueError:
            return _error(404, "SCAN_NOT_FOUND", "The analysis was not found.")
        record = manager.get_record(normalized_id)
        if record is None:
            return _error(404, "SCAN_NOT_FOUND", "The analysis was not found.")

        raw_last_id = request.headers.get("last-event-id", "0")
        try:
            last_id = max(0, min(int(raw_last_id), 1_000_000))
        except ValueError:
            last_id = 0

        async def events() -> AsyncIterator[str]:
            nonlocal last_id
            while True:
                heartbeat = False
                async with record.condition:
                    available = [
                        event for event in record.events if event.event_id > last_id
                    ]
                    terminal = record.status in {"completed", "failed", "cancelled"}
                    if not available and not terminal:
                        try:
                            await asyncio.wait_for(record.condition.wait(), timeout=15)
                        except TimeoutError:
                            heartbeat = True
                        available = [
                            event for event in record.events if event.event_id > last_id
                        ]
                        terminal = record.status in {
                            "completed",
                            "failed",
                            "cancelled",
                        }

                if heartbeat and not available:
                    yield ": keep-alive\n\n"
                    continue
                for event in available:
                    last_id = event.event_id
                    data = json.dumps(event.data, separators=(",", ":"), ensure_ascii=False)
                    yield f"id: {event.event_id}\nevent: {event.name}\ndata: {data}\n\n"
                if terminal and not available:
                    return
                if terminal:
                    return

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    return app


app = create_app()
