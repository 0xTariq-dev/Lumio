from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_EMAIL_BASE64_CHARS = ((MAX_EMAIL_BYTES + 2) // 3) * 4


class URLScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url"]
    url: str = Field(min_length=8, max_length=2048)
    consent: Literal[True]


class EmailScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["email"]
    emailBase64: str = Field(min_length=4, max_length=MAX_EMAIL_BASE64_CHARS)
    consent: Literal[True]

    @field_validator("emailBase64")
    @classmethod
    def validate_email_base64(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Email content is not valid base64") from exc
        if not decoded or len(decoded) > MAX_EMAIL_BYTES:
            raise ValueError("Email content size is invalid")
        return value


class EmailLinkScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["email_link"]
    originalScanId: UUID
    linkId: UUID
    consent: Literal[True]


ScanRequest = URLScanRequest | EmailScanRequest | EmailLinkScanRequest
AnalysisRequest = URLScanRequest | EmailScanRequest


class ScanPlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Literal[
        "consent_target",
        "sandbox",
        "http",
        "static",
        "browser",
        "email_parse",
        "report",
    ]
    status: Literal["pending", "running", "completed", "skipped", "failed", "blocked"]
    reasonCode: Literal[
        "consent_checked",
        "no_browser_required",
        "redirect_blocked",
        "not_html",
        "static_body_limit",
        "http_unavailable",
        "http_fetch_failed",
        "browser_error",
        "earlier_step_failed",
        "analysis_failed",
    ] | None = None


class ProgressPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: Literal[
        "validating",
        "queued",
        "starting_sandbox",
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
        "completed",
        "failed",
    ]
    message: str = Field(max_length=160)
    completedSteps: int = Field(ge=0)
    totalSteps: int = Field(ge=1)
    plan: list[ScanPlanStep] = Field(min_length=4, max_length=6)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=100)
    explanation: str = Field(min_length=1, max_length=500)
    severity: Literal["informational", "low", "moderate", "high", "critical"]
    strength: Literal["direct", "contextual"]
    source: Literal[
        "url_navigation",
        "browser",
        "email_headers",
        "email_body",
        "attachment_metadata",
    ]
    sanitizedObservedValue: str | None = Field(default=None, max_length=300)
    limitations: list[str] = Field(default_factory=list, max_length=20)


class CoverageCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    status: Literal["completed", "skipped", "blocked", "failed"]
    reason: str | None = Field(default=None, max_length=200)


class Coverage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sufficient: bool
    checks: list[CoverageCheck] = Field(max_length=30)


class EmailLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    linkId: UUID
    anchorText: str = Field(min_length=1, max_length=120)
    displayUrl: str = Field(min_length=1, max_length=300)
    targetHost: str = Field(min_length=1, max_length=253)
    scanAvailable: bool


class ScanReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url", "email", "email_link"]
    riskBand: Literal["low", "moderate", "high", "critical", "inconclusive"]
    completedAt: datetime
    ruleSetVersion: str = Field(min_length=1, max_length=80)
    findings: list[Finding] = Field(max_length=100)
    coverage: Coverage
    executionPlan: list[ScanPlanStep] | None = Field(
        default=None, min_length=4, max_length=6
    )
    links: list[EmailLink] | None = Field(default=None, max_length=50)


class ScanSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url", "email", "email_link"]
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    createdAt: datetime
    expiresAt: datetime
    latestProgress: ProgressPayload | None = None


def to_jsonable(model: BaseModel) -> dict[str, object]:
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)
