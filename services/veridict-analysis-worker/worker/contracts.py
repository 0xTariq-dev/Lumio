from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class URLScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url"]
    url: str = Field(min_length=8, max_length=2048)
    consent: Literal[True]


class ProgressPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: Literal[
        "validating",
        "queued",
        "starting_sandbox",
        "navigating",
        "collecting_evidence",
        "analyzing_email",
        "building_report",
    ]
    message: str = Field(max_length=160)
    completedSteps: int = Field(ge=0)
    totalSteps: int = Field(ge=1)


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


class ScanReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url"]
    riskBand: Literal["low", "moderate", "high", "critical", "inconclusive"]
    completedAt: datetime
    ruleSetVersion: str = Field(min_length=1, max_length=80)
    findings: list[Finding] = Field(max_length=100)
    coverage: Coverage
    links: list[dict[str, object]] | None = Field(default=None, max_length=50)


class ScanSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url"]
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    createdAt: datetime
    expiresAt: datetime
    latestProgress: ProgressPayload | None = None


def to_jsonable(model: BaseModel) -> dict[str, object]:
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)
