from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_EMAIL_BASE64_CHARS = ((MAX_EMAIL_BYTES + 2) // 3) * 4
MAX_ATTACHMENT_DOCUMENTS = 20
MAX_ATTACHMENT_DOCUMENT_CHARS = 10_000
MAX_ATTACHMENT_DOCUMENT_TOTAL_CHARS = 20_000

AttachmentDocumentText = Annotated[
    str,
    Field(max_length=MAX_ATTACHMENT_DOCUMENT_CHARS),
]


class URLScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url"]
    url: str = Field(min_length=8, max_length=2048)
    consent: Literal[True]
    # Opt-in, approval-gated agent review before the report is published.
    agentReview: bool = False
    # Internal only: set by the worker for an approved browser follow-up.
    # The public submit endpoint rejects payloads that include it.
    browserRequested: bool = False


class EmailScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["email"]
    emailBase64: str = Field(min_length=4, max_length=MAX_EMAIL_BASE64_CHARS)
    consent: Literal[True]
    parseAttachmentsWithAi: bool = False
    agentReview: bool = False

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
        "awaiting_review",
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


class SoftwareEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product: Literal["WordPress"]
    version: str | None = Field(default=None, max_length=30)
    evidenceStrength: Literal["strong", "weak", "ambiguous"]
    evidenceSource: Literal[
        "html_generator_and_wp_asset_path",
        "html_generator_only",
        "wp_asset_path_only",
    ]


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


AgentTool = Literal["link_metadata_share", "email_link_visit", "url_browser_observation"]
AgentActionStatus = Literal["running", "completed", "skipped", "blocked", "failed"]
AgentActionReason = Literal[
    "declined",
    "expired",
    "cancelled",
    "timed_out",
    "insufficient_time",
    "link_unavailable",
    "browser_not_eligible",
    "analysis_failed",
]
MAX_AGENT_ACTIONS = 3


class AgentActionResult(BaseModel):
    """One approval-gated follow-up action and its truthful state."""

    model_config = ConfigDict(extra="forbid")

    actionId: UUID
    tool: AgentTool
    status: AgentActionStatus
    reasonCode: AgentActionReason | None = None
    targetHost: str | None = Field(default=None, max_length=253)
    riskBand: Literal["low", "moderate", "high", "critical", "inconclusive"] | None = None
    findings: list[Finding] = Field(default_factory=list, max_length=25)
    coverageSufficient: bool | None = None


class AgentRunCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: Literal["run"]
    actionId: UUID
    tool: AgentTool
    linkId: UUID | None = None


class AgentSkipCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: Literal["skip"]
    actionId: UUID
    tool: AgentTool
    reason: Literal["declined", "expired", "cancelled"]


class AgentFinalizeCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: Literal["finalize"]


AgentReviewCommand = AgentRunCommand | AgentSkipCommand | AgentFinalizeCommand


class ScanReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url", "email", "email_link"]
    riskBand: Literal["low", "moderate", "high", "critical", "inconclusive"]
    completedAt: datetime
    ruleSetVersion: str = Field(min_length=1, max_length=80)
    findings: list[Finding] = Field(max_length=100)
    coverage: Coverage
    softwareEvidence: list[SoftwareEvidence] = Field(default_factory=list, max_length=10)
    partial: bool | None = None
    partialReason: str | None = Field(default=None, max_length=200)
    executionPlan: list[ScanPlanStep] | None = Field(
        default=None, min_length=4, max_length=6
    )
    links: list[EmailLink] | None = Field(default=None, max_length=50)
    attachmentDocuments: list[AttachmentDocumentText] | None = Field(
        default=None,
        max_length=MAX_ATTACHMENT_DOCUMENTS,
    )
    agentActions: list[AgentActionResult] | None = Field(
        default=None, max_length=MAX_AGENT_ACTIONS
    )

    @model_validator(mode="after")
    def validate_attachment_document_total(self) -> "ScanReport":
        documents = self.attachmentDocuments or []
        if sum(len(document) for document in documents) > MAX_ATTACHMENT_DOCUMENT_TOTAL_CHARS:
            raise ValueError("Extracted attachment text exceeds its aggregate limit")
        return self


class ScanSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanId: UUID
    type: Literal["url", "email", "email_link"]
    status: Literal[
        "queued", "running", "awaiting_review", "completed", "failed", "cancelled"
    ]
    createdAt: datetime
    expiresAt: datetime
    latestProgress: ProgressPayload | None = None


def to_jsonable(model: BaseModel) -> dict[str, object]:
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)
