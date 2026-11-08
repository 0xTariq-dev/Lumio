import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { Router, type IRouter, type Request, type Response } from "express";
import multer from "multer";
import {
  CreateEmailScanBody,
  CreateEmailScanResponse,
  CreateSelectedEmailLinkScanBody,
  CreateSelectedEmailLinkScanParams,
  CreateSelectedEmailLinkScanResponse,
  CreateUrlScanBody,
  CreateUrlScanResponse,
  GetAnalysisStatusResponse,
  GetScanParams,
} from "@workspace/api-zod";
import { z } from "zod";
import { safeAttachmentFindingCopy } from "../lib/attachment-report";
import {
  AgentActionResultSchema,
  ReviewReadyEventSchema,
  cancelWorkerScan,
  fetchWorkerScan,
  fetchWorkerReport,
  getAnalysisWorkerHealth,
  openWorkerScanEvents,
  postWorkerScan,
  type WorkerHealth,
  type WorkerScanPayload,
} from "../lib/analysis-worker";
import { agentReviewRegistry } from "../lib/agent-review";
import {
  isTerminalAnalysisEvent,
  toPublicWorkerFailureEvent,
  toPublicWorkerCancellationEvent,
} from "../lib/analysis-event-safety";
import { serializePublicSseEvent } from "../lib/analysis-sse";
import { normalizeScanTargetInput } from "../lib/normalize-target";
import {
  areScanQuotaLimitsEnabled,
  SCAN_LIMITS,
} from "../lib/scan-quota-config";
import {
  getOrCreateBrowserToken,
  getScanQuotaUsage,
  QuotaConfigurationError,
  refundRejectedScan,
  reserveScanStart,
  type QuotaReservationEntry,
} from "../lib/scan-quotas";
import { logger } from "../lib/logger";
import { createExplanationToken } from "../lib/serverless-inference";

const router: IRouter = Router();
const MAX_EMAIL_BYTES = 10 * 1024 * 1024;
const ACTIVE_SCAN_LIMIT = 1;
const QUEUED_SCAN_LIMIT = 10;
const REPORT_TTL_MS = 15 * 60 * 1000;
const MAX_ACTIVE_EMAIL_UPLOADS = 2;
let activeEmailUploads = 0;

const ScanProgressSchema = z.object({
  stage: z.enum([
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
  ]),
  message: z.string().max(160),
  completedSteps: z.number().int().min(0),
  totalSteps: z.number().int().min(1),
  plan: z.array(z.object({
    id: z.enum(["consent_target", "sandbox", "http", "static", "browser", "email_parse", "report"]),
    status: z.enum(["pending", "running", "completed", "skipped", "failed", "blocked"]),
    reasonCode: z.enum([
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
    ]).optional(),
  })).min(4).max(6).optional(),
});

const ScanReportSchema = z.object({
  scanId: z.uuid(),
  type: z.enum(["url", "email", "email_link"]),
  riskBand: z.enum(["low", "moderate", "high", "critical", "inconclusive"]),
  completedAt: z.iso.datetime(),
  ruleSetVersion: z.string(),
  findings: z.array(
    z.object({
      id: z.string(),
      title: z.string().max(100),
      explanation: z.string().max(500),
      severity: z.enum(["informational", "low", "moderate", "high", "critical"]),
      strength: z.enum(["direct", "contextual"]),
      source: z.enum([
        "url_navigation",
        "browser",
        "email_headers",
        "email_body",
        "attachment_metadata",
      ]),
      sanitizedObservedValue: z.string().max(300).nullable().optional(),
      limitations: z.array(z.string().max(200)).optional(),
    }),
  ),
  softwareEvidence: z.array(z.object({
    product: z.literal('WordPress'),
    version: z.string().max(30).nullable().optional(),
    evidenceStrength: z.enum(['strong', 'weak', 'ambiguous']),
    evidenceSource: z.enum([
      'html_generator_and_wp_asset_path',
      'html_generator_only',
      'wp_asset_path_only',
    ]),
  })).max(10).optional(),
  partial: z.boolean().optional(),
  partialReason: z.string().max(200).optional(),
  coverage: z.object({
    sufficient: z.boolean(),
    checks: z.array(
      z.object({
        name: z.string().max(80),
        status: z.enum(["completed", "skipped", "blocked", "failed"]),
        reason: z.string().max(200).nullable().optional(),
      }),
    ),
  }),
  executionPlan: z.array(z.object({
    id: z.enum(["consent_target", "sandbox", "http", "static", "browser", "email_parse", "report"]),
    status: z.enum(["pending", "running", "completed", "skipped", "failed", "blocked"]),
    reasonCode: z.enum([
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
    ]).optional(),
  })).min(4).max(6).optional(),
  links: z
    .array(
      z.object({
        linkId: z.uuid(),
        anchorText: z.string().max(200),
        displayUrl: z.string().max(300),
        targetHost: z.string().max(253),
        scanAvailable: z.boolean(),
      }),
    )
    .max(50)
    .optional(),
  agentActions: z.array(AgentActionResultSchema).max(3).optional(),
  explanationToken: z.string().max(12_000).optional(),
});

type ScanReportPayload = z.infer<typeof ScanReportSchema>;

const uploadEml = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_EMAIL_BYTES,
    files: 1,
    fields: 2,
    parts: 3,
    fieldNameSize: 40,
    fieldSize: 8,
  },
}).single("file");

function sendApiError(
  res: Response,
  status: number,
  code: string,
  message: string,
  retryable = false,
  retryAfterSeconds?: number,
) {
  const body = {
    code,
    message,
    retryable,
    ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
  };
  return res.status(status).json(body);
}

function queueIsFull(worker: WorkerHealth): boolean {
  return worker.queue.active + worker.queue.queued >= ACTIVE_SCAN_LIMIT + QUEUED_SCAN_LIMIT;
}

async function requireReadyWorker(req: Request, res: Response, next: () => void) {
  const worker = await getAnalysisWorkerHealth();
  if (!worker) {
    sendApiError(
      res,
      503,
      "ANALYSIS_WORKER_UNAVAILABLE",
      "The isolated analysis worker is unavailable. No scan was started.",
      true,
    );
    return;
  }
  if (queueIsFull(worker)) {
    sendApiError(
      res,
      429,
      "SCAN_QUEUE_FULL",
      "The analysis queue is full. Please try again when a slot opens.",
      true,
    );
    return;
  }
  res.locals.workerHealth = worker;
  next();
}

function ipv4IsRestricted(hostname: string): boolean {
  const parts = hostname.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return true;
  }
  const [first, second, third] = parts;
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0 && third === 0) ||
    (first === 192 && second === 0 && third === 2) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19)) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113)
  );
}

function isRestrictedDestination(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    !normalized ||
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".internal") ||
    normalized.endsWith(".test") ||
    normalized.endsWith(".example") ||
    normalized.endsWith(".invalid") ||
    !normalized.includes(".")
  ) {
    return true;
  }

  const ipVersion = isIP(normalized);
  if (ipVersion === 4) return ipv4IsRestricted(normalized);
  if (ipVersion === 6) {
    if (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fe80:") ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("ff")
    ) {
      return true;
    }
    if (normalized.startsWith("::ffff:")) {
      const mapped = normalized.slice("::ffff:".length);
      if (isIP(mapped) === 4) return ipv4IsRestricted(mapped);
    }
  }
  return false;
}

function isPublicHttpTarget(value: string): boolean {
  try {
    const url = new URL(value);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      isRestrictedDestination(url.hostname)
    ) {
      return false;
    }
    const expectedPort = url.protocol === "https:" ? "443" : "80";
    return !url.port || url.port === expectedPort;
  } catch {
    return false;
  }
}

function safeProgressMessage(stage: string): string {
  const messages: Record<string, string> = {
    validating: "Checking the submitted input.",
    queued: "Waiting for an isolated scan slot.",
    starting_sandbox: "Starting a temporary analysis sandbox.",
    navigating: "Inspecting the public page.",
    collecting_evidence: "Collecting technical evidence.",
    http_failed: "HTTP inspection did not complete; coverage may be reduced.",
    browser_inspection: "Checking the page in a browser based on observed signals.",
    browser_completed: "Browser inspection completed.",
    browser_skipped: "Browser inspection was skipped based on observed signals.",
    browser_blocked: "Browser inspection was blocked by the scan policy.",
    browser_failed: "Browser inspection did not complete; coverage may be reduced.",
    analyzing_email: "Extracting email indicators and links.",
    building_report: "Preparing the evidence report.",
    awaiting_review: "Waiting for your decision on a follow-up step.",
    completed: "The execution plan completed and the report is ready.",
    failed: "Analysis ended before all planned steps completed.",
  };
  return messages[stage] ?? "Analysis is in progress.";
}

function acceptedBody(scanId: string, status: "queued" | "running") {
  return {
    scanId,
    status,
    eventsPath: `/api/scans/${scanId}/events`,
    expiresAt: new Date(Date.now() + REPORT_TTL_MS).toISOString(),
  };
}

async function reserveQuota(
  req: Request,
  res: Response,
): Promise<
  | { allowed: true; entries: QuotaReservationEntry[] }
  | { allowed: false }
> {
  const ipAddress = req.ip || req.socket.remoteAddress || "";
  try {
    const browserToken = getOrCreateBrowserToken(req, res);
    const result = await reserveScanStart(ipAddress, browserToken);
    if (!result.allowed) {
      const message =
        result.reason === "lifetime"
          ? "This network or browser has reached its total scan limit."
          : result.reason === "day"
            ? "This network or browser has reached its daily scan limit."
            : "The scan start limit has been reached. Please try again shortly.";
      sendApiError(
        res,
        429,
        "SCAN_LIMIT_REACHED",
        message,
        result.reason !== "lifetime",
        result.retryAfterSeconds,
      );
      return { allowed: false };
    }
    return { allowed: true, entries: result.entries };
  } catch (error) {
    if (error instanceof QuotaConfigurationError) {
      sendApiError(
        res,
        503,
        "ABUSE_CONTROLS_UNAVAILABLE",
        "Scan protection is temporarily unavailable. No scan was started.",
        true,
      );
      return { allowed: false };
    }
    logger.error({ errorType: "quota_reservation_failed" }, "Could not reserve scan quota");
    sendApiError(
      res,
      503,
      "ABUSE_CONTROLS_UNAVAILABLE",
      "Scan protection is temporarily unavailable. No scan was started.",
      true,
    );
    return { allowed: false };
  }
}

async function createScan(
  req: Request,
  res: Response,
  input: WorkerScanPayload,
  responseSchema:
    | typeof CreateUrlScanResponse
    | typeof CreateEmailScanResponse
    | typeof CreateSelectedEmailLinkScanResponse,
) {
  const worker = res.locals.workerHealth as WorkerHealth | undefined;
  if (!worker) {
    return sendApiError(
      res,
      503,
      "ANALYSIS_WORKER_UNAVAILABLE",
      "The isolated analysis worker is unavailable. No scan was started.",
      true,
    );
  }
  if (queueIsFull(worker)) {
    return sendApiError(
      res,
      429,
      "SCAN_QUEUE_FULL",
      "The analysis queue is full. Please try again when a slot opens.",
      true,
    );
  }

  const reservation = await reserveQuota(req, res);
  if (!reservation.allowed) return;

  const scanId = randomUUID();
  const agentReview = "agentReview" in input && input.agentReview === true;
  if (agentReview) {
    // Bind before the worker can pause, so only this browser drives the review.
    agentReviewRegistry.register(scanId, getOrCreateBrowserToken(req, res));
  }
  const workerResult = await postWorkerScan({
    ...input,
    scanId,
  });
  if (workerResult.kind === "rejected") {
    await refundRejectedScan(reservation.entries).catch(() => {
      logger.error(
        { errorType: "quota_refund_failed" },
        "Could not release quota after worker rejection",
      );
    });
    if (workerResult.status === 429) {
      return sendApiError(
        res,
        429,
        "SCAN_QUEUE_FULL",
        "The analysis queue is full. Please try again when a slot opens.",
        true,
      );
    }
    return sendApiError(
      res,
      400,
      "SCAN_REJECTED",
      "The isolated worker declined this scan request.",
      false,
    );
  }
  if (workerResult.kind !== "accepted") {
    return sendApiError(
      res,
      503,
      "ANALYSIS_WORKER_UNAVAILABLE",
      "The worker did not confirm this scan. The attempt may count toward your limit.",
      true,
    );
  }

  return res
    .status(202)
    .json(responseSchema.parse(acceptedBody(scanId, workerResult.status)));
}

router.get("/analysis/status", async (req, res) => {
  const worker = await getAnalysisWorkerHealth();
  const quotaLimitsEnabled = areScanQuotaLimitsEnabled();
  const quotaUsage = quotaLimitsEnabled
    ? await getScanQuotaUsage(
        req.ip || req.socket.remoteAddress || "",
        getOrCreateBrowserToken(req, res),
      )
    : null;
  const data = GetAnalysisStatusResponse.parse({
    workerStatus: worker ? "ready" : "unavailable",
    scannerAvailable: Boolean(
      worker && !queueIsFull(worker),
    ),
    queue: {
      active: worker?.queue.active ?? 0,
      queued: worker?.queue.queued ?? 0,
      activeLimit: ACTIVE_SCAN_LIMIT,
      queuedLimit: QUEUED_SCAN_LIMIT,
    },
    limits: {
      maxUrlLength: 2048,
      maxEmailBytes: MAX_EMAIL_BYTES,
      maxExtractedLinks: 50,
      browserTimeoutSeconds: 90,
      sandboxKillSeconds: 180,
      startsPerMinute: SCAN_LIMITS.startsPerMinute,
      startsPerDay: SCAN_LIMITS.startsPerDay,
      lifetimeStartsPerIp: SCAN_LIMITS.lifetimeStartsPerIp,
    },
    scanQuota: {
      enabled: quotaLimitsEnabled,
      daily: {
        used: quotaUsage?.dailyUsed ?? null,
        total: SCAN_LIMITS.startsPerDay,
      },
      lifetime: {
        used: quotaUsage?.lifetimeUsed ?? null,
        total: SCAN_LIMITS.lifetimeStartsPerIp,
      },
    },
  });
  res.json(data);
});

router.post("/scans/url", requireReadyWorker, async (req, res) => {
  const body =
    req.body && typeof req.body === "object" && !Array.isArray(req.body)
      ? (req.body as Record<string, unknown>)
      : {};
  const normalizedUrl = normalizeScanTargetInput(body.url);
  if (!normalizedUrl) {
    return sendApiError(
      res,
      400,
      "INVALID_URL_SCAN",
      "Enter a domain, public IP, or HTTP(S) URL and confirm consent.",
    );
  }
  const parsed = CreateUrlScanBody.safeParse({
    ...body,
    url: normalizedUrl,
  });
  if (!parsed.success) {
    return sendApiError(
      res,
      400,
      "INVALID_URL_SCAN",
      "Enter a domain, public IP, or HTTP(S) URL and confirm consent.",
    );
  }
  if (!isPublicHttpTarget(parsed.data.url)) {
    return sendApiError(
      res,
      400,
      "URL_NOT_ALLOWED",
      "This URL is not eligible for public web analysis.",
    );
  }
  return createScan(
    req,
    res,
    {
      type: "url",
      url: parsed.data.url,
      consent: true,
      agentReview: parsed.data.agentReview === true,
    },
    CreateUrlScanResponse,
  );
});

function emailUploadMiddleware(req: Request, res: Response, next: () => void) {
  if (activeEmailUploads >= MAX_ACTIVE_EMAIL_UPLOADS) {
    sendApiError(
      res,
      429,
      "UPLOAD_CAPACITY_REACHED",
      "Email intake is busy. Please try again shortly.",
      true,
      5,
    );
    return;
  }

  activeEmailUploads += 1;
  uploadEml(req, res, (error) => {
    activeEmailUploads -= 1;
    if (error instanceof multer.MulterError) {
      const tooLarge = error.code === "LIMIT_FILE_SIZE";
      sendApiError(
        res,
        tooLarge ? 413 : 400,
        tooLarge ? "EMAIL_TOO_LARGE" : "INVALID_EMAIL_UPLOAD",
        tooLarge
          ? "The .eml file must be 10 MB or smaller."
          : "Choose one .eml file and confirm consent.",
      );
      return;
    }
    if (error) {
      sendApiError(
        res,
        400,
        "INVALID_EMAIL_UPLOAD",
        "Choose one .eml file and confirm consent.",
      );
      return;
    }
    next();
  });
}

router.post(
  "/scans/email",
  requireReadyWorker,
  emailUploadMiddleware,
  async (req, res) => {
    const file = req.file;
    if (!file || !file.originalname.toLowerCase().endsWith(".eml")) {
      return sendApiError(
        res,
        400,
        "INVALID_EMAIL_FILE",
        "Choose an .eml file and confirm consent.",
      );
    }

    const bytes = Uint8Array.from(file.buffer);
    const parsed = CreateEmailScanBody.safeParse({
      file: new Blob([bytes.buffer as ArrayBuffer], {
        type: "message/rfc822",
      }),
      consent: req.body.consent === "true",
    });
    if (!parsed.success) {
      return sendApiError(
        res,
        400,
        "INVALID_EMAIL_FILE",
        "Choose an .eml file and confirm consent.",
      );
    }

    return createScan(
      req,
      res,
      {
        type: "email",
        emailBase64: file.buffer.toString("base64"),
        consent: true,
        agentReview: req.body.agentReview === "true",
      },
      CreateEmailScanResponse,
    );
  },
);

router.get("/scans/:scanId", async (req, res) => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    return sendApiError(res, 400, "INVALID_SCAN_ID", "The scan reference is invalid.");
  }
  const result = await fetchWorkerScan(params.data.scanId);
  if (result.kind === "not_found") {
    return sendApiError(res, 404, "SCAN_NOT_FOUND", "This scan is no longer available.");
  }
  if (result.kind === "unavailable") {
    return sendApiError(
      res,
      503,
      "ANALYSIS_WORKER_UNAVAILABLE",
      "The scan status is temporarily unavailable.",
      true,
    );
  }
  const scan = result.scan.latestProgress
    ? {
        ...result.scan,
        latestProgress: {
          ...result.scan.latestProgress,
          message: safeProgressMessage(result.scan.latestProgress.stage),
        },
      }
    : result.scan;
  return res.json(scan);
});

router.post("/scans/:scanId/cancel", async (req, res) => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    sendApiError(res, 400, "INVALID_SCAN_ID", "The scan reference is invalid.");
    return;
  }
  const result = await cancelWorkerScan(params.data.scanId);
  if (result.kind === "not_found") {
    sendApiError(res, 404, "SCAN_NOT_FOUND", "This scan is no longer available.");
    return;
  }
  if (result.kind === "unavailable") {
    sendApiError(
      res,
      503,
      "ANALYSIS_WORKER_UNAVAILABLE",
      "The scan could not be cancelled because the isolated worker is unavailable.",
      true,
    );
    return;
  }
  res.json(result.cancellation);
});

router.get("/scans/:scanId/report", async (req, res) => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    return sendApiError(res, 400, "INVALID_SCAN_ID", "The scan reference is invalid.");
  }
  const result = await fetchWorkerReport(params.data.scanId);
  if (result.kind === "not_found") {
    return sendApiError(res, 404, "REPORT_NOT_FOUND", "This scan report is no longer available.");
  }
  if (result.kind === "unavailable") {
    return sendApiError(
      res,
      503,
      "ANALYSIS_WORKER_UNAVAILABLE",
      "The scan report is temporarily unavailable.",
      true,
    );
  }
  if (result.report.scanId !== params.data.scanId) {
    return sendApiError(res, 502, "INVALID_WORKER_RESPONSE", "The scan report could not be verified.");
  }
  const safeReport = sanitizeEmailReport(result.report);
  const browserToken = getOrCreateBrowserToken(req, res);
  return res.json({
    ...safeReport,
    ...(safeReport.partial
      ? {}
      : { explanationToken: createExplanationToken(safeReport, browserToken) }),
  });
});

router.post(
  "/scans/:scanId/links/:linkId",
  requireReadyWorker,
  async (req, res) => {
    const params = CreateSelectedEmailLinkScanParams.safeParse(req.params);
    const body = CreateSelectedEmailLinkScanBody.safeParse(req.body);
    if (!params.success || !body.success) {
      return sendApiError(
        res,
        400,
        "INVALID_LINK_SCAN",
        "Select one link and confirm consent before scanning it.",
      );
    }
    return createScan(
      req,
      res,
      {
        type: "email_link",
        originalScanId: params.data.scanId,
        linkId: params.data.linkId,
        consent: true,
      },
      CreateSelectedEmailLinkScanResponse,
    );
  },
);

function parseEventBlock(
  block: string,
  expectedScanId: string,
  browserToken: string,
): { id?: string; event: string; data: unknown } | undefined {
  let eventName = "message";
  let eventId: string | undefined;
  const dataLines: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (!line || line.startsWith(":")) continue;
    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    const value =
      separator === -1
        ? ""
        : line.slice(separator + 1).replace(/^ /, "");
    if (field === "event") eventName = value;
    if (field === "id") {
      if (!/^\d{1,10}$/.test(value)) {
        throw new Error("Invalid worker event ID");
      }
      eventId = value;
    }
    if (field === "data") dataLines.push(value);
  }
  if (dataLines.length === 0) return undefined;

  let data: unknown;
  try {
    data = JSON.parse(dataLines.join("\n"));
  } catch {
    throw new Error("Invalid worker event payload");
  }
  const withId = (event: string, eventData: unknown) => ({
    ...(eventId ? { id: eventId } : {}),
    event,
    data: eventData,
  });

  if (eventName === "progress") {
    const progress = ScanProgressSchema.parse(data);
    return withId("progress", {
      ...progress,
      message: safeProgressMessage(progress.stage),
    });
  }
  if (eventName === "completed") {
    const report = ScanReportSchema.parse(data);
    if (report.scanId !== expectedScanId) {
      throw new Error("Worker event scan reference mismatch");
    }
    const safeReport = sanitizeEmailReport(report);
    return withId("completed", {
      ...safeReport,
      explanationToken: createExplanationToken(safeReport, browserToken),
    });
  }
  if (eventName === "review_ready") {
    const ready = ReviewReadyEventSchema.parse(data);
    if (ready.scanId !== expectedScanId) {
      throw new Error("Worker event scan reference mismatch");
    }
    return withId("review_ready", {
      scanId: ready.scanId,
      deadline: ready.deadline,
    });
  }
  if (eventName === "agent_action") {
    return withId("agent_action", AgentActionResultSchema.parse(data));
  }
  if (eventName === "failed") {
    return { ...toPublicWorkerFailureEvent(data), ...(eventId ? { id: eventId } : {}) };
  }
  if (eventName === "cancelled") {
    return { ...toPublicWorkerCancellationEvent(data), ...(eventId ? { id: eventId } : {}) };
  }
  return undefined;
}

function sanitizeEmailReport(report: ScanReportPayload): ScanReportPayload {
  if (report.type !== "email") return report;
  return {
    ...report,
    findings: report.findings.map((finding) => {
      if (finding.source === "email_body") {
        return {
          ...finding,
          title: "Message body indicator",
          explanation:
            "A message-body indicator was detected. The submitted body is not shown.",
          sanitizedObservedValue: null,
          limitations: [],
        };
      }
      if (finding.source === "attachment_metadata") {
        const safeFinding = safeAttachmentFindingCopy(finding.id);
        return {
          ...finding,
          ...safeFinding,
          sanitizedObservedValue: null,
          limitations: [],
        };
      }
      return finding;
    }),
    coverage: {
      ...report.coverage,
      checks: report.coverage.checks.map((check) => ({
        ...check,
        reason: null,
      })),
    },
    links: report.links?.map((link, index) => ({
      ...link,
      anchorText: `Email link ${index + 1}`,
    })),
  };
}

router.get("/scans/:scanId/events", async (req, res) => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    return sendApiError(res, 400, "INVALID_SCAN_ID", "The scan reference is invalid.");
  }

  const controller = new AbortController();
  const hardTimeout = setTimeout(() => controller.abort(), 185_000);
  const browserToken = getOrCreateBrowserToken(req, res);
  const onClose = () => {
    if (!res.writableEnded) controller.abort();
  };
  res.on("close", onClose);

  let heartbeat: NodeJS.Timeout | undefined;
  try {
    const upstream = await openWorkerScanEvents(
      params.data.scanId,
      req.get("last-event-id"),
      controller.signal,
    );
    if (!upstream) {
      return sendApiError(
        res,
        503,
        "ANALYSIS_WORKER_UNAVAILABLE",
        "Live scan updates are temporarily unavailable.",
        true,
      );
    }
    if (upstream.status === 404) {
      return sendApiError(res, 404, "SCAN_NOT_FOUND", "This scan is no longer available.");
    }
    if (
      !upstream.ok ||
      !upstream.body ||
      !upstream.headers.get("content-type")?.toLowerCase().includes("text/event-stream")
    ) {
      return sendApiError(
        res,
        503,
        "ANALYSIS_WORKER_UNAVAILABLE",
        "Live scan updates are temporarily unavailable.",
        true,
      );
    }

    res.status(200).set({
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    res.flushHeaders();
    heartbeat = setInterval(() => res.write(": keep-alive\n\n"), 15_000);

    const reader = upstream.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let done = false;
    while (!done && !controller.signal.aborted) {
      const chunk = await reader.read();
      done = chunk.done;
      buffer += decoder.decode(chunk.value, { stream: !done });
      if (buffer.length > 256 * 1024) {
        throw new Error("Worker event exceeded the stream buffer limit");
      }
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const event = parseEventBlock(block, params.data.scanId, browserToken);
        if (event) {
          res.write(serializePublicSseEvent(event));
          if (isTerminalAnalysisEvent(event.event)) {
            done = true;
            controller.abort();
            break;
          }
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
  } catch {
    if (res.headersSent && !res.writableEnded) {
      res.write(
        `event: failed\ndata: ${JSON.stringify({
          code: "ANALYSIS_STREAM_FAILED",
          message: "Live updates were interrupted. Check scan status before retrying.",
          retryable: true,
        })}\n\n`,
      );
    } else if (!res.headersSent) {
      sendApiError(
        res,
        503,
        "ANALYSIS_WORKER_UNAVAILABLE",
        "Live scan updates are temporarily unavailable.",
        true,
      );
    }
  } finally {
    if (heartbeat) clearInterval(heartbeat);
    clearTimeout(hardTimeout);
    res.off("close", onClose);
    if (!res.writableEnded) res.end();
  }
  return;
});

export default router;
