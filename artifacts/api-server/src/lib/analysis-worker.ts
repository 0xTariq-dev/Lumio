import { isIP } from "node:net";
import { z } from "zod";
import { GetScanResponse } from "@workspace/api-zod";

type ScanSnapshot = z.infer<typeof GetScanResponse>;

const WorkerHealthSchema = z.object({
  status: z.literal("ready"),
  queue: z.object({
    active: z.number().int().min(0),
    queued: z.number().int().min(0),
  }),
});

const WorkerAcceptedSchema = z.object({
  accepted: z.literal(true),
  status: z.enum(["queued", "running"]),
});

const WorkerCancellationSchema = z.object({
  scanId: z.uuid(),
  cancelled: z.boolean(),
  status: z.enum(["queued", "running", "awaiting_review", "completed", "failed", "cancelled"]),
});

const WorkerFindingSchema = z.object({
  id: z.string(),
  title: z.string(),
  explanation: z.string(),
  severity: z.enum(["informational", "low", "moderate", "high", "critical"]),
  strength: z.enum(["direct", "contextual"]),
  source: z.enum(["url_navigation", "browser", "email_headers", "email_body", "attachment_metadata"]),
  sanitizedObservedValue: z.string().nullable().optional(),
  limitations: z.array(z.string()).optional(),
});

export const AGENT_WORKER_TOOLS = [
  "link_metadata_share",
  "email_link_visit",
  "url_browser_observation",
] as const;
export type AgentWorkerTool = (typeof AGENT_WORKER_TOOLS)[number];

export const AgentActionResultSchema = z.object({
  actionId: z.uuid(),
  tool: z.enum(AGENT_WORKER_TOOLS),
  status: z.enum(["running", "completed", "skipped", "blocked", "failed"]),
  reasonCode: z.enum([
    "declined",
    "expired",
    "cancelled",
    "timed_out",
    "insufficient_time",
    "link_unavailable",
    "browser_not_eligible",
    "analysis_failed",
  ]).optional(),
  targetHost: z.string().max(253).optional(),
  riskBand: z.enum(["low", "moderate", "high", "critical", "inconclusive"]).optional(),
  findings: z.array(z.object({
    id: z.string().max(120),
    title: z.string().max(100),
    explanation: z.string().max(500),
    severity: z.enum(["informational", "low", "moderate", "high", "critical"]),
    strength: z.enum(["direct", "contextual"]),
    source: z.enum(["url_navigation", "browser", "email_headers", "email_body", "attachment_metadata"]),
    sanitizedObservedValue: z.string().max(300).nullable().optional(),
    limitations: z.array(z.string().max(200)).max(20).optional(),
  }).strict()).max(25).optional(),
  coverageSufficient: z.boolean().optional(),
}).strict();
export type AgentActionResult = z.infer<typeof AgentActionResultSchema>;

export const ReviewReadyEventSchema = z.object({
  scanId: z.uuid(),
  deadline: z.iso.datetime({ offset: true }),
  linkCount: z.number().int().min(0).max(50),
}).strict();

const WorkerReportSchema = z.object({
  scanId: z.uuid(),
  type: z.enum(["url", "email", "email_link"]),
  riskBand: z.enum(["low", "moderate", "high", "critical", "inconclusive"]),
  completedAt: z.string(),
  ruleSetVersion: z.string(),
  partial: z.boolean().optional(),
  partialReason: z.string().max(200).optional(),
  findings: z.array(WorkerFindingSchema),
  agentActions: z.array(AgentActionResultSchema).max(3).optional(),
  coverage: z.object({
    sufficient: z.boolean(),
    checks: z.array(z.object({
      name: z.string(),
      status: z.enum(["completed", "skipped", "blocked", "failed"]),
      reason: z.string().nullable().optional(),
    })),
  }),
  softwareEvidence: z.array(z.object({
    product: z.enum(["WordPress"]),
    version: z.string().max(30).nullable().optional(),
    evidenceStrength: z.enum(["strong", "weak", "ambiguous"]),
    evidenceSource: z.enum(["html_generator_and_wp_asset_path", "html_generator_only", "wp_asset_path_only"]),
  })).max(10).optional(),
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
  links: z.array(z.object({
    linkId: z.uuid(),
    anchorText: z.string().max(200),
    displayUrl: z.string().max(300),
    targetHost: z.string().max(253),
    scanAvailable: z.boolean(),
  })).max(50).optional(),
});

export type WorkerReport = z.infer<typeof WorkerReportSchema>;

const WorkerReviewSchema = z.object({
  scanId: z.uuid(),
  type: z.enum(["url", "email"]),
  deadline: z.iso.datetime({ offset: true }),
  report: WorkerReportSchema,
  actions: z.array(AgentActionResultSchema).max(3),
  linkCandidates: z.array(z.object({
    linkId: z.uuid(),
    host: z.string().min(1).max(253),
  }).strict()).max(50),
  linkMetadataShared: z.boolean(),
  browserEligible: z.boolean(),
  busy: z.boolean(),
  linkContext: z.array(z.object({
    linkId: z.uuid(),
    host: z.string().max(253),
    path: z.string().max(400),
    anchor: z.string().max(80),
  }).strict()).max(50).optional(),
}).strict();

export type WorkerReview = z.infer<typeof WorkerReviewSchema>;

export type WorkerReviewCommand =
  | { command: "run"; actionId: string; tool: AgentWorkerTool; linkId?: string }
  | {
      command: "skip";
      actionId: string;
      tool: AgentWorkerTool;
      reason: "declined" | "expired" | "cancelled";
    }
  | { command: "finalize" };

export type WorkerHealth = z.infer<typeof WorkerHealthSchema>;

export type WorkerScanInput =
  | { scanId: string; type: "url"; url: string; consent: true; agentReview?: boolean }
  | {
      scanId: string;
      type: "email";
      emailBase64: string;
      consent: true;
      agentReview?: boolean;
    }
  | {
      scanId: string;
      type: "email_link";
      originalScanId: string;
      linkId: string;
      consent: true;
    };

export type WorkerScanPayload =
  | { type: "url"; url: string; consent: true; agentReview?: boolean }
  | { type: "email"; emailBase64: string; consent: true; agentReview?: boolean }
  | {
      type: "email_link";
      originalScanId: string;
      linkId: string;
      consent: true;
    };

type WorkerConfig = { baseUrl: URL; token: string };
type WorkerPostResult =
  | { kind: "accepted"; status: "queued" | "running" }
  | { kind: "rejected"; status: number }
  | { kind: "unavailable" };

function isLoopbackOrLocal(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local")
  ) {
    return true;
  }

  const ipVersion = isIP(normalized);
  if (ipVersion === 4) {
    const first = Number(normalized.split(".")[0]);
    return (
      first === 0 ||
      first === 127 ||
      first >= 224 ||
      normalized.startsWith("169.254.")
    );
  }
  if (ipVersion === 6) {
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fe80:") ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd")
    );
  }
  return false;
}

function loadWorkerConfig(): WorkerConfig | undefined {
  const rawUrl = process.env.ANALYSIS_WORKER_URL;
  const token = process.env.ANALYSIS_WORKER_TOKEN;
  if (!rawUrl || !token || token.length < 32) return undefined;

  try {
    const baseUrl = new URL(rawUrl);
    if (
      baseUrl.protocol !== "https:" ||
      baseUrl.username ||
      baseUrl.password ||
      baseUrl.search ||
      baseUrl.hash ||
      baseUrl.pathname !== "/" ||
      isLoopbackOrLocal(baseUrl.hostname)
    ) {
      return undefined;
    }

    return { baseUrl, token };
  } catch {
    return undefined;
  }
}

function endpointUrl(baseUrl: URL, path: string): URL {
  return new URL(path, baseUrl);
}

function workerHeaders(token: string, accept = "application/json") {
  return {
    authorization: `Bearer ${token}`,
    accept,
  };
}

export async function getAnalysisWorkerHealth(): Promise<
  WorkerHealth | undefined
> {
  const config = loadWorkerConfig();
  if (!config) return undefined;

  try {
    const response = await fetch(endpointUrl(config.baseUrl, "/healthz"), {
      headers: workerHeaders(config.token),
      signal: AbortSignal.timeout(2_500),
    });
    if (!response.ok) return undefined;
    const parsed = WorkerHealthSchema.safeParse(await response.json());
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

export async function postWorkerScan(
  input: WorkerScanInput,
): Promise<WorkerPostResult> {
  const config = loadWorkerConfig();
  if (!config) return { kind: "unavailable" };

  const requestTimeoutMs = input.type === "email" ? 20_000 : 7_500;
  try {
    const response = await fetch(
      endpointUrl(config.baseUrl, "/v1/scans"),
      {
        method: "POST",
        headers: {
          ...workerHeaders(config.token),
          "content-type": "application/json",
        },
        body: JSON.stringify(input),
        signal: AbortSignal.timeout(requestTimeoutMs),
      },
    );
    if (response.status === 429) return { kind: "rejected", status: 429 };
    if (response.status >= 400 && response.status < 500) {
      return { kind: "rejected", status: response.status };
    }
    if (!response.ok) return { kind: "unavailable" };

    const parsed = WorkerAcceptedSchema.safeParse(await response.json());
    if (!parsed.success) return { kind: "unavailable" };
    return { kind: "accepted", status: parsed.data.status };
  } catch {
    return { kind: "unavailable" };
  }
}

export async function fetchWorkerScan(
  scanId: string,
): Promise<
  | { kind: "found"; scan: ScanSnapshot }
  | { kind: "not_found" }
  | { kind: "unavailable" }
> {
  const config = loadWorkerConfig();
  if (!config) return { kind: "unavailable" };

  try {
    const response = await fetch(
      endpointUrl(config.baseUrl, `/v1/scans/${encodeURIComponent(scanId)}`),
      {
        headers: workerHeaders(config.token),
        signal: AbortSignal.timeout(3_000),
      },
    );
    if (response.status === 404) return { kind: "not_found" };
    if (!response.ok) return { kind: "unavailable" };

    const parsed = GetScanResponse.safeParse(await response.json());
    if (!parsed.success) return { kind: "unavailable" };
    return { kind: "found", scan: parsed.data };
  } catch {
    return { kind: "unavailable" };
  }
}

export async function cancelWorkerScan(
  scanId: string,
): Promise<
  | { kind: "found"; cancellation: z.infer<typeof WorkerCancellationSchema> }
  | { kind: "not_found" }
  | { kind: "unavailable" }
> {
  const config = loadWorkerConfig();
  if (!config) return { kind: "unavailable" };
  try {
    const response = await fetch(
      endpointUrl(config.baseUrl, `/v1/scans/${encodeURIComponent(scanId)}/cancel`),
      {
        method: "POST",
        headers: workerHeaders(config.token),
        signal: AbortSignal.timeout(3_000),
      },
    );
    if (response.status === 404) return { kind: "not_found" };
    if (!response.ok) return { kind: "unavailable" };
    const parsed = WorkerCancellationSchema.safeParse(await response.json());
    return parsed.success
      ? { kind: "found", cancellation: parsed.data }
      : { kind: "unavailable" };
  } catch {
    return { kind: "unavailable" };
  }
}

export async function fetchWorkerReport(
  scanId: string,
): Promise<
  | { kind: "found"; report: WorkerReport }
  | { kind: "not_found" }
  | { kind: "unavailable" }
> {
  const config = loadWorkerConfig();
  if (!config) return { kind: "unavailable" };
  try {
    const response = await fetch(endpointUrl(config.baseUrl, `/v1/scans/${encodeURIComponent(scanId)}/report`), {
      headers: workerHeaders(config.token),
      signal: AbortSignal.timeout(3_000),
    });
    if (response.status === 404) return { kind: "not_found" };
    if (!response.ok) return { kind: "unavailable" };
    const parsed = WorkerReportSchema.safeParse(await response.json());
    return parsed.success ? { kind: "found", report: parsed.data } : { kind: "unavailable" };
  } catch {
    return { kind: "unavailable" };
  }
}

export async function fetchWorkerReview(
  scanId: string,
): Promise<
  | { kind: "found"; review: WorkerReview }
  | { kind: "not_found" }
  | { kind: "not_reviewing" }
  | { kind: "unavailable" }
> {
  const config = loadWorkerConfig();
  if (!config) return { kind: "unavailable" };
  try {
    const response = await fetch(
      endpointUrl(config.baseUrl, `/v1/scans/${encodeURIComponent(scanId)}/review`),
      {
        headers: workerHeaders(config.token),
        signal: AbortSignal.timeout(3_000),
      },
    );
    if (response.status === 404) return { kind: "not_found" };
    if (response.status === 409) return { kind: "not_reviewing" };
    if (!response.ok) return { kind: "unavailable" };
    const parsed = WorkerReviewSchema.safeParse(await response.json());
    if (!parsed.success || parsed.data.scanId !== scanId) return { kind: "unavailable" };
    return { kind: "found", review: parsed.data };
  } catch {
    return { kind: "unavailable" };
  }
}

const WorkerErrorSchema = z.object({
  error: z.object({ code: z.string().max(80) }),
});

export async function postWorkerReviewCommand(
  scanId: string,
  command: WorkerReviewCommand,
): Promise<
  | { kind: "accepted" }
  | { kind: "rejected"; status: number; code: string }
  | { kind: "unavailable" }
> {
  const config = loadWorkerConfig();
  if (!config) return { kind: "unavailable" };
  try {
    const response = await fetch(
      endpointUrl(config.baseUrl, `/v1/scans/${encodeURIComponent(scanId)}/review/commands`),
      {
        method: "POST",
        headers: {
          ...workerHeaders(config.token),
          "content-type": "application/json",
        },
        body: JSON.stringify(command),
        signal: AbortSignal.timeout(3_000),
      },
    );
    if (response.status === 202) return { kind: "accepted" };
    if (response.status >= 400 && response.status < 500) {
      const parsed = WorkerErrorSchema.safeParse(await response.json().catch(() => null));
      return {
        kind: "rejected",
        status: response.status,
        code: parsed.success ? parsed.data.error.code : "REJECTED",
      };
    }
    return { kind: "unavailable" };
  } catch {
    return { kind: "unavailable" };
  }
}

export async function openWorkerScanEvents(
  scanId: string,
  lastEventId: string | undefined,
  signal: AbortSignal,
): Promise<Response | undefined> {
  const config = loadWorkerConfig();
  if (!config) return undefined;

  try {
    const headers = workerHeaders(config.token, "text/event-stream");
    if (lastEventId && /^[\w-]{1,128}$/.test(lastEventId)) {
      Object.assign(headers, { "last-event-id": lastEventId });
    }
    return await fetch(
      endpointUrl(
        config.baseUrl,
        `/v1/scans/${encodeURIComponent(scanId)}/events`,
      ),
      { headers, signal },
    );
  } catch {
    return undefined;
  }
}
