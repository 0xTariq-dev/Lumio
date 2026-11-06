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

export type WorkerHealth = z.infer<typeof WorkerHealthSchema>;

export type WorkerScanInput =
  | { scanId: string; type: "url"; url: string; consent: true }
  | {
      scanId: string;
      type: "email";
      emailBase64: string;
      consent: true;
    }
  | {
      scanId: string;
      type: "email_link";
      originalScanId: string;
      linkId: string;
      consent: true;
    };

export type WorkerScanPayload =
  | { type: "url"; url: string; consent: true }
  | { type: "email"; emailBase64: string; consent: true }
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

function isPrivateIpv4(hostname: string): boolean {
  const parts = hostname.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return false;
  }
  const [first, second] = parts;
  return (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}

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
      !["https:", "http:"].includes(baseUrl.protocol) ||
      baseUrl.username ||
      baseUrl.password ||
      baseUrl.search ||
      baseUrl.hash ||
      baseUrl.pathname !== "/" ||
      isLoopbackOrLocal(baseUrl.hostname)
    ) {
      return undefined;
    }

    const isPrivateAddress =
      isIP(baseUrl.hostname) === 4 && isPrivateIpv4(baseUrl.hostname);
    const isPrivateServiceName =
      !baseUrl.hostname.includes(".") ||
      baseUrl.hostname.toLowerCase().endsWith(".internal");
    if (
      baseUrl.protocol === "http:" &&
      !isPrivateAddress &&
      !isPrivateServiceName
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
        signal: AbortSignal.timeout(7_500),
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
