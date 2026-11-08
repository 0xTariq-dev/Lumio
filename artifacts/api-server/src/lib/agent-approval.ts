import { createHash, randomUUID } from "node:crypto";
import type { AgentProposal } from "./agent-orchestration";

const MAX_APPROVAL_LIFETIME_MS = 180_000;

export type AgentApprovalStatus =
  | "pending"
  | "approved"
  | "declined"
  | "cancelled"
  | "expired";

export type AgentApprovalDecision = "approve" | "decline";

export interface AgentApprovalRequest {
  requestId: string;
  scanId: string;
  proposal: AgentProposal;
  status: AgentApprovalStatus;
  createdAt: number;
  expiresAt: number;
  browserBinding?: string;
  /** Destination host for an email-link visit, from the worker's link list. */
  targetLabel?: string;
}

export interface AgentApprovalCreateOptions {
  /** Absolute epoch ms; the request never outlives the scan's hard cap. */
  deadline?: number;
  targetLabel?: string;
}

export interface AgentApprovalEvent {
  type: "approval_required" | "approval_resolved";
  data: {
    requestId: string;
    scanId: string;
    proposal: AgentProposal;
    status: AgentApprovalStatus;
    expiresAt: string;
    targetLabel?: string;
  };
}

export type AgentApprovalResolution =
  | AgentApprovalRequest
  | {
    code:
      | "BROWSER_MISMATCH"
      | "SCAN_MISMATCH"
      | "REQUEST_NOT_FOUND"
      | "REQUEST_NOT_PENDING";
    };

export class AgentApprovalStore {
  private readonly records = new Map<string, AgentApprovalRequest>();
  private readonly listeners = new Map<string, Set<(event: AgentApprovalEvent) => void>>();
  private readonly now: () => number;
  private readonly lifetimeMs: number;

  constructor(options: { now?: () => number; lifetimeMs?: number } = {}) {
    this.now = options.now ?? Date.now;
    this.lifetimeMs = Math.min(
      Math.max(1, options.lifetimeMs ?? MAX_APPROVAL_LIFETIME_MS),
      MAX_APPROVAL_LIFETIME_MS,
    );
  }

  create(
    scanId: string,
    proposal: AgentProposal,
    browserToken?: string,
    options: AgentApprovalCreateOptions = {},
  ): AgentApprovalRequest {
    const createdAt = this.now();
    const lifetimeEnd = createdAt + this.lifetimeMs;
    const request = {
      requestId: randomUUID(),
      scanId,
      proposal,
      status: "pending" as const,
      createdAt,
      expiresAt:
        options.deadline !== undefined && Number.isFinite(options.deadline)
          ? Math.min(lifetimeEnd, options.deadline)
          : lifetimeEnd,
      ...(browserToken ? { browserBinding: bindBrowser(browserToken) } : {}),
      ...(options.targetLabel ? { targetLabel: options.targetLabel } : {}),
    };
    this.records.set(request.requestId, request);
    this.publish({ type: "approval_required", data: this.eventData(request) });
    return request;
  }

  subscribe(
    scanId: string,
    browserToken: string,
    listener: (event: AgentApprovalEvent) => void,
  ): () => void {
    const key = `${scanId}:${bindBrowser(browserToken)}`;
    const listeners = this.listeners.get(key) ?? new Set();
    listeners.add(listener);
    this.listeners.set(key, listeners);
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) this.listeners.delete(key);
    };
  }

  /** The still-pending request for this scan and browser, if any. */
  findPending(scanId: string, browserToken: string): AgentApprovalRequest | undefined {
    const binding = bindBrowser(browserToken);
    for (const request of this.records.values()) {
      if (request.scanId !== scanId || request.browserBinding !== binding) continue;
      this.expireIfNeeded(request);
      if (request.status === "pending") return request;
    }
    return undefined;
  }

  /** Pending requests for a scan, read before cancelling them. */
  pendingForScan(scanId: string, browserToken?: string): AgentApprovalRequest[] {
    const result: AgentApprovalRequest[] = [];
    for (const request of this.records.values()) {
      if (request.scanId !== scanId) continue;
      if (
        request.browserBinding &&
        (!browserToken || request.browserBinding !== bindBrowser(browserToken))
      ) {
        continue;
      }
      this.expireIfNeeded(request);
      if (request.status === "pending") result.push(request);
    }
    return result;
  }

  get(scanId: string, requestId: string): AgentApprovalRequest | undefined {
    const request = this.records.get(requestId);
    if (!request || request.scanId !== scanId) return undefined;
    this.expireIfNeeded(request);
    return request;
  }

  resolve(
    scanId: string,
    requestId: string,
    decision: AgentApprovalDecision,
    browserToken?: string,
  ): AgentApprovalResolution {
    const request = this.records.get(requestId);
    if (!request) return { code: "REQUEST_NOT_FOUND" };
    if (request.scanId !== scanId) return { code: "SCAN_MISMATCH" };
    if (
      request.browserBinding &&
      (!browserToken || request.browserBinding !== bindBrowser(browserToken))
    ) {
      return { code: "BROWSER_MISMATCH" };
    }
    this.expireIfNeeded(request);
    if (request.status !== "pending") return { code: "REQUEST_NOT_PENDING" };
    request.status = decision === "approve" ? "approved" : "declined";
    this.publish({ type: "approval_resolved", data: this.eventData(request) });
    return request;
  }

  cancelPending(scanId: string, browserToken?: string): number {
    let cancelled = 0;
    for (const request of this.records.values()) {
      if (request.scanId !== scanId) continue;
      if (
        request.browserBinding &&
        (!browserToken || request.browserBinding !== bindBrowser(browserToken))
      ) {
        continue;
      }
      this.expireIfNeeded(request);
      if (request.status !== "pending") continue;
      request.status = "cancelled";
      this.publish({ type: "approval_resolved", data: this.eventData(request) });
      cancelled += 1;
    }
    return cancelled;
  }

  private expireIfNeeded(request: AgentApprovalRequest): void {
    if (request.status === "pending" && this.now() >= request.expiresAt) {
      request.status = "expired";
    }
  }

  private eventData(request: AgentApprovalRequest): AgentApprovalEvent["data"] {
    return {
      requestId: request.requestId,
      scanId: request.scanId,
      proposal: request.proposal,
      status: request.status,
      expiresAt: new Date(request.expiresAt).toISOString(),
      ...(request.targetLabel ? { targetLabel: request.targetLabel } : {}),
    };
  }

  /** Drop resolved records older than the hard cap so memory stays bounded. */
  prune(): void {
    const cutoff = this.now() - MAX_APPROVAL_LIFETIME_MS * 2;
    for (const [requestId, request] of this.records) {
      this.expireIfNeeded(request);
      if (request.status !== "pending" && request.createdAt < cutoff) {
        this.records.delete(requestId);
      }
    }
  }

  private publish(event: AgentApprovalEvent): void {
    const request = this.records.get(event.data.requestId);
    if (!request?.browserBinding) return;
    const listeners = this.listeners.get(`${request.scanId}:${request.browserBinding}`);
    listeners?.forEach((listener) => listener(event));
  }
}

function bindBrowser(browserToken: string): string {
  return createHash("sha256").update(browserToken).digest("hex");
}

export const agentApprovalStore = new AgentApprovalStore();

export function createAgentApprovalRequest(
  scanId: string,
  proposal: AgentProposal,
  browserToken: string,
  options: AgentApprovalCreateOptions = {},
): AgentApprovalRequest {
  agentApprovalStore.prune();
  return agentApprovalStore.create(scanId, proposal, browserToken, options);
}