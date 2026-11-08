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
  ): AgentApprovalRequest {
    const createdAt = this.now();
    const request = {
      requestId: randomUUID(),
      scanId,
      proposal,
      status: "pending" as const,
      createdAt,
      expiresAt: createdAt + this.lifetimeMs,
      ...(browserToken ? { browserBinding: bindBrowser(browserToken) } : {}),
    };
    this.records.set(request.requestId, request);
    return request;
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
      cancelled += 1;
    }
    return cancelled;
  }

  private expireIfNeeded(request: AgentApprovalRequest): void {
    if (request.status === "pending" && this.now() >= request.expiresAt) {
      request.status = "expired";
    }
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
): AgentApprovalRequest {
  return agentApprovalStore.create(scanId, proposal, browserToken);
}