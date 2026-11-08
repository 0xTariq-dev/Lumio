import { z } from "zod";

const TOOL_IDS = [
  "url_http_observation",
  "url_static_evidence",
  "url_browser_observation",
  "email_header_analysis",
  "email_body_analysis",
  "email_link_metadata",
  "email_link_visit",
] as const;

const DATA_FIELDS = [
  "redirect_chain",
  "browser_metadata",
  "static_page_signals",
  "coverage_summary",
  "authentication_results",
  "header_metadata",
  "body_indicators",
  "link_metadata",
] as const;

const proposalSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("tool"),
      tool: z.string().trim().min(1).max(80),
      target: z.enum(["current_scan", "selected_email_link"]),
      purpose: z.string().trim().min(1).max(240),
      requestedFields: z.array(z.string().trim().min(1).max(80)).max(8),
      sendRedactedExcerpt: z.boolean(),
      linkId: z.uuid().optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("data"),
      target: z.enum(["current_scan", "selected_email_link"]),
      purpose: z.string().trim().min(1).max(240),
      fields: z.array(z.string().trim().min(1).max(80)).min(1).max(4),
      sendRedactedExcerpt: z.boolean(),
    })
    .strict(),
]);

const URL_TOOLS = new Set([
  "url_http_observation",
  "url_static_evidence",
  "url_browser_observation",
]);
const EMAIL_TOOLS = new Set([
  "email_header_analysis",
  "email_body_analysis",
  "email_link_metadata",
  "email_link_visit",
]);
const URL_FIELDS = new Set([
  "redirect_chain",
  "browser_metadata",
  "static_page_signals",
  "coverage_summary",
]);
const EMAIL_FIELDS = new Set([
  "authentication_results",
  "header_metadata",
  "body_indicators",
  "link_metadata",
]);

export type AgentScanType = "url" | "email" | "email_link";

export interface AgentProposalContext {
  scanType: AgentScanType;
  hasSelectedEmailLink: boolean;
  /** Link ids the worker reported as scan-available for this review. */
  allowedLinkIds?: readonly string[];
}

export type AgentProposal = z.infer<typeof proposalSchema>;

export type AgentProposalValidation =
  | {
      ok: true;
      proposal: AgentProposal;
      requiresApproval: true;
    }
  | {
      ok: false;
      code:
        | "MALFORMED_PROPOSAL"
        | "UNKNOWN_TOOL"
        | "UNSUPPORTED_DATA_FIELD"
        | "TARGET_SCOPE_NOT_ALLOWED"
        | "TOOL_NOT_ALLOWED_FOR_SCAN";
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasUnknownValue(values: unknown, allowed: Set<string>): boolean {
  return Array.isArray(values)
    ? values.some((value) => typeof value !== "string" || !allowed.has(value))
    : false;
}

export function validateAgentProposal(
  input: unknown,
  context: AgentProposalContext,
): AgentProposalValidation {
  if (!isRecord(input)) return { ok: false, code: "MALFORMED_PROPOSAL" };

  if (
    input.kind === "tool" &&
    typeof input.tool === "string" &&
    !TOOL_IDS.includes(input.tool as (typeof TOOL_IDS)[number])
  ) {
    return { ok: false, code: "UNKNOWN_TOOL" };
  }

  if (
    input.kind === "data" &&
    hasUnknownValue(input.fields, new Set(DATA_FIELDS))
  ) {
    return { ok: false, code: "UNSUPPORTED_DATA_FIELD" };
  }

  const parsed = proposalSchema.safeParse(input);
  if (!parsed.success) return { ok: false, code: "MALFORMED_PROPOSAL" };

  const proposal = parsed.data;
  if (proposal.kind === "tool" && proposal.tool === "email_link_visit") {
    // The model may only pick a link id the worker itself listed.
    if (
      context.scanType !== "email" ||
      proposal.target !== "selected_email_link" ||
      !proposal.linkId ||
      !context.allowedLinkIds?.includes(proposal.linkId)
    ) {
      return { ok: false, code: "TARGET_SCOPE_NOT_ALLOWED" };
    }
  } else {
    if (proposal.kind === "tool" && proposal.linkId !== undefined) {
      return { ok: false, code: "MALFORMED_PROPOSAL" };
    }
    if (
      proposal.target === "selected_email_link" &&
      (context.scanType !== "email_link" || !context.hasSelectedEmailLink)
    ) {
      return { ok: false, code: "TARGET_SCOPE_NOT_ALLOWED" };
    }
  }

  const allowedTools = context.scanType === "email" ? EMAIL_TOOLS : URL_TOOLS;
  if (proposal.kind === "tool") {
    if (!allowedTools.has(proposal.tool)) {
      return { ok: false, code: "TOOL_NOT_ALLOWED_FOR_SCAN" };
    }
    const allowedFields = context.scanType === "email" ? EMAIL_FIELDS : URL_FIELDS;
    if (hasUnknownValue(proposal.requestedFields, allowedFields)) {
      return { ok: false, code: "UNSUPPORTED_DATA_FIELD" };
    }
  } else {
    const allowedFields = context.scanType === "email" ? EMAIL_FIELDS : URL_FIELDS;
    if (hasUnknownValue(proposal.fields, allowedFields)) {
      return { ok: false, code: "UNSUPPORTED_DATA_FIELD" };
    }
  }

  return {
    ok: true,
    proposal,
    requiresApproval: true,
  };
}

const LOCAL_PROPOSALS: Record<AgentProposalContext["scanType"], unknown> = {
  url: {
    kind: "tool",
    tool: "url_browser_observation",
    target: "current_scan",
    purpose: "Inspect browser behavior after the baseline evidence.",
    requestedFields: ["browser_metadata", "coverage_summary"],
    sendRedactedExcerpt: false,
  },
  email: {
    kind: "data",
    target: "current_scan",
    purpose: "Request authentication and header coverage.",
    fields: ["authentication_results", "header_metadata"],
    sendRedactedExcerpt: true,
  },
  email_link: {
    kind: "tool",
    tool: "url_http_observation",
    target: "selected_email_link",
    purpose: "Inspect the selected email link redirect chain.",
    requestedFields: ["redirect_chain", "coverage_summary"],
    sendRedactedExcerpt: false,
  },
};

export type ReviewWorkerTool =
  | "link_metadata_share"
  | "email_link_visit"
  | "url_browser_observation";

/** Map an approved proposal to the only worker step it authorizes. */
export function workerToolForProposal(proposal: AgentProposal): ReviewWorkerTool | null {
  if (proposal.kind === "data") {
    return proposal.fields.length === 1 && proposal.fields[0] === "link_metadata"
      ? "link_metadata_share"
      : null;
  }
  if (proposal.tool === "email_link_visit") return "email_link_visit";
  if (proposal.tool === "url_browser_observation") return "url_browser_observation";
  return null;
}

export interface ReviewPlanInput {
  scanType: "url" | "email";
  linkCandidates: readonly { linkId: string; host: string }[];
  linkMetadataShared: boolean;
  browserEligible: boolean;
  usedTools: readonly string[];
  inferenceEnabled: boolean;
}

export type ReviewPlanStep = "share_links" | "visit_link" | "browser" | "finish";

/** Bounded, deterministic order of follow-up steps for one paused scan. */
export function nextReviewStep(input: ReviewPlanInput): ReviewPlanStep {
  const used = new Set(input.usedTools);
  if (input.scanType === "url") {
    return input.browserEligible && !used.has("url_browser_observation") ? "browser" : "finish";
  }
  if (!input.linkCandidates.length || used.has("email_link_visit")) return "finish";
  // Sharing link details is only asked when they would leave for Vultr.
  if (input.inferenceEnabled && !input.linkMetadataShared) {
    return used.has("link_metadata_share") ? "finish" : "share_links";
  }
  return "visit_link";
}

export function shareLinksProposal(): unknown {
  return {
    kind: "data",
    target: "current_scan",
    purpose:
      "Share redacted link details (host, path, and link text) with Vultr so the agent can suggest one link to inspect. Queries and secrets are removed.",
    fields: ["link_metadata"],
    sendRedactedExcerpt: true,
  };
}

export function localLinkVisitProposal(
  candidates: readonly { linkId: string; host: string }[],
): unknown {
  const first = candidates[0];
  return {
    kind: "tool",
    tool: "email_link_visit",
    target: "selected_email_link",
    linkId: first?.linkId,
    purpose: "Visit one link from this email in the isolated worker and report what the page shows.",
    requestedFields: ["link_metadata"],
    sendRedactedExcerpt: false,
  };
}

export function browserFollowUpProposal(): unknown {
  return {
    kind: "tool",
    tool: "url_browser_observation",
    target: "current_scan",
    purpose:
      "Open the page in an isolated browser. The first check skipped this because the page had no scripts.",
    requestedFields: ["browser_metadata", "coverage_summary"],
    sendRedactedExcerpt: false,
  };
}

export function createLocalAgentProposal(
  scanType: AgentProposalContext["scanType"],
  hasSelectedEmailLink = scanType === "email_link",
): AgentProposalValidation {
  return validateAgentProposal(LOCAL_PROPOSALS[scanType], {
    scanType,
    hasSelectedEmailLink,
  });
}