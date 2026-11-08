import { z } from "zod";

const TOOL_IDS = [
  "url_http_observation",
  "url_static_evidence",
  "url_browser_observation",
  "email_header_analysis",
  "email_body_analysis",
  "email_link_metadata",
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
  if (
    proposal.target === "selected_email_link" &&
    (context.scanType !== "email_link" || !context.hasSelectedEmailLink)
  ) {
    return { ok: false, code: "TARGET_SCOPE_NOT_ALLOWED" };
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

export function createLocalAgentProposal(
  scanType: AgentProposalContext["scanType"],
  hasSelectedEmailLink = scanType === "email_link",
): AgentProposalValidation {
  return validateAgentProposal(LOCAL_PROPOSALS[scanType], {
    scanType,
    hasSelectedEmailLink,
  });
}