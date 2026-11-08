import {
  type AgentProposalContext,
  type AgentProposalValidation,
  validateAgentProposal,
} from "./agent-orchestration.ts";

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