import assert from "node:assert/strict";
import test from "node:test";
import { createLocalAgentProposal, validateAgentProposal } from "./agent-orchestration.ts";
import { AgentApprovalStore } from "./agent-approval.ts";

const urlContext = {
  scanType: "url",
  hasSelectedEmailLink: false,
};

test("accepts a reviewed URL tool proposal but keeps it approval-gated", () => {
  const result = validateAgentProposal(
    {
      kind: "tool",
      tool: "url_browser_observation",
      target: "current_scan",
      purpose: "Inspect browser behavior after static signals indicate scripts.",
      requestedFields: ["redirect_chain", "browser_metadata"],
      sendRedactedExcerpt: false,
    },
    urlContext,
  );

  assert.deepEqual(result, {
    ok: true,
    proposal: {
      kind: "tool",
      tool: "url_browser_observation",
      target: "current_scan",
      purpose: "Inspect browser behavior after static signals indicate scripts.",
      requestedFields: ["redirect_chain", "browser_metadata"],
      sendRedactedExcerpt: false,
    },
    requiresApproval: true,
  });
});

test("rejects an unknown tool before dispatch", () => {
  const result = validateAgentProposal(
    {
      kind: "tool",
      tool: "run_shell_command",
      target: "current_scan",
      purpose: "Inspect the target.",
      requestedFields: [],
      sendRedactedExcerpt: false,
    },
    urlContext,
  );

  assert.deepEqual(result, {
    ok: false,
    code: "UNKNOWN_TOOL",
  });
});

test("rejects typed fields that are outside the reviewed catalog", () => {
  const result = validateAgentProposal(
    {
      kind: "data",
      target: "current_scan",
      purpose: "Request more context.",
      fields: ["password"],
      sendRedactedExcerpt: true,
    },
    urlContext,
  );

  assert.deepEqual(result, {
    ok: false,
    code: "UNSUPPORTED_DATA_FIELD",
  });
});

test("rejects an email-link target without a selected link scope", () => {
  const result = validateAgentProposal(
    {
      kind: "tool",
      tool: "url_http_observation",
      target: "selected_email_link",
      purpose: "Inspect the selected link.",
      requestedFields: ["redirect_chain"],
      sendRedactedExcerpt: false,
    },
    urlContext,
  );

  assert.deepEqual(result, {
    ok: false,
    code: "TARGET_SCOPE_NOT_ALLOWED",
  });
});

test("accepts a typed email request only for the email scan catalog", () => {
  const result = validateAgentProposal(
    {
      kind: "data",
      target: "current_scan",
      purpose: "Summarize authentication header coverage.",
      fields: ["authentication_results", "header_metadata"],
      sendRedactedExcerpt: true,
    },
    {
      scanType: "email",
      hasSelectedEmailLink: false,
    },
  );

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.requiresApproval, true);
    assert.equal(result.proposal.sendRedactedExcerpt, true);
  }
});

test("keeps an approval request single-use and bound to its scan", () => {
  const store = new AgentApprovalStore({ now: () => 1_000 });
  const proposal = {
    kind: "tool",
    tool: "url_http_observation",
    target: "current_scan",
    purpose: "Inspect the current redirect chain.",
    requestedFields: ["redirect_chain"],
    sendRedactedExcerpt: false,
  };
  const request = store.create("scan-a", proposal);

  assert.equal(store.resolve("scan-b", request.requestId, "approve").code, "SCAN_MISMATCH");
  assert.equal(store.resolve("scan-a", request.requestId, "decline").status, "declined");
  assert.equal(store.resolve("scan-a", request.requestId, "approve").code, "REQUEST_NOT_PENDING");
});

test("expires pending approvals at the hard scan lifetime", () => {
  let now = 1_000;
  const store = new AgentApprovalStore({ now: () => now });
  const request = store.create("scan-a", {
    kind: "data",
    target: "current_scan",
    purpose: "Request the coverage summary.",
    fields: ["coverage_summary"],
    sendRedactedExcerpt: false,
  });

  now = request.expiresAt + 1;

  assert.equal(store.get("scan-a", request.requestId)?.status, "expired");
  assert.equal(store.resolve("scan-a", request.requestId, "approve").code, "REQUEST_NOT_PENDING");
});

test("cancels only pending approvals for a scan", () => {
  const store = new AgentApprovalStore({ now: () => 1_000 });
  const first = store.create("scan-a", {
    kind: "data",
    target: "current_scan",
    purpose: "Request the coverage summary.",
    fields: ["coverage_summary"],
    sendRedactedExcerpt: false,
  });
  const second = store.create("scan-a", {
    kind: "tool",
    tool: "url_static_evidence",
    target: "current_scan",
    purpose: "Review static signals.",
    requestedFields: ["static_page_signals"],
    sendRedactedExcerpt: false,
  });
  store.resolve("scan-a", first.requestId, "approve");

  assert.equal(store.cancelPending("scan-a"), 1);
  assert.equal(store.get("scan-a", first.requestId)?.status, "approved");
  assert.equal(store.get("scan-a", second.requestId)?.status, "cancelled");
});

test("binds approval resolution to the browser that received it", () => {
  const store = new AgentApprovalStore({ now: () => 1_000 });
  const request = store.create("scan-a", {
    kind: "tool",
    tool: "url_http_observation",
    target: "current_scan",
    purpose: "Inspect the current redirect chain.",
    requestedFields: ["redirect_chain"],
    sendRedactedExcerpt: false,
  }, "browser-a");

  assert.equal(
    store.resolve("scan-a", request.requestId, "approve", "browser-b").code,
    "BROWSER_MISMATCH",
  );
  assert.equal(
    store.resolve("scan-a", request.requestId, "approve", "browser-a").status,
    "approved",
  );
});

test("creates a deterministic URL proposal through the same validator", () => {
  const result = createLocalAgentProposal("url");

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.proposal.kind, "tool");
    assert.equal(result.proposal.tool, "url_browser_observation");
    assert.equal(result.requiresApproval, true);
  }
});

test("creates a typed email proposal without requesting raw message content", () => {
  const result = createLocalAgentProposal("email");

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.deepEqual(result.proposal, {
      kind: "data",
      target: "current_scan",
      purpose: "Request authentication and header coverage.",
      fields: ["authentication_results", "header_metadata"],
      sendRedactedExcerpt: true,
    });
  }
});