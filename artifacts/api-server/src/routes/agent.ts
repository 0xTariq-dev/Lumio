import { Router, type IRouter } from "express";
import { z } from "zod";
import { getOrCreateBrowserToken } from "../lib/scan-quotas";
import {
  agentApprovalStore,
  createAgentApprovalRequest,
  type AgentApprovalRequest,
} from "../lib/agent-approval";
import {
  fetchWorkerReview,
  postWorkerReviewCommand,
  type WorkerReview,
} from "../lib/analysis-worker";
import {
  browserFollowUpProposal,
  localLinkVisitProposal,
  nextReviewStep,
  shareLinksProposal,
  validateAgentProposal,
  workerToolForProposal,
  type AgentProposalValidation,
} from "../lib/agent-orchestration";
import { agentReviewRegistry } from "../lib/agent-review";
import { getVultrInferenceConfig } from "../lib/serverless-inference";
import { requestAgentProposal } from "../lib/agent-inference";
import { logger } from "../lib/logger";

const router: IRouter = Router();
const approvalParamsSchema = z.object({
  scanId: z.uuid(),
  requestId: z.uuid(),
});
const scanParamsSchema = z.object({ scanId: z.uuid() });
const approvalDecisionSchema = z.object({
  decision: z.enum(["approve", "decline"]),
}).strict();
const proposalTriggerSchema = z.object({
  scanType: z.enum(["url", "email", "email_link"]),
}).strict();

router.get("/scans/:scanId/agent/events", (req, res) => {
  const params = scanParamsSchema.safeParse(req.params);
  if (!params.success) {
    return sendError(res, 400, "INVALID_SCAN_ID", "The scan reference is invalid.");
  }

  const browserToken = getOrCreateBrowserToken(req, res);
  res.status(200).set({
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  });
  res.flushHeaders();

  let closed = false;
  const heartbeat = setInterval(() => res.write(": keep-alive\n\n"), 15_000);
  const hardTimeout = setTimeout(() => {
    closed = true;
    res.end();
  }, 180_000);
  const unsubscribe = agentApprovalStore.subscribe(
    params.data.scanId,
    browserToken,
    (event) => {
      if (closed || res.writableEnded) return;
      res.write(`event: ${event.type}\ndata: ${JSON.stringify(event.data)}\n\n`);
      if (event.type === "approval_resolved") {
        closed = true;
        res.end();
      }
    },
  );
  res.on("close", () => {
    closed = true;
    clearInterval(heartbeat);
    clearTimeout(hardTimeout);
    unsubscribe();
  });
  return;
});

function sendError(
  res: Parameters<Parameters<IRouter["post"]>[1]>[1],
  status: number,
  code: string,
  message: string,
  retryable = false,
) {
  return res.status(status).json({ code, message, retryable });
}

function approvalBody(request: AgentApprovalRequest) {
  return {
    requestId: request.requestId,
    scanId: request.scanId,
    proposal: request.proposal,
    status: request.status,
    expiresAt: new Date(request.expiresAt).toISOString(),
    ...(request.targetLabel ? { targetLabel: request.targetLabel } : {}),
  };
}

/** Ask the paused worker to publish its report from the completed checks. */
async function finalizeReview(scanId: string): Promise<boolean> {
  const result = await postWorkerReviewCommand(scanId, { command: "finalize" });
  return result.kind === "accepted";
}

async function buildReviewProposal(
  review: WorkerReview,
): Promise<AgentProposalValidation | "finish"> {
  const config = getVultrInferenceConfig();
  const inferenceEnabled = process.env.VERIDICT_AGENT_INFERENCE_ENABLED === "true" && Boolean(config);
  const step = nextReviewStep({
    scanType: review.type,
    linkCandidates: review.linkCandidates,
    linkMetadataShared: review.linkMetadataShared,
    browserEligible: review.browserEligible,
    usedTools: review.actions.map((action) => action.tool),
    inferenceEnabled,
  });
  const context = {
    scanType: review.type,
    hasSelectedEmailLink: false,
    allowedLinkIds: review.linkCandidates.map((link) => link.linkId),
  } as const;

  if (step === "finish") return "finish";
  if (step === "share_links") return validateAgentProposal(shareLinksProposal(), context);
  if (step === "browser") return validateAgentProposal(browserFollowUpProposal(), context);

  // visit_link: Vultr chooses from the redacted list only after the user
  // approved sharing it; otherwise the deterministic local planner picks.
  if (inferenceEnabled && config && review.linkContext?.length) {
    try {
      return await requestAgentProposal(config, review.report, context, fetch, {
        linkContext: review.linkContext,
      });
    } catch (error) {
      logger.warn(
        { errorType: error instanceof Error ? error.name : "unknown" },
        "Agent link proposal failed closed",
      );
      return "finish";
    }
  }
  return validateAgentProposal(localLinkVisitProposal(review.linkCandidates), context);
}

router.post("/scans/:scanId/agent/proposals", async (req, res) => {
  const params = scanParamsSchema.safeParse(req.params);
  const body = proposalTriggerSchema.safeParse(req.body);
  if (!params.success || !body.success) {
    return sendError(
      res,
      400,
      "INVALID_AGENT_PROPOSAL_REQUEST",
      "The scan type is required to continue analysis.",
    );
  }
  const scanId = params.data.scanId;
  const browserToken = getOrCreateBrowserToken(req, res);
  const ownership = agentReviewRegistry.check(scanId, browserToken);
  if (ownership === "other") {
    return sendError(
      res,
      403,
      "AGENT_REVIEW_NOT_AUTHORIZED",
      "This follow-up review belongs to another browser session.",
    );
  }
  if (ownership === "unknown") {
    return sendError(
      res,
      409,
      "AGENT_REVIEW_NOT_ENABLED",
      "Follow-up review was not enabled for this scan.",
    );
  }

  // Idempotent: a reconnecting browser gets the same pending request back.
  const existing = agentApprovalStore.findPending(scanId, browserToken);
  if (existing) return res.status(202).json(approvalBody(existing));

  const reviewResult = await fetchWorkerReview(scanId);
  if (reviewResult.kind === "not_found") {
    return sendError(res, 404, "SCAN_NOT_FOUND", "This scan is no longer available.");
  }
  if (reviewResult.kind === "not_reviewing") {
    return sendError(
      res,
      409,
      "SCAN_NOT_AWAITING_REVIEW",
      "This scan is not waiting for a follow-up decision.",
    );
  }
  if (reviewResult.kind === "unavailable") {
    return sendError(
      res,
      503,
      "ANALYSIS_WORKER_UNAVAILABLE",
      "The follow-up review is temporarily unavailable.",
      true,
    );
  }
  const review = reviewResult.review;
  if (review.type !== body.data.scanType) {
    return sendError(res, 400, "SCAN_TYPE_MISMATCH", "The requested scan type does not match this scan.");
  }
  if (review.busy || review.actions.some((action) => action.status === "running")) {
    return sendError(
      res,
      409,
      "AGENT_ACTION_RUNNING",
      "A follow-up step is still running. Wait for its result.",
      true,
    );
  }

  const proposal = await buildReviewProposal(review);
  if (proposal === "finish" || !proposal.ok) {
    await finalizeReview(scanId);
    return sendError(
      res,
      409,
      "AGENT_REVIEW_COMPLETE",
      "No further follow-up step is available. The report is being finalized.",
    );
  }

  const linkId = proposal.proposal.kind === "tool" ? proposal.proposal.linkId : undefined;
  const targetLabel = linkId
    ? review.linkCandidates.find((link) => link.linkId === linkId)?.host
    : undefined;
  const deadline = Date.parse(review.deadline);
  const request = createAgentApprovalRequest(scanId, proposal.proposal, browserToken, {
    deadline: Number.isFinite(deadline) ? deadline : undefined,
    targetLabel,
  });
  return res.status(202).json(approvalBody(request));
});

router.post("/scans/:scanId/agent/approvals/:requestId", async (req, res) => {
  const params = approvalParamsSchema.safeParse(req.params);
  const body = approvalDecisionSchema.safeParse(req.body);
  if (!params.success || !body.success) {
    return sendError(
      res,
      400,
      "INVALID_AGENT_APPROVAL",
      "Choose approve or decline for this request.",
    );
  }

  const browserToken = getOrCreateBrowserToken(req, res);
  const result = agentApprovalStore.resolve(
    params.data.scanId,
    params.data.requestId,
    body.data.decision,
    browserToken,
  );
  if ("code" in result) {
    if (result.code === "BROWSER_MISMATCH") {
      return sendError(
        res,
        403,
        "AGENT_APPROVAL_NOT_AUTHORIZED",
        "This approval belongs to another browser session.",
      );
    }
    if (result.code === "REQUEST_NOT_PENDING") {
      return sendError(
        res,
        409,
        "AGENT_APPROVAL_RESOLVED",
        "This approval request is no longer pending.",
      );
    }
    return sendError(
      res,
      404,
      "AGENT_APPROVAL_NOT_FOUND",
      "This approval request is no longer available.",
    );
  }

  // Dispatch uses only the stored, validated proposal: the client sends a
  // decision, never a tool, target, or link.
  const tool = workerToolForProposal(result.proposal);
  if (!tool) {
    await finalizeReview(result.scanId);
    return res.json({
      requestId: result.requestId,
      scanId: result.scanId,
      status: result.status,
      next: "finalizing",
    });
  }

  if (result.status === "declined") {
    const skipped = await postWorkerReviewCommand(result.scanId, {
      command: "skip",
      actionId: result.requestId,
      tool,
      reason: "declined",
    });
    if (skipped.kind !== "accepted") await finalizeReview(result.scanId);
    return res.json({
      requestId: result.requestId,
      scanId: result.scanId,
      status: result.status,
      next: "finalizing",
    });
  }

  const linkId = result.proposal.kind === "tool" ? result.proposal.linkId : undefined;
  const dispatched = await postWorkerReviewCommand(result.scanId, {
    command: "run",
    actionId: result.requestId,
    tool,
    ...(linkId ? { linkId } : {}),
  });
  if (dispatched.kind !== "accepted") {
    logger.warn(
      {
        errorType: dispatched.kind === "rejected" ? dispatched.code : "worker_unavailable",
      },
      "Approved agent step was not dispatched",
    );
    await finalizeReview(result.scanId);
    return res.json({
      requestId: result.requestId,
      scanId: result.scanId,
      status: result.status,
      next: "finalizing",
    });
  }
  return res.json({
    requestId: result.requestId,
    scanId: result.scanId,
    status: result.status,
    next: "running",
  });
});

router.post("/scans/:scanId/agent/cancel", async (req, res) => {
  const params = scanParamsSchema.safeParse(req.params);
  if (!params.success) {
    return sendError(
      res,
      400,
      "INVALID_SCAN_ID",
      "The scan reference is invalid.",
    );
  }

  const scanId = params.data.scanId;
  const browserToken = getOrCreateBrowserToken(req, res);
  const pending = agentApprovalStore.pendingForScan(scanId, browserToken);
  const cancelled = agentApprovalStore.cancelPending(scanId, browserToken);

  let reviewFinalized = false;
  if (agentReviewRegistry.check(scanId, browserToken) === "owner") {
    const first = pending[0];
    const tool = first ? workerToolForProposal(first.proposal) : null;
    if (first && tool) {
      const skipped = await postWorkerReviewCommand(scanId, {
        command: "skip",
        actionId: first.requestId,
        tool,
        reason: "cancelled",
      });
      reviewFinalized = skipped.kind === "accepted";
    }
    if (!reviewFinalized) reviewFinalized = await finalizeReview(scanId);
  }

  return res.json({
    scanId,
    cancelledApprovalRequests: cancelled,
    reviewFinalized,
  });
});

export default router;
