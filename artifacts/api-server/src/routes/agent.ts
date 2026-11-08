import { Router, type IRouter } from "express";
import { z } from "zod";
import { getOrCreateBrowserToken } from "../lib/scan-quotas";
import { agentApprovalStore } from "../lib/agent-approval";

const router: IRouter = Router();
const approvalParamsSchema = z.object({
  scanId: z.uuid(),
  requestId: z.uuid(),
});
const scanParamsSchema = z.object({ scanId: z.uuid() });
const approvalDecisionSchema = z.object({
  decision: z.enum(["approve", "decline"]),
}).strict();

function sendError(
  res: Parameters<Parameters<IRouter["post"]>[1]>[1],
  status: number,
  code: string,
  message: string,
) {
  return res.status(status).json({ code, message, retryable: false });
}

router.post("/scans/:scanId/agent/approvals/:requestId", (req, res) => {
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

  return res.json({
    requestId: result.requestId,
    scanId: result.scanId,
    status: result.status,
  });
});

router.post("/scans/:scanId/agent/cancel", (req, res) => {
  const params = scanParamsSchema.safeParse(req.params);
  if (!params.success) {
    return sendError(
      res,
      400,
      "INVALID_SCAN_ID",
      "The scan reference is invalid.",
    );
  }

  const browserToken = getOrCreateBrowserToken(req, res);
  return res.json({
    scanId: params.data.scanId,
    cancelledApprovalRequests: agentApprovalStore.cancelPending(
      params.data.scanId,
      browserToken,
    ),
  });
});

export default router;