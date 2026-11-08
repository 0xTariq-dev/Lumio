import { createHash, createHmac } from "node:crypto";
import {
  Router,
  type IRouter,
  type NextFunction,
  type Request,
  type Response,
} from "express";
import {
  SpeakScanSummaryBody,
  SpeakScanSummaryParams,
  StreamScanExplanationBody,
  StreamScanExplanationParams,
} from "@workspace/api-zod";
import { createHmacWindowLimiter } from "../lib/explanation-rate-limit";
import { getOrCreateBrowserToken } from "../lib/scan-quotas";
import {
  type ExplanationClaims,
  type VultrInferenceConfig,
  DEFAULT_VULTR_SPEECH_MODEL,
  generateVultrSpeech,
  getVultrInferenceConfig,
  MAX_SPEECH_INPUT_CHARS,
  sanitizeSpeechText,
  verifyExplanationToken,
  streamVultrExplanation,
  VultrInferenceError,
} from "../lib/serverless-inference";

const router: IRouter = Router();
const MAX_CONCURRENT_EXPLANATIONS = 2;
const REQUEST_TIMEOUT_MS = 30_000;
const EXPLANATION_REQUESTS_PER_IP_PER_MINUTE = 2;
const MAX_CONCURRENT_SPEECH_REQUESTS = 2;
const SPEECH_REQUEST_TIMEOUT_MS = 25_000;
const SPEECH_REQUESTS_PER_IP_PER_MINUTE = 2;
const explanationRateLimiter = process.env.SESSION_SECRET
  ? createHmacWindowLimiter(
      process.env.SESSION_SECRET,
      EXPLANATION_REQUESTS_PER_IP_PER_MINUTE,
      60_000,
    )
  : undefined;
const speechRateLimiter = process.env.SESSION_SECRET
  ? createHmacWindowLimiter(
      process.env.SESSION_SECRET,
      SPEECH_REQUESTS_PER_IP_PER_MINUTE,
      60_000,
    )
  : undefined;
let activeExplanations = 0;
let activeSpeechRequests = 0;
const inFlightTokens = new Set<string>();
const consumedTokens = new Map<string, number>();
const inFlightSpeechTokens = new Set<string>();
const consumedSpeechTokens = new Map<string, number>();

interface AuthorizedExplanation {
  claims: ExplanationClaims;
  config: VultrInferenceConfig;
  tokenId: string;
  userMessage: string;
}

interface AuthorizedSpeech {
  claims: ExplanationClaims;
  config: VultrInferenceConfig;
  tokenId: string;
  summary: string;
}

function sendError(
  res: Parameters<Parameters<IRouter["post"]>[1]>[1],
  status: number,
  code: string,
  message: string,
  retryable = false,
) {
  return res.status(status).json({ code, message, retryable });
}

function validateExplanationRequest(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (req.method !== "POST") {
    next("router");
    return;
  }

  const params = StreamScanExplanationParams.safeParse(req.params);
  const body = StreamScanExplanationBody.safeParse(req.body);
  if (!params.success || !body.success) {
    sendError(
      res,
      400,
      "INVALID_EXPLANATION_REQUEST",
      "Confirm consent and request an explanation for this report.",
    );
    return;
  }

  if (!process.env.SESSION_SECRET || !explanationRateLimiter) {
    sendError(
      res,
      503,
      "EXPLANATION_UNAVAILABLE",
      "The explanation service is not configured. Your report is unchanged.",
      true,
    );
    return;
  }

  const config = getVultrInferenceConfig();
  if (!config) {
    sendError(
      res,
      503,
      "INFERENCE_UNAVAILABLE",
      "The optional explanation service is not configured. Your report is unchanged.",
      true,
    );
    return;
  }

  const browserToken = getOrCreateBrowserToken(req, res);
  const claims = verifyExplanationToken(
    body.data.explanationToken,
    params.data.scanId,
    browserToken,
  );
  if (!claims) {
    sendError(
      res,
      403,
      "EXPLANATION_NOT_AUTHORIZED",
      "This explanation request is no longer authorized. Start a new scan.",
    );
    return;
  }

  const tokenId = createHash("sha256")
    .update(body.data.explanationToken)
    .digest("hex");
  res.locals.authorizedExplanation = {
    claims,
    config,
    tokenId,
    userMessage: body.data.userMessage ?? "",
  } satisfies AuthorizedExplanation;
  next();
}

function validateSpeechRequest(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  res.setHeader("cache-control", "no-store, no-cache, no-transform");
  res.setHeader("pragma", "no-cache");
  const params = SpeakScanSummaryParams.safeParse(req.params);
  const body = SpeakScanSummaryBody.safeParse(req.body);
  if (!params.success || !body.success) {
    sendError(
      res,
      400,
      "INVALID_SPEECH_REQUEST",
      "Confirm consent and request speech for a completed summary.",
    );
    return;
  }

  if (!process.env.SESSION_SECRET || !speechRateLimiter) {
    sendError(
      res,
      503,
      "SPEECH_UNAVAILABLE",
      "Speech generation is not configured. The summary and report are unchanged.",
      true,
    );
    return;
  }

  const config = getVultrInferenceConfig();
  if (!config) {
    sendError(
      res,
      503,
      "SPEECH_UNAVAILABLE",
      "Speech generation is not configured. The summary and report are unchanged.",
      true,
    );
    return;
  }
  const browserToken = getOrCreateBrowserToken(req, res);
  const claims = verifyExplanationToken(
    body.data.explanationToken,
    params.data.scanId,
    browserToken,
  );
  if (!claims) {
    sendError(
      res,
      403,
      "SPEECH_NOT_AUTHORIZED",
      "This speech request is no longer authorized. Start a new scan.",
    );
    return;
  }

  const summary = sanitizeSpeechText(body.data.summary);
  if (!summary || summary.length > MAX_SPEECH_INPUT_CHARS) {
    sendError(
      res,
      400,
      "INVALID_SPEECH_TEXT",
      "The summary has no speakable text after sensitive details are removed.",
    );
    return;
  }
  const tokenId = createHash("sha256")
    .update(body.data.explanationToken)
    .digest("hex");
  res.locals.authorizedSpeech = {
    claims,
    config,
    tokenId,
    summary,
  } satisfies AuthorizedSpeech;
  next();
}

function enforceBoundedExplanationRateLimit(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (!process.env.SESSION_SECRET || !explanationRateLimiter || !req.ip) {
    sendError(
      res,
      503,
      "EXPLANATION_UNAVAILABLE",
      "The explanation service is not configured. Your report is unchanged.",
      true,
    );
    return;
  }

  const result = explanationRateLimiter(req.ip);
  if (!result.allowed) {
    if (result.retryAfterSeconds) {
      res.setHeader("Retry-After", String(result.retryAfterSeconds));
    }
    sendError(
      res,
      429,
      "EXPLANATION_RATE_LIMITED",
      "Too many explanation requests. Try again later; your report is unchanged.",
      true,
    );
    return;
  }

  next();
}

function enforceBoundedSpeechRateLimit(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (!process.env.SESSION_SECRET || !speechRateLimiter || !req.ip) {
    sendError(
      res,
      503,
      "SPEECH_UNAVAILABLE",
      "Speech generation is not configured. The summary and report are unchanged.",
      true,
    );
    return;
  }

  const result = speechRateLimiter(req.ip);
  if (!result.allowed) {
    if (result.retryAfterSeconds) {
      res.setHeader("Retry-After", String(result.retryAfterSeconds));
    }
    sendError(
      res,
      429,
      "SPEECH_RATE_LIMITED",
      "Too many speech requests. Try again later; the summary and report are unchanged.",
      true,
    );
    return;
  }
  next();
}

function writeEvent(
  res: Parameters<Parameters<IRouter["post"]>[1]>[1],
  event: "delta" | "completed" | "error",
  data: unknown,
): void {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function pruneConsumedTokens(now: number): void {
  for (const [key, expiry] of consumedTokens) {
    if (expiry <= now) consumedTokens.delete(key);
  }
}

function pruneConsumedSpeechTokens(now: number): void {
  for (const [key, expiry] of consumedSpeechTokens) {
    if (expiry <= now) consumedSpeechTokens.delete(key);
  }
}

router.use(
  "/scans/:scanId/explanation/stream",
  validateExplanationRequest,
  enforceBoundedExplanationRateLimit,
);

router.use(
  "/scans/:scanId/explanation/speech",
  validateSpeechRequest,
  enforceBoundedSpeechRateLimit,
);

router.post(
  "/scans/:scanId/explanation/stream",
  async (req, res): Promise<void> => {
    const { claims, config, tokenId, userMessage } = res.locals
      .authorizedExplanation as AuthorizedExplanation;
    pruneConsumedTokens(Date.now());
    if (consumedTokens.has(tokenId) || inFlightTokens.has(tokenId)) {
      sendError(
        res,
        409,
        "EXPLANATION_ALREADY_USED",
        "This report's explanation request has already been used.",
      );
      return;
    }
    if (activeExplanations >= MAX_CONCURRENT_EXPLANATIONS) {
      sendError(
        res,
        429,
        "EXPLANATION_CAPACITY_FULL",
        "The explanation service is busy. Try again shortly.",
        true,
      );
      return;
    }

    activeExplanations += 1;
    inFlightTokens.add(tokenId);
    const controller = new AbortController();
    let clientDisconnected = false;
    let firstDeltaSent = false;
    let outputChars = 0;
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const onClose = () => {
      if (!res.writableEnded) {
        clientDisconnected = true;
        controller.abort();
      }
    };
    res.on("close", onClose);

    res.status(200).set({
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-cache, no-transform",
      pragma: "no-cache",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    res.flushHeaders();
    const heartbeat = setInterval(() => res.write(": keep-alive\n\n"), 12_000);

    try {
      const result = await streamVultrExplanation(
        config,
        claims.evidence,
        controller.signal,
        (delta) => {
          firstDeltaSent = true;
          outputChars += delta.length;
          consumedTokens.set(tokenId, claims.expiresAt);
          writeEvent(res, "delta", { text: delta });
        },
        { userMessage },
      );
      if (clientDisconnected) return;
      if (outputChars === 0 || result.outputChars !== outputChars) {
        throw new VultrInferenceError("Inference stream ended without usable text");
      }
      consumedTokens.set(tokenId, claims.expiresAt);
      req.log.info(
        {
          scanId: claims.scanId,
          model: config.model,
          outputChars,
          promptTokens: result.promptTokens,
          completionTokens: result.completionTokens,
        },
        "Vultr explanation stream completed",
      );
      writeEvent(res, "completed", {});
    } catch (error) {
      const status = error instanceof VultrInferenceError ? error.status : undefined;
      req.log.warn(
        {
          scanId: claims.scanId,
          model: config.model,
          upstreamStatus: status,
          errorType: error instanceof Error ? error.name : "UnknownError",
          timedOut: controller.signal.aborted && !clientDisconnected,
        },
        "Vultr explanation stream failed",
      );
      if (!clientDisconnected && !res.writableEnded) {
        const message = firstDeltaSent
          ? "The explanation stream ended early. Treat any partial text as incomplete; the report is unchanged."
          : controller.signal.aborted
            ? "The explanation timed out before it completed. Your report is unchanged."
            : "The optional explanation could not be completed. Your report is unchanged.";
        writeEvent(res, "error", { message });
      }
    } finally {
      clearTimeout(timeout);
      clearInterval(heartbeat);
      res.off("close", onClose);
      activeExplanations = Math.max(0, activeExplanations - 1);
      inFlightTokens.delete(tokenId);
      if (!res.writableEnded) res.end();
    }
  },
);

router.post(
  "/scans/:scanId/explanation/speech",
  async (req, res): Promise<void> => {
    const { claims, config, tokenId, summary } = res.locals
      .authorizedSpeech as AuthorizedSpeech;
    pruneConsumedSpeechTokens(Date.now());
    if (
      consumedSpeechTokens.has(tokenId) ||
      inFlightSpeechTokens.has(tokenId)
    ) {
      sendError(
        res,
        409,
        "SPEECH_ALREADY_REQUESTED",
        "Speech was already generated for this summary. The readable summary is unchanged.",
      );
      return;
    }
    if (activeSpeechRequests >= MAX_CONCURRENT_SPEECH_REQUESTS) {
      sendError(
        res,
        429,
        "SPEECH_CAPACITY_FULL",
        "The speech service is busy. Try again shortly.",
        true,
      );
      return;
    }

    activeSpeechRequests += 1;
    inFlightSpeechTokens.add(tokenId);
    consumedSpeechTokens.set(tokenId, claims.expiresAt);
    const controller = new AbortController();
    let clientDisconnected = false;
    const timeout = setTimeout(
      () => controller.abort(),
      SPEECH_REQUEST_TIMEOUT_MS,
    );
    const onClose = () => {
      if (!res.writableEnded) {
        clientDisconnected = true;
        controller.abort();
      }
    };
    res.on("close", onClose);

    try {
      const result = await generateVultrSpeech(
        config,
        summary,
        controller.signal,
      );
      if (clientDisconnected) return;
      req.log.info(
        {
          scanId: claims.scanId,
          model: DEFAULT_VULTR_SPEECH_MODEL,
          inputChars: summary.length,
          outputBytes: result.audio.byteLength,
          usageSeconds: result.usageSeconds,
        },
        "Vultr summary speech completed",
      );
      res.status(200).set({
        "content-type": "audio/mpeg",
        "content-length": String(result.audio.byteLength),
        "cache-control": "no-store, no-cache, no-transform",
        pragma: "no-cache",
        "x-content-type-options": "nosniff",
        "content-disposition": "inline; filename=\"summary.mp3\"",
      }).send(Buffer.from(result.audio));
    } catch (error) {
      const status = error instanceof VultrInferenceError
        ? error.status
        : undefined;
      req.log.warn(
        {
          scanId: claims.scanId,
          model: DEFAULT_VULTR_SPEECH_MODEL,
          inputChars: summary.length,
          upstreamStatus: status,
          errorType: error instanceof Error ? error.name : "UnknownError",
          timedOut: controller.signal.aborted && !clientDisconnected,
        },
        "Vultr summary speech failed",
      );
      if (!clientDisconnected && !res.writableEnded) {
        sendError(
          res,
          503,
          "SPEECH_GENERATION_FAILED",
          "Speech could not be generated. The readable summary and deterministic report are unchanged.",
          true,
        );
      }
    } finally {
      clearTimeout(timeout);
      res.off("close", onClose);
      activeSpeechRequests = Math.max(0, activeSpeechRequests - 1);
      inFlightSpeechTokens.delete(tokenId);
    }
  },
);

export default router;
