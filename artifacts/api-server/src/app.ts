import { createHmac } from "node:crypto";
import express, { type Express } from "express";
import cookieParser from "cookie-parser";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();
const trustedProxyCidrs = process.env.TRUSTED_PROXY_CIDRS
  ?.split(",")
  .map((value) => value.trim())
  .filter(Boolean);
app.set("trust proxy", trustedProxyCidrs?.length ? trustedProxyCidrs : 1);

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
const sessionSecret = process.env.SESSION_SECRET;
if (sessionSecret) {
  app.use(cookieParser(sessionSecret));
} else {
  app.use(cookieParser());
}
app.use(express.json({ limit: "32kb" }));

const apiRequestRateLimiter = rateLimit({
  windowMs: 60_000,
  limit: 120,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = req.ip ?? "";
    const normalizedIp = ip ? ipKeyGenerator(ip, 56) : "missing-ip";
    const secret = process.env.SESSION_SECRET ?? "unconfigured";
    return createHmac("sha256", secret)
      .update("veridict:api-request-limit:v1\0")
      .update(normalizedIp)
      .digest("hex");
  },
  handler: (_req, res) => {
    res.status(429).json({
      code: "API_RATE_LIMITED",
      message: "Too many requests. Try again shortly.",
      retryable: true,
    });
  },
});
app.use(apiRequestRateLimiter);

app.use("/api", router);

app.use((error: unknown, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (res.headersSent) {
    next(error);
    return;
  }
  const errorName = error instanceof Error ? error.name : "UnknownError";
  logger.error({ errorName, requestId: req.id }, "Unhandled API request error");
  res.status(500).json({
    code: "INTERNAL_ERROR",
    message: "The request could not be completed.",
    retryable: true,
  });
});

export default app;
