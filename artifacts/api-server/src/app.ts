import express, { type Express } from "express";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();
app.set("trust proxy", 1);

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
