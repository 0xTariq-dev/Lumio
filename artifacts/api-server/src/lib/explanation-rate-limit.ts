import { createHmac } from "node:crypto";

export interface RateLimitDecision {
  allowed: boolean;
  retryAfterSeconds?: number;
}

export function createHmacWindowLimiter(
  secret: string,
  limit: number,
  windowMs: number,
  maxSubjects = 10_000,
): (subject: string, now?: number) => RateLimitDecision {
  const requestsBySubject = new Map<string, number[]>();

  return (subject, now = Date.now()) => {
    if (!secret || !subject || limit < 1 || windowMs < 1) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil(windowMs / 1000)),
      };
    }

    const key = createHmac("sha256", secret)
      .update("veridict:explanation-rate:v1\0")
      .update(subject)
      .digest("hex");
    const windowStart = now - windowMs;
    const current = requestsBySubject.get(key) ?? [];
    const recent = current.filter((timestamp) => timestamp > windowStart);

    if (recent.length >= limit) {
      requestsBySubject.set(key, recent);
      return {
        allowed: false,
        retryAfterSeconds: Math.max(
          1,
          Math.ceil((recent[0] + windowMs - now) / 1000),
        ),
      };
    }

    if (!requestsBySubject.has(key) && requestsBySubject.size >= maxSubjects) {
      for (const [storedKey, timestamps] of requestsBySubject) {
        if (timestamps.every((timestamp) => timestamp <= windowStart)) {
          requestsBySubject.delete(storedKey);
        }
      }
      if (requestsBySubject.size >= maxSubjects) {
        return {
          allowed: false,
          retryAfterSeconds: Math.max(1, Math.ceil(windowMs / 1000)),
        };
      }
    }

    requestsBySubject.set(key, [...recent, now]);
    return { allowed: true };
  };
}
