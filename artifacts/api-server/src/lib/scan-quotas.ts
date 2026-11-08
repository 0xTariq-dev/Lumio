import { createHmac, randomUUID } from "node:crypto";
import type { Request, Response } from "express";
import { pool } from "@workspace/db";
import {
  areScanQuotaLimitsEnabled,
  SCAN_LIMITS,
} from "./scan-quota-config";

const CLIENT_COOKIE = "veridict_client";
const CLIENT_COOKIE_MAX_AGE = 365 * 24 * 60 * 60 * 1000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class QuotaConfigurationError extends Error {
  constructor() {
    super("Abuse-control configuration is unavailable");
    this.name = "QuotaConfigurationError";
  }
}

export type QuotaBlockReason = "minute" | "day" | "lifetime";

export interface QuotaReservationEntry {
  quotaKey: string;
  minuteWindowStartedAt: Date;
  dailyWindowStartedAt: Date;
}

export type QuotaReservationResult =
  | { allowed: true; entries: QuotaReservationEntry[] }
  | {
      allowed: false;
      reason: QuotaBlockReason;
      retryAfterSeconds?: number;
    };

interface QuotaRow {
  minuteWindowStartedAt: Date;
  minuteCount: number;
  dailyWindowStartedAt: Date;
  dailyCount: number;
  lifetimeCount: number;
}

interface QuotaUsageRow {
  dailyWindowStartedAt: Date;
  dailyCount: number;
  lifetimeCount: number;
}

function getQuotaSecret(): string {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new QuotaConfigurationError();
  }
  return secret;
}

function digestKey(type: "ip" | "browser", value: string): string {
  const digest = createHmac("sha256", getQuotaSecret())
    .update(`veridict:scan-quota:${type}:v1\0`)
    .update(value)
    .digest("hex");
  return `${type}:${digest}`;
}

export function getOrCreateBrowserToken(req: Request, res: Response): string {
  const existing = req.signedCookies?.[CLIENT_COOKIE];
  if (typeof existing === "string" && UUID_PATTERN.test(existing)) {
    return existing;
  }

  const token = randomUUID();
  res.cookie(CLIENT_COOKIE, token, {
    signed: true,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: CLIENT_COOKIE_MAX_AGE,
    path: "/api",
  });
  return token;
}

function utcDayStart(now: Date): Date {
  return new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
  );
}

export async function getScanQuotaUsage(
  ipAddress: string,
  browserToken: string,
): Promise<{ dailyUsed: number; lifetimeUsed: number }> {
  if (!ipAddress) {
    throw new QuotaConfigurationError();
  }

  const quotaKeys = [
    digestKey("ip", ipAddress),
    digestKey("browser", browserToken),
  ].sort();
  const todayStart = utcDayStart(new Date());
  const result = await pool.query<QuotaUsageRow>(
    `SELECT
      daily_window_started_at AS "dailyWindowStartedAt",
      daily_count AS "dailyCount",
      lifetime_count AS "lifetimeCount"
    FROM veridict_scan_quotas
    WHERE quota_key = ANY($1::text[])`,
    [quotaKeys],
  );

  return result.rows.reduce(
    (usage, row) => ({
      dailyUsed: Math.max(
        usage.dailyUsed,
        row.dailyWindowStartedAt >= todayStart ? row.dailyCount : 0,
      ),
      lifetimeUsed: Math.max(usage.lifetimeUsed, row.lifetimeCount),
    }),
    { dailyUsed: 0, lifetimeUsed: 0 },
  );
}

export async function reserveScanStart(
  ipAddress: string,
  browserToken: string,
): Promise<QuotaReservationResult> {
  if (!ipAddress) {
    throw new QuotaConfigurationError();
  }

  const now = new Date();
  const minuteCutoff = new Date(now.getTime() - 60_000);
  const todayStart = utcDayStart(now);
  const enforceDailyAndLifetimeLimits = areScanQuotaLimitsEnabled();
  const quotaKeys = [
    digestKey("ip", ipAddress),
    digestKey("browser", browserToken),
  ].sort();
  const client = await pool.connect();
  const reservations: QuotaReservationEntry[] = [];

  try {
    await client.query("BEGIN");

    for (const quotaKey of quotaKeys) {
      await client.query(
        `INSERT INTO veridict_scan_quotas (
          quota_key,
          minute_window_started_at,
          minute_count,
          daily_window_started_at,
          daily_count,
          lifetime_count,
          updated_at
        ) VALUES ($1, $2, 0, $3, 0, 0, $2)
        ON CONFLICT (quota_key) DO NOTHING`,
        [quotaKey, now, todayStart],
      );

      const result = await client.query<QuotaRow>(
        `SELECT
          minute_window_started_at AS "minuteWindowStartedAt",
          minute_count AS "minuteCount",
          daily_window_started_at AS "dailyWindowStartedAt",
          daily_count AS "dailyCount",
          lifetime_count AS "lifetimeCount"
        FROM veridict_scan_quotas
        WHERE quota_key = $1
        FOR UPDATE`,
        [quotaKey],
      );
      const row = result.rows[0];
      if (!row) {
        throw new Error("Quota row was not available");
      }

      const minuteExpired =
        row.minuteWindowStartedAt.getTime() <= minuteCutoff.getTime();
      const dayExpired =
        row.dailyWindowStartedAt.getTime() < todayStart.getTime();
      const effectiveMinuteCount = minuteExpired ? 0 : row.minuteCount;
      const effectiveDayCount = dayExpired ? 0 : row.dailyCount;

      if (effectiveMinuteCount >= SCAN_LIMITS.startsPerMinute) {
        await client.query("ROLLBACK");
        const retryAfterSeconds = minuteExpired
          ? 1
          : Math.max(
              1,
              Math.ceil(
                (row.minuteWindowStartedAt.getTime() + 60_000 - now.getTime()) /
                  1000,
              ),
            );
        return { allowed: false, reason: "minute", retryAfterSeconds };
      }
      if (
        enforceDailyAndLifetimeLimits &&
        effectiveDayCount >= SCAN_LIMITS.startsPerDay
      ) {
        await client.query("ROLLBACK");
        const nextDay = new Date(todayStart.getTime() + 24 * 60 * 60 * 1000);
        return {
          allowed: false,
          reason: "day",
          retryAfterSeconds: Math.max(
            1,
            Math.ceil((nextDay.getTime() - now.getTime()) / 1000),
          ),
        };
      }
      if (
        enforceDailyAndLifetimeLimits &&
        row.lifetimeCount >= SCAN_LIMITS.lifetimeStartsPerIp
      ) {
        await client.query("ROLLBACK");
        return { allowed: false, reason: "lifetime" };
      }

      const minuteWindowStartedAt = minuteExpired
        ? now
        : row.minuteWindowStartedAt;
      const dailyWindowStartedAt = dayExpired
        ? todayStart
        : row.dailyWindowStartedAt;

      await client.query(
        `UPDATE veridict_scan_quotas
        SET minute_window_started_at = $2,
            minute_count = $3,
            daily_window_started_at = $4,
            daily_count = $5,
            lifetime_count = $6,
            updated_at = $7
        WHERE quota_key = $1`,
        [
          quotaKey,
          minuteWindowStartedAt,
          effectiveMinuteCount + 1,
          dailyWindowStartedAt,
          effectiveDayCount + 1,
          row.lifetimeCount + 1,
          now,
        ],
      );
      reservations.push({
        quotaKey,
        minuteWindowStartedAt,
        dailyWindowStartedAt,
      });
    }

    await client.query("COMMIT");
    return { allowed: true, entries: reservations };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function refundRejectedScan(
  entries: QuotaReservationEntry[],
): Promise<void> {
  if (entries.length === 0) return;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const entry of entries) {
      await client.query(
        `UPDATE veridict_scan_quotas
        SET minute_count = CASE
              WHEN minute_window_started_at = $2
              THEN GREATEST(minute_count - 1, 0)
              ELSE minute_count
            END,
            daily_count = CASE
              WHEN daily_window_started_at = $3
              THEN GREATEST(daily_count - 1, 0)
              ELSE daily_count
            END,
            lifetime_count = GREATEST(lifetime_count - 1, 0),
            updated_at = $4
        WHERE quota_key = $1`,
        [
          entry.quotaKey,
          entry.minuteWindowStartedAt,
          entry.dailyWindowStartedAt,
          new Date(),
        ],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
