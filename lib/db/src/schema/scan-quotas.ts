import { createInsertSchema } from "drizzle-zod";
import { integer, pgTable, text, timestamp } from "drizzle-orm/pg-core";
import { z } from "zod";

export const scanQuotasTable = pgTable("veridict_scan_quotas", {
  quotaKey: text("quota_key").primaryKey(),
  minuteWindowStartedAt: timestamp("minute_window_started_at", {
    withTimezone: true,
  }).notNull(),
  minuteCount: integer("minute_count").notNull().default(0),
  dailyWindowStartedAt: timestamp("daily_window_started_at", {
    withTimezone: true,
  }).notNull(),
  dailyCount: integer("daily_count").notNull().default(0),
  lifetimeCount: integer("lifetime_count").notNull().default(0),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const insertScanQuotaSchema = createInsertSchema(scanQuotasTable).omit({
  updatedAt: true,
});

export type InsertScanQuota = z.infer<typeof insertScanQuotaSchema>;
export type ScanQuota = typeof scanQuotasTable.$inferSelect;
