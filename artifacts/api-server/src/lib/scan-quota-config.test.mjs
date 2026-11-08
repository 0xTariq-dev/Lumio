import assert from "node:assert/strict";
import { test } from "node:test";
import {
  areScanQuotaLimitsEnabled,
  SCAN_LIMITS,
} from "./scan-quota-config.ts";

test("scan quota limits default to enabled", () => {
  assert.equal(areScanQuotaLimitsEnabled(undefined), true);
});

test("only an explicit false disables daily and lifetime caps", () => {
  assert.equal(areScanQuotaLimitsEnabled("false"), false);
  assert.equal(areScanQuotaLimitsEnabled(" FALSE "), false);
  assert.equal(areScanQuotaLimitsEnabled("true"), true);
  assert.equal(areScanQuotaLimitsEnabled("0"), true);
});

test("scan caps preserve the burst guard and allow fifteen daily and lifetime scans", () => {
  assert.deepEqual(SCAN_LIMITS, {
    startsPerMinute: 2,
    startsPerDay: 15,
    lifetimeStartsPerIp: 15,
  });
});
