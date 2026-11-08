import assert from "node:assert/strict";
import test from "node:test";
import { createHmacWindowLimiter } from "./explanation-rate-limit.ts";

test("allows two explanation streams per IP per minute", () => {
  const limit = createHmacWindowLimiter("test-secret", 2, 60_000);

  assert.deepEqual(limit("192.0.2.1", 1_000), { allowed: true });
  assert.deepEqual(limit("192.0.2.1", 1_001), { allowed: true });
  assert.deepEqual(limit("192.0.2.1", 1_002), {
    allowed: false,
    retryAfterSeconds: 60,
  });
});

test("throttles speech generation attempts independently per IP", () => {
  const limit = createHmacWindowLimiter("test-secret", 2, 60_000);

  assert.deepEqual(limit("speech-ip", 10_000), { allowed: true });
  assert.deepEqual(limit("speech-ip", 10_001), { allowed: true });
  assert.deepEqual(limit("speech-ip", 10_002), {
    allowed: false,
    retryAfterSeconds: 60,
  });
});

test("expires the IP window and keeps other IPs independent", () => {
  const limit = createHmacWindowLimiter("test-secret", 1, 60_000);

  assert.deepEqual(limit("192.0.2.1", 1_000), { allowed: true });
  assert.deepEqual(limit("192.0.2.2", 1_001), { allowed: true });
  assert.deepEqual(limit("192.0.2.1", 61_001), { allowed: true });
});

test("fails closed when the HMAC subject or secret is missing", () => {
  const limit = createHmacWindowLimiter("", 2, 30_000);

  assert.deepEqual(limit("192.0.2.1", 1_000), {
    allowed: false,
    retryAfterSeconds: 30,
  });
});
