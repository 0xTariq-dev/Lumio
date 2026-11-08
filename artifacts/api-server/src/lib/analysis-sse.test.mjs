import assert from "node:assert/strict";
import test from "node:test";
import { safeLastEventId, serializePublicSseEvent } from "./analysis-sse.ts";

test("accepts numeric reconnect cursors and rejects injected SSE fields", () => {
  assert.equal(safeLastEventId("17"), "17");
  assert.equal(safeLastEventId(undefined), undefined);
  assert.equal(safeLastEventId("17\nid: 900"), undefined);
  assert.equal(safeLastEventId("a".repeat(10)), undefined);
  assert.equal(safeLastEventId("12345678901"), undefined);
});

test("preserves the worker event ID so browsers can reconnect without gaps", () => {
  assert.equal(
    serializePublicSseEvent({
      id: "17",
      event: "review_ready",
      data: { scanId: "scan-a" },
    }),
    'id: 17\nevent: review_ready\ndata: {"scanId":"scan-a"}\n\n',
  );
});

test("serializes public events that do not include a worker ID", () => {
  assert.equal(
    serializePublicSseEvent({ event: "message", data: { ok: true } }),
    'event: message\ndata: {"ok":true}\n\n',
  );
});

test("rejects event IDs that could inject SSE fields", () => {
  assert.throws(
    () => serializePublicSseEvent({ id: "1\nevent: completed", event: "progress", data: {} }),
    /Invalid server-sent event ID/,
  );
});
