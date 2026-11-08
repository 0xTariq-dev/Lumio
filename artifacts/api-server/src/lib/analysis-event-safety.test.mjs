import assert from "node:assert/strict";
import test from "node:test";
import {
  isTerminalAnalysisEvent,
  toPublicWorkerFailureEvent,
} from "./analysis-event-safety.ts";

test("worker failure payloads are replaced with a safe terminal event", () => {
  const privateMarker = "SYNTHETIC_PRIVATE_EMAIL_BODY";
  const event = toPublicWorkerFailureEvent({
    message: privateMarker,
    stack: "internal worker stack",
    emailBase64: privateMarker,
  });

  assert.deepEqual(event, {
    event: "failed",
    data: {
      code: "ANALYSIS_FAILED",
      message: "This analysis could not be completed. No report is available.",
      retryable: true,
    },
  });
  assert.equal(isTerminalAnalysisEvent(event.event), true);
  assert.equal(JSON.stringify(event).includes(privateMarker), false);
});

test("progress events do not terminate the public stream", () => {
  assert.equal(isTerminalAnalysisEvent("progress"), false);
  assert.equal(isTerminalAnalysisEvent("completed"), true);
});
