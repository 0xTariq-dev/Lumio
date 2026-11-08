import assert from "node:assert/strict";
import test from "node:test";
import {
  buildExplanationEvidence,
  createExplanationToken,
  DEFAULT_VULTR_INFERENCE_MODEL,
  getVultrInferenceConfig,
  streamVultrExplanation,
  verifyExplanationToken,
} from "./serverless-inference.ts";

const report = {
  scanId: "5bf67a1a-21b0-4e11-8eb9-cd273aa6904d",
  type: "url",
  riskBand: "moderate",
  findings: [{
    title: "Cross-host redirect",
    explanation: "The URL redirected to a different public host. Confirm the destination is expected.",
    severity: "moderate",
    strength: "contextual",
    source: "url_navigation",
    sanitizedObservedValue: "https://person@example.org/path?token=abc → 192.0.2.4",
    limitations: ["This is an indicator, not proof of fraud."],
  }],
  coverage: {
    sufficient: true,
    checks: [{ name: "http_response", status: "completed" }],
  },
};

const testEnv = {
  SESSION_SECRET: "s".repeat(40),
  VULTR_INFERENCE_API_KEY: "synthetic-test-key",
};

test("inference config prefers the canonical secret and trims its value", () => {
  const config = getVultrInferenceConfig({
    INFERECE_SUBSCRIPTION_KEY: "  subscription-test-key  ",
    VULTR_INFERENCE_API_KEY: "  canonical-test-key  ",
  });
  assert.equal(config?.apiKey, "canonical-test-key");
  const legacyConfig = getVultrInferenceConfig({
    INFERECE_SUBSCRIPTION_KEY: "subscription-test-key",
  });
  assert.equal(legacyConfig?.apiKey, "subscription-test-key");
});

test("explanation evidence redacts observed PII and excludes report links", () => {
  const evidence = buildExplanationEvidence(report);
  const serialized = JSON.stringify(evidence);
  assert.equal(evidence.riskBand, "moderate");
  assert.equal(evidence.findings[0].observedExcerpt.includes("person@example.org"), false);
  assert.equal(evidence.findings[0].observedExcerpt.includes("192.0.2.4"), false);
  assert.equal(serialized.includes("token=abc"), false);
});

test("explanation token is time-limited, scan-bound, and browser-bound", () => {
  const now = 1_000_000;
  const token = createExplanationToken(report, "browser-session-a", testEnv, now);
  assert.ok(token);
  assert.equal(
    verifyExplanationToken(token, report.scanId, "browser-session-a", testEnv, now + 1).scanId,
    report.scanId,
  );
  assert.equal(
    verifyExplanationToken(token, report.scanId, "browser-session-b", testEnv, now + 1),
    undefined,
  );
  assert.equal(
    verifyExplanationToken(token, "aa7a8f52-eef1-4c7d-a34e-ff113542b38a", "browser-session-a", testEnv, now + 1),
    undefined,
  );
  assert.equal(
    verifyExplanationToken(token, report.scanId, "browser-session-a", testEnv, now + 16 * 60_000),
    undefined,
  );
});

test("Vultr stream sends bounded chat requests without tools and forwards text only", async () => {
  let requestBody;
  const encoder = new TextEncoder();
  const response = new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"Cautious "}}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"explanation."}}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"choices":[],"usage":{"prompt_tokens":42,"completion_tokens":8}}\n\n'));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      },
    }),
    { status: 200, headers: { "content-type": "text/event-stream" } },
  );
  const chunks = [];

  const result = await streamVultrExplanation(
    { apiKey: "synthetic-test-key", model: DEFAULT_VULTR_INFERENCE_MODEL },
    buildExplanationEvidence(report),
    new AbortController().signal,
    (delta) => chunks.push(delta),
    async (_input, init) => {
      requestBody = JSON.parse(String(init.body));
      return response;
    },
  );

  assert.equal(chunks.join(""), "Cautious explanation.");
  assert.equal(result.outputChars, "Cautious explanation.".length);
  assert.equal(result.promptTokens, 42);
  assert.equal(result.completionTokens, 8);
  assert.equal(requestBody.model, DEFAULT_VULTR_INFERENCE_MODEL);
  assert.equal(requestBody.stream, true);
  assert.equal(requestBody.max_completion_tokens, 220);
  assert.equal("tools" in requestBody, false);
});
