import assert from "node:assert/strict";
import test from "node:test";
import {
  AGENT_CHAT_MODEL_OPTIONS,
  createAgentModelCatalogLoader,
  defaultAgentChatModelId,
} from "./agent-model-catalog.ts";

test("filters live Vultr models to the four supported agent chat options", async () => {
  const loader = createAgentModelCatalogLoader({
    fetcher: async (url, init) => {
      assert.equal(url, "https://api.vultrinference.com/v1/models");
      assert.equal(init.method, "GET");
      assert.ok(init.signal instanceof AbortSignal);
      return new Response(JSON.stringify({
        data: [
          { id: "glm-5.2" },
          { id: "whisper-large-v3-turbo" },
          { id: "qwen3.8-27b" },
          { id: "qwen3.8-flash-next" },
          { id: "deepseek-v4.1-flash-1017" },
          { id: "arbitrary/model" },
        ],
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const models = await loader();
  assert.deepEqual(models.map((model) => model.id), [
    "qwen3.8-flash-next",
    "qwen3.8-27b",
    "deepseek-v4.1-flash-1017",
    "glm-5.2",
  ]);
  assert.equal(models.length, AGENT_CHAT_MODEL_OPTIONS.length);
  assert.equal(defaultAgentChatModelId(models), "qwen3.8-flash-next");
});

test("caches successful catalog responses and refreshes after the TTL", async () => {
  let now = 10_000;
  let calls = 0;
  const loader = createAgentModelCatalogLoader({
    now: () => now,
    ttlMs: 500,
    fetcher: async () => {
      calls += 1;
      return new Response(JSON.stringify({
        data: [{ id: calls === 1 ? "qwen3.8-flash-next" : "glm-5.2" }],
      }), { status: 200 });
    },
  });

  assert.deepEqual((await loader()).map((model) => model.id), ["qwen3.8-flash-next"]);
  assert.deepEqual((await loader()).map((model) => model.id), ["qwen3.8-flash-next"]);
  assert.equal(calls, 1);

  now += 501;
  assert.deepEqual((await loader()).map((model) => model.id), ["glm-5.2"]);
  assert.equal(calls, 2);
});

test("does not cache an invalid or failed provider catalog response", async () => {
  let calls = 0;
  const loader = createAgentModelCatalogLoader({
    fetcher: async () => {
      calls += 1;
      return new Response("not-json", { status: 200 });
    },
  });

  await assert.rejects(loader(), /malformed JSON/i);
  await assert.rejects(loader(), /malformed JSON/i);
  assert.equal(calls, 2);
});
