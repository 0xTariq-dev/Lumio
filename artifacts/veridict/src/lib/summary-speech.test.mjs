import assert from "node:assert/strict";
import test from "node:test";
import { requestSummarySpeech } from "./summary-speech.ts";
import { SummarySpeechPlayer } from "./summary-speech-player.ts";

test("speech client requests audio only after the playback action", async () => {
  let request;
  const audioBlob = new Blob([Uint8Array.from([73, 68, 51])], {
    type: "audio/mpeg",
  });
  const result = await requestSummarySpeech(
    "5bf67a1a-21b0-4e11-8eb9-cd273aa6904d",
    "signed-token",
    "Summary text.",
    new AbortController().signal,
    async (url, init) => {
      request = { url, init };
      return new Response(audioBlob, {
        status: 200,
        headers: { "content-type": "audio/mpeg" },
      });
    },
  );

  assert.match(request.url, /\/api\/scans\/.*\/explanation\/speech$/);
  assert.equal(request.init.credentials, "same-origin");
  assert.equal(request.init.cache, "no-store");
  assert.deepEqual(JSON.parse(request.init.body), {
    consent: true,
    explanationToken: "signed-token",
    summary: "Summary text.",
  });
  assert.equal(result.type, "audio/mpeg");
  assert.equal(result.size, 3);
});

test("speech client keeps errors safe and rejects invalid audio responses", async () => {
  await assert.rejects(
    requestSummarySpeech(
      "scan-id",
      "token",
      "Readable summary",
      new AbortController().signal,
      async () => new Response("provider details", { status: 503 }),
    ),
    /readable summary and report are unchanged/,
  );
  await assert.rejects(
    requestSummarySpeech(
      "scan-id",
      "token",
      "Readable summary",
      new AbortController().signal,
      async () => new Response("not audio", {
        status: 200,
        headers: { "content-type": "text/plain" },
      }),
    ),
    /Spoken audio was unavailable/,
  );
});

test("playback has no automatic start, toggles play and stop, and releases audio", async () => {
  let requests = 0;
  let revoked = "";
  let removedSrc = false;
  let audio;
  const states = [];
  const player = new SummarySpeechPlayer({
    requestAudio: async () => {
      requests += 1;
      return new Blob([Uint8Array.from([73, 68, 51])], { type: "audio/mpeg" });
    },
    createObjectURL: () => "blob:summary-audio",
    revokeObjectURL: (url) => { revoked = url; },
    createAudio: () => {
      audio = {
        paused: true,
        currentTime: 0,
        onended: null,
        onerror: null,
        play: async function () { this.paused = false; },
        pause: function () { this.paused = true; },
        removeAttribute: (name) => { if (name === "src") removedSrc = true; },
        load: () => {},
      };
      return audio;
    },
  }, () => {});
  player.subscribe((state) => states.push(state));

  assert.equal(requests, 0);
  assert.deepEqual(states, ["idle"]);
  await player.toggle();
  assert.equal(requests, 1);
  assert.equal(states.at(-1), "playing");
  await player.toggle();
  assert.equal(audio.paused, true);
  assert.equal(states.at(-1), "stopped");
  await player.toggle();
  assert.equal(requests, 1);
  assert.equal(states.at(-1), "playing");

  player.dispose();
  assert.equal(audio.paused, true);
  assert.equal(removedSrc, true);
  assert.equal(revoked, "blob:summary-audio");
});

test("playback failures are announced without replacing the summary", async () => {
  let announced = "";
  const player = new SummarySpeechPlayer({
    requestAudio: async () => { throw new Error("Spoken audio failed safely."); },
    createObjectURL: () => "blob:unused",
    revokeObjectURL: () => {},
    createAudio: () => { throw new Error("Should not be called"); },
  }, (message) => { announced = message; });
  const states = [];
  player.subscribe((state) => states.push(state));

  await player.toggle();
  assert.equal(states.at(-1), "error");
  assert.equal(announced, "Spoken audio failed safely.");
  player.dispose();
});
