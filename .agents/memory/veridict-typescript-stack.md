---
name: Veridict TypeScript stack
description: Confirmed language/runtime choice and service boundaries for the Veridict MVP.
---

Use TypeScript/Node.js for the Veridict web app, control plane, and analysis worker. Do not add Python solely for `.eml` parsing; parse messages with a maintained MIME library inside the isolated worker. The UI uses React, TypeScript, and Vite. Playwright handles browser navigation, while REA passively observes the same Chromium session.

**Why:** The user confirmed TypeScript throughout; REA, Playwright, the existing Express API, and the Microsandbox TypeScript SDK fit that stack, avoiding an extra runtime and cross-language protocol.

**How to apply:** Keep the necessary control-plane-to-worker boundary as a bounded private service contract. Do not move untrusted email or URL analysis onto the public API host.
