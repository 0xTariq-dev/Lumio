---
name: Veridict hybrid TypeScript and Python stack
description: Confirmed language/runtime choice and service boundaries for the Veridict MVP.
---

Use TypeScript/Node.js for the React/Vite web app and Express control plane, with a Python 3.12 worker for isolated analysis and Scrapling. Keep the worker on a separate Vultr host and communicate with it over a bounded private HTTPS service contract. Plain Playwright handles JavaScript navigation; REA may later passively observe the same Chromium session.

**Why:** The user chose Python for the isolated worker to use Scrapling and Python Playwright, while keeping the existing web/API stack TypeScript. The worker boundary accepts the extra runtime because it keeps untrusted analysis off the public API host.

**How to apply:** Keep web and control-plane features in TypeScript; keep scan parsing, static fetch, and browser work in the isolated Python worker. Do not move untrusted email or URL analysis onto the public API host.
