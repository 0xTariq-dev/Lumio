---
name: Veridict agent workflow
description: Product boundary for multi-step agent behavior in the Veridict MVP.
---

The user approved extending the explanation-only model role to structured next-tool/data proposals. This is approved product scope, not proof that the interactive agent loop is implemented. Initial scan consent starts the bounded baseline. The model may propose only vetted catalog tools; the TypeScript API validates consent, target policy, typed fields, quotas, redaction, and runtime limits before dispatching approved work into the separate worker's MicroSandbox. The model cannot execute directly, access MCP/host credentials, run arbitrary commands, or change deterministic findings/risk bands. Start with existing scan tools; review later enrichments per scan type.

**Why:** The user explicitly approved an agent-first interaction with per-request user control, while preserving containment and the selected redacted-evidence boundary.

**How to apply:** Each new tool/data request pauses for ReUI approval showing purpose, action, target, fields, and any transfer to Vultr. Use typed API-validated requests; send additional sensitive context only as bounded redacted excerpts after explicit request-specific consent. Never request credentials or send raw email/page contents, complete/tokenized URLs, or secrets. Declines skip the action and mark a limitation without alternate-route retries. Cancel stops the sandbox and shows completed partial findings. Approval waiting consumes the worker slot and remains inside the 180-second hard cap. Stream actions, findings, and brief rationale, not hidden reasoning or raw content. Keep report explanations read-only, validate all model output as untrusted, and retain prohibitions on credential entry, form submission, downloads/execution, and active exploitation. Provider retention/training terms remain unverified; the user accepted MVP use with explicit disclosure, not as proof of privacy terms.

For the approved email-link agent step, the worker may retain the submitted email transiently in memory for the existing scan/approval window, capped at 180 seconds. Before report finalization, and only after separate explicit consent to the model transfer, the agent may receive bounded metadata for extracted links: host, path, and anchor text. Strip queries, fragments, credentials, and secret-like path values; never send the raw email body or complete URLs. Treat anchor text as untrusted input. A link visit remains a separate per-link approval and must use the isolated worker.

**Why:** The user explicitly authorized host/path/anchor metadata before report generation, while requiring transient-only retention and separate approval for link visits.

**How to apply:** Keep this as a narrow exception to the no-link-list rule above; it does not authorize sending raw link targets, query/fragment values, or email content to the model.

Vultr's Serverless Inference `/v1/models` endpoint returned HTTP 200 without authorization during testing, so a successful model-catalog request does not prove that the subscription API key is valid.

**Why:** The first synthetic chat-completion request returned HTTP 401 even though the public model catalog was reachable.

**How to apply:** Validate credentials with a minimal synthetic chat-completion request. Never use real scan or email content for credential troubleshooting.

Do not use Vultr's account-level `POST /v2/apikeys` endpoint as the Serverless Inference credential. It creates a general current-user Vultr API key; inference uses the key assigned to a specific inference subscription.

**Why:** The official Vultr documentation distinguishes current-user API key creation from each subscription's own inference API key.

**How to apply:** Use the subscription's **Copy API Key** action in its Overview, or have the account owner retrieve its `api_key` through the documented read-only inference-detail endpoint. Keep account-control and model-inference credentials separate.

Vultr's `qwen3.8-flash-next` defaults to thinking mode; with a small completion cap it can spend every token on `reasoning` deltas and return no user-facing answer. On Vultr, `chat_template_kwargs: { enable_thinking: false }` produced concise visible text.

**Why:** A synthetic stream exhausted the 220-token cap with reasoning-only output until thinking mode was disabled.

**How to apply:** Keep thinking disabled for this short explanation feature, ignore reasoning deltas, and forward only bounded `content` text to the browser.
