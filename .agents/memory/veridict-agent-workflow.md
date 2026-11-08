---
name: Veridict agent workflow
description: Product boundary for multi-step agent behavior in the Veridict MVP.
---

Veridict's execution behavior remains deterministic and policy-constrained. The TypeScript API gates consent and quotas; the Python worker supervisor sends an allow-listed action plan into a fresh MicroSandbox, and the guest conditionally selects browser inspection from observed HTTP/static signals. Reports distinguish planned, completed, skipped, blocked, and failed steps. The user selected Vultr Agent Rush Challenge 1, so Vultr Serverless Inference is only for explaining an already-computed report. The user explicitly accepted proceeding with the MVP integration despite unresolved provider retention/training terms, citing low expected traffic. This does not authorize raw email or page content: only a bounded, redacted report-evidence summary may be sent after separate per-scan opt-in. The model must not plan, dispatch tools, change risk bands, or take actions.

**Why:** The user explicitly chose to proceed with the MVP inference implementation despite the unresolved provider terms, while keeping the selected redacted-evidence scope.

**How to apply:** Keep the plan fixed and auditable, with no arbitrary tool use, credential entry, form submission, downloads/execution, or active exploitation. Keep inference server-side and explanation-only. Require explicit per-scan opt-in; send only bounded excerpts after deterministic redaction, and never send raw email bodies, full page content, complete/tokenized URLs, email-link lists, or secrets. Validate model output as untrusted and make actual execution/coverage visible. Disclose that provider retention/training terms are unverified.

Vultr's Serverless Inference `/v1/models` endpoint returned HTTP 200 without authorization during testing, so a successful model-catalog request does not prove that the subscription API key is valid.

**Why:** The first synthetic chat-completion request returned HTTP 401 even though the public model catalog was reachable.

**How to apply:** Validate credentials with a minimal synthetic chat-completion request. Never use real scan or email content for credential troubleshooting.

Do not use Vultr's account-level `POST /v2/apikeys` endpoint as the Serverless Inference credential. It creates a general current-user Vultr API key; inference uses the key assigned to a specific inference subscription.

**Why:** The official Vultr documentation distinguishes current-user API key creation from each subscription's own inference API key.

**How to apply:** Use the subscription's **Copy API Key** action in its Overview, or have the account owner retrieve its `api_key` through the documented read-only inference-detail endpoint. Keep account-control and model-inference credentials separate.
