---
name: Veridict agent workflow
description: Product boundary for multi-step agent behavior in the Veridict MVP.
---

Veridict's execution behavior remains deterministic and policy-constrained. The TypeScript API gates consent and quotas; the Python worker supervisor sends an allow-listed action plan into a fresh MicroSandbox, and the guest conditionally selects browser inspection from observed HTTP/static signals. Reports distinguish planned, completed, skipped, blocked, and failed steps. The user selected Vultr Agent Rush Challenge 1, so Vultr Serverless Inference is now required only to explain an already-computed report. The user approved short redacted email/page excerpts after separate per-scan opt-in. Live inference remains disabled until endpoint-specific prompt/response retention and model-training terms are verified. The model must not plan, dispatch tools, change risk bands, or take actions.

**Why:** The user explicitly changed the challenge target to Challenge 1 and approved a narrow excerpt payload; vendor handling terms still need confirmation before any production transmission.

**How to apply:** Keep the plan fixed and auditable, with no arbitrary tool use, credential entry, form submission, downloads/execution, or active exploitation. Keep inference server-side and explanation-only. Require explicit per-scan opt-in; send only bounded excerpts after deterministic redaction, fail closed on uncertainty, and never send raw email bodies, full page content, complete/tokenized URLs, or secrets. Validate model output as untrusted and make actual execution/coverage visible.
