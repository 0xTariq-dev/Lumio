---
name: Veridict agent workflow
description: Product boundary for multi-step agent behavior in the Veridict MVP.
---

Veridict's MVP agent behavior is deterministic and policy-constrained. The TypeScript API gates consent and quotas; the Python worker supervisor sends an allow-listed action plan into a fresh MicroSandbox, and the guest conditionally selects browser inspection from observed HTTP/static signals. Reports distinguish planned, completed, skipped, blocked, and failed steps. Do not add hosted LLM/inference without an explicit scope change.

**Why:** The user selected no hosted model for the MVP, while the hackathon requires real multi-step execution inside a sandbox.

**How to apply:** Keep the plan fixed and auditable, with no arbitrary tool use, credential entry, form submission, downloads/execution, or active exploitation. Make actual execution and coverage visible rather than presenting planned work as completed.
