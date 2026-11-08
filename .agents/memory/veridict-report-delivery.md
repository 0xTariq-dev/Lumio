---
name: Veridict report delivery
description: Confirmed MVP report export, risk labels, progress streaming, and transient-only email body analysis.
---

Use a self-contained HTML download as Veridict's primary report export, with browser-native Print/Save as PDF. Do not add a PDF-generation service or JSON user export to the MVP. Challenge 1 requires Vultr Serverless Inference for a bounded explanation; the user approved short redacted excerpts only after separate per-scan opt-in. Keep deterministic analysis-stage progress independent of model output; model explanations must not replace the deterministic report. Keep live calls disabled until endpoint-specific retention/training terms are verified.

Present risk as a deterministic band supported by evidence rather than an uncalibrated user-facing number. The selected labels are Low, Moderate, High, Critical, and Inconclusive. The user approved the proposed evidence-field scope. Thresholds and evidence-to-band rules need test-based calibration.

**Why:** The user chose HTML as the friendliest report, accepted print-to-PDF without server-side generation overhead, selected risk-band-plus-evidence presentation and the five labels, later selected Challenge 1, then approved short redacted excerpts after explicit opt-in.

**How to apply:** Scan email bodies transiently inside the isolated worker for relevant signals, but do not display them verbatim, retain them, or log them. Keep report content transient and escape submitted content in HTML. For inference, require separate explicit consent, send only bounded redacted excerpts, fail closed if redaction is uncertain, and never send raw content, full URLs, identifiers, or secrets; verify provider retention/training terms first.
