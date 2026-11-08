---
name: Veridict report delivery
description: Confirmed MVP report export, risk labels, progress streaming, and transient-only email body analysis.
---

Use a self-contained HTML download as Lumio's primary report export, with browser-native Print/Save as PDF. Open that same escaped report HTML in an isolated browser window before invoking native print; do not print the analyzer shell. Keep responsive preview and pagination rules in the self-contained document. Do not add a PDF-generation service or JSON user export to the MVP. Challenge 1 requires Vultr Serverless Inference for a bounded explanation; the user approved short redacted excerpts only after separate per-scan opt-in. Model explanations must not replace the deterministic report. The separately approved action-proposal loop is governed by the agent workflow note; it does not authorize model-generated evidence or risk bands. The user accepted MVP inference despite unverified provider retention/training terms, with explicit disclosure.

Present risk as a deterministic band supported by evidence rather than an uncalibrated user-facing number. The selected labels are Low, Moderate, High, Critical, and Inconclusive. The user approved the proposed evidence-field scope. Thresholds and evidence-to-band rules need test-based calibration.

**Why:** The user chose HTML as the friendliest report, accepted print-to-PDF without server-side generation overhead, selected risk-band-plus-evidence presentation and the five labels, later selected Challenge 1, then approved short redacted excerpts after explicit opt-in. Printing the app with visibility-only CSS preserved the hidden app's layout and created blank PDF pages; isolated printing avoids that.

**How to apply:** Scan email bodies transiently inside the isolated worker for relevant signals, but do not display them verbatim, retain them, or log them. Keep report content transient and escape submitted content in HTML; wrap long values and avoid splitting findings or explanation sections across printed pages. For inference, require separate explicit consent, send only bounded redacted excerpts, fail closed if redaction is uncertain, and never send raw content, full URLs, identifiers, or secrets. Disclose the unresolved provider terms and do not claim the user's MVP acceptance verifies them.
