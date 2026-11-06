---
name: Veridict report delivery
description: Confirmed MVP report export, risk labels, progress streaming, and transient-only email body analysis.
---

Use a self-contained HTML download as Veridict's primary report export, with browser-native Print/Save as PDF. Do not add a PDF-generation service or JSON user export to the MVP. Do not call a hosted model or generate model explanations in the MVP. Stream deterministic analysis-stage progress only; final report remains usable without any generated explanation.

Present risk as a deterministic band supported by evidence rather than an uncalibrated user-facing number. The selected labels are Low, Moderate, High, Critical, and Inconclusive. The user approved the proposed evidence-field scope. Thresholds and evidence-to-band rules need test-based calibration.

**Why:** The user chose HTML as the friendliest report, accepted print-to-PDF without server-side generation overhead, selected risk-band-plus-evidence presentation and the five labels, and chose not to send evidence to a hosted model.

**How to apply:** Scan email bodies transiently inside the isolated worker for relevant signals, but do not display them verbatim, retain them, log them, or send them to external providers. Keep report content transient, escape submitted content in the HTML, and send only deterministic progress events to the UI. Any future model explanation requires a separate product decision.
