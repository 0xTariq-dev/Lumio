---
name: Veridict report delivery
description: Confirmed MVP report export, risk presentation, and progress-streaming scope.
---

Use a self-contained HTML download as Veridict's primary report export, with browser-native Print/Save as PDF. Do not add a PDF-generation service or JSON user export to the MVP. Do not call a hosted model or generate model explanations in the MVP. Stream deterministic analysis-stage progress only; final report remains usable without any generated explanation.

Present risk as a deterministic band supported by evidence rather than an uncalibrated user-facing number. Use a separate Inconclusive result when available coverage is insufficient; exact labels and thresholds still need to be defined.

**Why:** The user chose HTML as the friendliest report, accepted print-to-PDF without server-side generation overhead, selected risk-band-plus-evidence presentation over a numeric score or indicator-only view, and chose not to send evidence to a hosted model.

**How to apply:** Keep report content transient, escape submitted content in the HTML, and send only deterministic progress events to the UI. Any future model explanation requires a separate product decision.
