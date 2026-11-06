---
name: Veridict report delivery
description: Confirmed MVP report export and explanation-streaming behavior.
---

Use a self-contained HTML download as Veridict's primary report export, with browser-native Print/Save as PDF. Do not add a PDF-generation service or JSON user export to the MVP. If the chosen model passes validation, stream only its explanation after the deterministic evidence and score are ready; the evidence/score report must remain usable if explanation generation fails.

Present risk as a deterministic band supported by evidence rather than an uncalibrated user-facing number. Use a separate Inconclusive result when available coverage is insufficient; exact labels and thresholds still need to be defined.

**Why:** The user chose HTML as the friendliest report, accepted print-to-PDF without server-side generation overhead, and selected risk-band-plus-evidence presentation over a numeric score or indicator-only view.

**How to apply:** Keep report data transient, escape submitted content in the HTML, and make model output explanatory only.
