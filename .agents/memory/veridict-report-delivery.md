---
name: Veridict report delivery
description: Confirmed MVP report export and explanation-streaming behavior.
---

Use a self-contained HTML download as Veridict's primary report export, with browser-native Print/Save as PDF. Do not add a PDF-generation service or JSON user export to the MVP. If the chosen model passes validation, stream only its explanation after the deterministic evidence and score are ready; the evidence/score report must remain usable if explanation generation fails.

**Why:** The user chose HTML as the friendliest report and accepted a print-to-PDF option without adding server-side generation overhead.

**How to apply:** Keep report data transient, escape submitted content in the HTML, and make model output explanatory only.
