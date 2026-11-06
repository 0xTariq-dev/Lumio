---
name: Veridict local-only intelligence
description: MVP handling of reputation sources, submitted URLs, email files, and later provider evaluation.
---

For the MVP, reputation analysis is local-only. Do not send submitted URLs or `.eml` data to third-party OSINT providers. Keep the researched provider options and costs available for a later product decision.

CVEs are deferred from the MVP. The separate backlog scope is passive, local KEV/NVD matching only, clearly marked unverified and kept separate from the phishing risk band; no active vulnerability probes.

**Why:** The user selected local-only to get a working MVP and asked to preserve the OSINT findings for later use.

**How to apply:** Keep per-scan external reputation requests disabled. Before reconsidering a provider, review the exact data sent, provider retention and visibility, terms, costs, and user consent. Keep CVE-related implementation out of the MVP and follow the separate backlog scope.
