---
name: Lumio loading boundaries
description: Performance tradeoffs for the single-route analyzer's initial bundle.
---

Keep the primary analyzer page in the initial application path for this single-route tool. Lazy-load only code with a real conditional boundary: the scan stepper after a scan starts and explanation streaming after separate opt-in. Maintain a startup HTML skeleton and a Suspense skeleton for deferred UI, and measure actual form readiness alongside first paint.

**Why:** Local measurements showed lazy-loading the primary page delayed the form behind a module waterfall, while deferring scan-only and opt-in code reduced initial JavaScript without delaying the main task UI.

**How to apply:** For future bundle or async changes, compare startup skeleton timing, actual input readiness, and production chunk sizes. A smaller entry bundle is not an improvement if the only primary route becomes slower.
