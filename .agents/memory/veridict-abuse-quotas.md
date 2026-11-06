---
name: Veridict abuse quotas
description: Permanent per-IP scan limits and the privacy-minimizing persistence required to enforce them.
---

Veridict's MVP quota is two scan starts per IP per minute, five per IP per day, and ten total per IP for the lifetime of that IP. The lifetime cap must survive control-plane restarts, so it requires a minimal durable quota marker even though report content is never stored server-side.

The implementation also uses a signed, first-party browser token as a second quota key so changing IPs does not immediately reset the browser's cap. This is a random cookie identifier, not a device fingerprint.

**Why:** The user chose a permanent per-IP ceiling to limit misuse and asked for an additional signal against VPN/IP changes, while requiring submitted content and reports to stay transient. A keyed IP or browser marker is still pseudonymous personal data; shared networks can be blocked together, and browser cookies can be reset.

**How to apply:** Store keyed digests and aggregate counters rather than raw IPs, browser tokens, or report content. Keep raw IPs out of logs, disclose counter retention and shared-network effects, use the browser token only as a friction signal, and do not add invasive fingerprinting. Add queue and global-cost controls rather than claiming these caps defeat determined abuse.
