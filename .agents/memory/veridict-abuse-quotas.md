---
name: Veridict abuse quotas
description: Permanent per-IP scan limits and the privacy-minimizing persistence required to enforce them.
---

Veridict's MVP quota is two scan starts per IP per minute, five per IP per day, and ten total per IP for the lifetime of that IP. The lifetime cap must survive control-plane restarts, so it requires a minimal durable quota marker even though report content is never stored server-side.

**Why:** The user chose a permanent per-IP ceiling to limit misuse, while also requiring reports to remain inline/local downloads and submitted content to be transient. A stable IP-derived marker is still pseudonymous personal data; shared networks can be blocked together, and VPN or IP changes can evade the cap.

**How to apply:** Store a keyed pseudonymous digest and quota counters rather than raw IP addresses or report content. Restrict access, keep raw IPs out of logs, disclose the retention and shared-network effect, and do not add invasive browser/device fingerprinting. Add session, queue, and global-cost controls as complementary abuse signals rather than claiming IP limits defeat VPN rotation.
