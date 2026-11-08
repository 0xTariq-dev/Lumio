---
name: Docker firewall ordering for Veridict
description: Prevent host firewall rules from breaking Docker bridge reply traffic.
---

**Rule:** In `DOCKER-USER`, accept `ESTABLISHED,RELATED` traffic before dropping packets based on private destination ranges.

**Why:** A blanket private-range drop catches return traffic from app containers and breaks DNS/HTTP, even when outbound policy is intended only to block private-network access from untrusted sandboxes.

**How to apply:** When tightening egress on Docker hosts that run worker containers, allow established replies first, then apply new-flow destination blocks; test DNS and HTTP from a fresh sandbox before rollout.
