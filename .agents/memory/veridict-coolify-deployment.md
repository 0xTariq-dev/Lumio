---
name: Veridict Coolify deployment
description: Project-specific deployment constraint and networking boundary for Veridict.
---

Veridict will use Coolify for deployment on Vultr. Keep the public web/control plane separate from the untrusted analysis worker. Do not assume a Coolify Compose network spans multiple servers; use an explicit private network or tightly restricted service connection between hosts.

**Why:** The user specified Coolify as the deployment platform, and browser analysis must remain on a separate worker host.

**How to apply:** Design deployment resources around Coolify-managed servers and verify where each container runs, which ports are exposed, and how the control plane reaches the worker before deploying.
