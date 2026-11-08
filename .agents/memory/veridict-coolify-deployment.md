---
name: Veridict Coolify deployment
description: Project-specific deployment constraint and networking boundary for Veridict.
---

Veridict will use two Vultr VMs: the public web/control-plane host runs the single Coolify controller, and the separate worker host runs untrusted analysis. Coolify manages the worker as a remote deployment server over SSH; do not assume a Coolify Compose network spans multiple servers. Use an explicit private network or tightly restricted service connection between hosts, and keep Coolify administration private or IP-allowlisted. New York is the initial target; the Vultr region API labels the matching EWR location as New Jersey, so confirm the location is acceptable before provisioning.

**Why:** The user chose the app/control-plane VM for the Coolify controller to keep the deployment to two billable VMs, selected New York as the initial deployment region, and wants the analysis worker isolated.

**How to apply:** Keep Coolify/Vultr API credentials out of public request handlers and all analysis sandboxes; store them as secrets, use the narrowest usable permissions, and never expose the worker manager publicly. Verify where each container runs, which ports are exposed, and how the control plane reaches the worker before deploying. Deleting a provider-linked server is irreversible, and any retained boot volume needs separate cleanup/billing handling.

The user chose a private PostgreSQL service on the existing app VM for abuse-quota persistence, with no published database port, a persistent volume, and a restricted API role. This database stores HMAC-derived quota identifiers and counters only; scan reports remain transient.

**Why:** The deployed API needs durable quota enforcement across restarts, while the user explicitly chose not to retain reports on the server.

**How to apply:** Keep the database on its internal Docker network, grant the API only table-level data privileges, and keep database credentials in root-only host environment files.
