---
name: Veridict Coolify deployment
description: Project-specific deployment constraint and networking boundary for Veridict.
---

Veridict will use Coolify for deployment on Vultr. Keep the public web/control plane separate from the untrusted analysis worker. Use one Coolify control plane to manage the worker as a remote deployment server over SSH; do not assume a Coolify Compose network spans multiple servers. Use an explicit private network or tightly restricted service connection between hosts.

**Why:** The user specified Coolify as the deployment platform and confirmed one controller should manage both hosts. Browser analysis must remain on a separate worker host. Coolify documents remote deployment servers and APIs for creating/removing provider-backed Vultr servers, so a second Coolify control plane is unnecessary for worker lifecycle automation.

**How to apply:** Keep Coolify/Vultr API credentials out of public request handlers and all analysis sandboxes; store them as secrets, use the narrowest usable permissions and private/allowlisted access, and never expose the worker manager publicly. Verify where each container runs, which ports are exposed, and how the control plane reaches the worker before deploying. Deleting a provider-linked server is irreversible, and any retained boot volume needs separate cleanup/billing handling.
