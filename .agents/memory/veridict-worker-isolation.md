---
name: Veridict worker isolation
description: Architecture constraint for isolating Veridict's untrusted URL and email analysis.
---

For Veridict, do not run untrusted URL or email analysis on the public API/control-plane host. Use a separate Vultr worker host and a fresh disposable sandbox for each analysis. Do not provision one new Vultr VM per scan without comparing its cost and latency with a persistent worker host.

**Why:** The user wants to avoid same-host analysis. The worker should not share the API host's credentials or primary service boundary, while per-scan Vultr VMs may add cost and provisioning delay.

**How to apply:** Keep the inference key and report/API responsibilities on the control plane. Validate Vultr KVM/Microsandbox and browser compatibility on the worker host; if that does not fit, evaluate a fresh gVisor sandbox on the separate host. Enforce controlled egress, hard time/resource limits, cleanup after each job, and orphan cleanup after failures.
