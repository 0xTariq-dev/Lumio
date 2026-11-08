---
name: Veridict worker isolation
description: Architecture constraint for isolating Veridict's untrusted URL and email analysis.
---

For Veridict, do not run untrusted URL or email analysis on the public API/control-plane host. The selected MVP direction is one separate VX1 worker host with a fresh Microsandbox microVM per analysis, subject to a browser/resource validation. The worker budget is $100/month. Do not provision one new Vultr VM per scan.

**Why:** The user wants to avoid same-host analysis and selected the VX1 microVM route after reviewing the per-scan VM, shared-kernel container, and persistent microVM costs. A persistent VX1 worker costs less than the $100 worker budget while providing a separate guest kernel per scan.

**How to apply:** Keep inference keys and report/API responsibilities on the control plane. Validate Vultr KVM/Microsandbox and browser compatibility on the worker host. Keep the worker warm for the MVP; do not implement idle destruction. Vultr stop/halt continues compute billing; destruction ends compute charges but removes the VM and local disk, while a bootable Block Storage volume remains and may keep billing. Revisit scale-to-zero only as a separate lifecycle decision, with reprovisioning, Coolify relinking, and ready-to-scan latency tests. Enforce controlled egress, hard time/resource limits, cleanup after each job, and orphan cleanup after failures.

For Microsandbox 0.7.13, an OCI image imported from a Docker archive runs from its local tag, but a digest-only reference is not resolvable from that local cache. Keep the immutable manifest digest separate from the local tag, verify the tag's digest before use, and run scans with `PullPolicy.NEVER`.

**Why:** This avoids adding a registry just to deploy a prebuilt guest image while preserving digest verification and preventing guest-time image pulls.

**How to apply:** Use the local-tag-plus-digest pattern only when the image is preloaded into the same service account's Microsandbox cache; use a registry-backed digest reference otherwise.
