---
name: Vultr SSH access
description: Safe SSH authentication details for the project's Vultr hosts.
---

Use the base64-encoded SSH private-key secret, materialized only as a mode-600 temporary key file. The raw private-key secret did not authenticate successfully. Both Vultr host fingerprints already match the workspace's trusted `known_hosts` entries.

**Why:** Strict host-key verification worked with the existing pinned fingerprints; bypassing verification is unnecessary.

**How to apply:** For future Vultr maintenance, decode the base64 secret into a temporary mode-600 file, set `StrictHostKeyChecking=yes` and the existing `known_hosts` file, and remove the temporary key on exit. Never print or persist the key.
