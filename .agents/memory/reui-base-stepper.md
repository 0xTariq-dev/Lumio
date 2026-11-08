---
name: ReUI Base component additions
description: Safely install a single Base UI ReUI component in Lumio's Radix-configured app.
---

When adding an individual Base UI component from ReUI to this Radix UI project, preserve the existing `radix-nova` project style. The installer may rewrite shared primitives when switched to `base-nova`; restore those shared files and isolate Base-only wrappers instead of migrating the rest of the component system.

**Why:** A one-component install can otherwise alter shared Button, Collapsible, or Separator behavior outside the requested feature.

**How to apply:** Before a ReUI install, inspect its style and generated-file scope. If using a temporary Base style, restore the project style afterward, review every overwritten shared file, and run the build and dependency audit.
