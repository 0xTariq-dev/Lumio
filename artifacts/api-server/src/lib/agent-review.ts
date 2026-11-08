import { createHash } from "node:crypto";

// A review-enabled scan can pause for at most the worker's 180-second hard
// cap; owner records are kept a little longer, then pruned.
const OWNER_TTL_MS = 15 * 60 * 1000;
const MAX_OWNERS = 5_000;

/**
 * Binds a review-enabled scan to the browser session that started it, so only
 * that browser can request proposals or drive the paused review.
 */
export class AgentReviewRegistry {
  private readonly owners = new Map<string, { binding: string; createdAt: number }>();
  private readonly now: () => number;

  constructor(options: { now?: () => number } = {}) {
    this.now = options.now ?? Date.now;
  }

  register(scanId: string, browserToken: string): void {
    this.prune();
    if (this.owners.size >= MAX_OWNERS) {
      const oldest = this.owners.keys().next().value;
      if (oldest !== undefined) this.owners.delete(oldest);
    }
    this.owners.set(scanId, { binding: bindBrowser(browserToken), createdAt: this.now() });
  }

  /** "owner", "other" (another browser), or "unknown" (not review-enabled here). */
  check(scanId: string, browserToken: string): "owner" | "other" | "unknown" {
    this.prune();
    const owner = this.owners.get(scanId);
    if (!owner) return "unknown";
    return owner.binding === bindBrowser(browserToken) ? "owner" : "other";
  }

  private prune(): void {
    const cutoff = this.now() - OWNER_TTL_MS;
    for (const [scanId, owner] of this.owners) {
      if (owner.createdAt >= cutoff) break;
      this.owners.delete(scanId);
    }
  }
}

function bindBrowser(browserToken: string): string {
  return createHash("sha256").update(browserToken).digest("hex");
}

export const agentReviewRegistry = new AgentReviewRegistry();
