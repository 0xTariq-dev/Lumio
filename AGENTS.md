# Project rules

- Keep intro text animation in a shared presentation component and transition timing in the analyzer page so scan logic is unchanged.
- Use a viewport-height flex layout for the active workspace, with only the conversation thread scrolling, so the composer and footer remain visible without fixed-position overlap.

- Agent follow-ups run only while the worker holds a scan in `awaiting_review` (hard cap from `ANALYSIS_AGENT_REVIEW_SECONDS`, max 180s); the browser only sends approve/decline, and the server dispatches the stored, validated proposal — why: the client and the model can never choose a tool, target, or raw URL.
- Follow-up results live in `agentActions` and never change the baseline risk band — why: the deterministic report stays authoritative.
