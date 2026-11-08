# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

General users, especially non-technical people, who need to check a suspicious URL or email message before acting on it.

## Product Purpose

Lumio analyzes submitted public URLs and `.eml` messages in an isolated worker and returns an evidence-led report with coverage limits. Success means users can understand what was observed and what was not checked before deciding what to do next.

## Positioning

Lumio combines explicit user consent, isolated analysis, deterministic risk bands, and prioritized observable evidence. It does not promise that a URL or message is safe.

## Operating Context

Each chat turn can include a short note plus one attached URL or `.eml` file. The note is context for the conversation, not input to deterministic scanning. Users follow scan progress, review results, and may separately select and confirm scans of eligible links extracted from an email. Follow-up tools require their own per-request approval.

## Capabilities and Constraints

- Scan public HTTP(S) targets and `.eml` files only; do not open or execute attachment contents.
- Email links are not visited unless the user explicitly selects them and confirms a separate scan.
- Keep chat, email content, and reports transient to the open browser tab; retain no durable conversation, note, or raw email content.
- Offer an optional, unchecked AI-summary consent in the first-scan consent dialog. If enabled for the tab, send only the sanitized chat note and redacted deterministic evidence to the summary model; never send raw URLs, raw email, or attachment contents. The model has no tools and cannot change the deterministic report.
- Preserve the existing deterministic risk model, public-target policy, scan quotas, queue limits, isolated worker, and tool-approval boundary.
- Cancellation must stop queued or running worker work, not merely close a browser event stream.
- Report observed evidence and coverage limitations; never state that a scan guarantees safety.

## Brand Commitments

- Use plain, concise language for people without security expertise.
- Preserve Lumio's current design language, icon, logo, and tagline.
- Keep the analysis stepper pinned at the top of the chat after a scan starts.
- Use Sonner for transient notices when appropriate and establish a clear typographic hierarchy.

## Evidence on Hand

The application contains the deterministic scan reports, progress plans, coverage checks, and sanitized findings returned by its isolated analysis worker. Do not invent detection results, customers, benchmarks, or other proof.

## Product Principles

- Ask for consent before analysis and keep follow-up approvals separate.
- Make deterministic evidence and coverage limits authoritative.
- Keep submitted email and conversation content transient.
- Make selective email-link scanning explicit.
- Stop work when the user cancels or withdraws consent.

## Accessibility & Inclusion

Use keyboard-accessible controls and dialogs, clear labels, responsive layouts, and direct language suitable for non-technical users.
