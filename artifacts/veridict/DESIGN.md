# Lumio analyzer interface

## Direction

The analyzer uses a single, bounded conversation as the investigation workspace. It keeps Lumio's existing neutral theme, system typography, restrained borders, animated/reduced-motion brand marks, and exact tagline. The imported `CInputGroup18` adapts the local ReUI input-group wrappers: its multiline textarea captures an optional user note, while the accessible plus dialog attaches exactly one public URL or one validated `.eml` file. The block-end toolbar contains only plus and send. The attachment is a removable chip; the textarea is never treated as a URL, and only the separately attached target is submitted to the scanner.

Each conversation turn visibly retains its note and attached target label in memory only; URLs are displayed without query strings or fragments, and `.eml` turns show only the filename. Earlier accepted submissions, completed reports, and optional summaries remain in a read-only in-memory history while the current report retains its separate tool-approval and email-link controls. The conversation body has a bounded height and only the message thread scrolls; the execution-plan stepper stays pinned above it from acceptance through completion. Reports, URLs, email data, notes, and summaries are never written to browser storage.

## Consent and cancellation

The first scan opens an accessible consent dialog. The required session consent and a separate optional AI-summary consent boolean (unchecked by default) are the only values stored in `sessionStorage`; submissions, messages, reports, email content, URLs, and summaries are not. The optional summary disclosure explains that a note and redacted deterministic evidence are sent to existing Vultr inference only after a completed report, while raw URLs, raw email, attachments, and tool calls are excluded. The summary can explain and suggest a safe follow-up question but cannot alter the deterministic report; users are asked not to include sensitive details. Vultr's retention and training terms are not verified. With consent disabled, the summary endpoint is never called. If browser storage rejects a consent write, consent still applies for the current tab and a Sonner notice explains that it could not be retained. Withdrawal increments a generation guard, aborts optional summaries, cancels outstanding approval requests and accepted scans, clears report/query state and the thread, and removes both consent decisions. Late accepted scans are cancelled rather than shown.

Email links are individually selectable. A separate confirmation lists only selected links before sequential requests are sent through the existing selected-link endpoint. If optional summary consent is enabled, a selected-link report may use the originating email turn's note as summary context, subject to the existing one-use token and rate limit. Summary failures are displayed separately and never affect scan results. Server quota and queue errors stop further dispatch and mark remaining selected items skipped. Per-link status, batch progress, returned evidence, and summaries stay in the conversation; completed scan reports can be exported as escaped standalone HTML or printed to PDF.

## Accessibility and safety language

Dialogs use the existing Radix wrapper for focus management and keyboard dismissal. Composer controls, links, statuses, errors, reports, and batch states have labels or live-region semantics and stable test IDs. File extensions and size are validated before submission. The UI describes observable evidence and coverage limits and does not make a safety guarantee.

## Verification

`pnpm typecheck` passes in `artifacts/veridict`. A browser screenshot and interactive keyboard review were not performed in this delegated implementation.
