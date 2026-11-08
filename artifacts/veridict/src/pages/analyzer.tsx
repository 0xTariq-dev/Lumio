import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import {
  useGetAnalysisStatus,
  getGetAnalysisStatusQueryKey,
  useCreateUrlScan,
  useCreateEmailScan,
  useGetScan,
  getScan,
  getScanReport,
  getGetScanQueryKey,
  useCreateSelectedEmailLinkScan,
  useCancelScan,
  getGetScanReportQueryKey,
  useCreateAgentProposal,
  useResolveAgentApproval,
  useCancelAgentApprovals,
} from '@workspace/api-client-react';
import type { AgentActionResult, AgentApprovalRequest, ScanAccepted, ScanCancellation, ScanProgress, ScanReport } from '@workspace/api-client-react';
import {
  AlertCircle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  CircleAlert,
  Download,
  Globe2,
  LoaderCircle,
  LockKeyhole,
  Printer,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import { Skeleton } from '@/components/ui/skeleton';
import {
  LOCAL_KEV_SNAPSHOT,
  evidenceSourceLabel,
  matchKevContext,
} from '@/lib/kev-context';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { toast } from 'sonner';
import { CInputGroup18, type LumioAttachment } from '@/components/examples/c-input-group-18';
import { AnimatedTagline } from '@/components/animated-tagline';
import { motion, useReducedMotion } from 'framer-motion';

type ConversationItem = { scanId: string; type: ScanReport['type']; input: string; displayLabel?: string; note: string; report: ScanReport | null; summary?: string; summaryStatus?: 'idle' | 'streaming' | 'complete' | 'error'; summaryError?: string; error?: string };
type StopNotice = { kind: 'withdrawal' | 'single' | 'batch'; scanIds: string[]; approvalIds: string[]; message: string; pendingAcceptanceCount?: number };
type StopOutcome = { kind: 'cancelled' | 'terminal' | 'active' | 'error'; response?: ScanCancellation };
const AGENT_TOOL_LABELS: Record<AgentActionResult['tool'], string> = {
  link_metadata_share: 'Share cleaned link details with Vultr AI',
  email_link_visit: 'Visit one email link in the isolated worker',
  url_browser_observation: 'Isolated browser check',
};
const AGENT_STATUS_LABELS: Record<AgentActionResult['status'], string> = {
  running: 'Running',
  completed: 'Completed',
  skipped: 'Skipped',
  blocked: 'Not run',
  failed: 'Did not finish',
};
const AGENT_REASON_LABELS: Record<NonNullable<AgentActionResult['reasonCode']>, string> = {
  declined: 'You declined this step.',
  expired: 'The approval expired.',
  cancelled: 'Stopped before it finished.',
  timed_out: 'Reached the review time limit.',
  insufficient_time: 'Not enough review time was left to run it.',
  link_unavailable: 'This link could not be visited safely.',
  browser_not_eligible: 'The page was not eligible for a browser check.',
  analysis_failed: 'The check did not complete.',
};

function apiErrorCode(error: unknown): string {
  if (error && typeof error === 'object' && 'data' in error) {
    const data = (error as { data?: unknown }).data;
    if (data && typeof data === 'object' && 'code' in data) return String((data as { code?: unknown }).code ?? '');
  }
  return '';
}

function agentActionsHtml(report: ScanReport) {
  const actions = report.agentActions ?? [];
  if (!actions.length) return '';
  const items = actions.map((action) => `
    <article class="finding">
      <div class="meta">${escapeHtml(AGENT_STATUS_LABELS[action.status])}${action.targetHost ? ` · ${escapeHtml(action.targetHost)}` : ''}</div>
      <h2>${escapeHtml(AGENT_TOOL_LABELS[action.tool])}</h2>
      ${action.reasonCode ? `<p class="muted">${escapeHtml(AGENT_REASON_LABELS[action.reasonCode])}</p>` : ''}
      ${action.riskBand ? `<p>Result for this step only: ${escapeHtml(riskLabel(action.riskBand))}</p>` : ''}
      ${(action.findings ?? []).map((finding) => `<p><strong>${escapeHtml(finding.title)}</strong> (${escapeHtml(finding.severity)}) — ${escapeHtml(finding.explanation)}</p>`).join('')}
    </article>`).join('');
  return `<h2>Follow-up steps you approved</h2><p class="muted">Listed separately. They do not change the risk band above.</p>${items}`;
}

const MAX_EMAIL_BYTES = 10 * 1024 * 1024;
const ScanProgressStepper = lazy(() =>
  import('@/components/examples/c-stepper-44').then(({ Pattern }) => ({
    default: Pattern,
  })),
);

type ScanPlanStep = NonNullable<ScanProgress['plan']>[number];

const planStepLabels: Partial<Record<ScanPlanStep['id'], string>> = {
  consent_target: 'Validate consent and public target',
  sandbox: 'Start an isolated sandbox',
  http: 'Inspect HTTP response and redirects',
  static: 'Review static page signals',
  browser: 'Inspect in a browser when needed',
  email_parse: 'Parse message headers, body, and links',
  report: 'Assemble the evidence report',
};

function planStepLabel(id: ScanPlanStep['id'], type: ScanReport['type']) {
  const emailLabels: Partial<Record<ScanPlanStep['id'], string>> = {
    consent_target: 'Validate consent and email file',
    sandbox: 'Start an isolated email sandbox',
    email_parse: 'Parse message headers, body, and links',
    report: 'Assemble the evidence report',
  };
  if (type === 'email') {
    const emailLabel = emailLabels[id];
    if (emailLabel) return emailLabel;
  }
  if (type === 'email_link' && id === 'consent_target') {
    return 'Validate selected-link consent and target';
  }
  return planStepLabels[id] ?? humanizePlanId(String(id));
}

function humanizePlanId(value: string) {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

const planStatusLabels: Partial<Record<ScanPlanStep['status'], string>> = {
  pending: 'Waiting',
  running: 'In progress',
  completed: 'Completed',
  skipped: 'Skipped',
  failed: 'Failed',
  blocked: 'Blocked',
};

const planReasonLabels: Partial<Record<NonNullable<ScanPlanStep['reasonCode']>, string>> = {
  consent_checked: 'Consent and public-target policy passed before dispatch.',
  no_browser_required: 'Static signals did not meet the browser-inspection criteria.',
  redirect_blocked: 'The redirect policy blocked browser navigation.',
  not_html: 'The response was not HTML.',
  static_body_limit: 'The response exceeded the static-inspection size limit.',
  http_unavailable: 'The HTTP result was unavailable.',
  http_fetch_failed: 'The HTTP request did not complete.',
  browser_error: 'Browser inspection failed; coverage may be reduced.',
  earlier_step_failed: 'Not run because an earlier step did not complete.',
  analysis_failed: 'The step ended before completion.',
};

function planReasonLabel(reason: NonNullable<ScanPlanStep['reasonCode']>, type: ScanReport['type']) {
  if (type === 'email' && reason === 'no_browser_required') {
    return 'Links are only visited after separate consent.';
  }
  return planReasonLabels[reason] ?? humanizePlanId(String(reason));
}

function planStatusLabel(status: ScanPlanStep['status']) {
  return planStatusLabels[status] ?? humanizePlanId(String(status));
}

function ExecutionPlanList({
  steps,
  testId,
  type,
}: {
  steps: ScanPlanStep[];
  testId: string;
  type: ScanReport['type'];
}) {
  return (
    <section className="mt-5" aria-label="Execution plan" data-testid={testId}>
      <h3 className="text-sm font-semibold">Execution plan</h3>
      <ol className="mt-3 space-y-2">
        {steps.map((step, index) => (
          <li key={`${step.id}-${index}`} className="flex items-start gap-3 rounded-lg border border-border px-3 py-2.5">
            <span className={`mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full text-xs ${
              step.status === 'completed' ? 'bg-emerald-600/10 text-emerald-700'
                : step.status === 'running' ? 'bg-primary/10 text-primary'
                  : step.status === 'failed' || step.status === 'blocked' ? 'bg-destructive/10 text-destructive'
                    : step.status === 'skipped' ? 'bg-amber-500/10 text-amber-800'
                      : 'bg-muted text-muted-foreground'
            }`} aria-hidden="true">
              {step.status === 'completed' ? '✓' : step.status === 'running' ? '…' : step.status === 'failed' || step.status === 'blocked' ? '!' : step.status === 'skipped' ? '–' : '·'}
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{planStepLabel(step.id, type)}</p>
              {step.reasonCode && <p className="mt-0.5 text-xs leading-5 text-muted-foreground">{planReasonLabel(step.reasonCode, type)}</p>}
            </div>
            <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{planStatusLabel(step.status)}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

function riskLabel(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function severityClass(severity: string) {
  if (severity === 'critical' || severity === 'high') return 'border-destructive/30 bg-destructive/5 text-destructive';
  if (severity === 'moderate') return 'border-border bg-muted/60 text-foreground';
  return 'border-border bg-background text-muted-foreground';
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function displayAttachment(type: ScanReport['type'], input: string) {
  if (type !== 'url') return input;
  const trimmed = input.trim();
  try {
    const parsed = new URL(/^[a-z]+:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    parsed.username = '';
    parsed.password = '';
    return `${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
  } catch {
    return trimmed.split(/[?#]/, 1)[0];
  }
}

function safeErrorMessage(error: unknown) {
  if (error && typeof error === 'object' && 'data' in error) {
    const data = (error as { data?: unknown }).data;
    if (data && typeof data === 'object' && 'code' in data) {
      const code = String((data as { code?: unknown }).code ?? '');
      if (code === 'URL_NOT_ALLOWED') {
        return 'Use a public domain or IP address. Private, reserved, and nonstandard-port targets are not allowed.';
      }
      if (code === 'INVALID_URL_SCAN') {
        return 'Enter a domain, public IP, or HTTP(S) URL under 2,048 characters.';
      }
    }
  }
  if (error && typeof error === 'object' && 'message' in error) {
    const message = String((error as { message?: unknown }).message ?? '');
    if (message.includes('unavailable')) return 'The isolated analysis worker is unavailable. No scan was started.';
    if (message.includes('Too Many') || message.includes('rate')) return 'The analyzer is at its request limit. Please try again later.';
  }
  return 'We could not start this analysis. No report was created. Please try again.';
}

function escapeHtml(value: unknown) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char] as string);
}

function kevStatusLabel(result: ReturnType<typeof matchKevContext>) {
  if (result.status === 'matched') return 'Possible match in the local snapshot';
  if (result.status === 'no-match') return 'No matching entry in this snapshot';
  if (result.reason === 'weak') return 'Evidence was too weak to match';
  if (result.reason === 'ambiguous') return 'Evidence was ambiguous, so no match was made';
  if (result.reason === 'unknown-version') return 'No exact version was available for matching';
  return 'No product and version evidence was available';
}

function kevContextHtml(report: ScanReport) {
  if (report.type !== 'url') return '';

  const result = matchKevContext(report.softwareEvidence);
  const evidence = result.evidence;
  const matches = result.matches.map((entry) => {
    const ranges = entry.affectedRanges
      .map((range) => `${range.from}–${range.through}`)
      .join('; ');
    return `
      <article class="kev-entry">
        <h3>${escapeHtml(entry.cveId)} · ${escapeHtml(entry.product)}</h3>
        <p>${escapeHtml(entry.summary)}</p>
        <p><strong>${escapeHtml(entry.kevStatus)}</strong> · Added ${escapeHtml(entry.kevDate)}</p>
        <p><strong>Affected releases:</strong> ${escapeHtml(ranges)}</p>
        <p><strong>Fixed-version reference:</strong> ${escapeHtml(entry.fixedVersion)}. ${escapeHtml(entry.branchNote)}</p>
        <p class="kev-sources">
          Sources:
          <a href="${escapeHtml(entry.cisaUrl)}" target="_blank" rel="noopener noreferrer">CISA alert</a> ·
          <a href="${escapeHtml(entry.cveRecordUrl)}" target="_blank" rel="noopener noreferrer">CVE record</a> ·
          <a href="${escapeHtml(entry.vendorAdvisoryUrl)}" target="_blank" rel="noopener noreferrer">WordPress advisory</a>
        </p>
      </article>`;
  }).join('');

  return `
    <section class="kev-context" aria-labelledby="kev-context-title">
      <h2 id="kev-context-title">Possible vulnerability context</h2>
      <p><strong>${escapeHtml(kevStatusLabel(result))}</strong></p>
      ${evidence
        ? `<p><strong>Observed:</strong> ${escapeHtml(evidence.product)} ${escapeHtml(evidence.version || 'version unknown')} · ${escapeHtml(evidenceSourceLabel(evidence.evidenceSource))}</p>`
        : ''}
      ${matches || '<p>No CVE context was matched from the available exact, strong evidence.</p>'}
      <p class="muted">Snapshot verified ${escapeHtml(LOCAL_KEV_SNAPSHOT.checkedAt)} · local data, not live.</p>
      <p class="muted">Possible/unverified; no vulnerability test performed. This context does not change the phishing risk band and a missing match does not establish safety.</p>
    </section>`;
}

function reportHtml(report: ScanReport, explanationText = '') {
  const executionPlan = (report.executionPlan ?? []).map((step) => `
    <li><strong>${escapeHtml(planStepLabel(step.id, report.type))}</strong> — ${escapeHtml(planStatusLabel(step.status))}${step.reasonCode ? `: ${escapeHtml(planReasonLabel(step.reasonCode, report.type))}` : ''}</li>`).join('');
  const findings = report.findings.map((finding) => `
    <article class="finding">
      <div class="meta">${escapeHtml(finding.severity)} · ${escapeHtml(finding.strength)} · ${escapeHtml(finding.source.replace(/_/g, ' '))}</div>
      <h2>${escapeHtml(finding.title)}</h2>
      <p>${escapeHtml(finding.explanation)}</p>
      ${finding.sanitizedObservedValue ? `<pre>${escapeHtml(finding.sanitizedObservedValue)}</pre>` : ''}
      ${(finding.limitations ?? []).map((item) => `<p class="muted">Limitation: ${escapeHtml(item)}</p>`).join('')}
    </article>`).join('');
  const checks = report.coverage.checks.map((check) =>
    `<li><strong>${escapeHtml(check.name)}</strong> — ${escapeHtml(check.status)}${check.reason ? `: ${escapeHtml(check.reason)}` : ''}</li>`).join('');
  const links = (report.links ?? []).map((link) =>
    `<li>${escapeHtml(link.anchorText || link.targetHost)} — ${escapeHtml(link.displayUrl)} <span class="muted">(${link.scanAvailable ? 'scan available' : 'not available'})</span></li>`).join('');
  const explanation = explanationText
    ? `<section class="explanation"><h2>Optional AI summary</h2><p>${escapeHtml(explanationText)}</p><p class="muted">AI-generated explanation only. It does not change the deterministic report or establish safety.</p></section>`
    : '';
  const partialBanner = report.partial
    ? `<section class="partial"><strong>Partial report</strong><p>${escapeHtml(report.partialReason ?? 'The scan was cancelled before all checks were complete. No findings do not establish safety.')}</p></section>`
    : '';
  return `<!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width">
      <title>Lumio analysis report</title>
      <style>
        *{box-sizing:border-box}
        html,body{min-height:100%;margin:0}
        body{background:#f6f6f7;color:#18181b;font:15px/1.6 system-ui,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
        main{width:calc(100% - 32px);max-width:860px;margin:40px auto;padding:36px;background:#fff;border:1px solid #e4e4e7;border-radius:14px}
        h1{font-size:30px;margin:8px 0}h2{font-size:18px;margin:8px 0;break-after:avoid-page}
        .meta,.muted{color:#71717a;font-size:13px}
        .band{display:inline-block;border:1px solid #d4d4d8;border-radius:999px;padding:3px 12px;font-weight:650}
        .partial{margin:18px 0;padding:14px;border:1px solid #d97706;border-radius:8px;background:#fffbeb}
        .finding{border-top:1px solid #e4e4e7;padding:18px 0}
        .kev-context{border-top:1px solid #e4e4e7;margin-top:24px;padding-top:18px;overflow-wrap:anywhere}
        .kev-entry{margin-top:14px;padding:14px 0;border-top:1px solid #e4e4e7}
        .kev-sources a{color:#18181b;text-underline-offset:3px}
        .explanation{border-top:1px solid #e4e4e7;margin-top:22px;padding-top:16px}
        pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f5;padding:10px;border-radius:8px}
        li{margin:7px 0;overflow-wrap:anywhere}footer{border-top:1px solid #e4e4e7;margin-top:24px;padding-top:16px;color:#71717a;font-size:12px;overflow-wrap:anywhere}
        @media screen and (max-width:720px){main{margin:16px auto;padding:24px}}
        @media print{
          @page{margin:14mm}
          html,body{height:auto;background:#fff}
          main{width:100%;max-width:none;margin:0;padding:0;border:0;border-radius:0}
          .finding,.kev-entry,.explanation,footer{break-inside:avoid-page;page-break-inside:avoid}
          li{break-inside:avoid-page;page-break-inside:avoid}
        }
      </style>
    </head>
    <body>
      <main><div class="meta">LUMIO · EVIDENCE REPORT</div><h1>${escapeHtml(riskLabel(report.riskBand))} risk</h1><p class="meta">Completed ${escapeHtml(formatDate(report.completedAt))} · Rule set ${escapeHtml(report.ruleSetVersion)}</p>
    ${partialBanner}
    ${executionPlan ? `<h2>Execution plan</h2><ol>${executionPlan}</ol>` : ''}
    <h2>Evidence and findings</h2>${findings || '<p>No findings were returned by the analyzer.</p>'}
    ${kevContextHtml(report)}
    ${agentActionsHtml(report)}
    <h2>Coverage</h2><p>${report.coverage.sufficient ? 'Coverage marked sufficient by the analyzer.' : 'Coverage is limited; interpret this result with caution.'}</p><ul>${checks}</ul>
    ${explanation}
    ${links ? `<h2>Links found in email</h2><ul>${links}</ul>` : ''}
    <footer>This report contains only the evidence returned by Lumio. It is not a guarantee that a message or URL is safe.</footer>
      </main>
    </body>
  </html>`;
}

function KevContextSection({ report }: { report: ScanReport }) {
  const result = matchKevContext(report.softwareEvidence);

  return (
    <section
      className="mt-6 border-t border-border pt-5"
      aria-labelledby="kev-context-title"
      data-testid="section-possible-vulnerability-context"
    >
      <div className="flex items-start gap-2">
        <CircleAlert className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div className="min-w-0">
          <h3 id="kev-context-title" className="text-sm font-semibold">Possible vulnerability context</h3>
          <p className="mt-1 text-sm font-medium">{kevStatusLabel(result)}</p>
          {result.evidence ? (
            <p className="mt-1 break-words text-sm text-muted-foreground" data-testid="kev-observed-evidence">
              Observed {result.evidence.product} {result.evidence.version || 'version unknown'} · {evidenceSourceLabel(result.evidence.evidenceSource)}
            </p>
          ) : (
            <p className="mt-1 text-sm text-muted-foreground">
              No exact, strong product/version evidence was available for local matching.
            </p>
          )}
        </div>
      </div>

      {result.matches.map((entry) => (
        <article key={entry.cveId} className="mt-4 border-t border-border pt-4" data-testid={`kev-entry-${entry.cveId}`}>
          <h4 className="text-sm font-semibold">{entry.cveId} · {entry.product}</h4>
          <p className="mt-1 text-sm leading-6 text-muted-foreground">{entry.summary}</p>
          <dl className="mt-3 space-y-2 text-sm">
            <div>
              <dt className="font-medium">{entry.kevStatus}</dt>
              <dd className="text-muted-foreground">Added {entry.kevDate}</dd>
            </div>
            <div>
              <dt className="font-medium">Affected release ranges</dt>
              <dd className="break-words text-muted-foreground">
                {entry.affectedRanges.map((range) => `${range.from}–${range.through}`).join('; ')}
              </dd>
            </div>
            <div>
              <dt className="font-medium">Fixed-version reference</dt>
              <dd className="text-muted-foreground">{entry.fixedVersion}. {entry.branchNote}</dd>
            </div>
          </dl>
          <p className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-sm">
            <a className="underline underline-offset-4" href={entry.cisaUrl} target="_blank" rel="noopener noreferrer">CISA alert</a>
            <a className="underline underline-offset-4" href={entry.cveRecordUrl} target="_blank" rel="noopener noreferrer">CVE record</a>
            <a className="underline underline-offset-4" href={entry.vendorAdvisoryUrl} target="_blank" rel="noopener noreferrer">WordPress advisory</a>
          </p>
        </article>
      ))}

      <p className="mt-3 text-xs leading-5 text-muted-foreground" data-testid="kev-snapshot-freshness">
        Local snapshot verified {LOCAL_KEV_SNAPSHOT.checkedAt}; it is not live.
      </p>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">
        Possible/unverified; no vulnerability test performed. This context does not change the phishing risk band, and a missing match does not establish safety.
      </p>
    </section>
  );
}

function ScanProgressLoadingSkeleton() {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-busy="true"
      data-testid="skeleton-scan-progress"
      className="space-y-3"
    >
      <span className="sr-only">Loading scan progress steps</span>
      <div
        aria-hidden="true"
        className="grid gap-4 sm:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]"
      >
        <div className="space-y-3">
          <Skeleton className="h-11 w-full" />
          <Skeleton className="h-11 w-5/6" />
          <Skeleton className="h-11 w-4/5" />
        </div>
        <div className="space-y-3">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-6 w-full" />
          <Skeleton className="h-11 w-40" />
        </div>
      </div>
    </div>
  );
}

export default function AnalyzerPage() {
  const queryClient = useQueryClient();
  const [shellActive, setShellActive] = useState(false);
  const [cardActive, setCardActive] = useState(false);
  const [cardLeaving, setCardLeaving] = useState(false);
  const reducedMotion = useReducedMotion();
  const layoutTransition = reducedMotion
    ? { duration: 0 }
    : cardLeaving
      ? { type: 'spring' as const, duration: 1.1, bounce: 0.1 }
      : { duration: 0.7, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] };
  const [heroLeaving, setHeroLeaving] = useState(false);
  const shellRef = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (!heroLeaving) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const transition = window.setTimeout(() => {
      setCardActive(true);
      window.scrollTo({ top: 0, behavior: reduced ? 'instant' : 'smooth' });
    }, reduced ? 0 : 700);
    return () => window.clearTimeout(transition);
  }, [heroLeaving]);
  useEffect(() => {
    if (!cardLeaving) return;
    const fullscreen = window.setTimeout(() => {
      window.scrollTo({ top: 0, behavior: 'instant' });
      setShellActive(true);
    }, reducedMotion ? 0 : 220);
    const focus = window.setTimeout(() => shellRef.current?.querySelector<HTMLElement>('textarea')?.focus({ preventScroll: true }), reducedMotion ? 0 : 1400);
    return () => { window.clearTimeout(fullscreen); window.clearTimeout(focus); };
  }, [cardLeaving, reducedMotion]);
  const activateShell = () => {
    setHeroLeaving(true);
  };
  const statusQuery = useGetAnalysisStatus({
    query: { queryKey: getGetAnalysisStatusQueryKey(), refetchInterval: 15000 },
  });
  const createUrl = useCreateUrlScan();
  const createEmail = useCreateEmailScan();
  const createSelectedLink = useCreateSelectedEmailLinkScan();
  const cancelScanMutation = useCancelScan();
  const createAgentProposal = useCreateAgentProposal();
  const resolveAgentApprovalMutation = useResolveAgentApproval();
  const cancelAgentApprovals = useCancelAgentApprovals();
  const cancelScan = useCancelScan();
  const [attachment, setAttachment] = useState<LumioAttachment | null>(null);
  const [chatNote, setChatNote] = useState('');
  const [formError, setFormError] = useState('');
  const [scanAccepted, setScanAccepted] = useState<ScanAccepted | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [emailReport, setEmailReport] = useState<ScanReport | null>(null);
  const [scanType, setScanType] = useState<ScanReport['type']>('url');
  const [streamError, setStreamError] = useState('');
  const [streamFinished, setStreamFinished] = useState(false);
  const [approvalRequest, setApprovalRequest] = useState<AgentApprovalRequest | null>(null);
  const [approvalError, setApprovalError] = useState('');
  const [agentReviewOptIn, setAgentReviewOptIn] = useState(false);
  const [reviewDeadline, setReviewDeadline] = useState<string | null>(null);
  const [liveActions, setLiveActions] = useState<AgentActionResult[]>([]);
  const [reviewNote, setReviewNote] = useState('');
  const reviewInFlightRef = useRef(false);
  const [sessionConsent, setSessionConsent] = useState(() => {
    try { return sessionStorage.getItem('lumio-session-consent') === 'yes'; } catch { return false; }
  });
  const [summaryConsent, setSummaryConsent] = useState(() => {
    try { return sessionStorage.getItem('lumio-summary-consent') === 'yes'; } catch { return false; }
  });
  const [consentDialogOpen, setConsentDialogOpen] = useState(false);
  const [batchDialogOpen, setBatchDialogOpen] = useState(false);
  const [selectedLinkIds, setSelectedLinkIds] = useState<string[]>([]);
  const [batchStates, setBatchStates] = useState<Record<string, { status: string; reason?: string; scanId?: string }>>({});
  const [batchLabels, setBatchLabels] = useState<Record<string, string>>({});
  const [batchProgress, setBatchProgress] = useState<ScanProgress | null>(null);
  const [batchPlanVisible, setBatchPlanVisible] = useState(false);
  const [activeBatchScans, setActiveBatchScans] = useState<string[]>([]);
  const [conversationHistory, setConversationHistory] = useState<ConversationItem[]>([]);
  const [cancelled, setCancelled] = useState(false);
  const [stopNotice, setStopNotice] = useState<StopNotice | null>(null);
  const generationRef = useRef(0);
  const recoveringScanIdsRef = useRef<Set<string>>(new Set());
  const activeScanIdsRef = useRef<Set<string>>(new Set());
  const terminalScanStatusRef = useRef<Map<string, ScanCancellation['status']>>(new Map());
  const unsafeBatchEventScanIdsRef = useRef<Set<string>>(new Set());
  const submissionRef = useRef<{ attachment: LumioAttachment; message: string } | null>(null);
  const batchCancelledRef = useRef(false);
  const pendingAcceptanceChecksRef = useRef(0);
  const summaryAbortControllersRef = useRef<Map<string, AbortController>>(new Map());
  const summaryStartedScanIdsRef = useRef<Set<string>>(new Set());
  const conversationNotesRef = useRef<Map<string, string>>(new Map());
  const summaryConsentRef = useRef(summaryConsent);
  summaryConsentRef.current = summaryConsent;
  const scanQuery = useGetScan(scanAccepted?.scanId ?? '', {
    query: {
      queryKey: getGetScanQueryKey(scanAccepted?.scanId ?? ''),
      enabled: Boolean(scanAccepted?.scanId) && !streamFinished,
      refetchInterval: (query) => {
        const status = query.state.data?.status;
        return status === 'completed' || status === 'failed' || status === 'cancelled' ? false : 4000;
      },
    },
  });
  const status = statusQuery.data;
  const workerUnavailable = status?.workerStatus === 'unavailable' || status?.scannerAvailable === false;
  const busy = createUrl.isPending || createEmail.isPending || createSelectedLink.isPending ||
    (!!scanAccepted && !streamFinished && !report) || activeBatchScans.length > 0;
  const emailLinks = useMemo(() => (emailReport?.links ?? []).slice(0, 50), [emailReport]);
  const activeReport = report;

  function acceptSessionConsent() {
    try {
      sessionStorage.setItem('lumio-session-consent', 'yes');
    } catch {
      toast.error('Consent is active for this tab, but could not be remembered for the rest of the session.');
    }
    try {
      sessionStorage.setItem('lumio-summary-consent', summaryConsent ? 'yes' : 'no');
    } catch {
      toast.error('The optional summary choice is active for this tab, but could not be remembered for the rest of the session.');
    }
    setSessionConsent(true);
    setConsentDialogOpen(false);
    const pending = submissionRef.current;
    submissionRef.current = null;
    if (pending) submitInput(pending.attachment, pending.message);
  }

  function submitInput(selectedAttachment: LumioAttachment, message: string) {
    const token = generationRef.current;
    setFormError('');
    setCancelled(false);
    if (selectedAttachment.type === 'url') {
      const rawTarget = selectedAttachment.value;
      if (/[\r\n]/.test(rawTarget)) { setFormError('Attach one URL or public domain on a single line.'); return; }
      const target = rawTarget.trim();
      if (!target) { setFormError('Enter a domain, public IP, or HTTP(S) URL.'); return; }
      if (target.length > 2048) { setFormError('Use a domain, public IP, or HTTP(S) URL under 2,048 characters.'); return; }
      createUrl.mutate({ data: { url: target, consent: true, ...(agentReviewOptIn ? { agentReview: true } : {}) } }, {
        onSuccess: (accepted) => {
          if (token !== generationRef.current) {
            void cancelLateAcceptedScan(accepted.scanId);
            return;
          }
          activeScanIdsRef.current.add(accepted.scanId);
          void statusQuery.refetch();
          conversationNotesRef.current.set(accepted.scanId, message);
          setConversationHistory((current) => [...current, { scanId: accepted.scanId, type: 'url', input: target, note: message, report: null, summaryStatus: 'idle' }]);
          setAttachment(null);
          setChatNote('');
          beginAccepted(accepted, 'url');
        },
        onError: (error) => {
          if (token === generationRef.current) setFormError(safeErrorMessage(error));
          else settleLateAcceptanceCheck();
        },
      });
    } else {
      const selectedFile = selectedAttachment.file;
      if (!selectedFile.name.toLowerCase().endsWith('.eml')) { setFormError('Choose an .eml file. Other file types are not accepted.'); return; }
      if (selectedFile.size > MAX_EMAIL_BYTES) { setFormError('The selected file is larger than the 10 MB limit.'); return; }
      createEmail.mutate({ data: { file: selectedFile, consent: true, ...(agentReviewOptIn ? { agentReview: true } : {}) } }, {
        onSuccess: (accepted) => {
          if (token !== generationRef.current) {
            void cancelLateAcceptedScan(accepted.scanId);
            return;
          }
          activeScanIdsRef.current.add(accepted.scanId);
          void statusQuery.refetch();
          conversationNotesRef.current.set(accepted.scanId, message);
          setConversationHistory((current) => [...current, { scanId: accepted.scanId, type: 'email', input: selectedFile.name, note: message, report: null, summaryStatus: 'idle' }]);
          beginAccepted(accepted, 'email');
          setAttachment(null);
          setChatNote('');
        },
        onError: (error) => {
          if (token === generationRef.current) setFormError(safeErrorMessage(error));
          else settleLateAcceptanceCheck();
        },
      });
    }
  }

  function requestSubmit(message: string, selectedAttachment: LumioAttachment | null) {
    if (!selectedAttachment) { setFormError('Attach one public URL or one .eml file before sending.'); return; }
    submissionRef.current = { attachment: selectedAttachment, message };
    if (!sessionConsent) { setConsentDialogOpen(true); return; }
    submissionRef.current = null;
    submitInput(selectedAttachment, message);
  }

  async function requestWorkerStop(scanId: string): Promise<StopOutcome> {
    const terminalBeforeRequest = terminalScanStatusRef.current.get(scanId);
    if (terminalBeforeRequest) {
      return terminalBeforeRequest === 'cancelled'
        ? { kind: 'cancelled', response: { scanId, cancelled: true, status: 'cancelled' } }
        : { kind: 'terminal', response: { scanId, cancelled: false, status: terminalBeforeRequest } };
    }
    try {
      const response = await cancelScan.mutateAsync({ scanId });
      if (response.cancelled || response.status === 'cancelled') return { kind: 'cancelled', response };
      if (response.status === 'completed' || response.status === 'failed') return { kind: 'terminal', response };
      const observedTerminal = terminalScanStatusRef.current.get(scanId);
      if (observedTerminal) {
        return observedTerminal === 'cancelled'
          ? { kind: 'cancelled', response: { scanId, cancelled: true, status: 'cancelled' } }
          : { kind: 'terminal', response: { scanId, cancelled: false, status: observedTerminal } };
      }
      return { kind: 'active', response };
    } catch {
      const observedTerminal = terminalScanStatusRef.current.get(scanId);
      if (observedTerminal) {
        return observedTerminal === 'cancelled'
          ? { kind: 'cancelled', response: { scanId, cancelled: true, status: 'cancelled' } }
          : { kind: 'terminal', response: { scanId, cancelled: false, status: observedTerminal } };
      }
      return { kind: 'error' };
    }
  }

  function setUnconfirmedNotice(kind: StopNotice['kind'], scanIds: string[], approvalIds: string[] = []) {
    const trackedScanIds = scanIds.filter((scanId) => activeScanIdsRef.current.has(scanId));
    const pendingAcceptanceCount = pendingAcceptanceChecksRef.current;
    if (!trackedScanIds.length && !approvalIds.length && pendingAcceptanceCount === 0) {
      setStopNotice(null);
      return;
    }
    const message = kind === 'withdrawal'
      ? 'Consent was withdrawn and the conversation was cleared, but Lumio could not confirm every scan and approval cancellation.'
      : kind === 'batch'
        ? 'Lumio could not confirm that every selected scan stopped. Unconfirmed scans remain tracked.'
        : 'Lumio could not confirm that this scan stopped. It remains tracked.';
    setStopNotice({ kind, scanIds: [...new Set(trackedScanIds)], approvalIds: [...new Set(approvalIds)], message, pendingAcceptanceCount });
  }

  function settleLateAcceptanceCheck() {
    pendingAcceptanceChecksRef.current = Math.max(0, pendingAcceptanceChecksRef.current - 1);
    setStopNotice((current) => {
      if (!current) return null;
      const pendingAcceptanceCount = pendingAcceptanceChecksRef.current;
      if (!current.scanIds.length && !current.approvalIds.length && pendingAcceptanceCount === 0) return null;
      return { ...current, pendingAcceptanceCount };
    });
  }

  async function cancelLateAcceptedScan(scanId: string) {
    activeScanIdsRef.current.add(scanId);
    const outcome = await requestWorkerStop(scanId);
    if (outcome.kind === 'cancelled' || outcome.kind === 'terminal') {
      activeScanIdsRef.current.delete(scanId);
    } else {
      setActiveBatchScans((current) => [...new Set([...current, scanId])]);
    }
    pendingAcceptanceChecksRef.current = Math.max(0, pendingAcceptanceChecksRef.current - 1);
    setStopNotice((current) => {
      const scanIds = new Set(current?.scanIds ?? []);
      if (outcome.kind === 'cancelled' || outcome.kind === 'terminal') scanIds.delete(scanId);
      else scanIds.add(scanId);
      const approvalIds = current?.approvalIds ?? [];
      const pendingAcceptanceCount = pendingAcceptanceChecksRef.current;
      if (!scanIds.size && !approvalIds.length && pendingAcceptanceCount === 0) return null;
      return {
        kind: 'withdrawal',
        scanIds: [...scanIds],
        approvalIds,
        pendingAcceptanceCount,
        message: 'Consent was withdrawn and the conversation was cleared, but Lumio could not confirm every scan and approval cancellation.',
      };
    });
  }

  function removeTrackedScan(scanId: string) {
    activeScanIdsRef.current.delete(scanId);
    setActiveBatchScans((current) => current.filter((id) => id !== scanId));
  }

  function resolveStopNoticeScan(scanId: string) {
    setStopNotice((current) => {
      if (!current) return null;
      const scanIds = current.scanIds.filter((id) => id !== scanId);
      if (!scanIds.length && !current.approvalIds.length && !current.pendingAcceptanceCount) return null;
      return { ...current, scanIds };
    });
  }

  function applyConfirmedStop(scanId: string, outcome: StopOutcome) {
    const status = outcome.response?.status;
    if (outcome.kind === 'cancelled') {
      unsafeBatchEventScanIdsRef.current.delete(scanId);
      terminalScanStatusRef.current.set(scanId, 'cancelled');
      resolveStopNoticeScan(scanId);
      removeTrackedScan(scanId);
      setBatchStates((current) => Object.fromEntries(Object.entries(current).map(([linkId, item]) =>
        item.scanId === scanId ? [linkId, { ...item, status: 'cancelled', reason: undefined }] : [linkId, item],
      )));
      setConversationHistory((current) => current.map((entry) => entry.scanId === scanId ? { ...entry, error: 'This analysis was cancelled by request.' } : entry));
      if (scanAccepted?.scanId === scanId) {
        setCancelled(true);
        setStreamFinished(true);
        setStreamError('This analysis was cancelled. Any completed reports remain available.');
      }
      return;
    }
    if (outcome.kind === 'terminal') {
      if (status) terminalScanStatusRef.current.set(scanId, status);
      if (status === 'failed') unsafeBatchEventScanIdsRef.current.delete(scanId);
      resolveStopNoticeScan(scanId);
      activeScanIdsRef.current.delete(scanId);
      if (status === 'failed') {
        setActiveBatchScans((current) => current.filter((id) => id !== scanId));
        setBatchStates((current) => Object.fromEntries(Object.entries(current).map(([linkId, item]) =>
          item.scanId === scanId ? [linkId, { ...item, status: 'failed', reason: 'The worker reported that this scan failed.' }] : [linkId, item],
        )));
        setConversationHistory((current) => current.map((entry) => entry.scanId === scanId ? { ...entry, error: 'The worker reported that this scan failed.' } : entry));
        if (scanAccepted?.scanId === scanId) {
          setStreamError('Analysis failed. No report is available for this scan.');
          setStreamFinished(true);
        }
      } else {
        if (unsafeBatchEventScanIdsRef.current.has(scanId)) {
          unsafeBatchEventScanIdsRef.current.delete(scanId);
          setActiveBatchScans((current) => current.filter((id) => id !== scanId));
          const reason = 'The worker completed, but its report event was unavailable.';
          setBatchStates((current) => Object.fromEntries(Object.entries(current).map(([linkId, item]) =>
            item.scanId === scanId ? [linkId, { ...item, status: 'completed', reason }] : [linkId, item],
          )));
          setConversationHistory((current) => current.map((entry) => entry.scanId === scanId ? { ...entry, error: reason } : entry));
        } else {
          setBatchStates((current) => Object.fromEntries(Object.entries(current).map(([linkId, item]) =>
            item.scanId === scanId ? [linkId, { ...item, status: 'completed', reason: 'Worker reported completion; this scan was not marked cancelled.' }] : [linkId, item],
          )));
          // Keep the current SSE open so a completed report can still arrive.
        }
      }
    }
  }

  async function withdrawConsent() {
    generationRef.current += 1;
    batchCancelledRef.current = true;
    summaryAbortControllersRef.current.forEach((controller) => controller.abort());
    summaryAbortControllersRef.current.clear();
    summaryStartedScanIdsRef.current.clear();
    conversationNotesRef.current.clear();
    const workerIds = [...activeScanIdsRef.current];
    const allSessionIds = [...new Set([...workerIds, ...conversationHistory.map((entry) => entry.scanId)])];
    pendingAcceptanceChecksRef.current = Number(createUrl.isPending) + Number(createEmail.isPending) + Number(createSelectedLink.isPending);
    try { sessionStorage.removeItem('lumio-session-consent'); } catch {
      toast.error('Consent was withdrawn for this tab, but the session decision could not be removed from browser storage.');
    }
    try { sessionStorage.removeItem('lumio-summary-consent'); } catch {
      toast.error('The optional summary consent could not be removed from browser storage.');
    }
    setSessionConsent(false);
    setSummaryConsent(false);
    summaryConsentRef.current = false;
    setScanAccepted(null); setProgress(null); setReport(null); setEmailReport(null);
    setStreamError(''); setStreamFinished(false); setApprovalRequest(null);
    setSelectedLinkIds([]); setBatchStates({}); setBatchLabels({}); setBatchProgress(null); setConversationHistory([]);
    setAttachment(null); setChatNote('');
    setBatchPlanVisible(false); setActiveBatchScans([]);
    allSessionIds.forEach((scanId) => queryClient.removeQueries({ queryKey: getGetScanQueryKey(scanId), exact: true }));
    queryClient.removeQueries({ predicate: (query) => Array.isArray(query.queryKey) && String(query.queryKey[0]).startsWith('/api/scans/') });
    setFormError(''); setCancelled(false); setBatchDialogOpen(false);
    submissionRef.current = null;
    setStopNotice({ kind: 'withdrawal', scanIds: workerIds, approvalIds: allSessionIds, message: 'Consent withdrawn and conversation cleared. Waiting for the worker and approval services to confirm cancellation.', pendingAcceptanceCount: pendingAcceptanceChecksRef.current });
    const [scanResults, approvalResults] = await Promise.all([
      Promise.all(workerIds.map(async (scanId) => ({ scanId, outcome: await requestWorkerStop(scanId) }))),
      Promise.all(allSessionIds.map(async (scanId) => {
        try {
          await cancelAgentApprovals.mutateAsync({ scanId });
          return { scanId, confirmed: true };
        } catch {
          return { scanId, confirmed: false };
        }
      })),
    ]);
    const unconfirmedScans: string[] = [];
    for (const { scanId, outcome } of scanResults) {
      if (outcome.kind === 'cancelled' || outcome.kind === 'terminal') {
        activeScanIdsRef.current.delete(scanId);
      } else {
        unconfirmedScans.push(scanId);
      }
    }
    const unconfirmedApprovals = approvalResults.filter((result) => !result.confirmed).map((result) => result.scanId);
    setStopNotice((current) => {
      const lateScanIds = current?.scanIds.filter((scanId) => !workerIds.includes(scanId)) ?? [];
      const lateApprovalIds = current?.approvalIds.filter((scanId) => !allSessionIds.includes(scanId)) ?? [];
      const scanIds = [...new Set([...unconfirmedScans.filter((scanId) => activeScanIdsRef.current.has(scanId)), ...lateScanIds])];
      const approvalIds = [...new Set([...unconfirmedApprovals, ...lateApprovalIds])];
      const pendingAcceptanceCount = pendingAcceptanceChecksRef.current;
      if (!scanIds.length && !approvalIds.length && pendingAcceptanceCount === 0) return null;
      return {
        kind: 'withdrawal',
        scanIds,
        approvalIds,
        pendingAcceptanceCount,
        message: 'Consent was withdrawn and the conversation was cleared, but Lumio could not confirm every scan and approval cancellation.',
      };
    });
    setActiveBatchScans((current) => [...new Set([
      ...unconfirmedScans.filter((scanId) => activeScanIdsRef.current.has(scanId)),
      ...current.filter((scanId) => !workerIds.includes(scanId) && activeScanIdsRef.current.has(scanId)),
    ])]);
  }

  async function runSelectedBatch() {
    if (!emailReport || !selectedLinkIds.length) return;
    batchCancelledRef.current = false;
    const batchGeneration = generationRef.current;
    const links = emailLinks.filter((link) => selectedLinkIds.includes(link.linkId) && link.scanAvailable);
    const sourceNote = conversationNotesRef.current.get(emailReport.scanId) ?? '';
    setBatchPlanVisible(true);
    setScanType('email_link');
    setBatchProgress({ stage: 'queued', message: 'Submitting selected links.', completedSteps: 0, totalSteps: 1, plan: [] });
    setBatchStates(Object.fromEntries(links.map((link, index) => [link.linkId, { status: index === 0 ? 'submitting' : 'pending' }])));
    setBatchLabels(Object.fromEntries(links.map((link) => [link.linkId, link.anchorText || link.targetHost])));
    setBatchDialogOpen(false);
    for (let index = 0; index < links.length; index += 1) {
      if (batchCancelledRef.current) {
        setBatchStates((current) => ({ ...current, ...Object.fromEntries(links.slice(index).map((link) => [link.linkId, { status: 'cancelled' }])) }));
        break;
      }
      const link = links[index];
      setBatchStates((current) => ({ ...current, [link.linkId]: { status: 'submitting' } }));
      try {
        const accepted = await createSelectedLink.mutateAsync({ scanId: emailReport.scanId, linkId: link.linkId, data: { consent: true } });
        if (batchGeneration !== generationRef.current) {
          void cancelLateAcceptedScan(accepted.scanId);
          return;
        }
        activeScanIdsRef.current.add(accepted.scanId);
        setActiveBatchScans((current) => [...new Set([...current, accepted.scanId])]);
        conversationNotesRef.current.set(accepted.scanId, sourceNote);
        setConversationHistory((current) => [...current, { scanId: accepted.scanId, type: 'email_link', input: link.displayUrl, displayLabel: link.anchorText || link.targetHost, note: sourceNote, report: null, summaryStatus: 'idle' }]);
        setBatchStates((current) => ({ ...current, [link.linkId]: { status: accepted.status, scanId: accepted.scanId } }));
        if (batchCancelledRef.current) {
          const outcome = await requestWorkerStop(accepted.scanId);
          if (outcome.kind === 'cancelled') {
            applyConfirmedStop(accepted.scanId, outcome);
            continue;
          }
          if (outcome.kind === 'terminal' && outcome.response?.status === 'failed') {
            applyConfirmedStop(accepted.scanId, outcome);
            continue;
          }
          if (outcome.kind === 'terminal' && outcome.response?.status === 'completed') {
            applyConfirmedStop(accepted.scanId, outcome);
          } else {
            setBatchStates((current) => ({ ...current, [link.linkId]: { status: accepted.status, scanId: accepted.scanId, reason: 'Stop requested; the worker has not confirmed cancellation.' } }));
            setUnconfirmedNotice('batch', [accepted.scanId]);
          }
        }
        setBatchProgress((current) => ({
          stage: accepted.status === 'running' ? 'starting_sandbox' : 'queued',
          message: `Selected link accepted and ${accepted.status}.`,
          completedSteps: current?.completedSteps ?? 0,
          totalSteps: current?.totalSteps ?? 1,
          plan: current?.plan ?? [],
        }));
        try {
          const eventUrl = new URL(accepted.eventsPath, window.location.origin);
          if (eventUrl.origin === window.location.origin) {
            const stream = new EventSource(eventUrl.toString());
            let terminal = false;
            const finishBatchScan = () => {
              if (terminal) return;
              terminal = true;
              activeScanIdsRef.current.delete(accepted.scanId);
              setActiveBatchScans((current) => current.filter((id) => id !== accepted.scanId));
            };
            const setStatus = (status: string) => {
              if (batchGeneration !== generationRef.current) { stream.close(); return; }
              setBatchStates((current) => ({ ...current, [link.linkId]: { ...current[link.linkId], status, scanId: accepted.scanId } }));
              if (status === 'failed' || status === 'cancelled') {
                setConversationHistory((current) => current.map((entry) => entry.scanId === accepted.scanId ? { ...entry, error: status === 'failed' ? 'This link scan did not complete.' : 'This link scan was cancelled.' } : entry));
              }
              if (status === 'completed' || status === 'failed' || status === 'cancelled') {
                terminalScanStatusRef.current.set(accepted.scanId, status);
                resolveStopNoticeScan(accepted.scanId);
                finishBatchScan();
              }
            };
            stream.addEventListener('progress', (event) => {
              if (batchGeneration !== generationRef.current) { stream.close(); return; }
              try {
                const nextProgress = JSON.parse((event as MessageEvent).data) as ScanProgress;
                setBatchProgress(nextProgress);
              } catch {
                setBatchProgress((current) => current ? { ...current, message: 'Live progress could not be read; waiting for the worker result.' } : current);
              }
              setStatus('running');
            });
            const applyBatchReport = (result: ScanReport) => {
              const title = link.anchorText || link.targetHost;
              setConversationHistory((current) => current.map((entry) => entry.scanId === result.scanId ? { ...entry, report: result, summaryStatus: summaryConsentRef.current ? 'streaming' : 'idle' } : entry));
              setBatchProgress({ stage: 'completed', message: `Completed analysis for ${title}.`, completedSteps: result.executionPlan?.filter((step) => step.status === 'completed').length ?? 0, totalSteps: result.executionPlan?.length ?? 1, plan: result.executionPlan });
              if (summaryConsentRef.current) void generateSummaryForReport(result, conversationNotesRef.current.get(result.scanId) ?? '');
            };
            stream.addEventListener('completed', (event) => {
              if (batchGeneration !== generationRef.current) { stream.close(); return; }
              let reportRead = true;
              try {
                applyBatchReport(JSON.parse((event as MessageEvent).data) as ScanReport);
              } catch {
                reportRead = false;
                setBatchStates((current) => ({ ...current, [link.linkId]: { ...current[link.linkId], status: 'failed', reason: 'A completed result could not be read.' } }));
              }
              setStatus(reportRead ? 'completed' : 'failed'); stream.close();
            });
            stream.onerror = () => {
              if (terminal || batchGeneration !== generationRef.current) return;
              void (async () => {
                let snapshot: Awaited<ReturnType<typeof getScan>> | null = null;
                try { snapshot = await getScan(accepted.scanId); } catch { return; }
                if (terminal || batchGeneration !== generationRef.current) return;
                if (snapshot.status === 'completed') {
                  const recovered = await recoverCompletedReport(accepted.scanId);
                  if (terminal || batchGeneration !== generationRef.current) return;
                  if (recovered) {
                    applyBatchReport(recovered);
                    setStatus('completed');
                  } else {
                    setBatchStates((current) => ({ ...current, [link.linkId]: { ...current[link.linkId], status: 'completed', reason: 'The scan completed, but its report is no longer available.' } }));
                    setConversationHistory((current) => current.map((entry) => entry.scanId === accepted.scanId ? { ...entry, error: 'This scan completed, but its transient report is no longer available.' } : entry));
                    setStatus('completed');
                  }
                  stream.close();
                } else if (snapshot.status === 'failed' || snapshot.status === 'cancelled') {
                  setStatus(snapshot.status);
                  stream.close();
                }
              })();
            };
            stream.addEventListener('failed', () => { setStatus('failed'); stream.close(); });
            stream.addEventListener('cancelled', () => { setStatus('cancelled'); stream.close(); });
          } else {
            throw new Error('Unsafe event stream origin');
          }
        } catch {
          unsafeBatchEventScanIdsRef.current.add(accepted.scanId);
          const outcome = await requestWorkerStop(accepted.scanId);
          if (outcome.kind === 'cancelled') {
            applyConfirmedStop(accepted.scanId, outcome);
            setBatchStates((current) => ({ ...current, [link.linkId]: { status: 'cancelled', scanId: accepted.scanId, reason: 'The unsafe event stream was rejected and the worker confirmed cancellation.' } }));
          } else if (outcome.kind === 'terminal') {
            applyConfirmedStop(accepted.scanId, outcome);
            const completed = outcome.response?.status === 'completed';
            const reason = completed
              ? 'The worker completed, but the unsafe event stream was rejected and its report could not be read.'
              : 'The worker reported that this scan failed.';
            setBatchStates((current) => ({ ...current, [link.linkId]: { status: completed ? 'completed' : 'failed', scanId: accepted.scanId, reason } }));
            setConversationHistory((current) => current.map((entry) => entry.scanId === accepted.scanId ? { ...entry, error: reason } : entry));
            setActiveBatchScans((current) => current.filter((id) => id !== accepted.scanId));
          } else {
            const reason = 'Live scan updates could not be opened safely. Lumio could not confirm cancellation; retry the stop request.';
            setBatchStates((current) => ({ ...current, [link.linkId]: { status: accepted.status, scanId: accepted.scanId, reason } }));
            setConversationHistory((current) => current.map((entry) => entry.scanId === accepted.scanId ? { ...entry, error: reason } : entry));
            setUnconfirmedNotice('batch', [accepted.scanId]);
          }
        }
        void statusQuery.refetch();
      } catch (error) {
        if (batchGeneration !== generationRef.current) {
          settleLateAcceptanceCheck();
          return;
        }
        if (batchCancelledRef.current) {
          setBatchStates((current) => ({ ...current, [link.linkId]: { status: 'cancelled', reason: 'No scan was accepted before you stopped the batch.' } }));
          continue;
        }
        const code = error && typeof error === 'object' && 'data' in error
          ? String((error as { data?: { code?: string } }).data?.code ?? '') : '';
        if (code === 'SCAN_LIMIT_REACHED' || code === 'SCAN_QUEUE_FULL') {
          setBatchStates((current) => ({
            ...current,
            [link.linkId]: { status: 'skipped', reason: code === 'SCAN_LIMIT_REACHED' ? 'Daily or lifetime scan quota reached.' : 'The scan queue is full.' },
            ...Object.fromEntries(links.slice(index + 1).map((remaining) => [remaining.linkId, {
              status: 'skipped', reason: code === 'SCAN_LIMIT_REACHED' ? 'Skipped because the scan quota was reached.' : 'Skipped because the scan queue is full.',
            }])),
          }));
          break;
        }
        setBatchStates((current) => ({ ...current, [link.linkId]: { status: 'failed', reason: safeErrorMessage(error) } }));
      }
    }
  }

  async function cancelRemainingBatch() {
    batchCancelledRef.current = true;
    const pending = Object.entries(batchStates).filter(([, item]) => item.status === 'submitting' || item.status === 'accepted' || item.status === 'queued' || item.status === 'running');
    const attemptedScanIds = pending.flatMap(([, item]) => item.scanId ? [item.scanId] : []);
    const outcomes = await Promise.all(pending.map(async ([linkId, item]) => ({
      linkId,
      item,
      outcome: item.scanId ? await requestWorkerStop(item.scanId) : null,
    })));
    const unconfirmed: string[] = [];
    setBatchStates((current) => Object.fromEntries(Object.entries(current).map(([linkId, item]) =>
      item.status === 'pending' ? [linkId, { ...item, status: 'cancelled', reason: undefined }]
        : item.status === 'submitting' && !item.scanId ? [linkId, { ...item, reason: 'Stop requested; waiting for the submission response.' }]
          : [linkId, item],
    )));
    for (const { linkId, item, outcome } of outcomes) {
      if (!item.scanId || !outcome) continue;
      if (outcome.kind === 'cancelled') {
        applyConfirmedStop(item.scanId, outcome);
      } else if (outcome.kind === 'terminal') {
        applyConfirmedStop(item.scanId, outcome);
        if (outcome.response?.status === 'completed') {
          setBatchStates((current) => ({ ...current, [linkId]: { ...current[linkId], status: 'completed', reason: 'The worker completed before cancellation; waiting for its report.' } }));
        }
      } else {
        if (activeScanIdsRef.current.has(item.scanId)) unconfirmed.push(item.scanId);
      }
    }
    setBatchProgress((current) => current ? { ...current, message: unconfirmed.length ? 'Some selected scans may still be running.' : 'Selected-link scans stopped or reached a terminal state.' } : current);
    setStopNotice((current) => {
      const lateScanIds = current?.scanIds.filter((scanId) => !attemptedScanIds.includes(scanId)) ?? [];
      const scanIds = [...new Set([...unconfirmed, ...lateScanIds])];
      const approvalIds = current?.approvalIds ?? [];
      if (!scanIds.length && !approvalIds.length && !(current?.pendingAcceptanceCount ?? 0)) return null;
      return {
        kind: current?.kind ?? 'batch',
        scanIds,
        approvalIds,
        pendingAcceptanceCount: current?.pendingAcceptanceCount,
        message: current?.kind === 'withdrawal'
          ? current.message
          : 'Lumio could not confirm that every selected scan stopped. Unconfirmed scans remain tracked.',
      };
    });
  }

  async function retryStopNotice() {
    const notice = stopNotice;
    if (!notice) return;
    const scanResults = await Promise.all(notice.scanIds.map(async (scanId) => ({ scanId, outcome: await requestWorkerStop(scanId) })));
    const remainingScans: string[] = [];
    for (const { scanId, outcome } of scanResults) {
      if (outcome.kind === 'cancelled' || outcome.kind === 'terminal') applyConfirmedStop(scanId, outcome);
      else remainingScans.push(scanId);
    }
    const approvalResults = await Promise.all(notice.approvalIds.map(async (scanId) => {
      try {
        await cancelAgentApprovals.mutateAsync({ scanId });
        return { scanId, confirmed: true };
      } catch {
        return { scanId, confirmed: false };
      }
    }));
    const remainingApprovals = approvalResults.filter((result) => !result.confirmed).map((result) => result.scanId);
    setUnconfirmedNotice(notice.kind, remainingScans, remainingApprovals);
    if (!remainingScans.length && !remainingApprovals.length && pendingAcceptanceChecksRef.current === 0) {
      toast.success('Cancellation confirmed. The conversation remains cleared.');
    }
  }

  function applyPrimaryReport(nextReport: ScanReport) {
    setReport(nextReport);
    setApprovalRequest(null);
    setReviewDeadline(null);
    setReviewNote('');
    setConversationHistory((current) => current.map((entry) => entry.scanId === nextReport.scanId ? { ...entry, report: nextReport, summaryStatus: summaryConsentRef.current ? 'streaming' : 'idle' } : entry));
    if (summaryConsentRef.current) void generateSummaryForReport(nextReport, conversationNotesRef.current.get(nextReport.scanId) ?? '');
    terminalScanStatusRef.current.set(nextReport.scanId, 'completed');
    resolveStopNoticeScan(nextReport.scanId);
    activeScanIdsRef.current.delete(nextReport.scanId);
    if (nextReport.type === 'email') setEmailReport(nextReport);
    setStreamFinished(true);
    setStreamError('');
    void queryClient.invalidateQueries({ queryKey: getGetScanReportQueryKey(nextReport.scanId) });
    void queryClient.invalidateQueries({ queryKey: getGetAnalysisStatusQueryKey() });
  }

  async function recoverCompletedReport(scanId: string): Promise<ScanReport | null> {
    try {
      const recovered = await getScanReport(scanId);
      return recovered.scanId === scanId ? recovered : null;
    } catch {
      return null;
    }
  }

  useEffect(() => {
    if (!scanAccepted || streamFinished) return;
    let eventsUrl: URL;
    try {
      eventsUrl = new URL(scanAccepted.eventsPath, window.location.origin);
    } catch {
      setStreamError('The scan event stream could not be opened. Checking scan status for recovery.');
      return;
    }
    if (eventsUrl.origin !== window.location.origin) {
      setStreamError('The scan event stream could not be opened safely. Checking scan status for recovery.');
      return;
    }
    const source = new EventSource(eventsUrl.toString());
    const streamGeneration = generationRef.current;
    source.addEventListener('progress', (event) => {
      if (streamGeneration !== generationRef.current) return;
      try {
        setProgress(JSON.parse((event as MessageEvent).data) as ScanProgress);
      } catch {
        setStreamError('The progress stream returned an unreadable event. Checking scan status for recovery.');
      }
    });
    source.addEventListener('review_ready', (event) => {
      if (streamGeneration !== generationRef.current) return;
      try {
        const ready = JSON.parse((event as MessageEvent).data) as { scanId: string; deadline: string };
        if (ready.scanId !== scanAccepted.scanId) return;
        setReviewDeadline(ready.deadline);
        requestReviewProposal(ready.scanId, scanType);
      } catch {
        setApprovalError('The follow-up review could not be read. The report will use the completed checks.');
      }
    });
    source.addEventListener('agent_action', (event) => {
      if (streamGeneration !== generationRef.current) return;
      try {
        const action = JSON.parse((event as MessageEvent).data) as AgentActionResult;
        setLiveActions((current) => {
          const index = current.findIndex((item) => item.actionId === action.actionId);
          return index === -1 ? [...current, action].slice(0, 3) : current.map((item, i) => i === index ? action : item);
        });
        if (action.status === 'running') {
          setReviewNote('The approved step is running in the isolated worker.');
        } else if (action.status !== 'skipped') {
          setReviewNote('');
          // Ask for the next bounded step; the server finalizes when none is left.
          requestReviewProposal(scanAccepted.scanId, scanType);
        }
      } catch {
        setApprovalError('A follow-up result could not be read. The final report will list it.');
      }
    });
    source.addEventListener('completed', (event) => {
      if (streamGeneration !== generationRef.current) { source.close(); return; }
      try {
        applyPrimaryReport(JSON.parse((event as MessageEvent).data) as ScanReport);
      } catch {
        setStreamError('A report could not be read from the stream. The scan status is being recovered.');
      }
      source.close();
    });
    source.addEventListener('failed', (_event) => {
      if (streamGeneration !== generationRef.current) { source.close(); return; }
      setStreamError('Analysis did not complete. No report is available for this scan.');
      if (scanAccepted) terminalScanStatusRef.current.set(scanAccepted.scanId, 'failed');
      if (scanAccepted) resolveStopNoticeScan(scanAccepted.scanId);
      setConversationHistory((current) => current.map((entry) => entry.scanId === scanAccepted?.scanId ? { ...entry, error: 'Analysis did not complete. No report is available.' } : entry));
      setStreamFinished(true);
      if (scanAccepted) activeScanIdsRef.current.delete(scanAccepted.scanId);
      source.close();
    });
    source.addEventListener('cancelled', () => {
      if (streamGeneration !== generationRef.current) { source.close(); return; }
      setStreamError('This analysis was cancelled. No report is available for this scan.');
      if (scanAccepted) terminalScanStatusRef.current.set(scanAccepted.scanId, 'cancelled');
      if (scanAccepted) resolveStopNoticeScan(scanAccepted.scanId);
      setConversationHistory((current) => current.map((entry) => entry.scanId === scanAccepted?.scanId ? { ...entry, error: 'This analysis was cancelled.' } : entry));
      setCancelled(true);
      setStreamFinished(true);
      if (scanAccepted) activeScanIdsRef.current.delete(scanAccepted.scanId);
      source.close();
    });
    source.onerror = () => {
      if (!streamFinished) setStreamError('Live updates were interrupted. Lumio is checking the scan status.');
    };
    return () => source.close();
  }, [scanAccepted, streamFinished, queryClient]);

  useEffect(() => {
    const snapshot = scanQuery.data;
    if (!snapshot) return;
    if (snapshot.status === 'failed' || snapshot.status === 'cancelled') {
      terminalScanStatusRef.current.set(snapshot.scanId, snapshot.status);
      activeScanIdsRef.current.delete(snapshot.scanId);
      setConversationHistory((current) => current.map((entry) => entry.scanId === snapshot.scanId ? { ...entry, error: snapshot.status === 'cancelled' ? 'This analysis was cancelled.' : 'Analysis did not complete.' } : entry));
      setStreamError('Analysis did not complete. No report is available for this scan.');
      setStreamFinished(true);
    } else if (snapshot.status === 'completed' && !report) {
      if (recoveringScanIdsRef.current.has(snapshot.scanId)) return;
      recoveringScanIdsRef.current.add(snapshot.scanId);
      const generation = generationRef.current;
      void recoverCompletedReport(snapshot.scanId).then((recovered) => {
        recoveringScanIdsRef.current.delete(snapshot.scanId);
        if (generation !== generationRef.current) return;
        if (recovered) {
          applyPrimaryReport(recovered);
          return;
        }
        markCompletedReportUnavailable(snapshot.scanId);
      });
    }
  }, [scanQuery.data, report]);

  function markCompletedReportUnavailable(scanId: string) {
    {
      terminalScanStatusRef.current.set(scanId, 'completed');
      activeScanIdsRef.current.delete(scanId);
      setConversationHistory((current) => current.map((entry) => entry.scanId === scanId ? { ...entry, error: 'This scan completed, but its transient report is no longer available.' } : entry));
      setStreamFinished(true);
      setStreamError('This scan completed, but its transient report is no longer available. Start a new scan to receive a fresh report.');
    }
  }

  // Recovery: if live updates reconnect mid-review and miss review_ready, the
  // progress stage still shows the pause; the proposal request is idempotent.
  useEffect(() => {
    if (progress?.stage !== 'awaiting_review' || !scanAccepted || approvalRequest || report) return;
    requestReviewProposal(scanAccepted.scanId, scanType);
  }, [progress?.stage, scanAccepted?.scanId]);

  useEffect(() => () => {
    summaryAbortControllersRef.current.forEach((controller) => controller.abort());
    summaryAbortControllersRef.current.clear();
  }, []);

  function beginAccepted(accepted: ScanAccepted, type: ScanReport['type']) {
    setBatchPlanVisible(false);
    setScanAccepted(accepted);
    setScanType(type);
    setProgress(null);
    setReport(null);
    setStreamError('');
    setStreamFinished(false);
    setApprovalRequest(null);
    setApprovalError('');
    setReviewDeadline(null);
    setLiveActions([]);
    setReviewNote('');
    reviewInFlightRef.current = false;
    if (type !== 'email_link') {
      setEmailReport(null);
      setSelectedLinkIds([]);
    }
  }

  async function generateSummaryForReport(nextReport: ScanReport, note: string) {
    if (!summaryConsentRef.current || summaryStartedScanIdsRef.current.has(nextReport.scanId)) return;
    summaryStartedScanIdsRef.current.add(nextReport.scanId);
    const explanationToken = nextReport.explanationToken;
    if (!explanationToken) {
      setConversationHistory((current) => current.map((entry) => entry.scanId === nextReport.scanId
        ? { ...entry, summaryStatus: 'error', summaryError: 'A short-lived summary token was not available. The deterministic report is unchanged.' }
        : entry));
      return;
    }
    const tokenGeneration = generationRef.current;
    const controller = new AbortController();
    summaryAbortControllersRef.current.set(nextReport.scanId, controller);
    setConversationHistory((current) => current.map((entry) => entry.scanId === nextReport.scanId
      ? { ...entry, summary: '', summaryError: undefined, summaryStatus: 'streaming' }
      : entry));
    try {
      const { streamReportExplanation } = await import('@/lib/explanation-stream');
      await streamReportExplanation(
        nextReport.scanId,
        explanationToken,
        controller.signal,
        (delta) => {
          if (tokenGeneration !== generationRef.current) return;
          setConversationHistory((current) => current.map((entry) => entry.scanId === nextReport.scanId
            ? { ...entry, summary: `${entry.summary ?? ''}${delta}`.slice(0, 1400) }
            : entry));
        },
        note,
      );
      if (tokenGeneration === generationRef.current) {
        setConversationHistory((current) => current.map((entry) => entry.scanId === nextReport.scanId ? { ...entry, summaryStatus: 'complete' } : entry));
      }
    } catch (error) {
      if (tokenGeneration !== generationRef.current) return;
      setConversationHistory((current) => current.map((entry) => entry.scanId === nextReport.scanId
        ? { ...entry, summaryStatus: 'error', summaryError: error instanceof Error ? error.message : 'The optional AI summary could not be completed. The report is unchanged.' }
        : entry));
    } finally {
      if (summaryAbortControllersRef.current.get(nextReport.scanId) === controller) {
        summaryAbortControllersRef.current.delete(nextReport.scanId);
      }
    }
  }

  function reportSummary(scanId: string) {
    return conversationHistory.find((item) => item.scanId === scanId);
  }

  function exportReport() {
    if (!activeReport) return;
    const blob = new Blob([reportHtml(activeReport, reportSummary(activeReport.scanId)?.summary ?? '')], { type: 'text/html;charset=utf-8' });
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = objectUrl;
    anchor.download = `lumio-report-${activeReport.scanId}.html`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  }

  function printReport() {
    if (!activeReport) return false;
    let printWindow: Window | null = null;
    try {
      printWindow = window.open('', '_blank');
      if (!printWindow) return false;
      const printableWindow = printWindow;
      printableWindow.document.open();
      printableWindow.document.write(reportHtml(activeReport, reportSummary(activeReport.scanId)?.summary ?? ''));
      printableWindow.document.close();
      printableWindow.opener = null;
      printableWindow.requestAnimationFrame(() => {
        printableWindow.requestAnimationFrame(() => {
          if (printableWindow.closed) return;
          printableWindow.focus();
          printableWindow.print();
        });
      });
      return true;
    } catch {
      printWindow?.close();
      return false;
    }
  }

  function finishReviewFromCompletedChecks(scanId: string) {
    void cancelAgentApprovals.mutateAsync({ scanId }).catch(() => undefined);
  }

  function requestReviewProposal(scanId: string, type: ScanReport['type']) {
    if (type === 'email_link' || reviewInFlightRef.current) return;
    reviewInFlightRef.current = true;
    const proposalGeneration = generationRef.current;
    setApprovalError('');
    createAgentProposal.mutate(
      { scanId, data: { scanType: type } },
      {
        onSuccess: (request) => {
          if (proposalGeneration !== generationRef.current) {
            finishReviewFromCompletedChecks(request.scanId);
            return;
          }
          setApprovalRequest(request);
          setReviewNote('');
        },
        onError: (error) => {
          if (proposalGeneration !== generationRef.current) return;
          const code = apiErrorCode(error);
          if (code === 'AGENT_ACTION_RUNNING') return;
          if (code === 'AGENT_REVIEW_COMPLETE') {
            setReviewNote('No further follow-up step is available. Publishing the report from the completed checks.');
            return;
          }
          if (code === 'SCAN_NOT_AWAITING_REVIEW' || code === 'SCAN_NOT_FOUND') return;
          setReviewNote('A follow-up step could not be prepared. Publishing the report from the completed checks.');
          finishReviewFromCompletedChecks(scanId);
        },
        onSettled: () => { reviewInFlightRef.current = false; },
      },
    );
  }

  function resolveAgentApproval(decision: 'approve' | 'decline') {
    if (!approvalRequest) return;
    const { scanId, requestId } = approvalRequest;
    resolveAgentApprovalMutation.mutate(
      { scanId, requestId, data: { decision } },
      {
        onSuccess: (response) => {
          setApprovalRequest(null);
          setReviewNote(response.next === 'running'
            ? 'Approved. The step is starting in the isolated worker.'
            : decision === 'decline'
              ? 'Declined. Publishing the report from the completed checks.'
              : 'Publishing the report from the completed checks.');
        },
        onError: () => {
          setApprovalRequest(null);
          setApprovalError('Your decision could not be sent. Publishing the report from the completed checks.');
          finishReviewFromCompletedChecks(scanId);
        },
      },
    );
  }

  function skipAgentReview() {
    if (!scanAccepted) return;
    const scanId = scanAccepted.scanId;
    cancelAgentApprovals.mutate(
      { scanId },
      {
        onSuccess: () => {
          setApprovalRequest(null);
          setReviewNote('Follow-up skipped. Publishing the report from the completed checks.');
        },
        onError: () => setApprovalError('The follow-up could not be skipped. It will end on its own when the review time runs out.'),
      },
    );
  }

  const readinessText = statusQuery.isLoading
    ? 'Checking analyzer readiness'
    : statusQuery.isError
      ? 'Readiness could not be confirmed'
      : workerUnavailable
        ? 'Analyzer unavailable'
        : 'Analyzer ready';
  const progressMessage = progress?.message ??
    (scanAccepted?.status === 'queued' ? 'Waiting for an isolated worker.' : 'Connecting to the isolated worker.');

  const hasConversation = conversationHistory.length > 0 || Boolean(formError || cancelled);
  const currentPlan = batchPlanVisible ? batchProgress?.plan ?? [] : progress?.plan ?? activeReport?.executionPlan ?? [];
  const currentProgressMessage = batchPlanVisible ? batchProgress?.message ?? 'Submitting selected links.' : progressMessage;
  const cancelCurrentScan = async () => {
    const scanId = scanAccepted?.scanId;
    if (!scanId) return;
    const outcome = await requestWorkerStop(scanId);
    applyConfirmedStop(scanId, outcome);
      if ((outcome.kind === 'active' || outcome.kind === 'error') && activeScanIdsRef.current.has(scanId)) {
      setUnconfirmedNotice('single', [scanId]);
    }
  };

  return (
    <div className={`${shellActive ? 'flex h-[100dvh] flex-col overflow-hidden' : 'min-h-[100dvh] overflow-x-clip'} bg-background text-foreground`}>
      <header className="sticky top-0 z-40 shrink-0 border-b border-border/70 bg-card/75 backdrop-blur-xl backdrop-saturate-150">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-4 sm:px-6">
          <a href="/" data-testid="link-lumio-home" className="flex min-h-11 items-center gap-3 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label="Lumio home">
            <span className="flex size-9 shrink-0 items-center justify-center" aria-hidden="true">
              <img src="/lumio-mark-96.gif" alt="" className="size-full object-contain motion-reduce:hidden" />
              <img src="/lumio-icon-48.svg" alt="" className="hidden size-full object-contain motion-reduce:block" />
            </span>
            <span className="text-lg font-semibold tracking-tight">Lumio</span>
          </a>
          <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${workerUnavailable ? 'border-destructive/30 bg-destructive/5 text-destructive' : 'border-border bg-muted/60 text-muted-foreground'}`}
            role="status" aria-live="polite" data-testid="status-analyzer-readiness">
            <span className={`size-1.5 rounded-full ${workerUnavailable ? 'bg-destructive' : statusQuery.isLoading ? 'bg-muted-foreground' : 'bg-emerald-600'}`} />
            {readinessText}
          </div>
        </div>
      </header>
      <motion.main layout transition={{ layout: layoutTransition }} className={shellActive ? 'flex min-h-0 w-full flex-1 flex-col' : 'mx-auto w-full max-w-5xl px-4 pb-10 pt-8 sm:px-6 sm:pt-11'} data-workspace-stage={shellActive ? 'fullscreen' : cardActive ? 'card' : 'hero'}>
        {!shellActive && <section className={`relative flex flex-col transition-all duration-700 ease-out ${cardActive ? 'mb-7 max-w-3xl items-start gap-3 text-left' : 'mb-10 items-center gap-6 pt-6 text-center sm:gap-8 sm:pt-12'} ${(cardActive ? cardLeaving : heroLeaving) ? 'opacity-0' : 'opacity-100'}`} data-testid="hero">
          <div className={`hero-collapse grid ${cardActive ? 'hero-collapsed' : ''}`} inert={cardActive ? true : undefined} aria-hidden={cardActive || undefined}>
            <div className="min-h-0 overflow-hidden">
              <span className="hero-appear inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs font-medium">
                <span className="text-muted-foreground">Consent-based threat checks</span>
                <span className="flex items-center gap-1">How it works <ArrowRight className="size-3" aria-hidden="true" /></span>
              </span>
            </div>
          </div>
          <h1 className={`relative z-10 text-balance font-semibold leading-tight transition-all duration-700 ease-out ${cardActive ? 'max-w-3xl text-3xl text-foreground sm:text-4xl' : 'mb-4 w-full max-w-4xl pb-3 text-4xl text-foreground sm:mb-6 sm:pb-4 sm:text-6xl sm:leading-tight'}`}><AnimatedTagline key={cardActive ? 'heading-reveal' : 'heading-decrypt'} text={cardActive ? 'Lumio runs private, consent-based checks.' : 'Bringing threats to light. Investigate first, click later.'} reveal={cardActive} leaving={heroLeaving} /></h1>
          {cardActive && <p className="relative z-10 max-w-3xl text-sm font-medium leading-6 text-muted-foreground sm:text-base"><AnimatedTagline text="Suspicious URLs and email are investigated in an isolated worker. Reports show observable evidence and coverage limits—not a promise of safety." reveal leaving={false} decrypt={false} /></p>}
          <div className={`hero-collapse grid ${cardActive ? 'hero-collapsed' : ''}`} inert={cardActive ? true : undefined} aria-hidden={cardActive || undefined}>
            <div className="min-h-0 overflow-hidden">
              <div className="hero-appear hero-delay-300 relative z-10 flex flex-wrap justify-center gap-3">
                <button type="button" onClick={activateShell} data-testid="button-get-started" className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-6 text-sm font-medium text-primary-foreground shadow-sm hover:bg-primary/90">Get started <ArrowRight className="size-4" aria-hidden="true" /></button>
                <a href="https://github.com/0xTariq-dev/Lumio" target="_blank" rel="noreferrer" className="inline-flex min-h-11 items-center gap-2 rounded-md border border-border bg-card px-6 text-sm font-medium hover:bg-muted">View source</a>
              </div>
            </div>
          </div>
        </section>}
        {stopNotice && <aside role="alert" aria-live="assertive" className="mb-5 flex flex-col gap-3 rounded-xl border border-destructive/30 bg-destructive/5 p-4 sm:flex-row sm:items-center sm:justify-between" data-testid="status-stop-unconfirmed">
          <div><p className="text-sm font-semibold">{stopNotice.message}</p>{(stopNotice.pendingAcceptanceCount ?? 0) > 0 && <p className="mt-1 text-xs leading-5 text-muted-foreground">Waiting for {stopNotice.pendingAcceptanceCount} in-flight submission{stopNotice.pendingAcceptanceCount === 1 ? '' : 's'} to return an acceptance before a stop request can be sent.</p>}</div>
          {(stopNotice.scanIds.length > 0 || stopNotice.approvalIds.length > 0) && <button type="button" onClick={() => void retryStopNotice()} disabled={cancelScan.isPending || cancelAgentApprovals.isPending} className="min-h-11 shrink-0 rounded-md border border-destructive/30 bg-background px-4 text-sm font-medium hover:bg-destructive/5 disabled:opacity-50" data-testid="button-retry-stop">Retry stop request</button>}
        </aside>}
        <motion.div layout transition={{ layout: layoutTransition }} className={shellActive ? 'relative flex min-h-0 flex-1 flex-col' : cardActive ? 'relative' : 'relative hero-appear hero-delay-700'}>
        <div aria-hidden="true" className={`hero-glow-top pointer-events-none absolute inset-x-0 top-0 transition-opacity duration-700 ease-out ${heroLeaving ? 'opacity-0' : 'opacity-100'}`}>
          <div className="hero-glow-outer" />
          <div className="hero-glow-inner" />
        </div>
        <motion.div layout transition={{ layout: layoutTransition }} className={shellActive ? 'relative z-10 flex min-h-0 w-full flex-1 flex-col' : `relative z-10 mx-auto w-full max-w-4xl rounded-2xl ${cardActive ? 'p-0' : 'bg-accent/5 p-2'}`}>
        <motion.section layout transition={{ layout: layoutTransition }} id="workspace" ref={shellRef} inert={!cardActive ? true : undefined}
          className={shellActive ? 'shell-stage flex min-h-0 flex-1 flex-col overflow-hidden bg-background' : `shell-stage overflow-hidden rounded-2xl border border-border bg-card shadow-sm ${cardActive ? 'shell-active' : heroLeaving ? '' : 'shell-preview'}`} aria-label="Investigation conversation">
          <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3.5 sm:px-6">
            <div><h2 className="text-base font-semibold tracking-tight">Investigation workspace</h2><p className="mt-0.5 text-xs text-muted-foreground">One temporary conversation. Nothing here is saved after this tab closes.</p></div>
            {sessionConsent && <button type="button" onClick={withdrawConsent} data-testid="button-withdraw-consent" className="min-h-10 rounded-md px-3 text-xs font-medium text-muted-foreground underline-offset-4 hover:bg-muted hover:text-foreground hover:underline">Withdraw consent and clear</button>}
          </div>
          {(scanAccepted || batchPlanVisible) && (
            <div className="sticky top-0 z-10 shrink-0 border-b border-border bg-card/95 px-4 py-4 backdrop-blur-sm sm:px-6" data-testid="pinned-scan-stepper">
              <div className="mb-3 flex items-center justify-between gap-3">
                <div><p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Analysis plan</p><p className="mt-1 text-sm font-medium">{batchPlanVisible ? currentProgressMessage : activeReport ? 'Analysis complete' : cancelled ? 'Analysis cancelled' : progressMessage}</p></div>
                {batchPlanVisible && activeBatchScans.length > 0
                  ? <button type="button" onClick={() => void cancelRemainingBatch()} disabled={cancelScan.isPending} data-testid="button-cancel-link-batch" className="inline-flex min-h-10 shrink-0 items-center gap-2 rounded-md border border-input px-3 text-sm font-medium hover:bg-muted disabled:opacity-50"><X className="size-4" aria-hidden="true" /> Stop selected links</button>
                  : scanAccepted && !streamFinished && <button type="button" onClick={() => void cancelCurrentScan()} disabled={cancelScan.isPending} data-testid="button-cancel-scan" className="inline-flex min-h-10 shrink-0 items-center gap-2 rounded-md border border-input px-3 text-sm font-medium hover:bg-muted disabled:opacity-50"><X className="size-4" aria-hidden="true" /> Stop analysis</button>}
              </div>
              <Suspense fallback={<ScanProgressLoadingSkeleton />}>
                <ScanProgressStepper steps={currentPlan.map((step) => ({ id: String(step.id), label: planStepLabel(step.id, batchPlanVisible ? 'email_link' : scanType), status: String(step.status), details: step.reasonCode ? planReasonLabel(step.reasonCode, batchPlanVisible ? 'email_link' : scanType) : undefined }))} testId="live-execution-plan" />
              </Suspense>
              {streamError && <p className="mt-2 text-xs text-muted-foreground" role="status" data-testid="status-stream-recovery">{streamError}</p>}
            </div>
          )}
       <div className={shellActive ? 'flex min-h-0 flex-1 flex-col' : 'flex min-h-[min(70vh,680px)] max-h-[min(75vh,760px)] flex-col'}>
            <div className="min-h-0 flex-1 overflow-y-auto px-4 py-5 sm:px-6" aria-live="polite" aria-relevant="additions text" data-testid="conversation-thread">
              {!hasConversation && !activeReport && (
                <div className="mx-auto flex min-h-72 max-w-xl flex-col items-center justify-center py-12 text-center">
                  <span className="flex size-12 items-center justify-center rounded-xl border border-border bg-muted/50"><ShieldCheck className="size-5 text-muted-foreground" aria-hidden="true" /></span>
                  <h3 className="mt-4 text-lg font-semibold tracking-tight">Start with what looks suspicious</h3>
                  <p className="mt-2 max-w-md text-sm leading-6 text-muted-foreground">Paste a public URL or attach one .eml message. Lumio will show what it could inspect and what it could not.</p>
                  <p className="mt-5 text-xs text-muted-foreground"><LockKeyhole className="mr-1 inline size-3.5" aria-hidden="true" /> Consent is requested before the first scan · Results stay in this tab</p>
                </div>
              )}
              {conversationHistory.filter((item) => item.scanId !== scanAccepted?.scanId).map((item) => (
                <article key={item.scanId} className="mb-6 border-b border-border pb-5" data-testid={`conversation-history-${item.scanId}`}>
                  <div className="mb-4 flex justify-end">
                    <div className="max-w-[90%] rounded-2xl rounded-br-sm bg-muted px-4 py-3 text-sm leading-6 sm:max-w-[75%]">
                      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">You submitted · {item.type === 'email' ? 'Email message' : item.type === 'email_link' ? 'Selected email link' : 'URL'}</p>
                      {item.displayLabel && <p className="break-all">{item.displayLabel}</p>}
                      <p className="break-all">{displayAttachment(item.type, item.input)}</p>
                      <p className="mt-2 whitespace-pre-wrap break-words text-muted-foreground">{item.note || 'No note added.'}</p>
                      {item.type === 'email' && <p className="mt-2 text-xs text-muted-foreground">Raw email content is not displayed. Attachment contents are not opened.</p>}
                    </div>
                  </div>
                  {item.report ? <BatchEvidence report={item.report} title={item.type === 'email' ? `Email analysis · ${item.input}` : item.displayLabel ?? displayAttachment(item.type, item.input)} summary={item.summary ?? ''} summaryStatus={item.summaryStatus ?? 'idle'} summaryError={item.summaryError ?? ''} /> : item.error ? <p className="rounded-lg border border-border bg-muted/30 p-3 text-sm text-muted-foreground" role="status">{item.error}</p> : <p className="text-sm text-muted-foreground" role="status">{activeBatchScans.includes(item.scanId) ? 'Selected link analysis is still running.' : 'This earlier scan has no report available in memory.'}</p>}
                </article>
              ))}
              {scanAccepted && conversationHistory.find((item) => item.scanId === scanAccepted.scanId) && (
                <div className="mb-5 flex justify-end" data-testid="message-user-submission">
                  <div className="max-w-[90%] rounded-2xl rounded-br-sm bg-muted px-4 py-3 text-sm leading-6 sm:max-w-[75%]">
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">You submitted</p>
                    <p className="break-all">{displayAttachment(scanType, conversationHistory.find((item) => item.scanId === scanAccepted.scanId)?.input ?? '')}</p>
                    <p className="mt-2 whitespace-pre-wrap break-words text-muted-foreground">{conversationHistory.find((item) => item.scanId === scanAccepted.scanId)?.note || 'No note added.'}</p>
                    {scanType === 'email' && <p className="mt-2 text-xs text-muted-foreground">Raw email content is not displayed. Attachments are metadata only.</p>}
                  </div>
                </div>
              )}
              {busy && !activeReport && <div className="mb-5 max-w-[90%] rounded-2xl rounded-bl-sm border border-border bg-background px-4 py-3 text-sm" role="status" data-testid="status-scan-progress"><p className="font-medium">Lumio is checking this in an isolated session</p><p className="mt-1 text-muted-foreground" data-testid="text-progress-message">{progressMessage}</p><p className="mt-2 text-xs text-muted-foreground">{progress ? `${progress.completedSteps} of ${progress.totalSteps} plan steps resolved` : 'Waiting for the scan service to publish its execution plan.'}</p></div>}
              {busy && !activeReport && reviewDeadline && (
                <AgentReviewPanel deadline={reviewDeadline} approvalRequest={approvalRequest} actions={liveActions}
                  pending={createAgentProposal.isPending || resolveAgentApprovalMutation.isPending || cancelAgentApprovals.isPending}
                  error={approvalError} note={reviewNote} onResolve={resolveAgentApproval} onSkip={skipAgentReview} />
              )}
              {activeReport && <div className="mt-2"><ReportView report={activeReport} onExport={exportReport} emailLinks={emailLinks}
                onPrint={printReport} selectedLinkIds={selectedLinkIds} setSelectedLinkIds={setSelectedLinkIds} onOpenBatch={() => setBatchDialogOpen(true)}
                summaryEnabled={summaryConsent} summaryText={reportSummary(activeReport.scanId)?.summary ?? ''} summaryError={reportSummary(activeReport.scanId)?.summaryError ?? ''}
                summaryStatus={reportSummary(activeReport.scanId)?.summaryStatus ?? 'idle'} />
              </div>}
              {streamError && !activeReport && <div className="my-4 rounded-xl border border-border bg-muted/30 p-4" role="status" data-testid="status-analysis-unavailable"><h3 className="font-semibold">No report available</h3><p className="mt-1 text-sm leading-6 text-muted-foreground">{streamError}</p></div>}
              {formError && <div role="alert" data-testid="error-analysis-form" className="mb-3 flex gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"><AlertCircle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />{formError}</div>}
              {workerUnavailable && <div role="status" className="mb-3 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm" data-testid="status-worker-unavailable">Analysis is temporarily unavailable. No scan has been started.</div>}
              {statusQuery.isError && <div role="alert" className="mb-3 flex justify-between gap-3 text-sm text-destructive" data-testid="error-readiness"><span>Analyzer readiness could not be confirmed.</span><button type="button" onClick={() => void statusQuery.refetch()} data-testid="button-retry-readiness" className="min-h-10 underline">Retry</button></div>}
              {!!Object.keys(batchStates).length && <section className="mt-5 rounded-xl border border-border bg-muted/20 p-4" aria-label="Selected link scan batch" data-testid="selected-link-batch"><div className="flex items-center justify-between gap-3"><h3 className="text-sm font-semibold">Selected link scans</h3>{Object.values(batchStates).some((item) => ['submitting', 'accepted', 'queued', 'running'].includes(item.status)) && <button type="button" onClick={() => void cancelRemainingBatch()} disabled={cancelScan.isPending} className="min-h-10 rounded-md border border-input px-3 text-xs font-medium hover:bg-muted disabled:opacity-50" data-testid="button-cancel-link-batch">Stop remaining scans</button>}</div><ul className="mt-3 space-y-2">{Object.entries(batchStates).map(([id, item]) => <li key={id} className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-border bg-card px-3 py-2 text-sm" data-testid={`batch-link-${id}`}><span className="min-w-0 flex-1 break-all">{batchLabels[id] || 'Selected link'}<span className="ml-2 text-xs text-muted-foreground">{item.reason ?? (item.status === 'running' ? 'Worker is analyzing this link.' : '')}</span></span><span className="shrink-0 rounded-full border border-border px-2 py-0.5 text-xs capitalize">{item.status}</span></li>)}</ul></section>}
            </div>
            <motion.div layout="position" transition={{ layout: layoutTransition }} className="shrink-0 border-t border-border bg-card p-3 sm:p-4" data-testid="pinned-agent-input"
              onClickCapture={(event) => {
                if (cardActive && !shellActive && !cardLeaving && event.target instanceof Element && event.target.closest('textarea')) setCardLeaving(true);
              }}>
              <CInputGroup18
                message={chatNote}
                showHelp={!cardLeaving}
                attachment={attachment}
                disabled={busy || workerUnavailable || statusQuery.isLoading || statusQuery.isError}
                onMessageChange={(value) => { setChatNote(value); setFormError(''); }}
                onAttachmentChange={(value) => { setAttachment(value); setFormError(''); }}
                reviewOptIn={agentReviewOptIn}
                summaryEnabled={summaryConsent}
                onReviewOptInChange={setAgentReviewOptIn}
                onSummaryChange={setSummaryConsent}
                 onSubmit={(message, selectedAttachment) => requestSubmit(message, selectedAttachment)}
                onError={setFormError}
              />
              {status?.scanQuota?.enabled && <p className="mx-auto mt-2 max-w-3xl px-1 text-[11px] text-muted-foreground" data-testid="status-scan-quota">Usage · Today {status.scanQuota.daily.used ?? '—'}/{status.scanQuota.daily.total} · Lifetime {status.scanQuota.lifetime.used ?? '—'}/{status.scanQuota.lifetime.total}</p>}
              {status?.queue && <p className="mx-auto mt-1 max-w-3xl px-1 text-[11px] text-muted-foreground" data-testid="text-queue-status">Queue · {status.queue.active} active of {status.queue.activeLimit} · {status.queue.queued} waiting of {status.queue.queuedLimit}</p>}
            </motion.div>
          </div>
        </motion.section>
        </motion.div>
        </motion.div>
        <motion.footer layout="position" transition={{ layout: layoutTransition }} className={shellActive ? 'flex shrink-0 flex-col justify-between gap-2 border-t border-border bg-card px-4 py-3 text-xs text-muted-foreground sm:flex-row sm:px-6' : 'mx-auto mt-6 flex max-w-4xl flex-col justify-between gap-2 border-t border-border pt-4 text-xs text-muted-foreground sm:flex-row'} data-testid="workspace-footer"><span>Lumio reports evidence, not certainty.</span><span>Reports and email content are not stored. One-way IP/browser counters enforce scan limits.</span></motion.footer>
      </motion.main>
      <Dialog open={consentDialogOpen} onOpenChange={(open) => { setConsentDialogOpen(open); if (!open) submissionRef.current = null; }}>
        <DialogContent aria-describedby="session-consent-copy" data-testid="dialog-first-scan-consent">
          <DialogHeader><DialogTitle>Before Lumio checks this</DialogTitle><DialogDescription id="session-consent-copy">Your submission is sent to an isolated worker for a temporary analysis. Lumio returns deterministic evidence and coverage limits; it cannot guarantee that a URL or message is safe.</DialogDescription></DialogHeader>
          <ul className="list-disc space-y-2 pl-5 text-sm leading-6 text-muted-foreground"><li>Only public HTTP(S) targets and .eml files are accepted.</li><li>Email link destinations are not visited unless you separately select and confirm them.</li><li>Raw email content, URLs, reports, and this conversation are not saved in this browser.</li><li>You can stop scans or withdraw consent to clear this conversation.</li></ul>
          <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-border bg-muted/20 p-3 text-sm leading-5">
            <input type="checkbox" checked={summaryConsent} onChange={(event) => { setSummaryConsent(event.target.checked); summaryConsentRef.current = event.target.checked; }} data-testid="checkbox-session-ai-summary" className="mt-0.5 size-4 shrink-0 accent-foreground" />
             <span><strong className="font-semibold">Optional AI summaries for this tab.</strong> If selected, the note you enter and redacted deterministic evidence are sent to existing Vultr inference for a short explanation and a suggested safe follow-up question. Raw URLs, raw email, attachments, and tool calls are excluded. AI cannot change the risk band or report. Vultr's retention and training terms are not verified. Do not include confidential or sensitive details in your note.</span>
          </label>
          <DialogFooter><button type="button" onClick={() => { setConsentDialogOpen(false); submissionRef.current = null; }} className="min-h-11 rounded-md border border-input px-4 text-sm font-medium hover:bg-muted" data-testid="button-decline-session-consent">Not now</button><button type="button" onClick={acceptSessionConsent} className="min-h-11 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:opacity-90" data-testid="button-accept-session-consent">I understand — continue</button></DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={batchDialogOpen} onOpenChange={setBatchDialogOpen}>
        <DialogContent aria-describedby="batch-consent-copy" data-testid="dialog-selected-links-confirm">
          <DialogHeader><DialogTitle>Scan selected email links?</DialogTitle><DialogDescription id="batch-consent-copy">Only the links you selected will be submitted, one by one. These destinations will be visited in separate isolated scans; queue and quota limits still apply.</DialogDescription></DialogHeader>
          <ul className="max-h-48 space-y-2 overflow-y-auto rounded-md border border-border bg-muted/20 p-3 text-sm">{emailLinks.filter((link) => selectedLinkIds.includes(link.linkId)).map((link) => <li key={link.linkId} className="break-all"><span className="font-medium">{link.anchorText || link.targetHost}</span><span className="block font-mono text-xs text-muted-foreground">{link.displayUrl}</span></li>)}</ul>
          <p className="text-xs leading-5 text-muted-foreground">This permission is separate from the session consent for your email. Unselected links will not be scanned.</p>
          <DialogFooter><button type="button" onClick={() => setBatchDialogOpen(false)} className="min-h-11 rounded-md border border-input px-4 text-sm font-medium hover:bg-muted">Go back</button><button type="button" onClick={() => void runSelectedBatch()} disabled={!selectedLinkIds.length} className="min-h-11 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50" data-testid="button-confirm-link-batch">Confirm {selectedLinkIds.length} link{selectedLinkIds.length === 1 ? '' : 's'}</button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );

}

function BatchEvidence({ report, title, summary, summaryStatus, summaryError }: { report: ScanReport; title: string; summary: string; summaryStatus: 'idle' | 'streaming' | 'complete' | 'error'; summaryError: string }) {
  const attachments = report.findings.filter((finding) => finding.source === 'attachment_metadata');
  function exportResult() {
    const objectUrl = URL.createObjectURL(new Blob([reportHtml(report, summary)], { type: 'text/html;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = objectUrl;
    anchor.download = `lumio-report-${report.scanId}.html`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  }
  function printResult() {
    let printWindow: Window | null = null;
    try {
      printWindow = window.open('', '_blank');
      if (!printWindow) { toast.error('Allow pop-ups to open the print-ready report.'); return; }
      const printableWindow = printWindow;
      printableWindow.document.open();
      printableWindow.document.write(reportHtml(report, summary));
      printableWindow.document.close();
      printableWindow.opener = null;
      printableWindow.requestAnimationFrame(() => {
        printableWindow.requestAnimationFrame(() => {
          if (printableWindow.closed) return;
          printableWindow.focus();
          printableWindow.print();
        });
      });
    } catch {
      printWindow?.close();
      toast.error('The print-ready report could not be opened. Your report is unchanged.');
    }
  }
  return (
    <article className="mt-4 rounded-xl border border-border bg-card p-4" aria-label={`Evidence report for ${title}`} data-testid={`batch-report-${report.scanId}`}>
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div><p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Earlier analysis</p><h4 className="mt-1 text-sm font-semibold">{title}</h4><p className="mt-1 text-xs text-muted-foreground">{riskLabel(report.riskBand)} risk · Completed {formatDate(report.completedAt)} · Ruleset {report.ruleSetVersion}</p></div>
        <div className="flex gap-2"><button type="button" onClick={exportResult} className="min-h-10 rounded-md border border-input px-3 text-xs font-medium hover:bg-muted" data-testid={`button-export-${report.scanId}`}>Export HTML</button><button type="button" onClick={printResult} className="min-h-10 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground hover:opacity-90" data-testid={`button-print-${report.scanId}`}>Print / PDF</button></div>
      </header>
      <p className="mt-3 rounded-md border border-border bg-muted/30 p-3 text-xs leading-5">{report.coverage.sufficient ? 'Coverage marked sufficient by the analyzer.' : 'Coverage is limited. A missing check is not evidence of safety.'} This result is not a guarantee that the submitted item is safe.</p>
      <h5 className="mt-4 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Evidence and findings</h5>
      {report.findings.length ? <ul className="mt-2 divide-y divide-border rounded-lg border border-border">{report.findings.map((finding) => <li key={finding.id} className="p-3"><div className="text-xs font-medium">{finding.severity} · {finding.strength} · {finding.source.replace(/_/g, ' ')}</div><h6 className="mt-1 text-sm font-semibold">{finding.title}</h6><p className="mt-1 text-sm leading-5 text-muted-foreground">{finding.explanation}</p>{finding.sanitizedObservedValue && <pre className="mt-2 whitespace-pre-wrap break-all rounded bg-muted/50 p-2 font-mono text-xs">{finding.sanitizedObservedValue}</pre>}{finding.limitations?.map((limitation, index) => <p key={`${finding.id}-${index}`} className="mt-2 text-xs text-muted-foreground">Limitation: {limitation}</p>)}</li>)}</ul> : <p className="mt-2 rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">No findings were returned. This does not establish safety.</p>}
      <h5 className="mt-4 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Coverage</h5>
      <ul className="mt-2 space-y-1 text-xs text-muted-foreground">{report.coverage.checks.map((check, index) => <li key={`${check.name}-${index}`}>{check.name}: {check.status}{check.reason ? ` · ${check.reason}` : ''}</li>)}</ul>
      {summaryStatus === 'streaming' && <p className="mt-4 text-xs text-muted-foreground" role="status">Preparing the optional AI summary…</p>}
      {summaryError && <p className="mt-4 rounded-md border border-border bg-muted/30 p-3 text-xs leading-5 text-muted-foreground" role="status">{summaryError} The deterministic report is unchanged.</p>}
      {summary && <section className="mt-4 rounded-lg border border-border bg-muted/20 p-3" aria-label="Optional AI summary"><h5 className="text-xs font-semibold">Optional AI summary</h5><p className="mt-2 whitespace-pre-wrap break-words text-sm leading-6">{summary}</p><p className="mt-2 text-xs leading-5 text-muted-foreground">This text is an explanation only. It does not change the deterministic report or establish safety.</p></section>}
      {attachments.length > 0 && <section className="mt-4 rounded-lg border border-border bg-muted/20 p-3"><h5 className="text-xs font-semibold">Attachment metadata only</h5><p className="mt-1 text-xs leading-5 text-muted-foreground">Attachment contents were not opened or analyzed.</p>{attachments.map((finding) => <p key={finding.id} className="mt-2 text-xs">{finding.title}{finding.sanitizedObservedValue ? ` · ${finding.sanitizedObservedValue}` : ''}</p>)}</section>}
    </article>
  );
}

function ReportView({
  report,
  onExport,
  onPrint,
  emailLinks,
  selectedLinkIds,
  setSelectedLinkIds,
  onOpenBatch,
  summaryEnabled,
  summaryText,
  summaryError,
  summaryStatus,
}: {
  report: ScanReport;
  onExport: () => void;
  onPrint: () => boolean;
  emailLinks: NonNullable<ScanReport['links']>;
  selectedLinkIds: string[];
  setSelectedLinkIds: (ids: string[]) => void;
  onOpenBatch: () => void;
  summaryEnabled: boolean;
  summaryText: string;
  summaryError: string;
  summaryStatus: 'idle' | 'streaming' | 'complete' | 'error';
}) {
  const [printError, setPrintError] = useState('');
  const riskColor = report.riskBand === 'critical' || report.riskBand === 'high'
    ? 'border-destructive/30 bg-destructive/5 text-destructive'
    : report.riskBand === 'moderate'
      ? 'border-border bg-muted/60 text-foreground'
      : report.riskBand === 'low'
        ? 'border-border bg-background text-foreground'
        : 'border-border bg-muted/30 text-muted-foreground';
  const attachments = report.findings.filter((finding) => finding.source === 'attachment_metadata');
  return (
    <article id="lumio-print-report" className="overflow-hidden rounded-xl border border-border bg-card shadow-sm" data-testid="report-analysis">
      <header className="border-b border-border px-5 py-5 sm:px-6">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <h2 className="text-xl font-semibold tracking-tight">Analysis complete</h2>
              <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${riskColor}`} data-testid="status-risk-band">
                {riskLabel(report.riskBand)}
              </span>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">Completed {formatDate(report.completedAt)} · Ruleset {report.ruleSetVersion}</p>
            {report.partial && (
              <div
                className="mt-3 rounded-lg border border-amber-600/30 bg-amber-500/5 px-4 py-3 text-sm"
                role="status"
                data-testid="status-partial-report"
              >
                <p className="font-semibold">Partial report</p>
                <p className="mt-1 text-muted-foreground">
                  {report.partialReason ?? 'The scan was cancelled before all checks were complete. No findings do not establish safety.'}
                </p>
              </div>
            )}
          </div>
          <div className="flex flex-col items-end gap-2">
            <div className="flex gap-2 print:hidden" data-testid="report-actions">
              <button type="button" onClick={onExport} data-testid="button-export-html" className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-input bg-background px-3 text-sm font-medium hover:bg-muted">
                <Download className="size-4" aria-hidden="true" /> Export HTML
              </button>
              <button type="button" onClick={() => setPrintError(onPrint() ? '' : 'The print-ready report did not open. Allow pop-ups for this page, then try again.')} data-testid="button-print-pdf" className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-primary px-3 text-sm font-medium text-primary-foreground hover:opacity-90">
                <Printer className="size-4" aria-hidden="true" /> Print / PDF
              </button>
            </div>
            {printError && <p className="max-w-xs text-right text-xs text-destructive print:hidden" role="status" data-testid="status-print-error">{printError}</p>}
          </div>
        </div>
        <div className={`mt-4 flex items-start gap-2 rounded-lg border p-3 text-sm ${report.coverage.sufficient ? 'border-border bg-muted/30 text-foreground' : 'border-amber-500/30 bg-amber-500/5 text-foreground'}`}
          role="status" data-testid="status-coverage-sufficient">
          {report.coverage.sufficient ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" /> : <AlertCircle className="mt-0.5 size-4 shrink-0 text-amber-700" aria-hidden="true" />}
          <span>{report.coverage.sufficient ? 'The analyzer marked coverage sufficient for this scan.' : 'Coverage is limited. A missing check is not evidence of safety.'}</span>
        </div>
      </header>

      <div className="p-5 sm:p-6">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold">Findings <span className="ml-1 text-muted-foreground">({report.findings.length})</span></h3>
        </div>
        {report.findings.length ? (
          <div className="divide-y divide-border rounded-lg border border-border">
            {report.findings.map((finding) => (
              <section key={finding.id} className="p-4" data-testid={`finding-${finding.id}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${severityClass(finding.severity)}`}>{finding.severity}</span>
                  <span className="text-xs text-muted-foreground">{finding.strength} evidence · {finding.source.replace(/_/g, ' ')}</span>
                </div>
                <h4 className="mt-2 text-sm font-semibold">{finding.title}</h4>
                <p className="mt-1 text-sm leading-6 text-muted-foreground">{finding.explanation}</p>
                {finding.sanitizedObservedValue && <pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-muted/60 p-3 font-mono text-xs" data-testid={`evidence-value-${finding.id}`}>{finding.sanitizedObservedValue}</pre>}
                {!!finding.limitations?.length && <ul className="mt-3 space-y-1 text-xs text-muted-foreground">{finding.limitations.map((limitation, index) => <li key={`${finding.id}-limitation-${index}`}>Limitation: {limitation}</li>)}</ul>}
              </section>
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-border bg-muted/20 p-5 text-sm text-muted-foreground" data-testid="empty-report-findings">No findings were returned. This is not a guarantee that the item is safe.</div>
        )}

        {report.type === 'url' && <KevContextSection report={report} />}

        <section className="mt-6" aria-labelledby="coverage-title">
          <h3 id="coverage-title" className="text-sm font-semibold">Checks and coverage</h3>
          <ul className="mt-3 divide-y divide-border rounded-lg border border-border">
            {report.coverage.checks.map((check, index) => (
              <li key={`${check.name}-${index}`} className="flex flex-col gap-1 px-3.5 py-3 sm:flex-row sm:items-center sm:justify-between" data-testid={`coverage-check-${index}`}>
                <span className="text-sm font-medium">{check.name}</span>
                <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
                  <span className={`size-1.5 rounded-full ${check.status === 'completed' ? 'bg-emerald-600' : check.status === 'failed' ? 'bg-destructive' : 'bg-amber-600'}`} />
                  {check.status}{check.reason ? ` · ${check.reason}` : ''}
                </span>
              </li>
            ))}
          </ul>
        </section>

        {!!report.executionPlan?.length && (
          <ExecutionPlanList steps={report.executionPlan} testId="report-execution-plan" type={report.type} />
        )}

        <AgentActionsSection actions={report.agentActions ?? []} />

        {summaryEnabled && (summaryStatus !== 'idle' || !!summaryError || !!summaryText) && (
          <section className="mt-6 rounded-lg border border-border bg-muted/20 p-4" aria-labelledby="summary-title" data-testid="section-ai-summary">
            <div className="flex items-start gap-3">
              <Sparkles className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <div className="min-w-0">
                <h3 id="summary-title" className="text-sm font-semibold">Optional AI summary</h3>
                {summaryStatus === 'streaming' && <p className="mt-1 text-xs text-muted-foreground" role="status" data-testid="status-ai-summary-streaming">Preparing a short explanation and safe follow-up suggestion…</p>}
              </div>
            </div>
            {summaryError && <p className="mt-3 rounded-md border border-border bg-background p-3 text-sm leading-5 text-muted-foreground" role="status" data-testid="status-ai-summary-error">{summaryError} The deterministic report is unchanged.</p>}
            {summaryText && <div className="mt-4 rounded-md border border-border bg-background p-4" aria-live="polite" data-testid="text-ai-summary">
              <p className="whitespace-pre-wrap break-words text-sm leading-6">{summaryText}</p>
              <p className="mt-3 text-xs leading-5 text-muted-foreground">AI-generated explanation only. Use the deterministic evidence and coverage above as the report; this text does not establish safety.</p>
            </div>}
          </section>
        )}

        {attachments.length > 0 && (
          <section className="mt-6 rounded-lg border border-border bg-muted/20 p-4" aria-labelledby="attachment-title" data-testid="section-attachment-metadata">
            <h3 id="attachment-title" className="text-sm font-semibold">Attachment metadata only</h3>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">Attachment contents were not opened or analyzed. These details are metadata supplied by the report.</p>
            <ul className="mt-3 space-y-2">{attachments.map((finding) => <li key={finding.id} className="text-sm"><span className="font-medium">{finding.title}</span>{finding.sanitizedObservedValue && <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{finding.sanitizedObservedValue}</p>}</li>)}</ul>
          </section>
        )}

        {!!emailLinks.length && (
          <section className="mt-6 border-t border-border pt-5" aria-labelledby="email-links-title">
            <div className="flex items-start justify-between gap-4">
              <div><h3 id="email-links-title" className="text-sm font-semibold">Links found in this email</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">Select only destinations you want to inspect. Links are never visited automatically.</p></div>
              <span className="shrink-0 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground">{emailLinks.length} shown</span>
            </div>
            <div className="mt-3 space-y-2">
              {emailLinks.map((link) => (
                <label key={link.linkId} className={`flex cursor-pointer gap-3 rounded-lg border p-3 transition-colors ${selectedLinkIds.includes(link.linkId) ? 'border-primary/50 bg-muted/50' : 'border-border hover:bg-muted/30'} ${!link.scanAvailable ? 'cursor-not-allowed opacity-60' : ''}`}>
                  <input type="checkbox" value={link.linkId} disabled={!link.scanAvailable} checked={selectedLinkIds.includes(link.linkId)}
                    onChange={(event) => setSelectedLinkIds(event.target.checked ? [...selectedLinkIds, link.linkId] : selectedLinkIds.filter((id) => id !== link.linkId))} data-testid={`checkbox-email-link-${link.linkId}`} className="mt-1 size-4 shrink-0 accent-foreground" />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-1 text-sm font-medium">{link.anchorText || link.targetHost}{link.scanAvailable && <ArrowUpRight className="size-3.5 text-muted-foreground" aria-hidden="true" />}</span>
                    <span className="mt-1 block break-all font-mono text-xs text-muted-foreground">{link.displayUrl}</span>
                    <span className="mt-1 block text-xs text-muted-foreground">Destination host: {link.targetHost} · {link.scanAvailable ? 'eligible for a separate scan' : 'not available for a separate scan'}</span>
                  </span>
                </label>
              ))}
            </div>
            <button type="button" onClick={onOpenBatch} disabled={!selectedLinkIds.length}
              data-testid="button-scan-selected-link" className="mt-3 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-lg border border-input bg-background px-4 text-sm font-medium hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50">
              <Globe2 className="size-4" aria-hidden="true" />
              Review {selectedLinkIds.length || ''} selected link{selectedLinkIds.length === 1 ? '' : 's'}
            </button>
          </section>
        )}
        <p className="mt-6 border-t border-border pt-4 text-xs leading-5 text-muted-foreground" data-testid="text-report-disclaimer">
          Risk labels reflect the evidence available to this scan. Inconclusive or limited coverage should not be interpreted as safe.
        </p>
      </div>
    </article>
  );
}

function useSecondsLeft(deadline: string) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const end = Date.parse(deadline);
  return Number.isFinite(end) ? Math.max(0, Math.round((end - now) / 1000)) : 0;
}

function AgentActionItem({ action }: { action: AgentActionResult }) {
  return (
    <li className="rounded-md border border-border bg-background p-3 text-sm" data-testid={`agent-action-${action.actionId}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium">{AGENT_TOOL_LABELS[action.tool]}</span>
        <span className="inline-flex items-center gap-1 rounded-full border border-border px-2 py-0.5 text-xs">
          {action.status === 'running' && <LoaderCircle className="size-3 animate-spin" aria-hidden="true" />}
          {AGENT_STATUS_LABELS[action.status]}
        </span>
      </div>
      {action.targetHost && <p className="mt-1 break-all text-xs text-muted-foreground">Destination host: {action.targetHost}</p>}
      {action.reasonCode && <p className="mt-1 text-xs text-muted-foreground">{AGENT_REASON_LABELS[action.reasonCode]}</p>}
      {action.riskBand && <p className="mt-2 text-xs">Result for this step only: <strong>{riskLabel(action.riskBand)}</strong>{action.coverageSufficient === false ? ' · limited coverage' : ''}</p>}
      {!!action.findings?.length && (
        <ul className="mt-2 space-y-1">
          {action.findings.map((finding) => (
            <li key={finding.id} className="text-xs leading-5 text-muted-foreground"><span className="font-medium text-foreground">{finding.title}</span> · {finding.severity} — {finding.explanation}</li>
          ))}
        </ul>
      )}
    </li>
  );
}

function AgentActionsSection({ actions }: { actions: AgentActionResult[] }) {
  if (!actions.length) return null;
  return (
    <section className="mt-6 rounded-lg border border-border bg-muted/20 p-4" aria-labelledby="agent-actions-title" data-testid="section-agent-actions">
      <h3 id="agent-actions-title" className="text-sm font-semibold">Follow-up steps you approved</h3>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">Listed separately. These results do not change the risk band above.</p>
      <ul className="mt-3 space-y-2">{actions.map((action) => <AgentActionItem key={action.actionId} action={action} />)}</ul>
    </section>
  );
}

function AgentReviewPanel({
  deadline,
  approvalRequest,
  actions,
  pending,
  error,
  note,
  onResolve,
  onSkip,
}: {
  deadline: string;
  approvalRequest: AgentApprovalRequest | null;
  actions: AgentActionResult[];
  pending: boolean;
  error: string;
  note: string;
  onResolve: (decision: 'approve' | 'decline') => void;
  onSkip: () => void;
}) {
  const secondsLeft = useSecondsLeft(deadline);
  const proposal = approvalRequest?.proposal;
  const tool = typeof proposal?.tool === 'string' ? proposal.tool : null;
  const isShare = proposal?.kind === 'data';
  const purpose = typeof proposal?.purpose === 'string' ? proposal.purpose : '';
  const title = isShare
    ? 'Share cleaned link details with Vultr AI?'
    : tool === 'email_link_visit'
      ? 'Visit this link in the isolated worker?'
      : tool === 'url_browser_observation'
        ? 'Open this page in an isolated browser?'
        : 'Approve this follow-up step?';
  const approveLabel = isShare ? 'Share details' : tool === 'email_link_visit' ? 'Visit link' : 'Run check';
  const declineLabel = isShare ? "Don't share" : tool === 'email_link_visit' ? "Don't visit" : 'Decline';
  return (
    <section className="mb-5 max-w-[90%] rounded-2xl rounded-bl-sm border border-border bg-card p-4 text-sm" aria-labelledby="agent-review-title" data-testid="section-agent-review">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-start gap-2">
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h3 id="agent-review-title" className="font-semibold">Follow-up review</h3>
            <p className="mt-0.5 text-xs leading-5 text-muted-foreground">The first checks are done. The report waits for your decisions, then uses whatever has finished.</p>
          </div>
        </div>
        <span className="rounded-full border border-border px-2 py-0.5 text-xs tabular-nums text-muted-foreground" role="timer" aria-live="off" data-testid="text-agent-review-time">
          {Math.floor(secondsLeft / 60)}:{String(secondsLeft % 60).padStart(2, '0')} left
        </span>
      </div>

      {approvalRequest && (
        <div className="mt-4 rounded-md border border-border bg-background p-4" role="dialog" aria-labelledby="agent-approval-title" data-testid="agent-approval-request">
          <h4 id="agent-approval-title" className="font-semibold">{title}</h4>
          {purpose && <p className="mt-1 text-muted-foreground">{purpose}</p>}
          {approvalRequest.targetLabel && <p className="mt-2 break-all text-xs"><span className="font-medium">Destination host:</span> {approvalRequest.targetLabel}</p>}
          {isShare ? (
            <p className="mt-3 text-xs leading-5 text-muted-foreground">Only each link's host, path and visible text are sent; queries, fragments and secret-looking values are removed. Vultr's retention and training terms are not verified. If you don't share, the report uses the checks already finished.</p>
          ) : (
            <p className="mt-3 text-xs leading-5 text-muted-foreground">Runs once in the isolated worker. Its result is listed separately and does not change the risk band of the first checks.</p>
          )}
          <div className="mt-4 flex flex-wrap gap-2">
            <button type="button" onClick={() => onResolve('approve')} disabled={pending} data-testid="button-approve-agent-request"
              className="inline-flex min-h-11 items-center justify-center rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">{approveLabel}</button>
            <button type="button" onClick={() => onResolve('decline')} disabled={pending} data-testid="button-decline-agent-request"
              className="inline-flex min-h-11 items-center justify-center rounded-lg border border-input bg-background px-4 text-sm font-medium hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50">{declineLabel}</button>
          </div>
        </div>
      )}

      {!approvalRequest && !note && pending && <p className="mt-3 inline-flex items-center gap-2 text-xs text-muted-foreground" role="status"><LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" /> Preparing the next step…</p>}
      {note && <p className="mt-3 text-xs text-muted-foreground" role="status" data-testid="status-agent-review-note">{note}</p>}
      {!!actions.length && <ul className="mt-3 space-y-2">{actions.map((action) => <AgentActionItem key={action.actionId} action={action} />)}</ul>}
      {error && <p className="mt-3 text-xs text-destructive" role="status" data-testid="status-agent-approval-error">{error}</p>}

      <button type="button" onClick={onSkip} disabled={pending} data-testid="button-skip-agent-review"
        className="mt-4 inline-flex min-h-10 items-center justify-center rounded-md border border-input bg-background px-3 text-xs font-medium hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50">
        Finish without more follow-up
      </button>
    </section>
  );
}
