import { type FormEvent, useEffect, useMemo, useState } from 'react';
import {
  useGetAnalysisStatus,
  getGetAnalysisStatusQueryKey,
  useCreateUrlScan,
  useCreateEmailScan,
  useGetScan,
  getGetScanQueryKey,
  useCreateSelectedEmailLinkScan,
} from '@workspace/api-client-react';
import type { ScanAccepted, ScanProgress, ScanReport } from '@workspace/api-client-react';
import {
  AlertCircle,
  ArrowUpRight,
  Check,
  CheckCircle2,
  CircleAlert,
  Clock3,
  Download,
  FileText,
  Globe2,
  LoaderCircle,
  LockKeyhole,
  Printer,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import {
  Stepper,
  StepperIndicator,
  StepperItem,
  StepperNav,
  StepperSeparator,
  StepperTrigger,
} from '@/components/reui/stepper';

type InputMode = 'url' | 'email';
type StreamFailure = { message?: string };

const MAX_EMAIL_BYTES = 10 * 1024 * 1024;

function stageIndex(stage?: string) {
  if (!stage) return 1;
  if (stage === 'validating' || stage === 'queued') return 1;
  if (stage === 'building_report' || stage === 'completed' || stage === 'failed') return 3;
  return 2;
}

type ScanPlanStep = NonNullable<ScanProgress['plan']>[number];

const planStepLabels: Record<ScanPlanStep['id'], string> = {
  consent_target: 'Validate consent and public target',
  sandbox: 'Start an isolated sandbox',
  http: 'Inspect HTTP response and redirects',
  static: 'Review static page signals',
  browser: 'Inspect in a browser when needed',
  report: 'Assemble the evidence report',
};

function planStepLabel(id: ScanPlanStep['id'], type: ScanReport['type']) {
  if (type === 'email') {
    const emailLabels: Record<ScanPlanStep['id'], string> = {
      consent_target: 'Validate consent and email file',
      sandbox: 'Start an isolated email sandbox',
      http: 'Review email headers',
      static: 'Inspect message body and attachment metadata',
      browser: 'Visit a selected link after consent',
      report: 'Assemble the evidence report',
    };
    return emailLabels[id];
  }
  if (type === 'email_link' && id === 'consent_target') {
    return 'Validate selected-link consent and target';
  }
  return planStepLabels[id];
}

const planStatusLabels: Record<ScanPlanStep['status'], string> = {
  pending: 'Waiting',
  running: 'In progress',
  completed: 'Completed',
  skipped: 'Skipped',
  failed: 'Failed',
  blocked: 'Blocked',
};

const planReasonLabels: Record<NonNullable<ScanPlanStep['reasonCode']>, string> = {
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
  return planReasonLabels[reason];
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
        {steps.map((step) => (
          <li key={step.id} className="flex items-start gap-3 rounded-lg border border-border px-3 py-2.5">
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
            <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{planStatusLabels[step.status]}</span>
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

function reportHtml(report: ScanReport) {
  const executionPlan = (report.executionPlan ?? []).map((step) => `
    <li><strong>${escapeHtml(planStepLabel(step.id, report.type))}</strong> — ${escapeHtml(planStatusLabels[step.status])}${step.reasonCode ? `: ${escapeHtml(planReasonLabel(step.reasonCode, report.type))}` : ''}</li>`).join('');
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
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Veridict analysis report</title><style>
    *{box-sizing:border-box}body{margin:0;background:#f6f6f7;color:#18181b;font:15px/1.6 system-ui,sans-serif}
    main{max-width:860px;margin:40px auto;padding:36px;background:white;border:1px solid #e4e4e7;border-radius:14px}
    h1{font-size:30px;margin:8px 0}h2{font-size:18px;margin:8px 0}.meta,.muted{color:#71717a;font-size:13px}
    .band{display:inline-block;border:1px solid #d4d4d8;border-radius:999px;padding:3px 12px;font-weight:650}
    .finding{border-top:1px solid #e4e4e7;padding:18px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f5;padding:10px;border-radius:8px}
    li{margin:7px 0}footer{border-top:1px solid #e4e4e7;margin-top:24px;padding-top:16px;color:#71717a;font-size:12px}
    @media print{body{background:white}main{margin:0 auto;border:0;padding:0}}
  </style><main><div class="meta">VERIDICT · EVIDENCE REPORT</div><h1>${escapeHtml(riskLabel(report.riskBand))} risk</h1><p class="meta">Completed ${escapeHtml(formatDate(report.completedAt))} · Rule set ${escapeHtml(report.ruleSetVersion)}</p>
    ${executionPlan ? `<h2>Execution plan</h2><ol>${executionPlan}</ol>` : ''}
    <h2>Evidence and findings</h2>${findings || '<p>No findings were returned by the analyzer.</p>'}
    <h2>Coverage</h2><p>${report.coverage.sufficient ? 'Coverage marked sufficient by the analyzer.' : 'Coverage is limited; interpret this result with caution.'}</p><ul>${checks}</ul>
    ${links ? `<h2>Links found in email</h2><ul>${links}</ul>` : ''}
    <footer>This report contains only the evidence returned by Veridict. It is not a guarantee that a message or URL is safe.</footer>
  </main></html>`;
}

export default function AnalyzerPage() {
  const queryClient = useQueryClient();
  const statusQuery = useGetAnalysisStatus({
    query: { queryKey: getGetAnalysisStatusQueryKey(), refetchInterval: 15000 },
  });
  const createUrl = useCreateUrlScan();
  const createEmail = useCreateEmailScan();
  const createSelectedLink = useCreateSelectedEmailLinkScan();
  const [mode, setMode] = useState<InputMode>('url');
  const [url, setUrl] = useState('');
  const [urlConsent, setUrlConsent] = useState(false);
  const [emailConsent, setEmailConsent] = useState(false);
  const [linkConsent, setLinkConsent] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [formError, setFormError] = useState('');
  const [scanAccepted, setScanAccepted] = useState<ScanAccepted | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [emailReport, setEmailReport] = useState<ScanReport | null>(null);
  const [scanType, setScanType] = useState<ScanReport['type']>('url');
  const [streamError, setStreamError] = useState('');
  const [streamFinished, setStreamFinished] = useState(false);
  const [selectedLinkId, setSelectedLinkId] = useState('');
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
    (!!scanAccepted && !streamFinished && !report);
  const currentStage = stageIndex(progress?.stage);
  const emailLinks = useMemo(() => (emailReport?.links ?? []).slice(0, 50), [emailReport]);
  const activeReport = report;

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
    source.addEventListener('progress', (event) => {
      try {
        setProgress(JSON.parse((event as MessageEvent).data) as ScanProgress);
      } catch {
        setStreamError('The progress stream returned an unreadable event. Checking scan status for recovery.');
      }
    });
    source.addEventListener('completed', (event) => {
      try {
        const nextReport = JSON.parse((event as MessageEvent).data) as ScanReport;
        setReport(nextReport);
        if (nextReport.type === 'email') setEmailReport(nextReport);
        setStreamFinished(true);
        setStreamError('');
        void queryClient.invalidateQueries({ queryKey: getGetAnalysisStatusQueryKey() });
      } catch {
        setStreamError('A report could not be read from the stream. The scan status is being recovered.');
      }
      source.close();
    });
    source.addEventListener('failed', (_event) => {
      setStreamError('Analysis did not complete. No report is available for this scan.');
      setStreamFinished(true);
      source.close();
    });
    source.onerror = () => {
      if (!streamFinished) setStreamError('Live updates were interrupted. Veridict is checking the scan status.');
    };
    return () => source.close();
  }, [scanAccepted, streamFinished, queryClient]);

  useEffect(() => {
    const snapshot = scanQuery.data;
    if (!snapshot) return;
    if (snapshot.status === 'failed' || snapshot.status === 'cancelled') {
      setStreamError('Analysis did not complete. No report is available for this scan.');
      setStreamFinished(true);
    } else if (snapshot.status === 'completed' && !report) {
      setStreamFinished(true);
      setStreamError('This scan completed, but its transient report is no longer available. Start a new scan to receive a fresh report.');
    }
  }, [scanQuery.data, report]);

  function beginAccepted(accepted: ScanAccepted, type: ScanReport['type'], preserveEmail = false) {
    setScanAccepted(accepted);
    setScanType(type);
    setProgress(null);
    setReport(null);
    setStreamError('');
    setStreamFinished(false);
    setUrlConsent(false);
    setEmailConsent(false);
    setLinkConsent(false);
    if (!preserveEmail) {
      setEmailReport(null);
      setSelectedLinkId('');
    }
  }

  function handleUrlSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError('');
    if (!urlConsent) {
      setFormError('Confirm consent before submitting this URL.');
      return;
    }
    const target = url.trim();
    if (!target) {
      setFormError('Enter a domain, public IP, or HTTP(S) URL.');
      return;
    }
    if (target.length > 2048) {
      setFormError('Use a domain, public IP, or HTTP(S) URL under 2,048 characters.');
      return;
    }
    createUrl.mutate(
      { data: { url: target, consent: true } },
      {
        onSuccess: (accepted) => beginAccepted(accepted, 'url'),
        onError: (error) => setFormError(safeErrorMessage(error)),
      },
    );
  }

  function handleEmailSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError('');
    if (!file) {
      setFormError('Choose an .eml file to continue.');
      return;
    }
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setFormError('This analyzer accepts .eml files only.');
      return;
    }
    if (file.size > MAX_EMAIL_BYTES) {
      setFormError('The selected file is larger than the 10 MB limit.');
      return;
    }
    if (!emailConsent) {
      setFormError('Confirm consent before submitting this email.');
      return;
    }
    createEmail.mutate(
      { data: { file, consent: true } },
      {
        onSuccess: (accepted) => beginAccepted(accepted, 'email'),
        onError: (error) => setFormError(safeErrorMessage(error)),
      },
    );
  }

  function scanSelectedLink() {
    if (!emailReport || !selectedLinkId || !linkConsent) {
      setFormError('Select a link and confirm separate consent before scanning it.');
      return;
    }
    const link = emailLinks.find((item) => item.linkId === selectedLinkId);
    if (!link?.scanAvailable) {
      setFormError('This link is not available for a separate scan.');
      return;
    }
    setFormError('');
    createSelectedLink.mutate(
      { scanId: emailReport.scanId, linkId: selectedLinkId, data: { consent: true } },
      {
        onSuccess: (accepted) => beginAccepted(accepted, 'email_link', true),
        onError: (error) => setFormError(safeErrorMessage(error)),
      },
    );
  }

  function exportReport() {
    if (!activeReport) return;
    const blob = new Blob([reportHtml(activeReport)], { type: 'text/html;charset=utf-8' });
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = objectUrl;
    anchor.download = `veridict-report-${activeReport.scanId}.html`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
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

  return (
    <div className="min-h-[100dvh] bg-background text-foreground">
      <header className="border-b border-border bg-card">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-4 sm:px-6">
          <a href="/" data-testid="link-veridict-home" className="flex items-center gap-3 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label="Veridict home">
            <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground"><ShieldCheck className="size-5" aria-hidden="true" /></span>
            <span className="text-lg font-semibold tracking-tight">Veridict</span>
          </a>
          <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${workerUnavailable ? 'border-destructive/30 bg-destructive/5 text-destructive' : 'border-border bg-muted/60 text-muted-foreground'}`}
            role="status" aria-live="polite" data-testid="status-analyzer-readiness">
            <span className={`size-1.5 rounded-full ${workerUnavailable ? 'bg-destructive' : statusQuery.isLoading ? 'bg-muted-foreground' : 'bg-emerald-600'}`} />
            {readinessText}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 pb-16 pt-8 sm:px-6 sm:pt-12">
        <section className="mb-8 max-w-3xl">
          <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            <LockKeyhole className="size-3.5" aria-hidden="true" /> Private, consent-based checks
          </div>
          <h1 className="max-w-2xl text-3xl font-semibold tracking-tight sm:text-4xl">Check the evidence before you click.</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground sm:text-base">
            Analyze a suspicious URL or email with an isolated worker. Veridict reports observable evidence and coverage limits—not a promise of safety.
          </p>
        </section>

        <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,0.92fr)_minmax(420px,1.08fr)]">
          <section className="overflow-hidden rounded-xl border border-border bg-card shadow-sm" aria-labelledby="analyzer-title">
            <div className="border-b border-border px-5 py-5 sm:px-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.13em] text-muted-foreground">Start an analysis</p>
                  <h2 id="analyzer-title" className="mt-1 text-xl font-semibold tracking-tight">What would you like to check?</h2>
                </div>
                <span className="hidden rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground sm:inline-flex">No account required</span>
              </div>
              <div className="mt-5 grid grid-cols-2 rounded-lg bg-muted p-1" role="group" aria-label="Analysis type">
                <button type="button" aria-pressed={mode === 'url'} onClick={() => { setMode('url'); setFormError(''); }}
                  data-testid="tab-analyze-url" className={`min-h-10 rounded-md px-3 text-sm font-medium transition-colors ${mode === 'url' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}>
                  <Globe2 className="mr-2 inline size-4" aria-hidden="true" /> URL
                </button>
                <button type="button" aria-pressed={mode === 'email'} onClick={() => { setMode('email'); setFormError(''); }}
                  data-testid="tab-analyze-email" className={`min-h-10 rounded-md px-3 text-sm font-medium transition-colors ${mode === 'email' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}>
                  <FileText className="mr-2 inline size-4" aria-hidden="true" /> Email file
                </button>
              </div>
            </div>

            <div className="p-5 sm:p-6">
              {mode === 'url' ? (
                <form onSubmit={handleUrlSubmit} noValidate>
                  <label htmlFor="url-input" className="mb-2 block text-sm font-medium">Suspicious domain, IP, or URL</label>
                  <div className="flex min-h-12 items-center gap-2 rounded-lg border border-input bg-background px-3 focus-within:ring-2 focus-within:ring-ring/30">
                    <Globe2 className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <input id="url-input" type="text" inputMode="url" autoComplete="url" value={url} maxLength={2048}
                      onChange={(event) => setUrl(event.target.value)} placeholder="example.com or https://example.com/path"
                      aria-describedby="url-help" data-testid="input-suspicious-url"
                      className="min-w-0 flex-1 bg-transparent py-3 text-sm outline-none placeholder:text-muted-foreground/70" />
                  </div>
                  <p id="url-help" className="mt-2 text-xs text-muted-foreground">Bare domains and IPs use HTTPS. Include http:// to request HTTP. Public targets only; maximum 2,048 characters.</p>
                  <label className="mt-5 flex cursor-pointer items-start gap-3 rounded-lg border border-border bg-muted/30 p-3.5 text-sm leading-5">
                    <input type="checkbox" checked={urlConsent} onChange={(event) => setUrlConsent(event.target.checked)}
                      data-testid="checkbox-url-consent" className="mt-0.5 size-4 shrink-0 accent-foreground" />
                    <span>I have permission to submit this URL for a transient, isolated analysis. I understand the site may be visited by an automated browser.</span>
                  </label>
                  <button type="submit" disabled={busy || workerUnavailable || statusQuery.isLoading || statusQuery.isError}
                    data-testid="button-submit-url"
                    className="mt-4 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">
                    {createUrl.isPending ? <LoaderCircle className="size-4 animate-spin" aria-hidden="true" /> : <ShieldCheck className="size-4" aria-hidden="true" />}
                    Analyze URL
                  </button>
                </form>
              ) : (
                <form onSubmit={handleEmailSubmit} noValidate>
                  <label htmlFor="email-file" className="mb-2 block text-sm font-medium">Email message (.eml)</label>
                  <label htmlFor="email-file" className="flex min-h-36 cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-input bg-muted/20 px-4 py-5 text-center transition-colors hover:bg-muted/40 focus-within:ring-2 focus-within:ring-ring/40">
                    <span className="mb-2 flex size-10 items-center justify-center rounded-full border border-border bg-card"><Upload className="size-4 text-muted-foreground" aria-hidden="true" /></span>
                    <span className="text-sm font-medium">{file ? file.name : 'Choose an .eml file'}</span>
                    <span className="mt-1 text-xs text-muted-foreground">{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : 'Maximum file size 10 MB'}</span>
                    <input id="email-file" type="file" accept=".eml,message/rfc822" className="sr-only"
                      onChange={(event) => { setFile(event.target.files?.[0] ?? null); setFormError(''); }}
                      data-testid="input-email-file" aria-describedby="email-help" />
                  </label>
                  <p id="email-help" className="mt-2 text-xs leading-5 text-muted-foreground">Message content is processed transiently. The raw email body is never shown. Attachments are limited to metadata; contents are not opened.</p>
                  <label className="mt-4 flex cursor-pointer items-start gap-3 rounded-lg border border-border bg-muted/30 p-3.5 text-sm leading-5">
                    <input type="checkbox" checked={emailConsent} onChange={(event) => setEmailConsent(event.target.checked)}
                      data-testid="checkbox-email-consent" className="mt-0.5 size-4 shrink-0 accent-foreground" />
                    <span>I have permission to submit this email for transient analysis and understand that extracted links are not visited unless I separately choose and consent to scan one.</span>
                  </label>
                  <button type="submit" disabled={busy || workerUnavailable || statusQuery.isLoading || statusQuery.isError}
                    data-testid="button-submit-email"
                    className="mt-4 inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">
                    {createEmail.isPending ? <LoaderCircle className="size-4 animate-spin" aria-hidden="true" /> : <ShieldCheck className="size-4" aria-hidden="true" />}
                    Analyze email
                  </button>
                </form>
              )}

              {formError && <div role="alert" data-testid="error-analysis-form" className="mt-4 flex gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"><AlertCircle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />{formError}</div>}

              {workerUnavailable && (
                <div role="status" data-testid="status-worker-unavailable" className="mt-4 flex gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-4">
                  <CircleAlert className="mt-0.5 size-5 shrink-0 text-destructive" aria-hidden="true" />
                  <div><p className="text-sm font-semibold">Analysis is temporarily unavailable</p><p className="mt-1 text-sm leading-5 text-muted-foreground">The isolated analyzer is unavailable. No scan has been started, and no result can be produced right now.</p></div>
                </div>
              )}
              {statusQuery.isError && <div role="alert" data-testid="error-readiness" className="mt-3 flex items-center justify-between gap-3 text-sm text-destructive"><span>Analyzer readiness could not be confirmed. Retry before submitting a scan.</span><button type="button" onClick={() => void statusQuery.refetch()} data-testid="button-retry-readiness" className="shrink-0 rounded-md border border-destructive/30 px-2.5 py-1.5 font-medium hover:bg-destructive/5">Retry</button></div>}

              <div className="mt-5 grid grid-cols-2 gap-3 border-t border-border pt-4 text-xs text-muted-foreground">
                <div className="flex items-center gap-2"><LockKeyhole className="size-3.5" aria-hidden="true" /> Consent before every scan</div>
                <div className="flex items-center gap-2"><Clock3 className="size-3.5" aria-hidden="true" /> Results are transient</div>
              </div>
            </div>
          </section>

          <section className="min-w-0" aria-label="Analysis report">
            {busy && !activeReport ? (
              <div className="rounded-xl border border-border bg-card p-5 shadow-sm sm:p-6" aria-live="polite" data-testid="status-scan-progress">
                <div className="flex items-start justify-between gap-3">
                  <div><p className="text-xs font-semibold uppercase tracking-[0.13em] text-muted-foreground">Live analysis</p><h2 className="mt-1 text-xl font-semibold tracking-tight">Working in an isolated session</h2></div>
                  <LoaderCircle className="mt-1 size-5 animate-spin text-muted-foreground" aria-hidden="true" />
                </div>
                <div className="mt-7">
                  <Stepper value={currentStage} className="w-full" indicators={{ completed: <Check className="size-3.5" />, loading: <LoaderCircle className="size-3.5 animate-spin" /> }}>
                    <StepperNav className="mb-5">
                      {[1, 2, 3].map((step) => (
                        <StepperItem key={step} step={step} loading={step === currentStage}>
                          <StepperTrigger type="button" tabIndex={-1} aria-label={`Analysis step ${step}`} className="cursor-default">
                            <StepperIndicator className="size-7 border-2 border-muted bg-card text-muted-foreground data-[state=active]:border-primary data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=completed]:border-primary data-[state=completed]:bg-primary data-[state=completed]:text-primary-foreground">{step}</StepperIndicator>
                          </StepperTrigger>
                          {step < 3 && <StepperSeparator className="mx-2 h-0.5 data-[state=completed]:bg-primary" />}
                        </StepperItem>
                      ))}
                    </StepperNav>
                  </Stepper>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <span className={currentStage >= 1 ? 'font-medium text-foreground' : 'text-muted-foreground'}>Request accepted</span>
                    <span className={`text-center ${currentStage >= 2 ? 'font-medium text-foreground' : 'text-muted-foreground'}`}>Isolated checks</span>
                    <span className={`text-right ${currentStage >= 3 ? 'font-medium text-foreground' : 'text-muted-foreground'}`}>Building report</span>
                  </div>
                </div>
                <div className="mt-5 rounded-lg border border-border bg-muted/30 px-4 py-3">
                  <p className="text-sm font-medium" data-testid="text-progress-message">{progressMessage}</p>
                    <p className="mt-1 text-xs text-muted-foreground">{progress ? `${progress.completedSteps} of ${progress.totalSteps} plan steps resolved` : 'Waiting for the scan service to publish its execution plan.'}</p>
                  {streamError && <p className="mt-2 text-xs text-muted-foreground" data-testid="status-stream-recovery">{streamError}</p>}
                </div>
                  {progress?.plan && <ExecutionPlanList steps={progress.plan} testId="live-execution-plan" type={scanType} />}
                {scanQuery.isError && <p className="mt-3 text-sm text-muted-foreground">Unable to recover the latest status. Waiting for the live scan stream.</p>}
              </div>
            ) : activeReport ? (
              <ReportView report={activeReport} onExport={exportReport} emailLinks={emailLinks}
                selectedLinkId={selectedLinkId} setSelectedLinkId={(id) => { setSelectedLinkId(id); setLinkConsent(false); setFormError(''); }}
                linkConsent={linkConsent} setLinkConsent={setLinkConsent} onScanLink={scanSelectedLink}
                selectedLinkPending={createSelectedLink.isPending} />
            ) : streamError ? (
              <div className="rounded-xl border border-border bg-card p-6 shadow-sm" role="status" data-testid="status-analysis-unavailable">
                <div className="flex size-10 items-center justify-center rounded-full bg-muted"><CircleAlert className="size-5 text-muted-foreground" aria-hidden="true" /></div>
                <h2 className="mt-4 text-lg font-semibold">No report available</h2>
                <p className="mt-1 text-sm leading-6 text-muted-foreground">{streamError}</p>
                {scanAccepted && <p className="mt-3 break-all font-mono text-xs text-muted-foreground">Scan reference: {scanAccepted.scanId}</p>}
              </div>
            ) : (
              <div className="rounded-xl border border-border bg-card shadow-sm">
                <div className="border-b border-border px-5 py-5 sm:px-6">
                  <p className="text-xs font-semibold uppercase tracking-[0.13em] text-muted-foreground">Evidence report</p>
                  <h2 className="mt-1 text-xl font-semibold tracking-tight">Your findings appear here</h2>
                </div>
                <div className="flex min-h-56 flex-col items-center justify-center px-6 py-10 text-center">
                  <div className="flex size-12 items-center justify-center rounded-xl border border-border bg-muted/50"><ShieldCheck className="size-5 text-muted-foreground" aria-hidden="true" /></div>
                  <p className="mt-4 max-w-sm text-sm leading-6 text-muted-foreground">Submit a URL or email with consent to receive an evidence-backed report. Nothing is inferred until the analyzer returns results.</p>
                </div>
              </div>
            )}
          </section>
        </div>

        {status?.queue && (
          <p className="mt-5 text-center text-xs text-muted-foreground" data-testid="text-queue-status">
            Queue status · {status.queue.active} active of {status.queue.activeLimit} · {status.queue.queued} waiting of {status.queue.queuedLimit}
          </p>
        )}
        <footer className="mt-10 flex flex-col justify-between gap-2 border-t border-border pt-5 text-xs text-muted-foreground sm:flex-row">
          <span>Veridict reports evidence, not certainty.</span>
          <span>Reports and email content are not stored. One-way IP/browser counters are retained to enforce scan limits.</span>
        </footer>
      </main>
    </div>
  );
}

function ReportView({
  report,
  onExport,
  emailLinks,
  selectedLinkId,
  setSelectedLinkId,
  linkConsent,
  setLinkConsent,
  onScanLink,
  selectedLinkPending,
}: {
  report: ScanReport;
  onExport: () => void;
  emailLinks: NonNullable<ScanReport['links']>;
  selectedLinkId: string;
  setSelectedLinkId: (id: string) => void;
  linkConsent: boolean;
  setLinkConsent: (consent: boolean) => void;
  onScanLink: () => void;
  selectedLinkPending: boolean;
}) {
  const riskColor = report.riskBand === 'critical' || report.riskBand === 'high'
    ? 'border-destructive/30 bg-destructive/5 text-destructive'
    : report.riskBand === 'moderate'
      ? 'border-border bg-muted/60 text-foreground'
      : report.riskBand === 'low'
        ? 'border-border bg-background text-foreground'
        : 'border-border bg-muted/30 text-muted-foreground';
  const attachments = report.findings.filter((finding) => finding.source === 'attachment_metadata');
  return (
    <article id="veridict-print-report" className="overflow-hidden rounded-xl border border-border bg-card shadow-sm" data-testid="report-analysis">
      <header className="border-b border-border px-5 py-5 sm:px-6">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.13em] text-muted-foreground">Evidence report</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <h2 className="text-xl font-semibold tracking-tight">Analysis complete</h2>
              <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${riskColor}`} data-testid="status-risk-band">
                {riskLabel(report.riskBand)}
              </span>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">Completed {formatDate(report.completedAt)} · Ruleset {report.ruleSetVersion}</p>
          </div>
          <div className="flex gap-2 print:hidden" data-testid="report-actions">
            <button type="button" onClick={onExport} data-testid="button-export-html" className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg border border-input bg-background px-3 text-sm font-medium hover:bg-muted">
              <Download className="size-4" aria-hidden="true" /> Export HTML
            </button>
            <button type="button" onClick={() => window.print()} data-testid="button-print-pdf" className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg bg-primary px-3 text-sm font-medium text-primary-foreground hover:opacity-90">
              <Printer className="size-4" aria-hidden="true" /> Print / PDF
            </button>
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
              <div><h3 id="email-links-title" className="text-sm font-semibold">Links found in this email</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">Displaying up to 50 sanitized links. A separate scan requires a new, explicit consent.</p></div>
              <span className="shrink-0 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground">{emailLinks.length} shown</span>
            </div>
            <div className="mt-3 space-y-2">
              {emailLinks.map((link) => (
                <label key={link.linkId} className={`flex cursor-pointer gap-3 rounded-lg border p-3 transition-colors ${selectedLinkId === link.linkId ? 'border-primary/50 bg-muted/50' : 'border-border hover:bg-muted/30'}`}>
                  <input type="radio" name="email-link-choice" value={link.linkId} checked={selectedLinkId === link.linkId}
                    onChange={() => setSelectedLinkId(link.linkId)} data-testid={`radio-email-link-${link.linkId}`} className="mt-1 size-4 shrink-0 accent-foreground" />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-1 text-sm font-medium">{link.anchorText || link.targetHost}{link.scanAvailable && <ArrowUpRight className="size-3.5 text-muted-foreground" aria-hidden="true" />}</span>
                    <span className="mt-1 block break-all font-mono text-xs text-muted-foreground">{link.displayUrl}</span>
                    <span className="mt-1 block text-xs text-muted-foreground">Destination host: {link.targetHost} · {link.scanAvailable ? 'separate scan available' : 'separate scan unavailable'}</span>
                  </span>
                </label>
              ))}
            </div>
            <label className="mt-3 flex cursor-pointer items-start gap-3 rounded-lg border border-border bg-muted/20 p-3 text-sm leading-5">
              <input type="checkbox" checked={linkConsent} onChange={(event) => setLinkConsent(event.target.checked)}
                data-testid="checkbox-selected-link-consent" className="mt-0.5 size-4 shrink-0 accent-foreground" />
              <span>I separately consent to visit and analyze the selected link in an isolated session.</span>
            </label>
            <button type="button" onClick={onScanLink} disabled={!selectedLinkId || !linkConsent || selectedLinkPending || !emailLinks.find((link) => link.linkId === selectedLinkId)?.scanAvailable}
              data-testid="button-scan-selected-link" className="mt-3 inline-flex min-h-10 w-full items-center justify-center gap-2 rounded-lg border border-input bg-background px-4 text-sm font-medium hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50">
              {selectedLinkPending ? <LoaderCircle className="size-4 animate-spin" aria-hidden="true" /> : <Globe2 className="size-4" aria-hidden="true" />}
              Scan selected link
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
