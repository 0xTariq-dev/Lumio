# Lumio

**Bringing threats to light.** Lumio is a consent-based analyzer for suspicious
URLs and email. It reports observable evidence and coverage limits; it does not
promise that a URL or message is safe.

**Live demo:** [Lumio](https://45.77.201.163.sslip.io)

## What Lumio does

- Analyzes a URL or an uploaded `.eml` message after the user gives consent.
- Shows evidence, a deterministic risk band, and which checks completed or
  were unavailable.
- Extracts links from an email without visiting them. A link is scanned only
  after the user selects it and gives separate consent.
- Offers an optional, separately consented explanation of a report. The
  explanation does not change the deterministic risk band.

Lumio does not click page controls, submit forms, or take remediation actions.
Reports describe observed signals and may be incomplete; use other trusted
checks for important decisions.

## Data handling

- Submitted email and URL content is processed transiently by the analysis
  service. Raw email content and addresses are not report fields or log data.
- URL reports omit paths, queries, and fragments. Reports stay in worker memory
  for up to 15 minutes and are not written to the database or filesystem.
- The database stores HMAC-derived abuse-quota counters, not raw IP addresses
  or scan reports. The current per-client limits are 15 scans per day and 15
  lifetime scans, with a separate per-minute burst limit.
- Email analysis runs without network access. URL analysis runs in a disposable
  Microsandbox microVM and allows DNS plus public HTTP and HTTPS only.
- If a user opts in to an AI explanation, Lumio sends Vultr a short, redacted
  evidence summary—not the raw email, full URL, or email link list. Vultr's
  prompt-retention and model-training terms have not been verified. The
  explanation may be wrong and does not change the report.

## Architecture

- **Web app:** React and Vite.
- **API:** Express and PostgreSQL; the database is used for quota counters,
  not scan reports.
- **Analysis worker:** a separate Python service on a Vultr VM. Each analysis
  runs in a disposable KVM-backed Microsandbox guest. The API reaches the
  worker over authenticated private TLS; the worker is not a public endpoint.
- **URL analysis:** the guest may access public web ports 80 and 443 only.
- **Email analysis:** the guest has no network access.

## Local development

Requirements: Node.js 24, pnpm, and Python 3.12+ for worker tests.

```sh
pnpm install --frozen-lockfile
pnpm run typecheck
```

Run the API and web app in separate terminals:

```sh
pnpm --filter @workspace/api-server run dev
```

```sh
pnpm --filter @workspace/veridict run dev
```

The API requires its database and worker environment to be configured. See
[`deploy/README.md`](deploy/README.md) before attempting a full local analysis.
Do not put credentials in source files or submit them as scan content.

Run the worker unit tests from the repository root after installing its Python
dependencies as described in the worker guide:

```sh
PYTHONPATH=services/veridict-analysis-worker \
  python -m unittest discover -s services/veridict-analysis-worker/tests -v
```

These worker tests use a fake analyzer and local fixtures; they do not boot
Microsandbox. The Replit development environment does not expose `/dev/kvm`, so
real guest-isolation and egress checks must be performed on the worker host.

## Deployment guides

- [Vultr app and worker deployment](deploy/README.md)
- [Analysis worker setup and security boundaries](services/veridict-analysis-worker/README.md)

## License

This project is licensed under the [MIT License](LICENSE).
