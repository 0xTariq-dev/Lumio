# Veridict analysis worker

This Python 3.12 service is the private control-plane endpoint for URL and
`.eml` scans. It keeps the React/TypeScript application and API server separate
from analysis. URL scans and consented email-link scans run in new, disposable
Microsandbox VMs; `.eml` parsing runs in a fresh guest with networking disabled.
The worker host itself must have working KVM support.

Veridict's own code is licensed under MIT; see the repository `LICENSE`.
Third-party package licenses, including the worker's unmodified MPL-2.0
`certifi` dependency, are listed in `THIRD_PARTY_NOTICES.md`.

## Current scope

- Public HTTP(S) URL scans and `.eml` scans. Email parsing runs in a no-network
  guest. It extracts transient message evidence and attachment metadata only;
  it does not fetch, unpack, or execute attachments.
- `.eml` files are limited to 10 MiB. The API request body limit is 15 MiB to
  allow for base64 transport. Up to 50 safe public links may be listed, but a
  link is scanned only after the user selects it and gives separate consent.
  Each selected link is analyzed in a new URL sandbox.
- One active scan and up to ten queued scans; new work is rejected when the
  queue is full.
- URL inputs must be public HTTP(S), use the standard port, and contain no
  credentials.
- Static inspection uses Scrapling's HTTP Fetcher without TLS impersonation,
  stealth headers, retries, or proxy rotation. It uses a plain Veridict
  User-Agent and follows redirects manually so each redirect is revalidated.
- The submitted URL, including its query, is sent to the intended site for the
  consented static fetch. The Playwright browser starts with query and fragment
  removed, and strips them from every allowed browser request. If that changes a
  script-driven scan, coverage is marked insufficient and the report is
  Inconclusive.
- Browser navigation uses plain Playwright, performs no clicks or form
  submissions, rejects non-read methods, blocks images/fonts/media, and caps
  page requests. It records metadata and counts only; page text, error messages,
  raw form values, cookies, and response bodies are not placed in reports.
- Reports omit URL paths, queries, and fragments. Raw email content and
  addresses are transient processing inputs, not report fields or log data.
  Reports are held in worker memory for 15 minutes and are not written to a
  database or filesystem.
- The worker passes the scan input to the guest over process stdin instead of
  writing it to a guest file. Guest VMs are disposable and receive no secrets.
- URL guests may use DNS and public TCP ports 80 and 443 only; private,
  loopback, host, metadata, and other ports are denied by default. Email parser
  guests have no network access.
- The worker uses a 1-vCPU, 2-GiB guest limit by default, a 90-second browser
  timeout, and a 180-second hard VM lifetime. Scrapling's response-size check is
  post-download: its high-level API does not expose a usable bounded body stream.
  The VM memory limit is containment, not a precise network byte cap.

Scrapling 0.5.1 imports Patchright and BrowserForge even for its static Fetcher.
The worker installs these pinned dependencies to satisfy those imports, but
never invokes Scrapling's browser fetcher or Patchright; JavaScript pages use
the separately installed plain Playwright package. The static Fetcher still
uses BrowserForge's default User-Agent unless explicitly overridden, so the
worker sets its own User-Agent and suppresses Scrapling URL-bearing logs.

## Host setup

1. Build the guest image on a trusted Docker-enabled build host, not on the
   worker VM:

   ```sh
   docker build -f guest/Dockerfile -t veridict-analysis-guest:<release-tag> .
   docker save -o /tmp/veridict-analysis-guest.tar veridict-analysis-guest:<release-tag>
   ```

2. Transfer the archive to the worker over a trusted channel, then import it
   into the `veridict-worker` account's Microsandbox image cache:

   ```sh
   sudo -u veridict-worker env HOME=/var/lib/veridict-worker \
     /opt/veridict/.venv/bin/msb image load \
     --input /path/to/veridict-analysis-guest.tar \
     --tag veridict-analysis-guest:<release-tag>
   ```

3. Inspect the imported image and configure its full digest, retaining the
   local tag for `PullPolicy.NEVER`:

   ```text
   ANALYSIS_GUEST_IMAGE=veridict-analysis-guest@sha256:<full-digest>
   ANALYSIS_GUEST_IMAGE_LOCAL=veridict-analysis-guest:<release-tag>
   ```

4. Install the host Python dependencies with the workspace's locked
   `pyproject.toml`/`uv.lock` in `/opt/veridict/.venv`.
5. Create `/etc/veridict/analysis-worker.env` with restrictive permissions:

   ```text
   ANALYSIS_WORKER_TOKEN=<random value of at least 32 characters>
   ANALYSIS_GUEST_IMAGE=veridict-analysis-guest@sha256:<full-digest>
   ANALYSIS_GUEST_IMAGE_LOCAL=veridict-analysis-guest:<release-tag>
   ANALYSIS_WORKER_BIND_HOST=<worker private-network address>
   ANALYSIS_WORKER_PORT=8001
   ANALYSIS_WORKER_TLS_CERT=/etc/veridict/worker.crt
   ANALYSIS_WORKER_TLS_KEY=/etc/veridict/worker.key
   ```

   Provision the certificate from a private CA for the worker's private DNS
   name, grant the service account read access to the key, and configure the
   API host to trust that CA (for Node.js, for example, with
   `NODE_EXTRA_CA_CERTS`). Keep the token and private key in the hosts' secret
   management flow; do not commit them or pass the token into a guest.
6. Install `deploy/veridict-analysis-worker.service`, create the
   `veridict-worker` account with access to `/dev/kvm`, then enable the service.
7. Restrict TCP port 8001 at the Vultr firewall and host firewall to the API
   server's private address. Use the private HTTPS endpoint from the API host.
   Do not expose the worker publicly. A single
   Coolify controller may deploy the application, but the Microsandbox
   supervisor remains a host service.

When `ANALYSIS_GUEST_IMAGE_LOCAL` is set, the service checks the local image's
manifest digest against `ANALYSIS_GUEST_IMAGE` at startup and before each scan,
then uses the cached image with `PullPolicy.NEVER`. Without that setting, it
pre-pulls the digest-pinned image at startup. Health remains unavailable until
configuration, KVM access, and image preparation all succeed.

## Local checks

From the repository root:

```sh
PYTHONPATH=services/veridict-analysis-worker \
  python -m unittest discover -s services/veridict-analysis-worker/tests -v
```

These tests use a fake analyzer and local HTTP fixtures. They do not boot
Microsandbox. This Replit environment has no `/dev/kvm`, so real VM isolation,
egress enforcement, Chromium behavior, image pulling, and the host service must
be smoke-tested on the Vultr worker VM.
