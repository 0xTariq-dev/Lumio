# Vultr deployment

The app/control plane runs on the app VM as two containers: the React static
site behind the existing Coolify Traefik proxy, and the private Express API.
Untrusted URL analysis stays on the separate Python worker host and runs in a
fresh Microsandbox microVM. Do not publish the API or worker ports directly.

## App host

The Compose project expects:

- `/etc/veridict/api.env` (`0600`, root-owned): `SESSION_SECRET`,
  `DATABASE_URL`, `ANALYSIS_WORKER_URL`, and `ANALYSIS_WORKER_TOKEN`.
- `/etc/veridict/db.env` (`0600`, root-owned): the Postgres administrator
  credentials plus a generated `VERIDICT_APP_PASSWORD`. Only the database
  container receives this file.
- `/etc/veridict/worker-ca.pem` (`0644`, public CA certificate only): the CA
  that issued the worker's private-network TLS certificate.
- `VERIDICT_HOST` in the Compose environment: the public HTTPS hostname.
- `SCAN_QUOTA_LIMITS_ENABLED` is optional and defaults to `true`. Set it to
  `false` in the Coolify Compose environment to disable the per-client daily
  and lifetime caps for testing. The 2-per-minute burst guard, global API
  request limit, and worker queue limits remain active.

When the cap is enabled, the analyzer shows each visitor's daily and lifetime
usage. Each cap allows 15 scans. The counters use HMAC-derived IP and signed
browser identifiers; raw addresses and browser tokens are not stored.

`ANALYSIS_WORKER_URL` must be the worker's private VPC HTTPS URL. The API
container trusts only the mounted CA for that connection. The browser never
receives the worker token or TLS private key.

From this directory, set `VERIDICT_HOST`, then deploy with:

```sh
docker compose -f docker-compose.yml up -d --build
```

The web container attaches to the existing `coolify` Docker network so
Traefik can route HTTPS and request a Let's Encrypt certificate. Only the web
container is reachable through Traefik; the API remains on the app-private
Docker network. PostgreSQL is attached only to an internal database network,
has no published port, and stores the HMAC-derived quota counters on a
persistent Docker volume. It does not store scan reports or submitted content.

Initialize the quota table and restricted API database role after Postgres is
healthy:

```sh
sh deploy/provision-db.sh
```

## Worker host

The Microsandbox supervisor is a systemd host service, not a container. It
requires Python 3.12+, `/dev/kvm`, a digest-pinned guest OCI image, private
VPC HTTPS, and TCP/8001 ingress restricted to the app VM's private address.
Keep per-host token and TLS key material in `/etc/veridict` with restrictive
permissions. Do not copy them into the guest image or its snapshot.

The guest image is built from
`services/veridict-analysis-worker/guest/Dockerfile`; its package lock and
third-party notices are maintained with that service. For this Vultr deployment,
the guest image is preloaded into the dedicated worker account's Microsandbox
cache. `ANALYSIS_GUEST_IMAGE_LOCAL` identifies that cached tag while
`ANALYSIS_GUEST_IMAGE` supplies its expected manifest digest; the service
verifies the digest before every scan and does not pull from a registry.
