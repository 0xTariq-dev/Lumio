# Vultr deployment

The app/control plane runs on the app VM as two containers: the React static
site behind the existing Coolify Traefik proxy, and the private Express API.
Untrusted URL analysis stays on the separate Python worker host and runs in a
fresh Microsandbox microVM. Do not publish the API or worker ports directly.

## App host

The Compose project expects:

- `/etc/veridict/api.env` (`0600`, root-owned): `SESSION_SECRET`,
  `ANALYSIS_WORKER_URL`, and `ANALYSIS_WORKER_TOKEN`.
- `/etc/veridict/worker-ca.pem` (`0644`, public CA certificate only): the CA
  that issued the worker's private-network TLS certificate.
- `VERIDICT_HOST` in the Compose environment: the public HTTPS hostname.

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
Docker network.

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
