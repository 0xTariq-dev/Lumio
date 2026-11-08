from __future__ import annotations

import ipaddress
import os
from pathlib import Path

import uvicorn

from .app import app


def main() -> None:
    cert_path = os.getenv("ANALYSIS_WORKER_TLS_CERT")
    key_path = os.getenv("ANALYSIS_WORKER_TLS_KEY")
    if not cert_path or not key_path:
        raise SystemExit("Worker TLS certificate and key paths are required")
    if not Path(cert_path).is_file() or not Path(key_path).is_file():
        raise SystemExit("Worker TLS certificate or key file is unavailable")

    bind_host = os.getenv("ANALYSIS_WORKER_BIND_HOST")
    if not bind_host:
        raise SystemExit("ANALYSIS_WORKER_BIND_HOST is required")
    try:
        bind_address = ipaddress.ip_address(bind_host)
    except ValueError as exc:
        raise SystemExit("Worker bind host must be a private-network IP address") from exc
    if not bind_address.is_private or bind_address.is_loopback or bind_address.is_link_local:
        raise SystemExit("Worker bind host must be a private-network IP address")

    try:
        port = int(os.getenv("ANALYSIS_WORKER_PORT", "8001"))
    except ValueError as exc:
        raise SystemExit("ANALYSIS_WORKER_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("ANALYSIS_WORKER_PORT is out of range")

    uvicorn.run(
        app,
        host=bind_host,
        port=port,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
        access_log=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()

__all__ = ["app"]
