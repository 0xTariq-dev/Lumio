from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit


MAX_URL_LENGTH = 2048
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RESERVED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".test",
    ".invalid",
    ".example",
)


class URLPolicyError(ValueError):
    """Raised when a URL is not eligible for public-web analysis."""


def _parse(raw_url: str) -> tuple[SplitResult, str, int | None]:
    if not isinstance(raw_url, str) or not raw_url or len(raw_url) > MAX_URL_LENGTH:
        raise URLPolicyError("URL length is invalid")
    if raw_url != raw_url.strip() or any(ord(char) < 32 for char in raw_url):
        raise URLPolicyError("URL contains whitespace or control characters")

    try:
        parts = urlsplit(raw_url)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise URLPolicyError("URL authority is invalid") from exc

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise URLPolicyError("Only HTTP and HTTPS URLs are supported")
    if not hostname or parts.username is not None or parts.password is not None:
        raise URLPolicyError("URL host is invalid")
    if "%" in hostname:
        raise URLPolicyError("Scoped IP addresses are not supported")

    expected_port = 80 if scheme == "http" else 443
    if port is not None and port != expected_port:
        raise URLPolicyError("Only standard HTTP and HTTPS ports are supported")

    host = hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLPolicyError("URL host is invalid") from exc
        if len(host) > 253 or host.endswith(_RESERVED_SUFFIXES):
            raise URLPolicyError("URL host is not public")
        labels = host.split(".")
        if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise URLPolicyError("URL host is not a public domain")
    else:
        if not address.is_global:
            raise URLPolicyError("URL host is not a public address")

    return parts, host, port


def normalize_public_http_url(raw_url: str) -> str:
    """Validate and normalize an HTTP(S) URL without resolving DNS on the host."""
    parts, host, port = _parse(raw_url)
    scheme = parts.scheme.lower()
    if ":" in host:
        netloc = f"[{host}]"
    else:
        netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit(
        (scheme, netloc, parts.path or "/", parts.query, parts.fragment)
    )
    if len(normalized) > MAX_URL_LENGTH:
        raise URLPolicyError("URL length is invalid")
    return normalized


def sanitized_url(raw_url: str) -> str:
    """Return only a report-safe origin; omit path, query, and fragment."""
    parts, host, port = _parse(raw_url)
    scheme = parts.scheme.lower()
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, "/", "", ""))[:300]


def hostname_for_url(raw_url: str) -> str:
    """Return the normalized host only; never include path or query data."""
    _, host, _ = _parse(raw_url)
    return host[:253]


def same_host(left: str, right: str) -> bool:
    try:
        return hostname_for_url(left) == hostname_for_url(right)
    except URLPolicyError:
        return False
