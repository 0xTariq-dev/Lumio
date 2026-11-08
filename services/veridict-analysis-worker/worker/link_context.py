"""Redacted email-link context for the approval-gated agent step.

Only host, path, and anchor text are exposed. Query strings, fragments,
credentials, ports, and secret-like path segments are removed so tokenized
links never reach a model. All values are untrusted data, never instructions.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlsplit

MAX_LINKS = 50
MAX_PATH_SEGMENTS = 6
MAX_SEGMENT_CHARS = 40
MAX_ANCHOR_CHARS = 80
REDACTED = "[redacted]"

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
_SECRET_LIKE = re.compile(r"^[A-Za-z0-9_\-+=%.]{20,}$")
_HAS_DIGIT_AND_LETTER = re.compile(r"(?=.*\d)(?=.*[A-Za-z])")
_LONG_NUMBER = re.compile(r"^\d{6,}$")
_EMAIL_LIKE = re.compile(r"[^@\s/]+@[^@\s/]+")


def _clean_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = _CONTROL_CHARS.sub(" ", value)
    text = re.sub(r"\s+", " ", text).strip()
    text = _EMAIL_LIKE.sub(REDACTED, text)
    return text[:limit]


def _redact_segment(segment: str) -> str:
    decoded = unquote(segment)
    if not decoded:
        return ""
    if _EMAIL_LIKE.search(decoded):
        return REDACTED
    if _LONG_NUMBER.match(decoded):
        return REDACTED
    if _SECRET_LIKE.match(decoded) and (
        _HAS_DIGIT_AND_LETTER.match(decoded) or len(decoded) >= 32
    ):
        return REDACTED
    cleaned = _CONTROL_CHARS.sub("", decoded)
    return cleaned[:MAX_SEGMENT_CHARS]


def redact_link_path(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return "/"
    segments = [segment for segment in parts.path.split("/") if segment]
    redacted = [_redact_segment(segment) for segment in segments[:MAX_PATH_SEGMENTS]]
    suffix = "/..." if len(segments) > MAX_PATH_SEGMENTS else ""
    return "/" + "/".join(redacted) + suffix if redacted else "/"


def build_link_context(
    public_links: Any,
    private_links: Any,
) -> list[dict[str, str]]:
    """Return bounded host/path/anchor metadata for scan-available links."""
    if not isinstance(public_links, list) or not isinstance(private_links, dict):
        return []
    context: list[dict[str, str]] = []
    for link in public_links[:MAX_LINKS]:
        if not isinstance(link, dict):
            continue
        link_id = link.get("linkId")
        raw_url = private_links.get(link_id) if isinstance(link_id, str) else None
        if not isinstance(raw_url, str):
            continue
        try:
            host = urlsplit(raw_url).hostname
        except ValueError:
            continue
        if not host:
            continue
        context.append(
            {
                "linkId": str(link_id),
                "host": host.lower()[:253],
                "path": redact_link_path(raw_url),
                "anchor": _clean_text(link.get("anchorText"), MAX_ANCHOR_CHARS),
            }
        )
    return context
