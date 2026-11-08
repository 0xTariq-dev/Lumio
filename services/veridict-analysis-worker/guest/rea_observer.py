from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any
from urllib.parse import urlsplit

from shared.url_policy import URLPolicyError, hostname_for_url, normalize_public_http_url

CDP_ENDPOINT = "http://127.0.0.1:9222"
REA_NODE = "/usr/local/bin/node"
REA_ENTRYPOINT = os.environ.get(
    "REA_ENTRYPOINT",
    "/opt/rea-runtime/node_modules/rea-agents/scripts/rea.mjs",
)
REA_PROCESS_TIMEOUT_SECONDS = 12
REA_COMMAND_TIMEOUT_MS = 8_000
REA_STDOUT_LIMIT_BYTES = 1_500_000
REA_MAX_SUMMARY_COUNT = 100_000
_TARGET_ID = re.compile(r"^[A-Za-z0-9._-]{1,256}$")
_COMPLETENESS = {
    "complete_within_window",
    "policy_filtered",
    "attach_limited",
    "truncated",
}


def _origin_url(raw_url: str) -> str:
    normalized = normalize_public_http_url(raw_url)
    parts = urlsplit(normalized)
    host = hostname_for_url(normalized)
    authority = f"[{host}]" if ":" in host else host
    default_port = 443 if parts.scheme == "https" else 80
    if parts.port and parts.port != default_port:
        authority = f"{authority}:{parts.port}"
    return f"{parts.scheme}://{authority}"


def _count(section: Any, total_keys: tuple[str, ...], array_keys: tuple[str, ...]) -> int | None:
    if isinstance(section, list):
        return min(len(section), REA_MAX_SUMMARY_COUNT)
    if not isinstance(section, dict):
        return None
    for key in total_keys:
        value = section.get(key)
        if type(value) is int and 0 <= value <= 2**53 - 1:
            return min(value, REA_MAX_SUMMARY_COUNT)
    for key in array_keys:
        value = section.get(key)
        if isinstance(value, list):
            return min(len(value), REA_MAX_SUMMARY_COUNT)
    return None


def _inspection_summary(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    normalized = payload.get("normalized_result")
    if not isinstance(normalized, dict):
        return None

    completeness = None
    completeness_record = normalized.get("completeness")
    if isinstance(completeness_record, dict):
        candidate = completeness_record.get("status")
        if isinstance(candidate, str) and candidate in _COMPLETENESS:
            completeness = candidate

    counts: dict[str, int] = {}
    sections = (
        ("frames", "frames", ("total",), ("items", "frames")),
        ("domNodes", "dom", ("total_nodes", "total"), ("nodes", "items")),
        (
            "accessibilityNodes",
            "accessibility",
            ("total_nodes", "total"),
            ("nodes", "items"),
        ),
        ("scripts", "scripts", ("total",), ("items", "scripts")),
        ("resources", "resources", ("total",), ("items", "resources")),
        (
            "networkRequests",
            "network",
            ("total_requests", "request_count", "total"),
            ("requests", "items"),
        ),
        (
            "consoleEvents",
            "console",
            ("total", "event_count"),
            ("events", "entries", "items"),
        ),
        (
            "websocketEvents",
            "websockets",
            ("total_frames", "frame_count", "total"),
            ("frames", "events", "items"),
        ),
        ("workers", "workers", ("total",), ("items", "workers")),
    )
    for output_name, section_name, total_keys, array_keys in sections:
        value = _count(normalized.get(section_name), total_keys, array_keys)
        if value is not None:
            counts[output_name] = value

    summary: dict[str, Any] = {"status": "completed", "counts": counts}
    if completeness:
        summary["completeness"] = completeness
    return summary


async def _kill_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        process.kill()
    except ProcessLookupError:
        pass
    await process.wait()


async def _run_rea_cli(args: list[str]) -> tuple[dict[str, Any] | None, str | None]:
    try:
        process = await asyncio.create_subprocess_exec(
            REA_NODE,
            REA_ENTRYPOINT,
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            cwd="/",
            env={
                "HOME": "/tmp",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "NODE_OPTIONS": "--max-old-space-size=256",
            },
        )
    except OSError:
        return None, "rea_runtime_unavailable"

    assert process.stdout is not None
    output = bytearray()
    try:
        async with asyncio.timeout(REA_PROCESS_TIMEOUT_SECONDS):
            while True:
                remaining = REA_STDOUT_LIMIT_BYTES + 1 - len(output)
                chunk = await process.stdout.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > REA_STDOUT_LIMIT_BYTES:
                    await _kill_process(process)
                    return None, "rea_output_limit"
            exit_code = await process.wait()
    except TimeoutError:
        await _kill_process(process)
        return None, "rea_timeout"
    except asyncio.CancelledError:
        await _kill_process(process)
        raise
    except Exception:
        await _kill_process(process)
        return None, "rea_process_error"

    if exit_code != 0:
        return None, "rea_command_failed"
    try:
        result = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "rea_invalid_json"
    if not isinstance(result, dict):
        return None, "rea_invalid_result"
    return result, None


async def observe_browser(raw_page_url: str) -> dict[str, Any]:
    try:
        origin = _origin_url(raw_page_url)
    except (URLPolicyError, ValueError):
        return {"status": "unavailable", "reasonCode": "invalid_origin"}

    targets_result, error = await _run_rea_cli(
        [
            "list-browser-targets",
            CDP_ENDPOINT,
            "--allowed-origins",
            origin,
            "--format",
            "json",
        ]
    )
    if error:
        return {"status": "unavailable", "reasonCode": error}
    targets_record = targets_result.get("normalized_result")
    targets = targets_record.get("targets") if isinstance(targets_record, dict) else None
    if not isinstance(targets, list):
        return {"status": "unavailable", "reasonCode": "rea_invalid_result"}

    candidates = [
        item
        for item in targets
        if isinstance(item, dict)
        and item.get("type") == "page"
        and item.get("origin") == origin
        and isinstance(item.get("target_id"), str)
        and _TARGET_ID.fullmatch(item["target_id"])
    ]
    if len(candidates) != 1:
        return {"status": "unavailable", "reasonCode": "rea_target_not_unique"}

    inspect_result, error = await _run_rea_cli(
        [
            "inspect-web-page",
            CDP_ENDPOINT,
            candidates[0]["target_id"],
            "--allowed-origins",
            origin,
            "--observation-ms",
            "0",
            "--command-timeout-ms",
            str(REA_COMMAND_TIMEOUT_MS),
            "--format",
            "json",
        ]
    )
    if error:
        return {"status": "unavailable", "reasonCode": error}

    summary = _inspection_summary(inspect_result)
    if summary is None:
        return {"status": "unavailable", "reasonCode": "rea_invalid_result"}
    return summary
