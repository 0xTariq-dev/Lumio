from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from playwright.async_api import async_playwright
from scrapling.core.utils import log as scrapling_log
from scrapling.fetchers import FetcherSession

from guest.rea_observer import observe_browser
from shared.url_policy import (
    URLPolicyError,
    hostname_for_url,
    normalize_public_http_url,
)

MAX_STATIC_BODY_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 10
MAX_BROWSER_REQUESTS = 100
MAX_BROWSER_TIMEOUT_SECONDS = 90
MAX_EVIDENCE_HOSTS = 25
MAX_FINDINGS = 50
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
NON_GET_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
RULE_SET_VERSION = "veridict-url-rules-2026-11-06"
EXPECTED_TASK_PLAN = ("http", "static", "browser", "report")

scrapling_log.setLevel(logging.CRITICAL + 1)


def emit(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":"), ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


def _clean_text(value: Any, limit: int = 200) -> str:
    if not isinstance(value, str):
        return ""
    normalized = re.sub(r"[\x00-\x1f\x7f]+", " ", value)
    normalized = " ".join(normalized.split())
    return normalized[:limit]


def _header(headers: Any, name: str) -> str:
    if not hasattr(headers, "items"):
        return ""
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _status(response: Any) -> int:
    value = getattr(response, "status", None)
    if value is None:
        value = getattr(response, "status_code", 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _browser_url(raw_url: str) -> str:
    """Drop query and fragment before handing a URL to page JavaScript."""
    normalized = normalize_public_http_url(raw_url)
    parts = urlsplit(normalized)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _redact_browser_request_url(raw_url: str) -> tuple[str, bool]:
    normalized = normalize_public_http_url(raw_url)
    redacted = _browser_url(normalized)
    return redacted, redacted != normalized


def _bounded_browser_timeout_seconds(value: Any) -> int:
    return min(MAX_BROWSER_TIMEOUT_SECONDS, max(1, int(value)))


def _origin(raw_url: str) -> tuple[str, str, int]:
    parts = urlsplit(normalize_public_http_url(raw_url))
    host = hostname_for_url(raw_url)
    default_port = 443 if parts.scheme == "https" else 80
    return parts.scheme, host, parts.port or default_port


def _same_origin(left: str, right: str) -> bool:
    try:
        return _origin(left) == _origin(right)
    except URLPolicyError:
        return False


def _safe_host(raw_url: str, base_url: str) -> str | None:
    try:
        return hostname_for_url(normalize_public_http_url(urljoin(base_url, raw_url)))
    except (URLPolicyError, ValueError):
        return None


def _static_fetch(raw_url: str) -> tuple[Any, list[str], bool, str]:
    current_url = normalize_public_http_url(raw_url)
    redirect_urls = [current_url]
    redirect_blocked = False

    with FetcherSession(
        impersonate=None,
        stealthy_headers=False,
        retries=0,
        timeout=30,
        follow_redirects=False,
        max_redirects=MAX_REDIRECTS,
        proxy=None,
        headers={"User-Agent": "Veridict URL Scanner/0.1"},
    ) as fetcher:
        for redirect_index in range(MAX_REDIRECTS + 1):
            response = fetcher.get(
                current_url,
                timeout=30,
                follow_redirects=False,
                max_redirects=MAX_REDIRECTS,
            )
            status = _status(response)
            location = _header(response.headers, "location")
            if status not in REDIRECT_STATUSES or not location:
                return response, redirect_urls, redirect_blocked, current_url
            if redirect_index >= MAX_REDIRECTS:
                return response, redirect_urls, True, current_url
            try:
                next_url = normalize_public_http_url(urljoin(current_url, location))
            except (URLPolicyError, ValueError):
                return response, redirect_urls, True, current_url
            redirect_urls.append(next_url)
            current_url = next_url

    return None, redirect_urls, True, current_url


def _static_evidence(response: Any, final_url: str) -> dict[str, Any]:
    headers = response.headers
    content_type = _header(headers, "content-type").split(";", 1)[0].strip().lower()
    body = getattr(response, "body", b"")
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    if not isinstance(body, bytes):
        body = b""

    evidence: dict[str, Any] = {
        "status": _status(response),
        "contentType": content_type[:100],
        "bodyBytes": len(body),
        "titlePresent": False,
        "scriptCount": 0,
        "scriptHosts": [],
        "linkCount": 0,
        "linkHosts": [],
        "forms": [],
        "isHtml": content_type in {"text/html", "application/xhtml+xml"},
        "oversized": len(body) > MAX_STATIC_BODY_BYTES,
    }
    if not evidence["isHtml"] or evidence["oversized"]:
        return evidence

    title = response.css("title::text").get()
    evidence["titlePresent"] = bool(_clean_text(title, 500))
    evidence["scriptCount"] = len(response.css("script"))

    script_hosts: set[str] = set()
    for source in response.css("script::attr(src)").getall()[:100]:
        host = _safe_host(source, final_url)
        if host:
            script_hosts.add(host)
    evidence["scriptHosts"] = sorted(script_hosts)[:MAX_EVIDENCE_HOSTS]

    link_hosts: set[str] = set()
    links = response.css("a::attr(href)").getall()[:500]
    evidence["linkCount"] = len(links)
    for link in links:
        host = _safe_host(link, final_url)
        if host:
            link_hosts.add(host)
    evidence["linkHosts"] = sorted(link_hosts)[:MAX_EVIDENCE_HOSTS]

    forms: list[dict[str, Any]] = []
    for form in response.css("form")[:50]:
        action = form.attrib.get("action", "")
        action_url = urljoin(final_url, action) if action else final_url
        password_fields = len(form.css('input[type="password"]'))
        host = _safe_host(action_url, final_url)
        try:
            action_scheme = urlsplit(normalize_public_http_url(action_url)).scheme
        except (URLPolicyError, ValueError):
            action_scheme = ""
        forms.append(
            {
                "actionHost": host,
                "sameOrigin": bool(host) and _same_origin(final_url, action_url),
                "passwordFields": min(password_fields, 100),
                "https": action_scheme == "https",
            }
        )
    evidence["forms"] = forms
    return evidence


async def _browser_evidence(
    raw_url: str, timeout_seconds: int
) -> tuple[dict[str, Any] | None, str | None]:
    navigation_url = _browser_url(raw_url)
    allowed_requests = 0
    blocked_requests = 0
    skipped_resources = 0
    request_hosts: set[str] = set()
    page_errors = 0
    request_failures = 0
    stripped_browser_query = False

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=9222",
            ],
        )
        try:
            context = await browser.new_context(
                accept_downloads=False,
                service_workers="block",
                java_script_enabled=True,
            )

            async def guard_request(route):
                nonlocal allowed_requests, blocked_requests, skipped_resources
                nonlocal stripped_browser_query
                request = route.request
                try:
                    safe_url = normalize_public_http_url(request.url)
                except (URLPolicyError, ValueError):
                    blocked_requests += 1
                    await route.abort()
                    return

                if request.method.upper() in NON_GET_METHODS:
                    blocked_requests += 1
                    await route.abort()
                    return
                if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                    blocked_requests += 1
                    await route.abort()
                    return
                if allowed_requests >= MAX_BROWSER_REQUESTS:
                    blocked_requests += 1
                    await route.abort()
                    return

                try:
                    host = hostname_for_url(safe_url)
                    request_hosts.add(host)
                except URLPolicyError:
                    blocked_requests += 1
                    await route.abort()
                    return

                if request.resource_type in {"image", "media", "font"}:
                    skipped_resources += 1
                    await route.abort()
                    return

                safe_url, was_redacted = _redact_browser_request_url(safe_url)
                if was_redacted:
                    stripped_browser_query = True

                allowed_requests += 1
                await route.continue_(url=safe_url)

            await context.route("**/*", guard_request)
            page = await context.new_page()

            def _increment(name: str) -> None:
                nonlocal page_errors, request_failures
                if name == "page_errors":
                    page_errors += 1
                elif name == "request_failures":
                    request_failures += 1

            page.on("pageerror", lambda _error: _increment("page_errors"))
            page.on("requestfailed", lambda _request: _increment("request_failures"))

            response = await page.goto(
                navigation_url,
                wait_until="domcontentloaded",
                timeout=max(1, timeout_seconds) * 1000,
            )
            snapshot = await page.evaluate(
                """() => ({
                  titlePresent: Boolean(document.title && document.title.trim()),
                  forms: Array.from(document.forms).slice(0, 50).map((form) => ({
                    action: form.getAttribute("action") || "",
                    passwordFields: Math.min(form.querySelectorAll('input[type="password"]').length, 100)
                  }))
                })"""
            )
            final_url = page.url
            forms: list[dict[str, Any]] = []
            for form in snapshot.get("forms", []):
                action_url = urljoin(final_url, form.get("action") or final_url)
                host = _safe_host(action_url, final_url)
                try:
                    action_https = (
                        urlsplit(normalize_public_http_url(action_url)).scheme == "https"
                    )
                except (URLPolicyError, ValueError):
                    action_https = False
                forms.append(
                    {
                        "actionHost": host,
                        "sameOrigin": bool(host) and _same_origin(final_url, action_url),
                        "passwordFields": min(
                            int(form.get("passwordFields", 0)), 100
                        ),
                        "https": action_https,
                    }
                )

            rea_observation = await observe_browser(final_url)
            return (
                {
                    "status": response.status if response else 0,
                    "finalHost": hostname_for_url(final_url),
                    "finalScheme": urlsplit(final_url).scheme,
                    "titlePresent": bool(snapshot.get("titlePresent")),
                    "forms": forms,
                    "requestHostCount": len(request_hosts),
                    "blockedRequestCount": blocked_requests,
                    "skippedResourceCount": skipped_resources,
                    "pageErrorCount": page_errors,
                    "requestFailureCount": request_failures,
                    "strippedBrowserQuery": stripped_browser_query,
                    "reaObservation": rea_observation,
                },
                None,
            )
        finally:
            await browser.close()


def _finding(
    finding_id: str,
    title: str,
    explanation: str,
    severity: str,
    strength: str,
    source: str,
    observed: str | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": finding_id,
        "title": title,
        "explanation": explanation,
        "severity": severity,
        "strength": strength,
        "source": source,
    }
    if observed:
        result["sanitizedObservedValue"] = _clean_text(observed, 300)
    if limitations:
        result["limitations"] = [
            _clean_text(item, 160) for item in limitations[:10]
        ]
    return result


def _build_report(
    scan_id: str,
    raw_url: str,
    static: dict[str, Any] | None,
    redirect_urls: list[str],
    redirect_blocked: bool,
    browser: dict[str, Any] | None,
    browser_failed: bool,
    fetch_failed: bool,
    *,
    query_redacted_for_browser: bool,
    static_final_url: str,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    initial_url = normalize_public_http_url(raw_url)
    initial_host = hostname_for_url(initial_url)
    needs_browser = False
    redirect_hosts = [
        hostname_for_url(item) for item in redirect_urls if item
    ] or [initial_host]
    if browser and browser.get("finalHost"):
        browser_final_host = str(browser["finalHost"])
        if browser_final_host not in redirect_hosts:
            redirect_hosts.append(browser_final_host)
    final_host = (
        str(browser.get("finalHost"))
        if browser and browser.get("finalHost")
        else hostname_for_url(static_final_url)
    )
    initial_scheme = urlsplit(initial_url).scheme
    final_scheme = (
        str(browser.get("finalScheme"))
        if browser and browser.get("finalScheme")
        else urlsplit(static_final_url).scheme
    )

    if fetch_failed:
        checks.extend(
            [
                {
                    "name": "http_response",
                    "status": "failed",
                    "reason": "The page could not be fetched safely.",
                },
                {
                    "name": "redirect_chain",
                    "status": "skipped",
                    "reason": "No response was available.",
                },
                {
                    "name": "static_html",
                    "status": "skipped",
                    "reason": "No response was available.",
                },
                {
                    "name": "browser_observation",
                    "status": "skipped",
                    "reason": "Static inspection did not produce a page.",
                },
            ]
        )
    else:
        checks.append(
            {
                "name": "http_response",
                "status": "completed",
                "reason": None,
            }
        )
        checks.append(
            {
                "name": "redirect_chain",
                "status": "blocked" if redirect_blocked else "completed",
                "reason": (
                    "A redirect target was outside the supported public HTTP(S) policy."
                    if redirect_blocked
                    else None
                ),
            }
        )
        if not static or not static.get("isHtml"):
            checks.append(
                {
                    "name": "static_html",
                    "status": "skipped",
                    "reason": "The response was not supported HTML.",
                }
            )
        elif static.get("oversized"):
            checks.append(
                {
                    "name": "static_html",
                    "status": "blocked",
                    "reason": "The response exceeded the parser size limit.",
                }
            )
        else:
            checks.append(
                {
                    "name": "static_html",
                    "status": "completed",
                    "reason": None,
                }
            )

        needs_browser = bool(static and static.get("scriptCount", 0) > 0)
        if not needs_browser:
            checks.append(
                {
                    "name": "browser_observation",
                    "status": "skipped",
                    "reason": "No page scripts were detected in static HTML.",
                }
            )
        elif browser_failed or browser is None:
            checks.append(
                {
                    "name": "browser_observation",
                    "status": "failed",
                    "reason": "The browser did not finish within its safety limits.",
                }
            )
        else:
            checks.append(
                {
                    "name": "browser_observation",
                    "status": "completed",
                    "reason": (
                        "Query and fragment were stripped from browser requests."
                        if query_redacted_for_browser or browser.get("strippedBrowserQuery")
                        else (
                            "Images, fonts, and media were omitted to limit page activity."
                            if browser.get("skippedResourceCount", 0)
                            else None
                        )
                    ),
                }
            )
            if browser.get("blockedRequestCount", 0):
                checks.append(
                    {
                        "name": "browser_request_policy",
                        "status": "blocked",
                        "reason": "Some browser requests were blocked by scan policy.",
                    }
                )
            if query_redacted_for_browser or browser.get("strippedBrowserQuery"):
                checks.append(
                    {
                        "name": "browser_query_policy",
                        "status": "blocked",
                        "reason": "The browser did not receive URL query or fragment data.",
                    }
                )

    if redirect_hosts and len(set(redirect_hosts)) > 1:
        chain = " → ".join(dict.fromkeys(redirect_hosts))[:250]
        findings.append(
            _finding(
                "cross-host-redirect",
                "Cross-host redirect",
                "The URL redirected to a different public host. This can be legitimate, but confirm that the destination is expected.",
                "moderate",
                "contextual",
                "url_navigation",
                chain,
            )
        )

    if initial_scheme == "https" and final_scheme == "http":
        findings.append(
            _finding(
                "https-downgrade",
                "HTTPS downgrade",
                "The inspected page moved from HTTPS to HTTP, so the final connection does not provide HTTPS transport protection.",
                "high",
                "direct",
                "url_navigation",
                f"https://{initial_host} → http://{final_host}",
            )
        )

    form_sources: list[tuple[dict[str, Any], str]] = []
    if static:
        form_sources.extend((form, "url_navigation") for form in static.get("forms", []))
    if browser:
        form_sources.extend((form, "browser") for form in browser.get("forms", []))
    seen_forms: set[tuple[str | None, int, bool]] = set()
    for form, source in form_sources:
        password_fields = int(form.get("passwordFields", 0))
        action_host = form.get("actionHost")
        same_origin = bool(form.get("sameOrigin"))
        action_https = bool(form.get("https"))
        signature = (action_host, password_fields, action_https)
        if not password_fields or signature in seen_forms:
            continue
        seen_forms.add(signature)
        if not action_https:
            findings.append(
                _finding(
                    "password-form-without-https",
                    "Password form without HTTPS",
                    "A password field was observed in a form whose destination is not HTTPS. Do not enter credentials unless you can verify the site and connection.",
                    "high",
                    "direct",
                    source,
                    action_host or "destination not verified",
                )
            )
        elif not same_origin and action_host:
            findings.append(
                _finding(
                    "password-form-cross-origin",
                    "Password form sends to another origin",
                    "A password form submits to a different origin than the page. This can be legitimate, but verify the destination before entering credentials.",
                    "moderate",
                    "direct",
                    source,
                    f"{final_host} → {action_host}",
                )
            )

    if static and static.get("scriptHosts"):
        findings.append(
            _finding(
                "external-script-hosts",
                "External scripts detected",
                "The page loads scripts from public hosts outside the inspected host. This is common, but those scripts can affect page behavior.",
                "informational",
                "contextual",
                "url_navigation",
                ", ".join(static["scriptHosts"][:8]),
            )
        )

    if browser and browser.get("blockedRequestCount", 0):
        findings.append(
            _finding(
                "browser-requests-blocked",
                "Some browser requests were blocked",
                "The sandbox blocked requests that violated the scan's network or request-method policy. The page may not have rendered completely.",
                "informational",
                "direct",
                "browser",
                f"{browser['blockedRequestCount']} request(s)",
            )
        )

    if browser and browser.get("pageErrorCount", 0):
        findings.append(
            _finding(
                "browser-runtime-errors",
                "Browser runtime errors observed",
                "The page produced browser runtime errors. Error text was discarded to avoid retaining page content.",
                "informational",
                "contextual",
                "browser",
                f"{browser['pageErrorCount']} error(s)",
            )
        )

    if static and static.get("status") and static["status"] >= 400:
        findings.append(
            _finding(
                "http-error-status",
                "HTTP error response",
                "The server returned an HTTP error status. This does not by itself indicate malicious behavior.",
                "informational",
                "direct",
                "url_navigation",
                f"HTTP {static['status']}",
            )
        )

    check_statuses = {check["name"]: check["status"] for check in checks}
    sufficient = (
        not fetch_failed
        and not redirect_blocked
        and check_statuses.get("http_response") == "completed"
        and check_statuses.get("redirect_chain") == "completed"
        and check_statuses.get("static_html") == "completed"
    )
    if static and static.get("scriptCount", 0) > 0:
        sufficient = sufficient and check_statuses.get("browser_observation") == "completed"
        sufficient = sufficient and not bool(
            browser and browser.get("blockedRequestCount", 0)
        )
    if (
        static
        and static.get("scriptCount", 0) > 0
        and (
            query_redacted_for_browser
            or bool(browser and browser.get("strippedBrowserQuery"))
        )
    ):
        sufficient = False

    checks = [
        {key: value for key, value in check.items() if value is not None}
        for check in checks
    ]
    if not sufficient and not any(
        check["status"] in {"blocked", "failed"} for check in checks
    ):
        checks.append(
            {
                "name": "coverage",
                "status": "blocked",
                "reason": "Some analysis coverage was reduced by the privacy policy.",
            }
        )

    if not needs_browser:
        checks.append(
            {
                "name": "rea_passive_observation",
                "status": "skipped",
                "reason": "No browser session was required for this URL.",
            }
        )
    elif browser_failed or browser is None:
        checks.append(
            {
                "name": "rea_passive_observation",
                "status": "skipped",
                "reason": "No completed Chromium session was available to inspect.",
            }
        )
    else:
        rea_observation = browser.get("reaObservation")
        if (
            isinstance(rea_observation, dict)
            and rea_observation.get("status") == "completed"
        ):
            completeness = rea_observation.get("completeness")
            counts = rea_observation.get("counts")
            count_labels = (
                ("domNodes", "DOM nodes"),
                ("scripts", "scripts"),
                ("resources", "resources"),
                ("networkRequests", "network requests"),
            )
            count_summary = [
                f"{label}: {counts[key]}"
                for key, label in count_labels
                if isinstance(counts, dict)
                and type(counts.get(key)) is int
                and 0 <= counts[key] <= 100_000
            ]
            details = ", ".join(count_summary) or "bounded page structure captured"
            if isinstance(completeness, str) and completeness in {
                "complete_within_window",
                "policy_filtered",
                "attach_limited",
                "truncated",
            }:
                details = f"{completeness}; {details}"
            checks.append(
                {
                    "name": "rea_passive_observation",
                    "status": "completed",
                    "reason": (
                        f"REA passively inspected the same Chromium session via CDP "
                        f"({details}). Raw page evidence was discarded."
                    ),
                }
            )
        else:
            checks.append(
                {
                    "name": "rea_passive_observation",
                    "status": "failed",
                    "reason": (
                        "REA's optional passive capture did not complete; the "
                        "Playwright scan results were retained."
                    ),
                }
            )

    if not sufficient:
        risk_band = "inconclusive"
    elif any(item["severity"] == "high" for item in findings):
        risk_band = "high"
    elif any(item["severity"] == "moderate" for item in findings):
        risk_band = "moderate"
    else:
        risk_band = "low"

    report: dict[str, Any] = {
        "scanId": scan_id,
        "type": "url",
        "riskBand": risk_band,
        "completedAt": datetime.now(timezone.utc).isoformat(),
        "ruleSetVersion": RULE_SET_VERSION,
        "findings": findings[:MAX_FINDINGS],
        "coverage": {"sufficient": sufficient, "checks": checks},
    }
    return report


async def analyze(job: dict[str, Any]) -> dict[str, Any]:
    task_plan = job.get("taskPlan")
    if not isinstance(task_plan, list) or tuple(task_plan) != EXPECTED_TASK_PLAN:
        raise ValueError("Unsupported analysis plan")
    scan_id = str(job["scanId"])
    raw_url = normalize_public_http_url(job["url"])
    timeout_seconds = _bounded_browser_timeout_seconds(
        job.get("browserTimeoutSeconds", MAX_BROWSER_TIMEOUT_SECONDS)
    )
    parts = urlsplit(raw_url)
    query_redacted_for_browser = bool(parts.query or parts.fragment)

    emit({"kind": "progress", "stage": "navigating"})
    response = None
    redirect_urls: list[str] = [raw_url]
    static_final_url = raw_url
    redirect_blocked = False
    fetch_failed = False
    try:
        if "http" not in task_plan:
            raise ValueError("HTTP inspection is not in the plan")
        response, redirect_urls, redirect_blocked, static_final_url = _static_fetch(raw_url)
        if response is None:
            fetch_failed = True
    except Exception:
        fetch_failed = True

    if fetch_failed:
        emit({
            "kind": "progress",
            "stage": "http_failed",
            "reasonCode": "http_fetch_failed",
        })
    else:
        emit({"kind": "progress", "stage": "collecting_evidence"})
    static: dict[str, Any] | None = None
    if "static" in task_plan and response is not None and not fetch_failed:
        static = _static_evidence(response, static_final_url)

    browser: dict[str, Any] | None = None
    browser_failed = False
    if (
        "browser" in task_plan
        and
        static
        and static.get("isHtml")
        and not static.get("oversized")
        and static.get("scriptCount", 0) > 0
        and not redirect_blocked
    ):
        emit({"kind": "progress", "stage": "browser_inspection"})
        try:
            browser, browser_error = await _browser_evidence(raw_url, timeout_seconds)
            browser_failed = browser_error is not None or browser is None
        except Exception:
            browser_failed = True
        emit({
            "kind": "progress",
            "stage": "browser_failed" if browser_failed else "browser_completed",
            **({"reasonCode": "browser_error"} if browser_failed else {}),
        })
    else:
        if redirect_blocked:
            skip_reason = "redirect_blocked"
            skip_stage = "browser_blocked"
        elif fetch_failed or static is None:
            skip_reason = "http_unavailable"
            skip_stage = "browser_skipped"
        elif static.get("oversized"):
            skip_reason = "static_body_limit"
            skip_stage = "browser_skipped"
        elif not static.get("isHtml"):
            skip_reason = "not_html"
            skip_stage = "browser_skipped"
        else:
            skip_reason = "no_browser_required"
            skip_stage = "browser_skipped"
        emit({
            "kind": "progress",
            "stage": skip_stage,
            "reasonCode": skip_reason,
        })

    if "report" not in task_plan:
        raise ValueError("Report assembly is not in the plan")
    emit({"kind": "progress", "stage": "building_report"})
    return _build_report(
        scan_id,
        raw_url,
        static,
        redirect_urls,
        redirect_blocked,
        browser,
        browser_failed,
        fetch_failed,
        query_redacted_for_browser=query_redacted_for_browser,
        static_final_url=static_final_url,
    )


def main() -> int:
    try:
        job = json.loads(sys.stdin.buffer.read())
    except (UnicodeDecodeError, json.JSONDecodeError):
        emit({"kind": "error", "code": "INVALID_JOB"})
        return 1
    try:
        report = asyncio.run(analyze(job))
        emit({"kind": "report", "report": report})
        return 0
    except Exception:
        emit({"kind": "error", "code": "ANALYSIS_FAILED"})
        return 1


if __name__ == "__main__":
    sys.exit(main())
