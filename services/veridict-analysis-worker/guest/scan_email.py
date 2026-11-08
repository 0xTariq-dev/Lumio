from __future__ import annotations

import base64
import binascii
import io
import json
import logging
import quopri
import re
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4
from xml.etree import ElementTree
from zipfile import ZipFile

from shared.url_policy import (
    URLPolicyError,
    hostname_for_url,
    normalize_public_http_url,
    sanitized_url,
)

MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_BODY_PART_BYTES = 2 * 1024 * 1024
MAX_MIME_PARTS = 300
MAX_ATTACHMENT_SIGNATURE_BYTES = 16
MAX_ATTACHMENT_PREFIX_SCAN_CHARS = 512
MAX_DOCUMENT_ATTACHMENT_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_ENCODED_PAYLOAD_CHARS = MAX_DOCUMENT_ATTACHMENT_BYTES * 4
MAX_DOCUMENT_TEXT_CHARS = 10_000
MAX_DOCUMENT_TEXT_TOTAL_CHARS = 20_000
MAX_DOCUMENTS = 20
MAX_DOCX_DOCUMENT_XML_BYTES = 4 * 1024 * 1024
MAX_PDF_PAGES = 20
MAX_LINK_CANDIDATES = 250
MAX_LINKS = 50
EXPECTED_TASK_PLAN = ("email_headers", "email_body", "email_links", "report")
DOCUMENT_EXTENSIONS = {".docx", ".pdf", ".txt"}
WORD_DOCUMENT_XML = "word/document.xml"
WORD_TEXT_TAG = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"
URL_PATTERN = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)
AUTH_FAILURE_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|permerror|temperror)\b",
    re.IGNORECASE,
)
RISKY_ATTACHMENT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".exe",
    ".hta",
    ".iso",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbe",
    ".vbs",
}
ZIP_ATTACHMENT_EXTENSIONS = {
    ".docm",
    ".docx",
    ".jar",
    ".odt",
    ".odp",
    ".ods",
    ".pptm",
    ".pptx",
    ".xlsm",
    ".xlsx",
    ".zip",
}
OLE_ATTACHMENT_EXTENSIONS = {".doc", ".msi", ".msg", ".ppt", ".xls"}
MZ_ATTACHMENT_EXTENSIONS = {
    ".com",
    ".cpl",
    ".dll",
    ".drv",
    ".efi",
    ".exe",
    ".ocx",
    ".scr",
    ".sys",
}
BASE64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)


def emit(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":"), ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "a":
            return
        href = next(
            (
                value
                for name, value in attrs
                if name.lower() == "href" and isinstance(value, str)
            ),
            None,
        )
        if href:
            self.links.append(href)


def _decoded_text(part: Any) -> str:
    payload = part.get_payload()
    if not isinstance(payload, str) or len(payload) > MAX_BODY_PART_BYTES * 2:
        return ""
    try:
        content = part.get_payload(decode=True)
    except Exception:
        return ""
    if not isinstance(content, bytes) or len(content) > MAX_BODY_PART_BYTES:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return content.decode(charset, errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


def _attachment_header_prefix(part: Any) -> bytes:
    """Decode at most the first 16 bytes without materializing the attachment."""
    payload = part.get_payload()
    if not isinstance(payload, str):
        return b""

    transfer_encoding = str(part.get("Content-Transfer-Encoding") or "").strip().lower()
    if transfer_encoding == "base64":
        encoded: list[str] = []
        for char in payload[:MAX_ATTACHMENT_PREFIX_SCAN_CHARS]:
            if char in " \t\r\n":
                continue
            if char not in BASE64_ALPHABET:
                return b""
            encoded.append(char)
            if len(encoded) >= ((MAX_ATTACHMENT_SIGNATURE_BYTES + 2) // 3) * 4:
                break

        complete_length = len(encoded) - (len(encoded) % 4)
        if complete_length == 0:
            return b""
        try:
            return base64.b64decode("".join(encoded[:complete_length]), validate=True)[
                :MAX_ATTACHMENT_SIGNATURE_BYTES
            ]
        except (binascii.Error, ValueError):
            return b""

    if transfer_encoding == "quoted-printable":
        decoded = bytearray()
        index = 0
        scan_limit = min(len(payload), MAX_ATTACHMENT_PREFIX_SCAN_CHARS)
        while index < scan_limit and len(decoded) < MAX_ATTACHMENT_SIGNATURE_BYTES:
            char = payload[index]
            if char == "=":
                if payload.startswith("=\r\n", index):
                    index += 3
                    continue
                if payload.startswith("=\n", index):
                    index += 2
                    continue
                if (
                    index + 2 < scan_limit
                    and re.fullmatch(r"[0-9A-Fa-f]{2}", payload[index + 1 : index + 3])
                ):
                    decoded.append(int(payload[index + 1 : index + 3], 16))
                    index += 3
                    continue
                return b""
            codepoint = ord(char)
            if codepoint > 255:
                return b""
            decoded.append(codepoint)
            index += 1
        return bytes(decoded)

    if transfer_encoding in {"", "7bit", "8bit", "binary"}:
        try:
            return payload[:MAX_ATTACHMENT_SIGNATURE_BYTES].encode(
                "ascii", errors="surrogateescape"
            )
        except UnicodeEncodeError:
            return b""
    return b""


def _attachment_signature(prefix: bytes) -> str | None:
    if prefix.startswith(b"%PDF-"):
        return "pdf"
    if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if prefix.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if prefix.startswith(b"MZ"):
        return "mz"
    return None


def _declared_attachment_kind(extension: str, content_type: str) -> set[str]:
    kinds: set[str] = set()
    if extension == ".pdf":
        kinds.add("pdf")
    if extension in ZIP_ATTACHMENT_EXTENSIONS:
        kinds.add("zip")
    if extension in OLE_ATTACHMENT_EXTENSIONS:
        kinds.add("ole")
    if extension in MZ_ATTACHMENT_EXTENSIONS:
        kinds.add("mz")

    if content_type == "application/pdf":
        kinds.add("pdf")
    elif (
        content_type in {"application/zip", "application/x-zip-compressed", "application/java-archive"}
        or content_type.startswith("application/vnd.openxmlformats-officedocument.")
        or content_type.startswith("application/vnd.oasis.opendocument.")
        or content_type
        in {
            "application/vnd.ms-excel.sheet.macroenabled.12",
            "application/vnd.ms-powerpoint.presentation.macroenabled.12",
            "application/vnd.ms-word.document.macroenabled.12",
        }
    ):
        kinds.add("zip")
    elif content_type in {
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-outlook",
        "application/vnd.ms-powerpoint",
        "application/x-ole-storage",
        "application/x-olecompoundfile",
        "application/x-msi",
    }:
        kinds.add("ole")
    elif content_type in {
        "application/vnd.microsoft.portable-executable",
        "application/x-dosexec",
        "application/x-msdownload",
    }:
        kinds.add("mz")
    return kinds


def _attachment_signature_findings(
    attachments: list[tuple[str, str, str | None]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    signature_copy = {
        "pdf": (
            "PDF header marker detected",
            "The first 16 attachment bytes matched a PDF header marker. This signature check does not inspect document text or establish safety.",
        ),
        "zip": (
            "ZIP container marker detected",
            "The first 16 attachment bytes matched a ZIP container marker. The archive was not decompressed or inspected.",
        ),
        "ole": (
            "OLE document marker detected",
            "The first 16 attachment bytes matched an OLE compound-document marker. This signature check does not inspect document text.",
        ),
        "mz": (
            "MZ executable-like marker detected",
            "The first 16 bytes began with MZ. This marker alone does not confirm a valid PE file or indicate malware.",
        ),
    }
    detected = {
        signature
        for _extension, _content_type, signature in attachments
        if signature is not None
    }
    for signature in sorted(detected):
        title, explanation = signature_copy[signature]
        findings.append(
            _finding(
                f"attachment-signature-{signature}",
                title,
                explanation,
                "informational",
                "attachment_metadata",
                strength="direct",
            )
        )

    mismatch = any(
        signature is not None
        and any(
            declared_kind != signature
            for declared_kind in _declared_attachment_kind(extension, content_type)
        )
        for extension, content_type, signature in attachments
    )
    if mismatch:
        findings.append(
            _finding(
                "attachment-signature-mismatch",
                "Attachment header differs from declared type",
                "A supported header marker conflicts with the declared filename extension or MIME type. These declarations are untrusted; no file content was parsed.",
                "moderate",
                "attachment_metadata",
                strength="contextual",
            )
        )
    return findings


def _domain(value: str) -> str | None:
    for _display_name, address in getaddresses([value]):
        _local, separator, domain = address.rpartition("@")
        if not separator or not domain:
            continue
        try:
            normalized = domain.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            continue
        if normalized:
            return normalized
    return None


def _message_parts(
    message: Any,
    *,
    parse_attachments: bool = False,
) -> tuple[list[str], list[tuple[str, str, str | None]], list[str], bool, bool]:
    body_texts: list[str] = []
    attachment_metadata: list[tuple[str, str, str | None]] = []
    attachment_documents: list[str] = []
    body_truncated = False
    mime_parts_truncated = False
    document_text_remaining = MAX_DOCUMENT_TEXT_TOTAL_CHARS

    for index, part in enumerate(message.walk()):
        if index >= MAX_MIME_PARTS:
            mime_parts_truncated = True
            break
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            extension = PurePosixPath(str(filename or "").replace("\\", "/")).suffix.lower()
            content_type = str(part.get_content_type()).lower()[:120]
            signature = _attachment_signature(_attachment_header_prefix(part))
            attachment_metadata.append((extension, content_type, signature))
            if (
                parse_attachments
                and extension in DOCUMENT_EXTENSIONS
                and len(attachment_documents) < MAX_DOCUMENTS
                and document_text_remaining > 0
            ):
                text = _extract_document_text(part, extension)
                if text:
                    text = text[: min(MAX_DOCUMENT_TEXT_CHARS, document_text_remaining)]
                    if text:
                        attachment_documents.append(text)
                        document_text_remaining -= len(text)
            continue

        if part.get_content_type() in {"text/plain", "text/html"}:
            text = _decoded_text(part)
            if text:
                body_texts.append(text)
            elif part.get_payload() is not None:
                body_truncated = True

    return (
        body_texts,
        attachment_metadata,
        attachment_documents,
        body_truncated,
        mime_parts_truncated,
    )


def _decoded_document_payload(part: Any) -> bytes | None:
    """Decode one supported document payload only after checking its encoded bound."""
    payload = part.get_payload()
    if not isinstance(payload, str) or len(payload) > MAX_DOCUMENT_ENCODED_PAYLOAD_CHARS:
        return None

    transfer_encoding = str(part.get("Content-Transfer-Encoding") or "").strip().lower()
    try:
        if transfer_encoding == "base64":
            compact = "".join(payload.split())
            content = base64.b64decode(compact, validate=True)
        elif transfer_encoding == "quoted-printable":
            content = quopri.decodestring(payload.encode("ascii", errors="strict"))
        elif transfer_encoding in {"", "7bit", "8bit", "binary"}:
            content = payload.encode("ascii", errors="surrogateescape")
        else:
            return None
    except (UnicodeEncodeError, binascii.Error, ValueError):
        return None

    if not content or len(content) > MAX_DOCUMENT_ATTACHMENT_BYTES:
        return None
    return content


def _decode_document_text(content: bytes, charset: str | None) -> str:
    try:
        return content.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


def _extract_txt_text(part: Any, content: bytes) -> str:
    text = _decode_document_text(content, part.get_content_charset())
    return text.strip()[:MAX_DOCUMENT_TEXT_CHARS]


def _extract_pdf_text(content: bytes) -> str:
    pdf_logger = logging.getLogger("pypdf")
    previous_log_level = pdf_logger.level
    pdf_logger.setLevel(logging.CRITICAL + 1)
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(content), strict=False)
        if reader.is_encrypted:
            return ""
        page_count = min(len(reader.pages), MAX_PDF_PAGES)
        pages: list[str] = []
        remaining = MAX_DOCUMENT_TEXT_CHARS
        for index in range(page_count):
            try:
                text = reader.pages[index].extract_text() or ""
            except Exception:
                continue
            text = text.strip()
            if text:
                pages.append(text[:remaining])
                remaining -= min(len(text), remaining)
            if remaining <= 0:
                break
        return "\n".join(pages)[:MAX_DOCUMENT_TEXT_CHARS].strip()
    except Exception:
        return ""
    finally:
        pdf_logger.setLevel(previous_log_level)


def _extract_docx_text(content: bytes) -> str:
    try:
        with ZipFile(io.BytesIO(content)) as archive:
            info = archive.getinfo(WORD_DOCUMENT_XML)
            if info.file_size > MAX_DOCX_DOCUMENT_XML_BYTES:
                return ""
            with archive.open(info) as document_xml:
                xml_content = document_xml.read(MAX_DOCX_DOCUMENT_XML_BYTES + 1)
            if len(xml_content) > MAX_DOCX_DOCUMENT_XML_BYTES:
                return ""
        # Reject DTD/entity declarations before handing the bounded XML to ElementTree.
        xml_lower = xml_content.lower()
        if b"\x00" in xml_content or b"<!doctype" in xml_lower or b"<!entity" in xml_lower:
            return ""
        root = ElementTree.fromstring(xml_content)
        fragments = [
            node.text
            for node in root.iter(WORD_TEXT_TAG)
            if isinstance(node.text, str) and node.text
        ]
        return " ".join(fragments).strip()[:MAX_DOCUMENT_TEXT_CHARS]
    except Exception:
        return ""


def _extract_document_text(part: Any, extension: str) -> str:
    content = _decoded_document_payload(part)
    if content is None:
        return ""
    if extension == ".txt":
        return _extract_txt_text(part, content)
    if extension == ".pdf":
        return _extract_pdf_text(content)
    if extension == ".docx":
        return _extract_docx_text(content)
    return ""


def _link_candidates(body_texts: list[str]) -> list[str]:
    candidates: list[str] = []
    for body in body_texts:
        if "<" in body and ">" in body:
            parser = _LinkParser()
            try:
                parser.feed(body[:MAX_BODY_PART_BYTES])
                candidates.extend(parser.links)
            except Exception:
                pass
        candidates.extend(match.group(0) for match in URL_PATTERN.finditer(body))
        if len(candidates) >= MAX_LINK_CANDIDATES:
            break
    return candidates[:MAX_LINK_CANDIDATES]


def _safe_links(candidates: list[str]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    links: list[dict[str, Any]] = []
    private_targets: dict[str, str] = {}
    seen: set[str] = set()

    for candidate in candidates:
        raw_url = candidate.rstrip(".,;:!?)]}")
        try:
            normalized = normalize_public_http_url(raw_url)
        except URLPolicyError:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)

        link_id = str(uuid4())
        try:
            display_url = sanitized_url(normalized)
            target_host = hostname_for_url(normalized)
        except URLPolicyError:
            continue
        links.append(
            {
                "linkId": link_id,
                "anchorText": f"Email link {len(links) + 1}",
                "displayUrl": display_url,
                "targetHost": target_host,
                "scanAvailable": True,
            }
        )
        private_targets[link_id] = normalized
        if len(links) >= MAX_LINKS:
            break

    return links, private_targets


def _finding(
    finding_id: str,
    title: str,
    explanation: str,
    severity: str,
    source: str,
    *,
    strength: str = "direct",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "explanation": explanation,
        "severity": severity,
        "strength": strength,
        "source": source,
    }


def analyze_email(job: dict[str, Any]) -> dict[str, Any]:
    if job.get("type") != "email" or tuple(job.get("taskPlan", ())) != EXPECTED_TASK_PLAN:
        raise ValueError("Unsupported email analysis plan")

    encoded = job.get("emailBase64")
    if not isinstance(encoded, str):
        raise ValueError("Email content is unavailable")

    try:
        raw_email = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Email content is invalid") from exc
    if not raw_email or len(raw_email) > MAX_EMAIL_BYTES:
        raise ValueError("Email content size is invalid")

    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    if not message.keys():
        raise ValueError("The uploaded file is not a readable email")

    (
        body_texts,
        attachments,
        attachment_documents,
        body_truncated,
        mime_parts_truncated,
    ) = _message_parts(
        message,
        parse_attachments=job.get("parseAttachmentsWithAi") is True,
    )
    links, private_targets = _safe_links(_link_candidates(body_texts))
    findings: list[dict[str, Any]] = []

    from_domain = _domain(str(message.get("From", "")))
    reply_to_domain = _domain(str(message.get("Reply-To", "")))
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        findings.append(
            _finding(
                "reply-domain-mismatch",
                "Reply-to domain differs from sender domain",
                "The reply destination uses a different domain from the sender field. This is an indicator, not proof of fraud.",
                "moderate",
                "email_headers",
                strength="contextual",
            )
        )

    auth_results = "\n".join(
        str(value)[:8192] for value in message.get_all("Authentication-Results", [])
    )
    failed_methods = sorted(
        {
            match.group(1).lower()
            for match in AUTH_FAILURE_PATTERN.finditer(auth_results)
        }
    )
    if failed_methods:
        findings.append(
            _finding(
                "email-authentication-failure",
                "Email authentication reported a failure",
                "An authentication-results header reports a failed sender-authentication check. These headers can be forged and must be interpreted cautiously.",
                "moderate",
                "email_headers",
                strength="contextual",
            )
        )

    if attachments:
        findings.extend(_attachment_signature_findings(attachments))
        risky_types = [extension for extension, _content_type, _signature in attachments if extension in RISKY_ATTACHMENT_EXTENSIONS]
        if risky_types:
            findings.append(
                _finding(
                    "risky-attachment-type",
                    "Potentially risky attachment type",
                "Attachment metadata includes a file type that can contain or launch executable content. The baseline check inspected only a bounded header prefix; no attachment content was executed.",
                    "moderate",
                    "attachment_metadata",
                    strength="contextual",
                )
            )
        findings.append(
            _finding(
                "attachment-bounded-inspection",
                "Attachment checks were bounded",
            "The baseline check read metadata and at most 16 header bytes within the MIME-part limit. Supported document text is extracted only after separate consent; no attachment content is executed.",
                "informational",
                "attachment_metadata",
                strength="direct",
            )
        )

    coverage_checks = [
        {"name": "email_headers", "status": "completed"},
        {
            "name": "email_body",
            "status": "completed" if body_texts else "skipped",
            **({"reason": "No supported text body was available."} if not body_texts else {}),
        },
        {
            "name": "email_links",
            "status": "completed",
            **(
                {"reason": "Some message parts exceeded safe parsing limits."}
                if body_truncated or mime_parts_truncated
                else {}
            ),
        },
        {"name": "attachment_metadata", "status": "completed"},
        {
            "name": "attachment_header_signature",
            "status": "skipped" if mime_parts_truncated else "completed",
            **(
                {"reason": "The MIME part limit was reached; some attachments may not have been checked."}
                if mime_parts_truncated
                else {}
            ),
        },
        {
            "name": "selected_link_scan",
            "status": "skipped",
            "reason": "A separate consent is required before visiting a link.",
        },
    ]
    report = {
        "scanId": str(job.get("scanId", "")),
        "type": "email",
        "riskBand": "inconclusive",
        "completedAt": datetime.now(timezone.utc).isoformat(),
        "ruleSetVersion": "veridict-email-rules-2026-11-08.1",
        "findings": findings[:50],
        "coverage": {"sufficient": False, "checks": coverage_checks},
        "links": links,
        "attachmentDocuments": attachment_documents,
        "_privateLinks": private_targets,
    }
    if job.get("parseAttachmentsWithAi") is True:
        report["attachmentDocuments"] = attachment_documents
    return report


def main() -> int:
    try:
        raw_job = sys.stdin.buffer.read(15 * 1024 * 1024 + 1)
        if len(raw_job) > 15 * 1024 * 1024:
            raise ValueError("Email request is too large")
        job = json.loads(raw_job)
        emit({"kind": "progress", "stage": "analyzing_email"})
        report = analyze_email(job)
        emit({"kind": "progress", "stage": "building_report"})
        emit({"kind": "report", "report": report})
        return 0
    except Exception:
        emit({"kind": "error", "code": "ANALYSIS_FAILED"})
        return 1


if __name__ == "__main__":
    sys.exit(main())
