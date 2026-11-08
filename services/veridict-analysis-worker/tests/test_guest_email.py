import base64
import io
import json
import unittest
import zipfile
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

from guest.scan_email import (
    MAX_DOCUMENT_ATTACHMENT_BYTES,
    MAX_DOCUMENT_TEXT_CHARS,
    MAX_DOCUMENT_TEXT_TOTAL_CHARS,
    MAX_DOCX_DOCUMENT_XML_BYTES,
    MAX_PDF_PAGES,
    _attachment_header_prefix,
    _extract_pdf_text,
    analyze_email,
)


def _scan_email_with_attachments(
    attachments: list[tuple[str, str, bytes]],
    *,
    parse_attachments: bool = False,
) -> dict:
    boundary = b"signature-boundary"
    raw_email = bytearray(
        b"From: security@example.com\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=signature-boundary\r\n\r\n"
        b"--signature-boundary\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Review the attached files.\r\n"
    )
    for filename, content_type, payload in attachments:
        raw_email.extend(b"--" + boundary + b"\r\n")
        raw_email.extend(f"Content-Type: {content_type}\r\n".encode("ascii"))
        raw_email.extend(
            f'Content-Disposition: attachment; filename="{filename}"\r\n'.encode("ascii")
        )
        raw_email.extend(b"Content-Transfer-Encoding: base64\r\n\r\n")
        raw_email.extend(base64.encodebytes(payload))
        raw_email.extend(b"\r\n")
    raw_email.extend(b"--" + boundary + b"--\r\n")
    return analyze_email(
        {
            "scanId": "d480c32b-d5e4-4a68-bbf4-5ffb6b7263a1",
            "type": "email",
            "taskPlan": ["email_headers", "email_body", "email_links", "report"],
            "emailBase64": base64.b64encode(raw_email).decode("ascii"),
            "parseAttachmentsWithAi": parse_attachments,
        }
    )


def _pdf_with_text(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
        + stream
        + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def _docx_with_text(text: str) -> bytes:
    xml = (
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
    ).encode("utf-8")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)
        archive.writestr(
            "word/header1.xml",
            '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:p><w:r><w:t>header text excluded</w:t></w:r></w:p></w:hdr>",
        )
        archive.writestr("docProps/core.xml", "metadata text excluded")
    return output.getvalue()


class GuestEmailTests(unittest.TestCase):
    def test_extracts_safe_evidence_without_returning_message_content(self):
        raw_email = (
            b"From: billing@sender.example\r\n"
            b"Reply-To: agent@other.example\r\n"
            b"Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=scan-boundary\r\n"
            b"\r\n"
            b"--scan-boundary\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Private body text. Visit https://example.com/login?token=private-value\r\n"
            b"--scan-boundary\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b'Content-Disposition: attachment; filename="invoice.exe"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"c2VjcmV0LWZpbGU=\r\n"
            b"--scan-boundary--\r\n"
        )
        report = analyze_email(
            {
                "scanId": "d480c32b-d5e4-4a68-bbf4-5ffb6b7263a1",
                "type": "email",
                "taskPlan": ["email_headers", "email_body", "email_links", "report"],
                "emailBase64": base64.b64encode(raw_email).decode("ascii"),
            }
        )

        links = report["links"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["displayUrl"], "https://example.com/")
        self.assertEqual(links[0]["targetHost"], "example.com")
        self.assertTrue(links[0]["scanAvailable"])
        self.assertEqual(
            report["_privateLinks"][links[0]["linkId"]],
            "https://example.com/login?token=private-value",
        )
        findings = {item["id"] for item in report["findings"]}
        self.assertIn("reply-domain-mismatch", findings)
        self.assertIn("email-authentication-failure", findings)
        self.assertIn("risky-attachment-type", findings)
        self.assertIn("attachment-bounded-inspection", findings)
        self.assertEqual(
            next(
                check
                for check in report["coverage"]["checks"]
                if check["name"] == "attachment_header_signature"
            )["status"],
            "completed",
        )
        self.assertEqual(report["riskBand"], "inconclusive")
        self.assertFalse(report["coverage"]["sufficient"])

        public_report = {key: value for key, value in report.items() if key != "_privateLinks"}
        serialized = json.dumps(public_report)
        for private_value in (
            "Private body text",
            "sender.example",
            "agent@other.example",
            "invoice.exe",
            "secret-file",
            "private-value",
        ):
            self.assertNotIn(private_value, serialized)

    def test_detects_pdf_and_zip_signatures_and_metadata_mismatch_without_file_data(self):
        report = _scan_email_with_attachments(
            [
                (
                    "private-contract.pdf",
                    "application/pdf",
                    b"%PDF-1.7\nPRIVATE-PDF-CONTENT",
                ),
                (
                    "invoice.pdf",
                    "application/pdf",
                    b"PK\x03\x04PRIVATE-ZIP-CONTENT",
                ),
            ]
        )

        finding_ids = {item["id"] for item in report["findings"]}
        self.assertIn("attachment-signature-pdf", finding_ids)
        self.assertIn("attachment-signature-zip", finding_ids)
        self.assertIn("attachment-signature-mismatch", finding_ids)
        public_report = {key: value for key, value in report.items() if key != "_privateLinks"}
        serialized = json.dumps(public_report)
        for private_value in (
            "private-contract.pdf",
            "invoice.pdf",
            "PRIVATE-PDF-CONTENT",
            "PRIVATE-ZIP-CONTENT",
        ):
            self.assertNotIn(private_value, serialized)

    def test_detects_ole_and_mz_marker_without_claiming_pe_validation(self):
        report = _scan_email_with_attachments(
            [
                (
                    "legacy.doc",
                    "application/msword",
                    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1PRIVATE-OLE-CONTENT",
                ),
                (
                    "setup.exe",
                    "application/octet-stream",
                    b"MZPRIVATE-EXECUTABLE-CONTENT",
                ),
            ]
        )

        findings = {item["id"]: item for item in report["findings"]}
        self.assertIn("attachment-signature-ole", findings)
        self.assertIn("attachment-signature-mz", findings)
        self.assertIn("risky-attachment-type", findings)
        self.assertIn(
            "does not confirm a valid PE file",
            findings["attachment-signature-mz"]["explanation"],
        )
        serialized = json.dumps(
            {key: value for key, value in report.items() if key != "_privateLinks"}
        )
        self.assertNotIn("PRIVATE-OLE-CONTENT", serialized)
        self.assertNotIn("PRIVATE-EXECUTABLE-CONTENT", serialized)

    def test_signature_decoder_reads_only_a_bounded_prefix(self):
        payload = b"%PDF-1.7-HEADER-AND-PRIVATE-DATA"
        part = Message()
        part["Content-Transfer-Encoding"] = "base64"
        part.set_payload(base64.b64encode(payload).decode("ascii"))

        prefix = _attachment_header_prefix(part)

        self.assertEqual(prefix, payload[:16])
        self.assertEqual(len(prefix), 16)

    def test_signature_decoder_handles_quoted_printable_and_fails_closed(self):
        part = Message()
        part["Content-Transfer-Encoding"] = "quoted-printable"
        part.set_payload("=25=50=44=46=2D1.7=0A" + ("A" * 2048))
        self.assertEqual(_attachment_header_prefix(part), b"%PDF-1.7\n" + b"A" * 7)

        malformed = Message()
        malformed["Content-Transfer-Encoding"] = "base64"
        malformed.set_payload("%%%")
        self.assertEqual(_attachment_header_prefix(malformed), b"")

    def test_mime_part_limit_marks_signature_coverage_incomplete(self):
        report = _scan_email_with_attachments(
            [
                (f"attachment-{index}.bin", "application/octet-stream", b"unknown")
                for index in range(301)
            ]
        )
        signature_check = next(
            check
            for check in report["coverage"]["checks"]
            if check["name"] == "attachment_header_signature"
        )

        self.assertEqual(signature_check["status"], "skipped")
        self.assertIn("MIME part limit", signature_check["reason"])

    def test_attachment_document_parsing_is_disabled_without_explicit_consent(self):
        secret_text = "consent-gated private document text"
        report = _scan_email_with_attachments(
            [("notes.txt", "text/plain", secret_text.encode())]
        )

        self.assertNotIn("attachmentDocuments", report)
        self.assertNotIn(secret_text, json.dumps(report["findings"]))

    def test_extracts_text_from_txt_pdf_and_only_docx_document_xml(self):
        txt = b"Text document content"
        pdf = _pdf_with_text("PDF document content")
        docx = _docx_with_text("DOCX document content")
        class FakePdfPage:
            def extract_text(self):
                return "PDF document content"

        class FakePdfReader:
            def __init__(self, _stream, *, strict=False):
                self.is_encrypted = False
                self.pages = [FakePdfPage()]

        with patch.dict(
            "sys.modules",
            {"pypdf": SimpleNamespace(PdfReader=FakePdfReader)},
        ):
            report = _scan_email_with_attachments(
                [
                    ("notes.txt", "text/plain; charset=utf-8", txt),
                    ("report.pdf", "application/pdf", pdf),
                    ("letter.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", docx),
                ],
                parse_attachments=True,
            )

        documents = report["attachmentDocuments"]
        self.assertEqual(len(documents), 3)
        combined_text = "\n".join(documents)
        self.assertIn("Text document content", combined_text)
        self.assertIn("PDF document content", combined_text)
        self.assertIn("DOCX document content", combined_text)
        self.assertNotIn("word/document.xml", combined_text)
        self.assertNotIn("report.pdf", combined_text)
        self.assertNotIn("header text excluded", combined_text)
        self.assertNotIn("metadata text excluded", combined_text)

    def test_unsupported_and_malformed_documents_are_ignored(self):
        oversized_docx = io.BytesIO()
        with zipfile.ZipFile(oversized_docx, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "word/document.xml",
                b"x" * (MAX_DOCX_DOCUMENT_XML_BYTES + 1),
            )
        report = _scan_email_with_attachments(
            [
                ("sheet.xlsx", "application/octet-stream", b"not parsed"),
                ("bad.pdf", "application/pdf", b"not a pdf"),
                ("bad.docx", "application/octet-stream", b"not a zip"),
                ("large.docx", "application/octet-stream", oversized_docx.getvalue()),
            ],
            parse_attachments=True,
        )
        self.assertEqual(report["attachmentDocuments"], [])

    def test_attachment_size_and_aggregate_text_limits_are_enforced(self):
        oversized = b"x" * (MAX_DOCUMENT_ATTACHMENT_BYTES + 1)
        report = _scan_email_with_attachments(
            [
                ("too-large.txt", "text/plain", oversized),
                ("first.txt", "text/plain", b"a" * (MAX_DOCUMENT_TEXT_CHARS + 100)),
                ("second.txt", "text/plain", b"b" * (MAX_DOCUMENT_TEXT_CHARS + 100)),
                ("third.txt", "text/plain", b"c" * (MAX_DOCUMENT_TEXT_CHARS + 100)),
            ],
            parse_attachments=True,
        )

        documents = report["attachmentDocuments"]
        self.assertEqual(len(documents), 2)
        self.assertTrue(all(len(document) <= MAX_DOCUMENT_TEXT_CHARS for document in documents))
        self.assertLessEqual(sum(map(len, documents)), MAX_DOCUMENT_TEXT_TOTAL_CHARS)
        self.assertNotIn("x" * 100, json.dumps(documents))

    def test_pdf_page_limit_is_enforced(self):
        pages = [
            SimpleNamespace(extract_text=lambda index=index: f"page-{index}")
            for index in range(MAX_PDF_PAGES + 1)
        ]
        fake_module = SimpleNamespace(
            PdfReader=lambda *_args, **_kwargs: SimpleNamespace(
                is_encrypted=False,
                pages=pages,
            )
        )
        with patch.dict("sys.modules", {"pypdf": fake_module}):
            text = _extract_pdf_text(b"bounded")

        self.assertIn(f"page-{MAX_PDF_PAGES - 1}", text)
        self.assertNotIn(f"page-{MAX_PDF_PAGES}", text)

    def test_rejects_non_email_and_invalid_base64(self):
        with self.assertRaises(ValueError):
            analyze_email({"type": "email", "taskPlan": [], "emailBase64": "eA=="})
        with self.assertRaises(ValueError):
            analyze_email(
                {
                    "type": "email",
                    "taskPlan": ["email_headers", "email_body", "email_links", "report"],
                    "emailBase64": "not base64!",
                }
            )


if __name__ == "__main__":
    unittest.main()
