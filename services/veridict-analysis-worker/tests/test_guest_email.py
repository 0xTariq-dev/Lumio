import base64
import json
import unittest
from email.message import Message

from guest.scan_email import _attachment_header_prefix, analyze_email


def _scan_email_with_attachments(
    attachments: list[tuple[str, str, bytes]],
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
        }
    )


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
