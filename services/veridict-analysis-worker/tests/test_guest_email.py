import base64
import json
import unittest

from guest.scan_email import analyze_email


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
