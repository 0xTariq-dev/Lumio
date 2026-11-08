import unittest

from shared.url_policy import (
    URLPolicyError,
    normalize_public_http_url,
    sanitized_url,
)


class URLPolicyTests(unittest.TestCase):
    def test_normalizes_domain_without_discarding_request_data(self):
        value = normalize_public_http_url(
            "HTTPS://Example.COM/account?id=private#tab"
        )
        self.assertEqual(value, "https://example.com/account?id=private#tab")

    def test_report_url_drops_path_query_and_fragment(self):
        value = sanitized_url(
            "https://example.com/account/customer-42?email=private#profile"
        )
        self.assertEqual(value, "https://example.com/")
        self.assertNotIn("customer-42", value)
        self.assertNotIn("private", value)

    def test_rejects_internal_addresses_and_names(self):
        for value in (
            "http://127.0.0.1/",
            "http://10.0.0.8/",
            "http://[::1]/",
            "http://service.local/",
            "http://example.invalid/",
        ):
            with self.subTest(value=value), self.assertRaises(URLPolicyError):
                normalize_public_http_url(value)

    def test_rejects_non_http_schemes_credentials_and_nonstandard_ports(self):
        for value in (
            "javascript:alert(1)",
            "https://user:password@example.com/",
            "https://example.com:8443/",
            "ftp://example.com/file",
        ):
            with self.subTest(value=value), self.assertRaises(URLPolicyError):
                normalize_public_http_url(value)

    def test_rejects_control_characters_and_oversized_urls(self):
        for value in ("https://example.com/\npath", "https://example.com/" + "x" * 2048):
            with self.subTest(length=len(value)), self.assertRaises(URLPolicyError):
                normalize_public_http_url(value)


if __name__ == "__main__":
    unittest.main()
