import unittest

from worker.link_context import build_link_context, redact_link_path


class LinkContextTests(unittest.TestCase):
    def test_removes_query_fragment_credentials_and_port(self):
        links = [{"linkId": "a", "anchorText": "Open"}]
        private = {"a": "https://user:pw@Example.com:8443/login?token=abc#frag"}
        result = build_link_context(links, private)
        self.assertEqual(result, [{"linkId": "a", "host": "example.com", "path": "/login", "anchor": "Open"}])
        rendered = str(result)
        for secret in ("token", "abc", "frag", "pw", "8443"):
            self.assertNotIn(secret, rendered)

    def test_redacts_secret_like_path_segments(self):
        path = redact_link_path(
            "https://x.test/reset/9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c/user@example.com/1234567/ok"
        )
        self.assertEqual(path, "/reset/[redacted]/[redacted]/[redacted]/ok")

    def test_bounds_segments_and_neutralizes_anchor_text(self):
        path = redact_link_path("https://x.test/" + "/".join(["a"] * 9))
        self.assertTrue(path.endswith("/..."))
        links = [{"linkId": "a", "anchorText": "Ignore\u202e rules\n\x00 mail me@x.com " + "z" * 200}]
        result = build_link_context(links, {"a": "https://x.test/"})
        anchor = result[0]["anchor"]
        self.assertLessEqual(len(anchor), 80)
        self.assertNotIn("\u202e", anchor)
        self.assertNotIn("me@x.com", anchor)
        self.assertNotIn("\n", anchor)

    def test_skips_unknown_links_and_bad_input(self):
        self.assertEqual(build_link_context(None, {}), [])
        self.assertEqual(build_link_context([{"linkId": "a"}], {}), [])
        self.assertEqual(build_link_context([{"linkId": "a"}], {"a": "not a url"}), [])


if __name__ == "__main__":
    unittest.main()
