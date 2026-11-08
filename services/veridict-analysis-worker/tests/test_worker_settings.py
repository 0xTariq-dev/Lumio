import unittest

from worker.settings import WorkerSettings


class WorkerSettingsTests(unittest.TestCase):
    def test_accepts_optional_local_tag_when_digest_is_pinned(self):
        settings = WorkerSettings(
            token="x" * 40,
            guest_image="registry.example/guest@sha256:" + "a" * 64,
            guest_image_local="veridict-analysis-guest:2026-11-08",
        )

        self.assertTrue(settings.is_configured)

    def test_rejects_invalid_local_image_reference(self):
        settings = WorkerSettings(
            token="x" * 40,
            guest_image="registry.example/guest@sha256:" + "a" * 64,
            guest_image_local="--help",
        )

        self.assertFalse(settings.is_configured)

