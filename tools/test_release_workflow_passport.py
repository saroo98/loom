"""Static release-workflow contract tests for exact passport publication."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowPassportTests(unittest.TestCase):
    def test_passport_is_generated_only_after_exact_artifacts_and_attestation(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8")
        order = [
            "Run exact source suite and rollback battery",
            "Download existing draft assets without publishing",
            "Verify canonical archive and checksums",
            "Expand exact native release evidence",
            "Build the bounded attestation subject",
            "attest-evidence-subject",
            "Verify attestation and compile the exact release passport",
            "Publish exact release passport assets to the draft",
        ]
        offsets = [text.index(item) for item in order]
        self.assertEqual(sorted(offsets), offsets)

    def test_release_passport_assets_are_authenticated_and_published(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8")
        for expected in (
                "RELEASE-READINESS.json", "RELEASE-EVIDENCE-SUBJECT.json",
                "RELEASE-EVIDENCE-ATTESTATION.json", "loom_release_passport.py",
                "loom_release_rollback.py", "subject-checksums:"):
            self.assertIn(expected, text)
        self.assertIn('gh release upload "$RELEASE_TAG"', text)


if __name__ == "__main__":
    unittest.main()
