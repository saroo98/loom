"""Static release-workflow contract tests for exact passport publication."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowPassportTests(unittest.TestCase):
    def test_candidates_are_reproduced_in_two_independent_clean_jobs(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8")
        self.assertIn("reproduce-candidates:", text)
        self.assertIn("candidate: A", text)
        self.assertIn("candidate: B", text)
        self.assertIn("needs: reproduce-candidates", text)
        self.assertIn("loom_release_candidate.py compare", text)

    def test_passport_is_generated_only_after_exact_artifacts_and_attestation(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8")
        order = [
            "Compile existing serial authority and run rollback battery",
            "Download existing draft assets without publishing",
            "Verify canonical base assets without a final manifest",
            "Expand exact native release evidence",
            "Build the bounded attestation subject",
            "attest-evidence-subject",
            "Verify attestation and compile the exact release passport",
            "Prepare exact release passport assets for protected staging",
            "stage-draft-assets:",
            "Revalidate and stage exact assets without overwrite",
        ]
        offsets = [text.index(item) for item in order]
        self.assertEqual(sorted(offsets), offsets)

    def test_release_passport_assets_are_authenticated_and_published(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8")
        for expected in (
                "RELEASE-READINESS.json", "RELEASE-EVIDENCE-SUBJECT.json",
                "RELEASE-EVIDENCE-ATTESTATION.json", "loom_release_passport.py",
                "loom_release_rollback.py", "CODEX-APP-EVIDENCE.json",
                "--codex-observation", "subject-checksums:"):
            self.assertIn(expected, text)
        self.assertIn('gh release upload "$RELEASE_TAG" "$asset"', text)
        self.assertNotIn("--clobber", text)

    def test_preexisting_draft_uses_base_validation_then_one_final_manifest(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8")
        required = (
            "Download existing draft assets without publishing",
            "verify-base-assets", "create-asset-manifest",
            'gh release upload "$RELEASE_TAG" release-passport/SHA256SUMS',
        )
        offsets = [text.find(item) for item in required]

        self.assertTrue(all(offset >= 0 for offset in offsets), offsets)
        self.assertEqual(sorted(offsets), offsets)
        self.assertNotIn("sha256sum --check SHA256SUMS", text)
        self.assertEqual(1, text.count("create-asset-manifest"))
        self.assertEqual(1, text.count(
            'gh release upload "$RELEASE_TAG" release-passport/SHA256SUMS'))
        self.assertEqual(1, text.count("--defer-checksum-manifest"))
        self.assertEqual(6, text.count('--tag "$RELEASE_TAG"'))
        for name in (
                "CODEX-APP-EVIDENCE.json", "RELEASE-SUBJECT.json",
                "loom-plugin-${RELEASE_TAG}.zip",
                "loom-plugin-${RELEASE_TAG}-repro.zip",
                "native-evidence-${platform}.zip", "RELEASE-READINESS.json",
                "RELEASE-EVIDENCE.json", "RELEASE-EVIDENCE-GRAPH.json",
                "RELEASE-EVIDENCE-SUBJECT.json",
                "RELEASE-EVIDENCE-ATTESTATION.json",
                "quality-matrix-certificate.json",
                "compatibility-matrix-certificate.json",
                "candidate-admission-v2.json",
                "release-candidate-suite-v2.json",
                "release-tag-evidence-v2.json",
                "release-certificate-v2.json",
                "release-authority-v2.json"):
            self.assertIn(name, text)

    def test_v4_verification_runs_only_after_actual_evidence_exists(self):
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8")
        verify_name = "Verify v4 subject against actual release evidence"
        required = (
            "--reproducibility-receipt", "--suite-certificate",
            "--suite-policy", "--promotion-policy", "--exact-cut-receipt",
        )
        self.assertIn(verify_name, release)
        self.assertLess(
            release.index("Compare independent candidate A and B"),
            release.index(verify_name))
        self.assertLess(
            release.index(verify_name),
            release.index("Verify attestation and compile the exact release passport"))
        for option in required:
            self.assertGreaterEqual(release.count(option), 2)
        self.assertIn("exact-cut-ci.json", release)

        for workflow in ("publish-release.yml", "post-release.yml"):
            text = (ROOT / ".github" / "workflows" / workflow).read_text(
                encoding="utf-8")
            for option in required:
                self.assertIn(option, text)


if __name__ == "__main__":
    unittest.main()
