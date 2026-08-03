"""Supply-chain policy checks for every GitHub Actions workflow."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


class WorkflowPolicyTests(unittest.TestCase):
    @staticmethod
    def _run_expression_findings(path):
        findings = []
        lines = path.read_text(encoding="utf-8").splitlines()
        run_indent = None
        for line_number, line in enumerate(lines, 1):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if run_indent is not None and stripped and indent <= run_indent:
                run_indent = None
            if re.match(r"^run:\s*", stripped):
                run_indent = indent
                if "${{ inputs." in stripped:
                    findings.append(f"{path.name}:{line_number}")
            elif run_indent is not None and "${{ inputs." in line:
                findings.append(f"{path.name}:{line_number}")
        return findings

    def test_every_external_action_is_pinned_to_a_full_commit_sha(self):
        findings = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                match = re.search(r"^\s*-\s+uses:\s+([^\s#]+)", line)
                if not match or match.group(1).startswith("./"):
                    continue
                reference = match.group(1)
                if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference):
                    findings.append(f"{path.name}:{line_number}:{reference}")
        self.assertEqual([], findings)

    def test_workflows_are_bounded_and_prs_have_no_release_authority(self):
        combined = "\n".join(
            path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.yml")))
        self.assertNotIn("pull_request_target:", combined)
        self.assertNotRegex(combined, r"(?m)^\s*permissions:\s*write-all\s*$")
        self.assertNotRegex(combined, r"(?m)^\s*uses:\s+[^\s]+@(v\d+|main|master|stable)\s*$")
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        self.assertGreaterEqual(quality.count("timeout-minutes:"), 3)
        self.assertEqual(
            quality.count("uses: actions/checkout@"),
            quality.count("persist-credentials: false"))
        self.assertNotIn("contents: write", quality)
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("environment: loom-release", release)
        self.assertIn("confirm_draft_only", release)
        self.assertNotIn("gh release create", release)
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            self.assertRegex(text, r"(?m)^\s+timeout-minutes:\s+\d+")
            if path.name not in {"release.yml", "publish-release.yml"}:
                self.assertNotIn("contents: write", text)

    def test_dispatch_and_reusable_inputs_are_never_interpolated_into_shell(self):
        findings = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            findings.extend(self._run_expression_findings(path))
        self.assertEqual([], findings)
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn('[[ "$RELEASE_TAG" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]', release)
        self.assertIn(
            "LOOM_RELEASE_SIGNING_PUBLIC_KEY: "
            "${{ vars.LOOM_RELEASE_SIGNING_PUBLIC_KEY }}", release)
        self.assertIn("loom-release@users.noreply.github.com", release)
        self.assertIn("git config gpg.format ssh", release)
        self.assertIn("git config gpg.ssh.allowedSignersFile", release)
        self.assertIn("git verify-tag", release)
        self.assertLess(
            release.index("git config gpg.ssh.allowedSignersFile"),
            release.index("git verify-tag"))
        helper = (WORKFLOWS / "build-helper.yml").read_text(encoding="utf-8")
        self.assertIn("LOOM_SOURCE_SHA: ${{ github.sha }}", helper)
        self.assertIn("printf '%s' \"$LOOM_SOURCE_SHA\" | sha256sum", helper)
        self.assertNotIn('--namespace-seed "${{ github.sha }}"', helper)

    def test_compatibility_matrix_builds_and_serially_verifies_one_exact_cut(self):
        compatibility = (WORKFLOWS / "compatibility.yml").read_text(encoding="utf-8")
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        verify = 'ARGS=(.. "${{ runner.temp }}/loom-public-cut" --output exact-cut-ci.json)'
        self.assertIn(verify, compatibility)
        self.assertNotIn("loom_release.py verify-cut ..", compatibility)
        self.assertIn("--serial-suite full-test-timings.json", compatibility)
        self.assertIn("loom_suite_certificate.py shadow-cell", compatibility)
        for workflow in (quality, compatibility):
            self.assertIn("tools/suite-shadow/cell-certificate.json", workflow)
            self.assertIn("tools/suite-shadow/shadow-comparison.json", workflow)
            self.assertNotIn("            tools/suite-shadow/\n", workflow)
            self.assertIn("SHADOW_OK=1", workflow)
            self.assertIn('test "$SHADOW_OK" -eq 1', workflow)
            self.assertIn('["status"])\' "$comparison")" = matched', workflow)

    def test_native_reproducibility_rebuilds_at_one_private_path(self):
        helper = (WORKFLOWS / "build-helper.yml").read_text(encoding="utf-8")
        self.assertIn("LOOM_BUILD_TARGET: ${{ runner.temp }}/loom-repro-build", helper)
        self.assertIn("export RUST_MIN_STACK=67108864", helper)
        self.assertEqual(2, helper.count('CARGO_TARGET_DIR="$LOOM_BUILD_TARGET" cargo build'))
        self.assertNotIn("loom-build-a", helper)
        self.assertNotIn("loom-build-b", helper)
        self.assertIn('"rebuild_sha256": digest(rebuild)', helper)
        self.assertIn('"provenance_sha256": digest(provenance_path)', helper)
        self.assertIn('"independent_build": True', helper)
        self.assertIn(
            'Path(".").resolve(), os.environ["LOOM_SOURCE_SHA"], source_digest,',
            helper,
        )

    def test_exact_cut_forbidden_token_cannot_match_shipped_workflow_bytes(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        self.assertNotIn("__ci_public_scan_sentinel_9f4c2d__", quality)
        self.assertIn(
            'loom-ci-${{ github.sha }}',
            quality,
        )

    def test_capability_matrix_uses_one_exact_publication_subject(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        invocation = re.search(r"ARGS=\(\.\. [^\n]+--output exact-cut-ci\.json\)", quality)
        self.assertIsNotNone(invocation)
        command = invocation.group(0)
        self.assertIn('--forbidden-token "loom-ci-${{ github.sha }}"', command)
        self.assertNotIn("${{ matrix.os }}", command)
        self.assertNotIn("${{ matrix.python }}", command)

    def test_fast_gate_preserves_primary_failure_without_missing_artifact_noise(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        self.assertIn("Verify successful fast-gate artifacts", quality)
        self.assertIn(
            "test -f fast-test-timings.json -a -f adapter-conformance.json "
            "-a -f performance-micro.json",
            quality,
        )
        self.assertEqual(2, quality.count("if-no-files-found: ignore"))

    def test_quality_avoids_duplicate_feature_pushes_without_weakening_main(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        trigger = "on:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\n  workflow_dispatch:\n"
        self.assertIn(trigger, quality)
        self.assertIn("if: github.event_name != 'pull_request'", quality)
        self.assertIn('os: [ubuntu-latest, macos-latest, windows-latest]', quality)
        self.assertIn('python: ["3.10", "3.11", "3.12", "3.13", "3.14"]', quality)
        self.assertIn("if: github.event_name != 'pull_request'", quality)
        self.assertIn("loom_test.py fast --output fast-test-timings.json", quality)
        self.assertNotIn("loom_test.py fast --max-seconds", quality)

    def test_release_suite_imports_exact_main_capability_evidence(self):
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("actions: read", release)
        self.assertIn('["gh", "run", "list"', release)
        self.assertIn("exact_success('quality.yml')", release)
        self.assertIn("gh run download", release)
        self.assertIn("loom_release_suite.py", release)
        self.assertIn("$RUNNER_TEMP/cut-receipt.json", release)
        self.assertNotIn("python -B loom_test.py full", release)
        self.assertIn("--serial-evidence-only", release)
        self.assertNotIn("--clobber", release)
        self.assertIn("loom_release_candidate.py reconstruct", release)
        self.assertIn('native-helper-*-${GITHUB_SHA}', release)
        self.assertIn("stage-draft-assets:", release)
        self.assertEqual(1, release.count("contents: write"))
        self.assertLess(release.index("stage-draft-assets:"),
                        release.index("contents: write"))
        self.assertIn("gh attestation verify \"$asset\"", release)
        self.assertIn("immutable-releases", release)

    def test_serial_authority_and_shadow_topology_are_explicit(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        compatibility = (WORKFLOWS / "compatibility.yml").read_text(encoding="utf-8")
        policy = (ROOT / "contracts" / "release-suite-policy-v1.json").read_text(
            encoding="utf-8")
        self.assertIn('"authority_mode":"serial"', policy.replace(" ", ""))
        for text in (quality, compatibility):
            self.assertIn("loom_suite_certificate.py shadow-cell", text)
            self.assertIn("loom_suite_certificate.py run-cell", text)
            self.assertIn("--static-only", text)
            self.assertIn("release-suite-timing-profile-v1.json", text)
        self.assertIn("quality-matrix-certificate", quality)
        self.assertIn("compatibility-matrix-certificate", compatibility)

    def test_full_suite_cells_transport_optional_closed_worker_diagnostics(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        compatibility = (WORKFLOWS / "compatibility.yml").read_text(
            encoding="utf-8")
        for text in (quality, compatibility):
            self.assertIn(
                "tools/suite-shadow/workers/*/worker-receipt.json", text)
            self.assertIn(
                "tools/suite-shadow/workers/*/failure-diagnostic.json", text)
            self.assertIn("permissions:\n  contents: read", text)
            self.assertIn("retention-days: 7", text)
            self.assertIn("if: always()", text)
            self.assertNotIn("failure-diagnostic.json --", text)
        self.assertIn(
            'os: [ubuntu-latest, macos-latest, windows-latest]', quality)
        self.assertIn(
            'python: ["3.10", "3.11", "3.12", "3.13", "3.14"]', quality)
        self.assertEqual(6, compatibility.count("- {runner:"))

    def test_publication_and_post_release_are_same_byte_gates(self):
        publish = (WORKFLOWS / "publish-release.yml").read_text(encoding="utf-8")
        post = (WORKFLOWS / "post-release.yml").read_text(encoding="utf-8")
        self.assertIn("environment: loom-release-publish", publish)
        self.assertIn("loom_release_promotion.py verify-draft", publish)
        self.assertIn("loom_release_suite.py --verify", publish)
        self.assertNotIn("actions: read", publish)
        self.assertEqual(2, publish.count("verify-asset-set"))
        self.assertLess(
            publish.index("verify-asset-set"),
            publish.index('gh release edit "$RELEASE_TAG" --draft=false'))
        self.assertGreater(
            publish.rindex("verify-asset-set"),
            publish.index('gh release edit "$RELEASE_TAG" --draft=false'))
        self.assertIn("gh release edit \"$RELEASE_TAG\" --draft=false", publish)
        self.assertNotIn("gh release upload", publish)
        self.assertNotIn("loom_release.py build", publish)
        self.assertNotIn("rm -f", publish)
        self.assertIn("represented-installed-subject", post)
        self.assertIn("installed/scripts/loom_bootstrap.py --ensure", post)
        self.assertIn("installed runtime selected the wrong native helper", post)
        self.assertIn("installed launcher entry point failed", post)
        self.assertIn("steps.installed-subject.outputs.runtime_tools", post)
        self.assertIn('"status":"pre-installation"', (
            WORKFLOWS / "release.yml").read_text(encoding="utf-8").replace(" ", ""))


if __name__ == "__main__":
    unittest.main()
