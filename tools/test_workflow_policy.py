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
            if path.name != "release.yml":
                self.assertNotIn("contents: write", text)

    def test_dispatch_and_reusable_inputs_are_never_interpolated_into_shell(self):
        findings = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            findings.extend(self._run_expression_findings(path))
        self.assertEqual([], findings)
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn('[[ "$RELEASE_TAG" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]', release)
        helper = (WORKFLOWS / "build-helper.yml").read_text(encoding="utf-8")
        self.assertIn("LOOM_SOURCE_SHA: ${{ github.sha }}", helper)
        self.assertIn("printf '%s' \"$LOOM_SOURCE_SHA\" | sha256sum", helper)
        self.assertNotIn('--namespace-seed "${{ github.sha }}"', helper)

    def test_compatibility_matrix_builds_before_it_verifies_the_exact_cut(self):
        compatibility = (WORKFLOWS / "compatibility.yml").read_text(encoding="utf-8")
        build = "loom_release.py build .. \"${{ runner.temp }}/loom-public-cut\""
        verify = "loom_release.py verify-cut \"${{ runner.temp }}/loom-public-cut\""
        self.assertIn(build, compatibility)
        self.assertIn(verify, compatibility)
        self.assertLess(compatibility.index(build), compatibility.index(verify))
        self.assertNotIn("loom_release.py verify-cut ..", compatibility)

    def test_exact_cut_forbidden_token_cannot_match_shipped_workflow_bytes(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        self.assertNotIn("__ci_public_scan_sentinel_9f4c2d__", quality)
        self.assertIn(
            'loom-ci-${{ github.run_id }}-${{ matrix.os }}-py${{ matrix.python }}',
            quality,
        )

    def test_fast_gate_preserves_primary_failure_without_missing_artifact_noise(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        self.assertIn("Verify successful fast-gate artifacts", quality)
        self.assertIn(
            "test -f fast-test-timings.json -a -f adapter-conformance.json "
            "-a -f performance-micro.json",
            quality,
        )
        self.assertEqual(2, quality.count("if-no-files-found: ignore"))


if __name__ == "__main__":
    unittest.main()
