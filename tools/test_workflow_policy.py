"""Supply-chain policy checks for every GitHub Actions workflow."""

import json
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
        verify = (
            'ARGS=(.. "${{ runner.temp }}/loom-public-cut" '
            '--output exact-cut-ci.json --suite-output full-test-timings.json '
            '--failure-diagnostic-output serial-failure-diagnostic.json '
            '--progress-diagnostic-output serial-progress-diagnostic.json)')
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
        self.assertIn("provenance_path.write_bytes(", helper)
        self.assertIn('.encode("utf-8") + b"\\n"', helper)
        self.assertIn("ensure_ascii=False", helper)
        self.assertNotIn("provenance_path.write_text(", helper)
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
        invocation = re.search(r"ARGS=\(\.\. [^\n]+\)", quality)
        self.assertIsNotNone(invocation)
        command = invocation.group(0)
        self.assertIn("--output exact-cut-ci.json", command)
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

    def test_release_and_publication_require_exact_origin_main_ancestry(self):
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        publish = (WORKFLOWS / "publish-release.yml").read_text(encoding="utf-8")
        combined = release + "\n" + publish
        self.assertNotIn("git branch -r --contains", combined)
        self.assertNotIn("grep -q 'origin/main'", combined)
        self.assertEqual(
            3,
            combined.count(
                'git merge-base --is-ancestor "$GITHUB_SHA" '
                "refs/remotes/origin/main"))
        self.assertNotIn("refs/remotes/origin/main-staging", combined)

    def test_active_authority_routes_normal_ci_without_losing_serial_admission(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        compatibility = (WORKFLOWS / "compatibility.yml").read_text(encoding="utf-8")
        authority = json.loads((
            ROOT / "contracts" / "release-authority-policy-v2.json").read_text(
                encoding="utf-8"))
        historical = json.loads((
            ROOT / "contracts" / "release-suite-policy-v1.json").read_text(
                encoding="utf-8"))
        qualification = (
            ROOT / "contracts" / "release-mechanism-qualification-v2.json"
        )
        public_manifest = ROOT / "BUILD-MANIFEST.json"
        if public_manifest.is_file():
            self.assertFalse((ROOT / ".git").exists())
            manifest = json.loads(public_manifest.read_text(encoding="utf-8"))
            paths = {
                row["path"] for row in manifest["files"]
                if isinstance(row, dict) and isinstance(row.get("path"), str)
            }
            self.assertFalse(qualification.is_file())
            self.assertNotIn(
                "contracts/release-mechanism-qualification-v2.json", paths)
        else:
            self.assertEqual(
                "certificate" if qualification.is_file() else "serial",
                authority["authority_mode"])
        self.assertEqual("serial", historical["authority_mode"])
        for text in (quality, compatibility):
            self.assertIn("release-authority-policy-v2.json", text)
            self.assertEqual(2, text.count("id: suite-route"))
            self.assertIn("EXECUTION=serial-shadow", text)
            self.assertIn("EXECUTION=certificate", text)
            self.assertIn('echo "execution=$EXECUTION"', text)
            self.assertIn('test "$EVENT_NAME" = workflow_dispatch', text)
            self.assertIn('test "$EVENT_NAME" = push', text)
            self.assertIn("loom_suite_certificate.py shadow-cell", text)
            self.assertIn("loom_suite_certificate.py run-cell", text)
            self.assertIn("--static-only", text)
            self.assertIn(
                "steps.suite-route.outputs.execution == 'serial-shadow'", text)
            self.assertIn(
                "steps.suite-route.outputs.execution == 'certificate'", text)
            self.assertIn("release-mechanism-qualification-v2.json", text)
            self.assertIn("verify-mechanism", text)
            self.assertIn("EXPECTED_COMPARISONS=0", text)
            self.assertIn("EXPECTED_COMPARISONS=15", text)
            self.assertIn("release-suite-timing-profile-v1.json", text)
            self.assertNotIn("cancel-in-progress: true", text)
        self.assertNotIn('test "$EVENT_NAME" = schedule', quality)
        self.assertIn('test "$EVENT_NAME" = schedule', compatibility)
        self.assertIn("quality-matrix-certificate", quality)
        self.assertIn("compatibility-matrix-certificate", compatibility)
        self.assertIn("--serial-suite full-test-timings.json", compatibility)
        self.assertIn(
            "--suite-certificate suite-shadow/cell-certificate.json",
            compatibility)

    def test_full_suite_cells_transport_closed_failure_diagnostics(self):
        quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
        compatibility = (WORKFLOWS / "compatibility.yml").read_text(
            encoding="utf-8")
        for text in (quality, compatibility):
            self.assertIn(
                "--failure-diagnostic-output serial-failure-diagnostic.json",
                text)
            self.assertIn(
                "--progress-diagnostic-output serial-progress-diagnostic.json",
                text)
            self.assertIn(
                "tools/serial-failure-diagnostic.json", text)
            self.assertIn(
                "tools/serial-progress-diagnostic.json", text)
            self.assertIn(
                "tools/suite-shadow/workers/*/worker-receipt.json", text)
            self.assertIn(
                "tools/suite-shadow/workers/*/failure-diagnostic.json", text)
            self.assertIn("permissions:\n  contents: read", text)
            self.assertIn("retention-days: 7", text)
            self.assertIn("if: always()", text)
            self.assertNotIn("serial-progress-diagnostic.json --", text)
        self.assertIn(
            'os: [ubuntu-latest, macos-latest, windows-latest]', quality)
        self.assertIn(
            'python: ["3.10", "3.11", "3.12", "3.13", "3.14"]', quality)
        self.assertEqual(6, compatibility.count("- {runner:"))

    def test_v2_candidate_and_mechanism_workflows_are_strictly_separated(self):
        candidate_quality = (WORKFLOWS / "quality.yml").read_text(
            encoding="utf-8")
        candidate_compatibility = (WORKFLOWS / "compatibility.yml").read_text(
            encoding="utf-8")
        for consumer in ("quality", "compatibility"):
            path = WORKFLOWS / f"qualification-{consumer}.yml"
            self.assertTrue(path.is_file())
            text = path.read_text(encoding="utf-8")
            trigger = text[text.index("on:"):text.index("permissions:")]
            self.assertIn("workflow_dispatch:", trigger)
            self.assertNotIn("push:", trigger)
            self.assertNotIn("pull_request:", trigger)
            self.assertNotIn("schedule:", trigger)
            self.assertNotIn("workflow_call:", trigger)
            self.assertNotIn("inputs:", trigger)
            self.assertIn("permissions:\n  contents: read", text)
            self.assertIn("loom_qualification_v2.py run-observation", text)
            self.assertIn("ARGS=(compile-batch", text)
            self.assertIn(
                "release-qualification-workload-policy-v2.json", text)
            self.assertIn("release-qualification-manifest-v2.json", text)
            self.assertNotIn("loom_exact_cut_ci.py", text)
            self.assertNotIn("loom_release_candidate.py", text)
            self.assertNotIn("native-helpers:", text)
            self.assertNotIn("cargo build", text)
        fault_path = WORKFLOWS / "qualification-faults.yml"
        self.assertTrue(fault_path.is_file())
        fault = fault_path.read_text(encoding="utf-8")
        fault_trigger = fault[fault.index("on:"):fault.index("permissions:")]
        self.assertIn("workflow_dispatch:", fault_trigger)
        self.assertNotIn("push:", fault_trigger)
        self.assertNotIn("pull_request:", fault_trigger)
        self.assertNotIn("schedule:", fault_trigger)
        self.assertIn("permissions:\n  contents: read", fault)
        self.assertIn("loom_qualification_v2.py run-fault-corpus", fault)
        self.assertEqual(3, fault.count("- {runner:"))
        self.assertNotIn("loom_exact_cut_ci.py", fault)
        self.assertNotIn("cargo build", fault)
        for text in (candidate_quality, candidate_compatibility):
            self.assertIn("release-authority-policy-v2.json", text)
            self.assertIn("loom_suite_certificate.py shadow-cell", text)
            self.assertIn("compile-candidate-bundle --root", text)
            self.assertIn("loom_qualification_v2.py \"${ARGS[@]}\"", text)
            self.assertIn("loom_suite_certificate.py run-cell", text)
            self.assertIn("--static-only", text)
            self.assertNotIn("loom_qualification_v2.py run-observation", text)
            self.assertIn("release-mechanism-qualification-v2.json", text)
        self.assertEqual(6, candidate_compatibility.count("- {runner:"))
        admission_path = WORKFLOWS / "candidate-admission.yml"
        self.assertTrue(admission_path.is_file())
        admission = admission_path.read_text(encoding="utf-8")
        admission_trigger = admission[
            admission.index("on:"):admission.index("permissions:")]
        self.assertIn("workflow_dispatch:", admission_trigger)
        self.assertNotIn("inputs:", admission_trigger)
        self.assertIn("actions: read", admission)
        self.assertIn("contents: read", admission)
        self.assertNotIn("contents: write", admission)
        self.assertIn("exact_success('quality.yml')", admission)
        self.assertIn("exact_success('compatibility.yml')", admission)
        self.assertIn("compile-candidate --root", admission)
        self.assertIn("loom_qualification_v2.py \"${ARGS[@]}\"", admission)
        self.assertIn("VERIFY=(verify-candidate --root", admission)
        self.assertIn("loom_qualification_v2.py \"${VERIFY[@]}\"", admission)
        self.assertNotIn("loom_test.py", admission)
        self.assertNotIn("cargo build", admission)

        equivalence_path = WORKFLOWS / "candidate-equivalence.yml"
        self.assertTrue(equivalence_path.is_file())
        equivalence = equivalence_path.read_text(encoding="utf-8")
        equivalence_trigger = equivalence[
            equivalence.index("on:"):equivalence.index("permissions:")]
        self.assertIn("workflow_run:", equivalence_trigger)
        self.assertIn("native-compatibility", equivalence_trigger)
        self.assertIn("types: [completed]", equivalence_trigger)
        self.assertIn("branches: [main]", equivalence_trigger)
        self.assertIn("actions: read", equivalence)
        self.assertIn("contents: read", equivalence)
        self.assertNotIn("contents: write", equivalence)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", equivalence)
        self.assertIn("github.event.workflow_run.event == 'push'", equivalence)
        self.assertIn("if len(matches) != 1:", equivalence)
        self.assertNotIn("selected = max(matches", equivalence)
        self.assertIn("candidate-admission-v2-${REVIEWED_COMMIT}", equivalence)
        self.assertIn("native-helper-*-${MERGE_COMMIT}", equivalence)
        self.assertIn("compile-equivalence", equivalence)
        self.assertIn("compile-rebound-candidate", equivalence)
        self.assertIn("verify-candidate", equivalence)
        self.assertIn(
            "candidate-admission-v2-${{ github.event.workflow_run.head_sha }}",
            equivalence)
        self.assertNotIn("loom_test.py", equivalence)
        self.assertNotIn("cargo build", equivalence)

        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("candidate-equivalence.yml", release)
        self.assertIn("candidate-admission.yml", release)
        self.assertIn("candidate admission fallback", release)
        self.assertIn("/actions/runs/{run_id}/artifacts", release)
        self.assertIn("candidate-admission-v2-{sha}", release)
        self.assertIn("not artifact.get('expired', False)", release)

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

    def test_release_publication_and_post_release_consume_the_separated_v2_chain(self):
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        publish = (WORKFLOWS / "publish-release.yml").read_text(
            encoding="utf-8")
        post = (WORKFLOWS / "post-release.yml").read_text(encoding="utf-8")
        self.assertIn("candidate-admission-v2-${LOOM_SOURCE_SHA}", release)
        self.assertIn("candidate-admission-v2.json", release)
        self.assertIn("loom_release_certificate.py record-tag", release)
        self.assertIn("loom_release_certificate.py record-tag", publish)
        self.assertIn("loom_release_certificate.py record-tag", post)
        self.assertIn("loom_release_certificate.py compile", release)
        self.assertIn("loom_release_certificate.py verify", release)
        self.assertIn("loom_release_authority.py candidate-suite", release)
        self.assertIn("loom_release_authority.py release-authority", release)
        self.assertIn("loom_release_authority.py verify", release)
        for name in (
                "candidate-admission-v2.json",
                "release-candidate-suite-v2.json",
                "release-certificate-v2.json",
                "release-authority-v2.json"):
            self.assertIn(name, release)
            self.assertIn(name, publish)
            self.assertIn(name, post)
        for text in (release, publish, post):
            self.assertIn("release-authority-policy-v2.json", text)
            self.assertIn("loom_release_authority.py verify", text)
            self.assertIn("loom_release_certificate.py verify", text)
            self.assertNotIn("run-observation", text)
            self.assertNotIn("compile-mechanism", text)
            self.assertNotIn("release-qualification-observation-v2", text)
            self.assertNotIn("release-qualification-batch-v2", text)
        self.assertIn("release-mechanism-qualification-v2.json", release)
        self.assertIn("release-mechanism-qualification-v2.json", publish)
        self.assertIn("release-mechanism-qualification-v2.json", post)
        self.assertNotIn("loom_test.py", publish)
        self.assertIn(
            "if: steps.installed-subject.outputs.rerun_required == 'true'",
            post)
        self.assertNotIn("cargo build", publish)
        self.assertNotIn("cargo build", post)


if __name__ == "__main__":
    unittest.main()
