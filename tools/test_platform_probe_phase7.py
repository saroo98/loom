import unittest

import loom_platform_probe


class PlatformProbePhase7Tests(unittest.TestCase):
    def test_local_probe_is_honest_and_content_bound(self):
        result = loom_platform_probe.collect()
        self.assertEqual("mechanical-local", result["evidence_class"])
        self.assertEqual("supported", result["filesystem_capabilities"]["atomic_replace"])
        self.assertIn(result["filesystem_capabilities"]["fifo"],
                      {"supported", "unavailable"})
        self.assertEqual(64, len(result["receipt_sha256"]))

    def test_named_runner_requires_a_bound_workflow_digest(self):
        with self.assertRaises(ValueError):
            loom_platform_probe.collect(runner="test-runner")
        result = loom_platform_probe.collect(
            runner="test-runner", workflow_digest="a" * 64)
        self.assertEqual("ci-reproduced", result["evidence_class"])
        self.assertEqual("test-runner", result["runner"])

    def test_workflow_digest_without_runner_is_refused(self):
        with self.assertRaises(ValueError):
            loom_platform_probe.collect(workflow_digest="a" * 64)

    def test_release_environment_binds_requested_and_resolved_identity(self):
        result = loom_platform_probe.release_environment(
            requested_label="macos-latest",
            image_os="macos26",
            image_version="20260728.001",
            workflow_path=".github/workflows/quality.yml",
            workflow_digest="a" * 64,
            action_manifest_digest="b" * 64,
            event_name="push",
            run_id="30701659488",
            run_attempt="2",
        )
        self.assertEqual("macos-latest", result["requested_label"])
        self.assertEqual("macos26", result["image_os"])
        self.assertNotEqual(result["requested_label"], result["image_os"])
        self.assertEqual("2", result["run_attempt"])
        self.assertRegex(result["environment_sha256"], r"^[0-9a-f]{64}$")

    def test_release_environment_rejects_incomplete_ci_identity(self):
        with self.assertRaises(ValueError):
            loom_platform_probe.release_environment(
                requested_label="ubuntu-24.04",
                image_os="ubuntu24",
                image_version="20260720.1",
                workflow_path=".github/workflows/quality.yml",
                workflow_digest="a" * 64,
                action_manifest_digest=None,
                event_name="push",
                run_id="1",
                run_attempt="1",
            )


if __name__ == "__main__":
    unittest.main()
