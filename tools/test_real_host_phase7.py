import subprocess
import unittest

import loom_host_registry
import loom_real_host


class RealHostPhase7Tests(unittest.TestCase):
    def test_discovery_never_claims_real_host_invocation(self):
        result = loom_real_host.discover(
            "codex", which=lambda _name: "codex",
            run=lambda *_args, **_kwargs: subprocess.CompletedProcess(
                ["codex", "--version"], 0, "codex-cli test\n", ""))
        self.assertEqual("detected", result["status"])
        self.assertEqual(2, result["schema_version"])
        self.assertEqual("loom-host-contracts-v2", result["contract_id"])
        self.assertEqual(["app", "cli", "ide"], result["surfaces"])
        self.assertEqual(30, result["proof_ttl_days"])
        self.assertEqual("host-observed", result["evidence_class"])
        self.assertIn("not a Loom invocation", result["limitations"][0])

    def test_absent_and_unsupported_hosts_remain_honest(self):
        absent = loom_real_host.discover("factory-droid", which=lambda _name: None)
        self.assertEqual("not-detected", absent["status"])
        self.assertEqual("unsupported",
                         loom_host_registry.contract("factory-droid")["evidence_status"])

    def test_contract_statuses_match_the_versioned_registry(self):
        for host in ("codex", "claude-code", "opencode", "copilot"):
            self.assertEqual("documented", loom_host_registry.contract(host)["contract_status"])
        self.assertEqual("stale", loom_host_registry.contract("gemini-cli")["contract_status"])
        self.assertEqual("experimental",
                         loom_host_registry.contract("factory-droid")["contract_status"])

    def test_fallback_executable_uses_the_contract_arguments(self):
        seen = []

        def finder(name):
            return "cursor" if name == "cursor" else None

        def run(command, **_kwargs):
            seen.append(command)
            return subprocess.CompletedProcess(command, 0, "cursor test\n", "")

        result = loom_real_host.discover("cursor", which=finder, run=run)
        self.assertEqual(["cursor", "--version"], seen[0])
        self.assertEqual("experimental", result["contract_status"])


if __name__ == "__main__":
    unittest.main()
