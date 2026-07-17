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
        self.assertEqual("host-observed", result["evidence_class"])
        self.assertIn("not a Loom invocation", result["limitations"][0])

    def test_absent_and_unsupported_hosts_remain_honest(self):
        absent = loom_real_host.discover("factory-droid", which=lambda _name: None)
        self.assertEqual("not-detected", absent["status"])
        self.assertEqual("unsupported",
                         loom_host_registry.contract("factory-droid")["evidence_status"])

    def test_only_codex_has_a_current_documented_headless_contract(self):
        self.assertEqual("documented", loom_host_registry.contract("codex")["contract_status"])
        for host in ("claude-code", "factory-droid", "gemini-cli", "opencode"):
            self.assertEqual("unverified", loom_host_registry.contract(host)["contract_status"])


if __name__ == "__main__":
    unittest.main()
