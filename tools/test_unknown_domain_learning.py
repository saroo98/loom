import datetime as dt
import tempfile
import unittest
from pathlib import Path

import domain_test_support
import loom_domain_learning
import loom_vault
from test_loom_vault_v11 import TestCrypto


class UnknownDomainLearningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vault = loom_vault.OwnerVault.create(
            Path(self.tmp.name) / "vault" / "owner.sqlite3",
            crypto=TestCrypto(), allow_test_crypto=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_gate_ready_invariant_reuses_only_in_exact_scope(self):
        invariant = domain_test_support.gate_ready_bundle()["invariants"][0]
        loom_domain_learning.store(self.vault, "invariant", invariant, source_sequence=1)
        selected = loom_domain_learning.select_active_invariants(
            self.vault, domain="quantum-optics", project_id="p-test",
            component="control", now=domain_test_support.NOW)
        self.assertEqual([invariant["invariant_id"]],
                         [item["invariant_id"] for item in selected])
        self.assertEqual([], loom_domain_learning.select_active_invariants(
            self.vault, domain="accounting", project_id="p-test",
            component="control", now=domain_test_support.NOW))
        self.assertEqual([], loom_domain_learning.select_active_invariants(
            self.vault, domain="quantum-optics", project_id="p-other",
            component="control", now=domain_test_support.NOW))

    def test_expired_invariant_is_not_selected(self):
        invariant = domain_test_support.gate_ready_bundle()["invariants"][0]
        loom_domain_learning.store(self.vault, "invariant", invariant, source_sequence=1)
        selected = loom_domain_learning.select_active_invariants(
            self.vault, domain="quantum-optics", project_id="p-test",
            component="control", now=dt.datetime(2031, 1, 1, tzinfo=dt.timezone.utc))
        self.assertEqual([], selected)

    def test_executable_payload_is_rejected_before_vault_write(self):
        with self.assertRaises(loom_domain_learning.DomainLearningError):
            loom_domain_learning.store(
                self.vault, "adapter", {"id": "adapter-bad", "command": "pwsh -c whoami"},
                source_sequence=1)
        self.assertEqual([], self.vault.list_entities("domain-adapter"))

    def test_entity_state_is_bounded_by_vault_materializer(self):
        for index in range(300):
            loom_domain_learning.store(
                self.vault, "discovery-utility",
                {"id": f"utility-{index:03d}", "helped": index % 2 == 0},
                source_sequence=index + 1)
        self.assertEqual(256, len(self.vault.list_entities(
            "domain-discovery-utility", limit=512)))


if __name__ == "__main__":
    unittest.main()
