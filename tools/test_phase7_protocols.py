import copy
import datetime as dt
import json
import unittest
from pathlib import Path

import loom_current_facts


ROOT = Path(__file__).resolve().parents[1]


class Phase7ProtocolTests(unittest.TestCase):
    def test_current_fact_manifest_is_current_at_implementation_date(self):
        value = json.loads((ROOT / "contracts" / "current-facts-v1.json").read_text(
            encoding="utf-8"))
        result = loom_current_facts.validate(
            value, as_of=dt.datetime(2026, 7, 17, 12, tzinfo=dt.timezone.utc))
        self.assertEqual("current", result["status"])
        self.assertIn("hosts.third-party-contracts", result["unverified"])

    def test_expired_fact_downgrades_manifest(self):
        value = json.loads((ROOT / "contracts" / "current-facts-v1.json").read_text(
            encoding="utf-8"))
        result = loom_current_facts.validate(
            value, as_of=dt.datetime(2026, 8, 17, tzinfo=dt.timezone.utc))
        self.assertEqual("stale", result["status"])
        self.assertIn("codex.noninteractive.exec", result["expired"])

    def test_external_protocol_never_self_awards_independence(self):
        text = (ROOT / "docs" / "phase-7-validation.md").read_text(encoding="utf-8")
        for phrase in ("implementer cannot award", "no automatic analytics request",
                       "zero unresolved", "not independent"):
            self.assertIn(phrase, text.lower())


if __name__ == "__main__":
    unittest.main()
