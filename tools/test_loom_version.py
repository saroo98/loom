"""Single-source version coherence tests."""

import unittest
from pathlib import Path

import loom_version


ROOT = Path(__file__).resolve().parents[1]


class VersionCoherenceTests(unittest.TestCase):
    def test_every_release_surface_uses_the_canonical_version(self):
        result = loom_version.verify(ROOT)
        self.assertEqual("coherent", result["status"])
        self.assertEqual(
            (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            result["version"],
        )


if __name__ == "__main__":
    unittest.main()
