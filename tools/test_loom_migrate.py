"""Tests for loom_migrate. Run: python -m unittest discover -s tools -p "test_*.py" """

import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_migrate  # noqa: E402

TODAY = dt.date.today().isoformat()


def make_pack_020(root):
    root = Path(root)
    (root / "work-orders").mkdir(parents=True)
    (root / "MANIFEST.md").write_text(f"""---
artifact: manifest
project: "mig-test"
tier: M
status: active
last_verified: {TODAY}
loom_version: "0.2.0"
---
# Pack
""", encoding="utf-8")
    (root / "work-orders" / "WO-001-a.md").write_text(f"""---
id: WO-001
title: A
status: ready
routing: strong-coding
size: S
last_verified: {TODAY}
---
body
""", encoding="utf-8")


class MigrateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pack = Path(self.tmp.name)
        make_pack_020(self.pack)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dry_run_changes_nothing_and_signals_pending(self):
        before = (self.pack / "work-orders" / "WO-001-a.md").read_text(encoding="utf-8")
        code = loom_migrate.migrate(self.pack, apply=False, target="0.4.0")
        self.assertEqual(code, 1)  # pending work
        self.assertEqual(before,
                         (self.pack / "work-orders" / "WO-001-a.md").read_text(encoding="utf-8"))
        self.assertFalse((self.pack / "outcomes.md").exists())

    def test_apply_migrates_020_to_040(self):
        code = loom_migrate.migrate(self.pack, apply=True, target="0.4.0")
        self.assertEqual(code, 0)
        wo = (self.pack / "work-orders" / "WO-001-a.md").read_text(encoding="utf-8")
        self.assertIn("touches: []", wo)                      # 0.3.0 migration
        self.assertTrue((self.pack / "outcomes.md").exists())  # 0.4.0 migration
        out = (self.pack / "outcomes.md").read_text(encoding="utf-8")
        self.assertIn("mig-test", out)                         # project name substituted
        self.assertNotIn("<YYYY-MM-DD>", out)
        man = (self.pack / "MANIFEST.md").read_text(encoding="utf-8")
        self.assertIn('loom_version: "0.4.0"', man)            # stamp bumped
        self.assertNotIn("loom_version", wo)                   # WOs never carry the stamp

    def test_idempotent(self):
        loom_migrate.migrate(self.pack, apply=True, target="0.4.0")
        snap = {p: p.read_text(encoding="utf-8") for p in self.pack.rglob("*.md")}
        code = loom_migrate.migrate(self.pack, apply=True, target="0.4.0")
        self.assertEqual(code, 0)
        for p, text in snap.items():
            self.assertEqual(text, p.read_text(encoding="utf-8"), f"{p} changed on re-run")

    def test_up_to_date_pack_is_noop(self):
        loom_migrate.migrate(self.pack, apply=True, target="0.4.0")
        self.assertEqual(loom_migrate.migrate(self.pack, apply=False, target="0.4.0"), 0)

    def test_current_version_reads_single_version_file(self):
        v = loom_migrate.current_version()
        self.assertEqual(v, (loom_migrate.LOOM_ROOT / "VERSION").read_text(
            encoding="utf-8").strip())

    def test_080_migration_adds_semantic_blockers_not_just_stamps(self):
        code = loom_migrate.migrate(self.pack, apply=True, target="0.8.0")
        self.assertEqual(code, 0)
        manifest = (self.pack / "MANIFEST.md").read_text(encoding="utf-8")
        wo = (self.pack / "work-orders" / "WO-001-a.md").read_text(encoding="utf-8")
        self.assertIn("execution_mode: build-first", manifest)
        self.assertIn("domain_id: unclassified", manifest)
        self.assertIn("domain_coverage: unknown", manifest)
        self.assertIn("domain-discovery.md", manifest)
        self.assertTrue((self.pack / "domain-discovery.md").is_file())
        self.assertIn("depends_on: []", wo)
        self.assertIn("blocks: []", wo)
        self.assertIn("touches: []", wo)
        self.assertIn('loom_version: "0.8.0"', manifest)


if __name__ == "__main__":
    unittest.main()
