import json
import os
import tempfile
import unittest
from pathlib import Path

import loom_lifecycle_kernel as kernel
from test_lifecycle_kernel import (
    _canonical_state_inputs, _canonical_world_observation,
)


class PlanStoreTests(unittest.TestCase):
    def setUp(self):
        try:
            import loom_plan_store
        except ModuleNotFoundError:
            self.fail("loom_plan_store is required")
        self.store = loom_plan_store
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "plans").mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def _index(self, **changes):
        value = {
            "schema_version": 1,
            "project_id": "project-1",
            "generation_id": "generation-1",
            "storage_kind": "generation-dir",
            "generation_path": "plans/generations/generation-1",
        }
        value.update(changes)
        value["index_sha256"] = kernel.digest(value)
        return value

    def _write_index(self, value=None):
        (self.root / "plans" / "active-generation.json").write_text(
            json.dumps(value or self._index(), sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _write_canonical_generation(self):
        generation = self.root / "plans" / "generations" / "generation-1"
        generation.mkdir(parents=True)
        _index, semantics, ledger, _witness = _canonical_state_inputs(kernel)
        (generation / "MANIFEST.md").write_text(
            "---\nexecution_policy: strict-serial-sequence-v1\n"
            "execution_sequence: [WO-001, WO-002]\n---\n",
            encoding="utf-8")
        (generation / "plan-semantics.json").write_text(
            json.dumps(semantics, sort_keys=True) + "\n", encoding="utf-8")
        (generation / "reviewed-world.json").write_text(
            json.dumps(_canonical_world_observation(kernel), sort_keys=True) + "\n",
            encoding="utf-8")
        (generation / "lifecycle.json").write_text(
            json.dumps(ledger, sort_keys=True) + "\n", encoding="utf-8")
        return generation

    def test_resolves_only_the_exact_indexed_generation(self):
        generation = self.root / "plans" / "generations" / "generation-1"
        generation.mkdir(parents=True)
        (generation / "MANIFEST.md").write_text("# reviewed\n", encoding="utf-8")
        (generation / "lifecycle.json").write_text("{}\n", encoding="utf-8")
        self._write_index()

        resolved = self.store.resolve(self.root)

        self.assertEqual("v3", resolved.authority_version)
        self.assertEqual("generation-1", resolved.generation_id)
        self.assertEqual(generation.resolve(), resolved.generation_root)

    def test_reviewable_revision_keeps_generation_identity_with_a_new_immutable_path(self):
        """Break caught: a same-generation revision requires an in-place directory swap."""
        relative = (
            "plans/generations/revisions/generation-1/"
            "r000002-" + "a" * 64)
        generation = self.root.joinpath(*Path(relative).parts)
        generation.mkdir(parents=True)
        (generation / "MANIFEST.md").write_text(
            "# reviewed revision\n", encoding="utf-8")
        (generation / "lifecycle.json").write_text("{}\n", encoding="utf-8")
        self._write_index(self._index(generation_path=relative))

        resolved = self.store.resolve(self.root)

        self.assertEqual("generation-1", resolved.generation_id)
        self.assertEqual(generation.resolve(), resolved.generation_root)

    def test_corrupt_v3_index_never_falls_back_to_plausible_legacy_pack(self):
        (self.root / "plans" / "MANIFEST.md").write_text(
            "# plausible legacy pack\n", encoding="utf-8")
        value = self._index()
        value["index_sha256"] = "0" * 64
        self._write_index(value)

        with self.assertRaisesRegex(self.store.PlanStoreError, "index"):
            self.store.resolve(self.root)

    def test_indexed_store_rejects_an_unexplained_extra_generation(self):
        """Break caught: an indexed store silently accepts an orphan generation."""
        self._write_canonical_generation()
        orphan = self.root / "plans" / "generations" / "unexplained"
        orphan.mkdir()
        self._write_index()

        with self.assertRaisesRegex(self.store.PlanStoreError, "mixed|unexplained"):
            self.store.resolve(self.root)

    def test_unindexed_generation_namespace_blocks_legacy_interpretation(self):
        generation = self.root / "plans" / "generations" / "orphan"
        generation.mkdir(parents=True)
        (generation / "MANIFEST.md").write_text("# orphan\n", encoding="utf-8")
        (self.root / "plans" / "MANIFEST.md").write_text(
            "# legacy\n", encoding="utf-8")

        with self.assertRaisesRegex(self.store.PlanStoreError, "mixed"):
            self.store.resolve(self.root)

    def test_legacy_root_remains_readable_when_no_v3_control_namespace_exists(self):
        manifest = self.root / "plans" / "MANIFEST.md"
        manifest.write_text("# legacy\n", encoding="utf-8")

        resolved = self.store.resolve(self.root)

        self.assertEqual("legacy-v2", resolved.authority_version)
        self.assertEqual((self.root / "plans").resolve(), resolved.generation_root)
        self.assertIsNone(resolved.generation_id)

    def test_active_index_hardlink_is_rejected(self):
        """The authority selector cannot share bytes with another pathname."""
        generation = self._write_canonical_generation()
        self._write_index()
        alias = self.root / "index-alias.json"
        try:
            os.link(self.root / "plans" / "active-generation.json", alias)
        except OSError as exc:
            self.skipTest(f"hard links are unavailable: {exc}")

        with self.assertRaisesRegex(self.store.PlanStoreError, "hardlink|redirected"):
            self.store.resolve(self.root)
        self.assertTrue(generation.is_dir())

    def test_indexed_generation_rejects_an_internal_hardlink(self):
        """No content-bearing generation file may have another filesystem name."""
        generation = self._write_canonical_generation()
        alias = generation / "semantics-alias.json"
        try:
            os.link(generation / "plan-semantics.json", alias)
        except OSError as exc:
            self.skipTest(f"hard links are unavailable: {exc}")
        self._write_index()

        with self.assertRaisesRegex(self.store.PlanStoreError, "hardlink|exact-tree"):
            self.store.resolve(self.root)

    def test_indexed_generation_rejects_an_internal_redirect(self):
        """A safe generation root cannot hide redirected descendants."""
        generation = self._write_canonical_generation()
        outside = self.root / "outside-file.txt"
        outside.write_text("outside\n", encoding="utf-8")
        try:
            os.symlink(outside, generation / "redirected.txt")
        except OSError as exc:
            self.skipTest(f"symlink privilege unavailable: {exc}")
        self._write_index()

        with self.assertRaisesRegex(self.store.PlanStoreError, "redirected|exact-tree"):
            self.store.resolve(self.root)

    @unittest.skipUnless(os.name == "nt", "Windows reparse/link behavior")
    def test_indexed_generation_link_is_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        target = self.root / "plans" / "generations" / "generation-1"
        target.parent.mkdir(parents=True)
        try:
            os.symlink(outside, target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink privilege unavailable: {exc}")
        self._write_index()

        with self.assertRaisesRegex(self.store.PlanStoreError, "redirected"):
            self.store.resolve(self.root)


if __name__ == "__main__":
    unittest.main()
