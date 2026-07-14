import json
import tempfile
import unittest
from pathlib import Path

import loom_install
import loom_release


class ReleaseStandardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def _source(self):
        source = self.root / "source"
        (source / "tools").mkdir(parents=True)
        (source / "docs").mkdir()
        (source / "skill" / "loom").mkdir(parents=True)
        (source / "README.md").write_text("/loom <request>\n", encoding="utf-8")
        (source / "START-HERE.md").write_text("/loom <request>\n", encoding="utf-8")
        (source / "VERSION").write_text("1.0.0\n", encoding="utf-8")
        (source / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        (source / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        (source / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
        (source / "PRIVACY.md").write_text("# Privacy\n", encoding="utf-8")
        (source / "tools" / "loom_example.py").write_text("VALUE = 1\n", encoding="utf-8")
        (source / "docs" / "index.html").write_text("<!doctype html>\n", encoding="utf-8")
        (source / "skill" / "loom" / "SKILL.md").write_text(
            "---\nname: loom\n---\n", encoding="utf-8")
        return source

    def test_public_build_is_reproducible_and_refuses_owner_content(self):
        source = self._source()
        first = loom_release.build_public(
            source, self.root / "first", forbidden_tokens=["real-owner-token"])
        second = loom_release.build_public(
            source, self.root / "second", forbidden_tokens=["real-owner-token"])
        self.assertEqual(first["root_sha256"], second["root_sha256"])
        self.assertTrue(first["firewall"]["clean"])
        self.assertEqual(first["files"], second["files"])

        (source / "docs" / "private.bin").write_bytes(b"prefix REAL-OWNER-TOKEN suffix")
        refused = self.root / "refused"
        with self.assertRaisesRegex(loom_release.ReleaseError, "firewall"):
            loom_release.build_public(
                source, refused, forbidden_tokens=["real-owner-token"])
        self.assertFalse(refused.exists())

    def test_installer_cycle_checks_and_removes_only_receipt_proven_files(self):
        source = self._source()
        built = self.root / "built"
        loom_release.build_public(source, built, forbidden_tokens=["owner-token"])
        target = self.root / "installed"
        installed = loom_install.install(built, target)
        checked = loom_install.check(target)
        self.assertEqual("installed", checked["status"])
        self.assertEqual(installed["install_id"], checked["install_id"])
        self.assertEqual((built / "skill" / "loom" / "SKILL.md").read_bytes(),
                         (target / "SKILL.md").read_bytes())
        removed = loom_install.uninstall(
            target, confirmation=installed["install_id"])
        self.assertEqual("uninstalled", removed["status"])
        self.assertFalse(target.exists())

    def test_uninstaller_fails_closed_before_deleting_any_file_when_one_changed(self):
        source = self._source()
        built = self.root / "built"
        loom_release.build_public(source, built, forbidden_tokens=["owner-token"])
        target = self.root / "installed"
        installed = loom_install.install(built, target)
        readme = target / "README.md"
        readme.write_text("changed by owner\n", encoding="utf-8")
        version_before = (target / "VERSION").read_bytes()
        with self.assertRaisesRegex(loom_install.InstallError, "changed"):
            loom_install.uninstall(target, confirmation=installed["install_id"])
        self.assertTrue(readme.is_file())
        self.assertEqual(version_before, (target / "VERSION").read_bytes())

    def test_release_certification_stays_blocked_without_external_evidence(self):
        report = loom_release.certification_report(local_checks={
            "suite": True, "adaptation": True, "privacy": True,
            "failure_injection": True, "reproducible_build": True,
            "installer_cycle": True, "performance_budgets": True,
            "docs": True, "twenty_project_bound": True,
        }, external_evidence={})
        self.assertEqual("blocked", report["status"])
        self.assertLess(report["score"], 100)
        self.assertEqual({
            "cross-platform-ci", "unfamiliar-user-usability",
            "independent-hostile-review",
        }, {item["id"] for item in report["unverified"]})

    def test_external_evidence_contract_rejects_high_findings_and_accepts_proof(self):
        local = {key: True for key in loom_release.LOCAL_CHECKS}
        external = {
            "cross-platform-ci": {"status": "passed", "evidence": "ci-run-42"},
            "unfamiliar-user-usability": {
                "status": "passed", "evidence": "study-7", "participant_count": 1},
            "independent-hostile-review": {
                "status": "passed", "evidence": "audit-9",
                "critical_findings": 0, "high_findings": 0},
        }
        passed = loom_release.certification_report(
            local_checks=local, external_evidence=external)
        self.assertEqual("certified", passed["status"])
        self.assertEqual(100, passed["score"])
        external["independent-hostile-review"]["high_findings"] = 1
        blocked = loom_release.certification_report(
            local_checks=local, external_evidence=external)
        self.assertEqual("blocked", blocked["status"])

    def test_public_release_evidence_redacts_local_home_and_repository_paths(self):
        local_home = self.root / "private-home"
        repository = local_home / "private-repository"
        suite = loom_release.sanitize_suite_evidence({
            "passed": True, "returncode": 0,
            "output": f"ERROR {repository}\\pack.md\nowner {local_home}\n",
        }, root=repository, home=local_home)
        self.assertNotIn(str(local_home), suite["output"])
        self.assertNotIn(str(repository), suite["output"])
        self.assertIn("[LOCAL_ROOT]", suite["output"])


if __name__ == "__main__":
    unittest.main()
