"""Adversarial privacy and sovereign-memory tests."""

import json
import os
import tempfile
import unittest
from pathlib import Path

import loom_memory
import loom_privacy
import loom_lifecycle


class PrivacyExcellenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def test_firewall_scans_binary_content_and_every_filename(self):
        cut = self.root / "cut"
        cut.mkdir()
        (cut / "safe.md").write_text("public", encoding="utf-8")
        (cut / "asset.bin").write_bytes(b"\x00OwnerProject\xff")
        (cut / "PersonalIdentifier-notes.txt").write_text("clean", encoding="utf-8")

        result = loom_privacy.scan_publication(
            cut, forbidden_tokens=["OwnerProject", "PersonalIdentifier"],
            require_owner_tokens=True)

        self.assertFalse(result["clean"])
        self.assertEqual(result["files_scanned"], 3)
        self.assertEqual(
            {(item["kind"], item["path"]) for item in result["findings"]},
            {("forbidden-content", "asset.bin"),
             ("forbidden-filename", "PersonalIdentifier-notes.txt")})

    def test_firewall_detects_utf16_owner_tokens(self):
        cut = self.root / "cut"
        cut.mkdir()
        (cut / "windows-notes.txt").write_text(
            "prefix PrivateOwnerSentinel suffix", encoding="utf-16")

        result = loom_privacy.scan_publication(
            cut, forbidden_tokens=["PrivateOwnerSentinel"],
            require_owner_tokens=True)

        self.assertFalse(result["clean"])
        self.assertEqual("forbidden-content", result["findings"][0]["kind"])
        self.assertEqual("windows-notes.txt", result["findings"][0]["path"])

    def test_firewall_detects_non_ascii_owner_tokens_exactly_and_casefolded(self):
        cut = self.root / "cut"
        cut.mkdir()
        (cut / "owner.txt").write_text("PRIVATE ÅOWNER", encoding="utf-8")

        result = loom_privacy.scan_publication(
            cut, forbidden_tokens=["PRIVATE ÅOWNER"],
            require_owner_tokens=True)

        self.assertFalse(result["clean"])
        self.assertEqual("forbidden-content", result["findings"][0]["kind"])

    def test_firewall_detects_utf16_secret_signatures(self):
        cut = self.root / "cut"
        cut.mkdir()
        secret = "OPENAI_API_KEY=sk-proj-" + "A1b2C3d4" * 6
        (cut / "windows.env").write_text(secret, encoding="utf-16")

        result = loom_privacy.scan_publication(cut, forbidden_tokens=[])

        self.assertFalse(result["clean"])
        self.assertEqual(result["findings"], [{
            "kind": "secret-signature",
            "path": "windows.env",
            "rule": "openai-token",
        }])

    def test_firewall_fails_closed_on_opaque_binary_content(self):
        cut = self.root / "cut"
        cut.mkdir()
        (cut / "opaque.bin").write_bytes(
            b"\x89PNG\r\n\x1a\n\x00\xff\x10\x80compressed-or-encrypted")

        result = loom_privacy.scan_publication(
            cut, forbidden_tokens=["PrivateOwnerSentinel"],
            require_owner_tokens=True)

        self.assertFalse(result["clean"])
        self.assertEqual(result["findings"], [{
            "kind": "opaque-content",
            "path": "opaque.bin",
            "rule": "unsupported-binary",
        }])

    def test_offline_audit_rejects_literal_network_subprocesses(self):
        tools_root = self.root / "tools"
        tools_root.mkdir()
        (tools_root / "loom_probe.py").write_text(
            "import subprocess\n"
            "subprocess.run(['curl', 'https://example.invalid'])\n",
            encoding="utf-8")

        result = loom_privacy.audit_offline_modules(tools_root)

        self.assertFalse(result["offline"])
        self.assertEqual(result["findings"], [{
            "path": "loom_probe.py",
            "line": 2,
            "kind": "network-subprocess",
            "command": "curl",
        }])

    def test_offline_audit_rejects_literal_dynamic_network_imports(self):
        tools_root = self.root / "tools"
        tools_root.mkdir()
        (tools_root / "loom_probe.py").write_text(
            "import importlib\n"
            "socket_module = __import__('socket')\n"
            "requests_module = importlib.import_module('requests')\n",
            encoding="utf-8")

        result = loom_privacy.audit_offline_modules(tools_root)

        self.assertFalse(result["offline"])
        self.assertEqual(
            {(item["line"], item["module"]) for item in result["findings"]},
            {(2, "socket"), (3, "requests")})

    def test_private_publication_without_real_owner_tokens_fails_closed(self):
        cut = self.root / "cut"
        cut.mkdir()
        with self.assertRaisesRegex(loom_privacy.PrivacyError, "owner tokens"):
            loom_privacy.scan_publication(
                cut, forbidden_tokens=[], require_owner_tokens=True)

    def test_secret_signatures_are_scanned_in_extensionless_and_binary_files(self):
        cut = self.root / "cut"
        cut.mkdir()
        (cut / "LICENSE").write_text(
            "-----BEGIN " + "PRIVATE" + " KEY-----\nnot-real\n", encoding="utf-8")
        (cut / "blob.dat").write_bytes(b"prefix ghp_" + b"a" * 40 + b" suffix")
        result = loom_privacy.scan_publication(cut, forbidden_tokens=[])
        self.assertFalse(result["clean"])
        self.assertEqual(
            {item["path"] for item in result["findings"]}, {"LICENSE", "blob.dat"})

    def test_firewall_rejects_common_provider_and_high_entropy_credentials(self):
        cut = self.root / "cut"
        cut.mkdir()
        fixtures = {
            "openai.env": "OPENAI_API_KEY=" + "sk-" + "proj-" + "A1b2C3d4" * 6,
            "google.env": "GOOGLE_API_KEY=" + "AI" + "za" + "Ab1_" * 8 + "XYZ",
            "stripe.env": "STRIPE_SECRET_KEY=" + "sk_" + "live_" + "Q7w8E9r0" * 4,
            "generic.env": (
                "SERVICE_CREDENTIAL=" + "mN7_" + "qP9-" + "Zx4/" + "Kv2+" * 8),
        }
        for name, value in fixtures.items():
            (cut / name).write_text(value, encoding="utf-8")

        result = loom_privacy.scan_publication(
            cut, forbidden_tokens=["real-owner-token"], require_owner_tokens=True)

        self.assertFalse(result["clean"])
        self.assertEqual(
            {item["path"] for item in result["findings"]}, set(fixtures))
        self.assertEqual(
            {item["rule"] for item in result["findings"]},
            {"openai-token", "google-api-key", "stripe-secret", "high-entropy-credential"})

    def test_secret_signatures_are_scanned_in_filenames(self):
        cut = self.root / "cut"
        cut.mkdir()
        name = "ghp_" + "d" * 40 + ".txt"
        (cut / name).write_text("no secret in body", encoding="utf-8")
        result = loom_privacy.scan_publication(cut, forbidden_tokens=[])
        self.assertFalse(result["clean"])
        self.assertEqual(result["findings"], [{
            "kind": "secret-filename", "path": name, "rule": "github-token"}])

    def test_redaction_never_persists_secret_or_absolute_owner_path(self):
        text = (
            f"token=ghp_{'b' * 40}\n"
            f"workspace={self.root / 'owner' / 'project'}\n"
            "result=passed\n")
        redacted = loom_privacy.minimize_evidence(text, roots=[self.root], max_chars=80)
        self.assertNotIn("ghp_", redacted)
        self.assertNotIn(str(self.root), redacted)
        self.assertIn("result=passed", redacted)
        self.assertLessEqual(len(redacted), 80)

    def test_acceptance_evidence_persists_only_minimized_transcripts(self):
        import sys
        repo = self.root / "repo"
        pack = repo / "plans"
        pack.mkdir(parents=True)
        (pack / "MANIFEST.md").write_text("fixture\n", encoding="utf-8")
        secret = "ghp_" + "c" * 40
        evidence = loom_lifecycle.capture_acceptance(
            pack, repo, "WO-101", medium="cli-process",
            command=[sys.executable, "-c",
                     f"print({secret!r}); print({str(repo)!r}); print('passed')"])
        serialized = (pack / "evidence" / "WO-101.json").read_text(encoding="utf-8")
        self.assertNotIn(secret, serialized)
        self.assertNotIn(str(repo), serialized)
        self.assertIn("passed", evidence["stdout"])
        self.assertTrue(evidence["transcript_minimized"])

    def test_forget_scrubs_active_and_archive_and_blocks_readmission(self):
        home = self.root / "home"
        install = self.root / "install"
        install.mkdir()
        instance = loom_memory.initialize(home, install)
        record = loom_memory.admit_learning(
            home, instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=0.9, domain="three-d")
        loom_memory.close_project(home, instance, "p-00000000000000000000000000000099")

        self.assertTrue(loom_memory.forget(home, instance, record["id"]))
        forgotten = loom_memory.inspect_record(home, instance, record["id"])
        self.assertEqual(forgotten, {
            "id": record["id"], "status": "forgotten", "content_erased": True})
        instance_dir = home / "instances" / instance
        for path in (instance_dir / "active.json", instance_dir / "archive.jsonl"):
            if path.exists():
                self.assertNotIn(record["id"], path.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(loom_memory.MemoryError, "forgotten"):
            loom_memory.admit_learning(
                home, instance, scope="domain", category="domain",
                signal="verification-caught-defect",
                future_decision="verification-strategy", evidence_count=3,
                confidence=0.9, domain="three-d")

    def test_private_export_is_receiver_bound_and_cross_instance_fails(self):
        home = self.root / "home"
        install = self.root / "install"
        install.mkdir()
        instance = loom_memory.initialize(home, install)
        destination = self.root / "exports" / "state.json"
        receipt = loom_privacy.export_private_state(
            home, instance, destination, receiver_id="owner-device-b")
        body = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(body["receiver_id"], "owner-device-b")
        self.assertEqual(receipt["sha256"], loom_privacy.file_sha256(destination))
        with self.assertRaises((loom_memory.MemoryError, loom_privacy.PrivacyError)):
            loom_privacy.export_private_state(
                home, "00000000-0000-0000-0000-000000000000",
                self.root / "bad.json", receiver_id="owner-device-b")

    def test_global_transferable_memory_rejects_raw_paths(self):
        home = self.root / "home"
        install = self.root / "install"
        install.mkdir()
        instance = loom_memory.initialize(home, install)
        with self.assertRaisesRegex(loom_memory.MemoryError, "raw local path"):
            loom_memory.set_preference(
                home, instance, "report_style", r"use C:\\Users\\Owner\\notes")

    def test_proven_owned_erase_removes_only_named_instance(self):
        home = self.root / "home"
        first_install = self.root / "first"
        second_install = self.root / "second"
        first_install.mkdir(); second_install.mkdir()
        first = loom_memory.initialize(home, first_install)
        second = loom_memory.initialize(home, second_install)
        sentinel = home / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(loom_privacy.PrivacyError, "confirmation"):
            loom_privacy.erase_private_state(home, first, confirmation=second)
        receipt = loom_privacy.erase_private_state(home, first, confirmation=first)
        self.assertEqual(receipt["instance_id"], first)
        self.assertFalse((home / "instances" / first).exists())
        self.assertTrue((home / "instances" / second).is_dir())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_firewall_rejects_symlinked_publication_entries(self):
        cut = self.root / "cut"
        outside = self.root / "outside.txt"
        cut.mkdir()
        outside.write_text("private", encoding="utf-8")
        link = cut / "linked.txt"
        try:
            os.symlink(outside, link)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with self.assertRaisesRegex(loom_privacy.PrivacyError, "symlink|reparse"):
            loom_privacy.scan_publication(cut, forbidden_tokens=[])


if __name__ == "__main__":
    unittest.main()
