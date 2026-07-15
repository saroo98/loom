"""Acceptance tests for the pure `/loom` invocation preparation slice."""

import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import loom_memory
import loom_runtime
import loom_survey
import loom_gate
import loom_lifecycle
from test_loom_lint import good_pack


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True,
        text=True, encoding="utf-8")


class RuntimeFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / "project"
        self.repo.mkdir()
        git(self.repo, "init")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Loom Test", "-c",
            "user.email=loom@example.invalid", "commit", "-m", "fixture")
        self.instance = str(uuid.uuid4())
        self.invocation = str(uuid.uuid4())
        self.owner_home = self.root / "owner-home"

    def tearDown(self):
        self.tmp.cleanup()

    def prepare(self, request="Build a command-line tool", **overrides):
        values = {
            "instance_id": self.instance,
            "invocation_id": self.invocation,
            "cwd": self.repo,
            "owner_home": self.owner_home,
            "now": dt.datetime.combine(
                dt.date.today(), dt.time(12), tzinfo=dt.timezone.utc),
        }
        values.update(overrides)
        return loom_runtime.prepare_invocation(request, **values)

    def authorize_fixture_pack(self):
        pack = self.repo / "plans"
        good_pack(pack)
        (pack / loom_gate.LIFECYCLE_FILE).unlink(missing_ok=True)
        self.assertEqual(loom_gate.start(pack, self.repo, "planned"), 0)
        self.assertEqual(
            loom_gate.seal_g1(pack, self.repo, pack / "reviews" / "G1-plan-review.md"), 0)
        self.assertEqual(loom_gate.authorize(pack, self.repo), 0)
        return pack


class ProjectResolutionTests(RuntimeFixture):
    def test_explicit_target_wins_without_scanning_siblings(self):
        other = self.root / "other"
        other.mkdir()
        sibling = self.root / "private-sibling"
        sibling.mkdir()
        with mock.patch.object(Path, "iterdir", autospec=True) as listing:
            result = loom_runtime.resolve_project(
                self.instance, explicit_target=other, cwd=self.repo,
                candidate_roots=[other])
        self.assertEqual(result.root, other)
        self.assertEqual(result.source, "explicit")
        listing.assert_not_called()

    def test_nested_git_cwd_resolves_canonical_root(self):
        nested = self.repo / "a" / "b"
        nested.mkdir(parents=True)
        result = loom_runtime.resolve_project(self.instance, cwd=nested)
        self.assertEqual(result.root, self.repo)
        self.assertEqual(result.source, "git-cwd")
        self.assertRegex(result.project_id, r"^p-[0-9a-f]{32}$")

    def test_non_git_uses_exact_cwd(self):
        plain = self.root / "plain"
        plain.mkdir()
        result = loom_runtime.resolve_project(self.instance, cwd=plain)
        self.assertEqual(result.root, plain)
        self.assertEqual(result.source, "filesystem-cwd")

    def test_git_project_identity_survives_a_repository_move(self):
        before = loom_runtime.resolve_project(self.instance, cwd=self.repo)
        moved = self.root / "renamed-project"
        self.repo.rename(moved)
        self.repo = moved
        after = loom_runtime.resolve_project(self.instance, cwd=moved)
        self.assertEqual(before.project_id, after.project_id)
        self.assertNotEqual(
            before.canonical_target_identity, after.canonical_target_identity)

    def test_non_git_project_identity_survives_same_filesystem_move(self):
        plain = self.root / "plain-before"
        plain.mkdir()
        before = loom_runtime.resolve_project(self.instance, cwd=plain)
        moved = self.root / "plain-after"
        plain.rename(moved)
        after = loom_runtime.resolve_project(self.instance, cwd=moved)
        self.assertEqual(before.project_id, after.project_id)

    def test_unreadable_target_fails_closed(self):
        with mock.patch.object(loom_runtime.os, "access", return_value=False):
            with self.assertRaisesRegex(
                    loom_runtime.RuntimeBlocked, "PROJECT_UNREADABLE"):
                loom_runtime.resolve_project(
                    self.instance, explicit_target=self.repo, cwd=self.repo)

    def test_symlink_escape_is_rejected(self):
        link = self.root / "linked-project"
        try:
            link.symlink_to(self.repo, target_is_directory=True)
        except OSError:
            with mock.patch.object(
                    loom_runtime, "_path_has_link_or_junction",
                    side_effect=lambda value: Path(value) == link):
                with self.assertRaisesRegex(
                        loom_runtime.RuntimeBlocked, "PROJECT_INDETERMINATE"):
                    loom_runtime.resolve_project(
                        self.instance, explicit_target=link, cwd=self.repo)
        else:
            with self.assertRaisesRegex(
                    loom_runtime.RuntimeBlocked, "PROJECT_INDETERMINATE"):
                loom_runtime.resolve_project(
                    self.instance, explicit_target=link, cwd=self.repo)

    def test_zero_and_conflicting_candidates_fail_without_guessing(self):
        with self.assertRaisesRegex(
                loom_runtime.RuntimeBlocked, "missing_or_invalid_invocation_cwd"):
            loom_runtime.resolve_project(self.instance, cwd=None)
        other = self.root / "other"
        other.mkdir()
        with self.assertRaisesRegex(
                loom_runtime.RuntimeBlocked, "PROJECT_AMBIGUOUS"):
            loom_runtime.resolve_project(
                self.instance, cwd=self.repo,
                candidate_roots=[self.repo, other])

    def test_malformed_explicit_target_is_a_typed_refusal(self):
        with self.assertRaisesRegex(
                loom_runtime.RuntimeBlocked, "PROJECT_INDETERMINATE"):
            loom_runtime.resolve_project(
                self.instance, explicit_target=123, cwd=self.repo)

    def test_candidate_iteration_stops_at_second_distinct_root(self):
        other = self.root / "other-project"
        other.mkdir()

        def candidates():
            yield self.repo
            yield other
            raise AssertionError("resolver over-consumed after conflict was known")

        with self.assertRaisesRegex(
                loom_runtime.RuntimeBlocked, "PROJECT_AMBIGUOUS"):
            loom_runtime.resolve_project(
                self.instance, cwd=self.repo, candidate_roots=candidates())

    def test_candidate_iteration_has_a_hard_bound(self):
        def repeated():
            while True:
                yield self.repo

        with self.assertRaisesRegex(
                loom_runtime.RuntimeBlocked, "candidate count exceeds"):
            loom_runtime.resolve_project(
                self.instance, cwd=self.repo, candidate_roots=repeated())


class IntentRoutingTests(unittest.TestCase):
    def test_every_required_plain_language_phrase_routes_with_state(self):
        cases = [
            ("Build a command-line tool", {}, "plan"),
            ("Continue", {"pack_exists": True}, "resume"),
            ("Build the next part", {
                "pack_exists": True, "authorized": True, "active_frontier": True,
            }, "execute"),
            ("Review this", {}, "review"),
            ("Fix the stale plan", {"drift": True}, "repair"),
            ("We are done", {"terminal": True}, "close"),
            ("Show me where we are", {}, "status"),
            ("Remember that I prefer concise reports", {}, "remember"),
            ("Be more careful", {}, "remember"),
            ("Forget that preference", {}, "forget"),
            ("Why did you do that?", {}, "why"),
            ("Undo the last Loom change", {}, "undo"),
            ("Continue", {"pack_exists": True, "drift": True}, "repair"),
        ]
        for request, state, expected in cases:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, state)
                self.assertEqual(decision["intent"], expected)
                self.assertFalse(decision["blocked"])

    def test_token_usage_request_uses_existing_status_surface(self):
        decision = loom_runtime.resolve_intent("Show my token usage", {})
        self.assertEqual("status", decision["intent"])
        self.assertFalse(decision["blocked"])

    def test_internal_command_vocabulary_is_not_required(self):
        requests = [
            "Keep going", "What has happened so far?", "Please inspect this",
            "Stop remembering my old stack", "Take back your last adjustment",
        ]
        for request in requests:
            decision = loom_runtime.resolve_intent(request, {})
            self.assertIn(decision["intent"], loom_runtime.INTENTS)
            self.assertFalse(request.startswith("/"))


class WorldFingerprintTests(RuntimeFixture):
    def test_pack_frontier_hash_has_unambiguous_file_framing(self):
        first = self.root / "pack-a"
        second = self.root / "pack-b"
        first.mkdir()
        second.mkdir()
        (first / "a").write_bytes(b"X\0b\0Y")
        (second / "a").write_bytes(b"X")
        (second / "b").write_bytes(b"Y")

        self.assertNotEqual(
            loom_runtime._hash_frontier(first),
            loom_runtime._hash_frontier(second))

    def test_absent_owner_state_never_collides_with_present_bytes(self):
        for label in (
                "context capsule state", "profile state", "prior session state"):
            with self.subTest(label=label):
                path = self.root / f"state-{label.split()[0]}"
                absent = loom_runtime._state_file_version(path, label)
                path.write_bytes(f"{label}:absent".encode("utf-8"))
                present = loom_runtime._state_file_version(path, label)
                self.assertNotEqual(absent, present)
                path.unlink()

    def test_each_world_component_changes_identity_independently(self):
        base = {
            "target_survey_hash": "1" * 64,
            "pack_hash": "2" * 64,
            "config_hash": "3" * 64,
            "lifecycle_hash": "4" * 64,
            "capsule_version": "capsule-1",
            "profile_version": "profile-1",
            "prior_session_hash": "5" * 64,
            "staleness_bucket": 100,
        }
        original = loom_runtime.compose_world_fingerprint(base)
        for key in base:
            changed = dict(base)
            changed[key] = (101 if key == "staleness_bucket" else f"changed-{key}")
            with self.subTest(key=key):
                self.assertNotEqual(
                    loom_runtime.compose_world_fingerprint(changed), original)

    def test_unknown_or_missing_world_components_are_rejected(self):
        valid = {key: "x" for key in loom_runtime.WORLD_COMPONENT_FIELDS}
        valid["staleness_bucket"] = 1
        for mutation in ("missing", "unknown"):
            value = dict(valid)
            if mutation == "missing":
                value.pop("pack_hash")
            else:
                value["surprise"] = "x"
            with self.assertRaisesRegex(
                    loom_runtime.RuntimeError, "world component fields"):
                loom_runtime.compose_world_fingerprint(value)

    def test_real_prepare_loader_binds_every_world_input(self):
        config = json.loads(json.dumps(loom_runtime.DEFAULT_CONFIG))
        config.update({
            "loom_version": "0.8.0", "domain_id": "cli", "domain_ids": ["cli"],
        })
        config_path = self.repo / "loom.config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        pack = self.repo / "plans"
        pack.mkdir()
        manifest = pack / "MANIFEST.md"
        manifest.write_text("# pack\n", encoding="utf-8")
        lifecycle = pack / "lifecycle.json"
        lifecycle.write_text(json.dumps({"events": []}), encoding="utf-8")
        project_id = loom_memory.project_identity(self.instance, self.repo)
        instance_root = self.owner_home / "instances" / self.instance
        project_runtime = instance_root / "runtime" / "projects" / project_id
        project_runtime.mkdir(parents=True)
        profile = instance_root / "active.json"
        profile.write_text('{"version":"profile-1"}', encoding="utf-8")
        capsule = project_runtime / "capsule.json"
        capsule.write_text('{"version":"capsule-1"}', encoding="utf-8")
        prior = project_runtime / "runtime.json"
        prior.write_text('{"version":"session-1"}', encoding="utf-8")
        baseline = self.prepare()

        readme = self.repo / "README.md"
        original_readme = readme.read_text(encoding="utf-8")
        readme.write_text(original_readme + "target mutation\n", encoding="utf-8")
        self.assertNotEqual(
            self.prepare().world_fingerprint, baseline.world_fingerprint)
        readme.write_text(original_readme, encoding="utf-8")
        self.assertEqual(
            self.prepare().world_fingerprint, baseline.world_fingerprint)

        manifest.write_text("# changed pack\n", encoding="utf-8")
        self.assertNotEqual(
            self.prepare().world_fingerprint, baseline.world_fingerprint)
        manifest.write_text("# pack\n", encoding="utf-8")
        self.assertEqual(
            self.prepare().world_fingerprint, baseline.world_fingerprint)

        changed_config = dict(config)
        changed_config["language"] = "fr"
        config_path.write_text(json.dumps(changed_config), encoding="utf-8")
        self.assertNotEqual(
            self.prepare().world_fingerprint, baseline.world_fingerprint)
        config_path.write_text(json.dumps(config), encoding="utf-8")
        self.assertEqual(
            self.prepare().world_fingerprint, baseline.world_fingerprint)

        lifecycle.write_text(json.dumps({
            "events": [{"event": "implementation-authorized"}],
        }), encoding="utf-8")
        self.assertNotEqual(
            self.prepare().world_fingerprint, baseline.world_fingerprint)
        lifecycle.write_text(json.dumps({"events": []}), encoding="utf-8")
        self.assertEqual(
            self.prepare().world_fingerprint, baseline.world_fingerprint)

        for key, path, value in (
                ("capsule_version", capsule, '{"version":"capsule-2"}'),
                ("profile_version", profile, '{"version":"profile-2"}'),
                ("prior_session_hash", prior, '{"version":"session-2"}')):
            original = path.read_text(encoding="utf-8")
            path.write_text(value, encoding="utf-8")
            with self.subTest(key=key):
                self.assertNotEqual(
                    self.prepare().world_fingerprint, baseline.world_fingerprint)
            path.write_text(original, encoding="utf-8")
            self.assertEqual(
                self.prepare().world_fingerprint, baseline.world_fingerprint)
        self.assertNotEqual(
            self.prepare(now="2026-07-28T12:00:00Z").world_fingerprint,
            baseline.world_fingerprint)

    def test_world_state_versions_cannot_be_supplied_by_a_caller(self):
        for field in (
                "lifecycle_state", "capsule_version", "profile_version",
                "prior_session_version"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                self.prepare(**{field: "forged"})

    def test_real_world_binds_same_head_branch_and_ignored_runtime_file(self):
        baseline = self.prepare()
        git(self.repo, "switch", "-q", "-c", "same-head-other-branch")
        branch = self.prepare()
        self.assertNotEqual(branch.world_fingerprint, baseline.world_fingerprint)

        info_exclude = self.repo / ".git" / "info" / "exclude"
        info_exclude.write_text(".env\n", encoding="utf-8")
        before_ignored = self.prepare()
        (self.repo / ".env").write_text(
            "DATABASE_URL=production-secret\n", encoding="utf-8")
        after_ignored = self.prepare()
        self.assertNotEqual(
            after_ignored.world_fingerprint, before_ignored.world_fingerprint)

    def test_unsafe_git_index_hints_block_preparation(self):
        for set_flag, clear_flag in (
                ("--assume-unchanged", "--no-assume-unchanged"),
                ("--skip-worktree", "--no-skip-worktree")):
            git(self.repo, "update-index", set_flag, "README.md")
            try:
                with self.subTest(flag=set_flag), self.assertRaisesRegex(
                        loom_runtime.RuntimeBlocked, "PROJECT_INDETERMINATE"):
                    self.prepare()
            finally:
                git(self.repo, "update-index", clear_flag, "README.md")


class PreparedInvocationTests(RuntimeFixture):
    def test_exact_schema_hash_immutability_and_no_capability(self):
        prepared = self.prepare()
        data = prepared.to_dict()
        schema = json.loads((Path(__file__).resolve().parent.parent /
                             "schemas" / "intent.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(data), loom_runtime.PREPARED_FIELDS)
        self.assertEqual(set(schema["properties"]), loom_runtime.PREPARED_FIELDS)
        self.assertEqual(set(schema["required"]), loom_runtime.PREPARED_FIELDS)
        route_schema = schema["properties"]["route_contract"]
        self.assertEqual(set(route_schema["properties"]), loom_runtime.ROUTE_FIELDS)
        self.assertEqual(set(route_schema["required"]), loom_runtime.ROUTE_FIELDS)
        session_schema = json.loads((Path(__file__).resolve().parent.parent /
                                     "schemas" / "session.schema.json").read_text(
                                         encoding="utf-8"))
        self.assertEqual(set(session_schema["properties"]), loom_runtime.SESSION_FIELDS)
        self.assertEqual(set(session_schema["required"]), loom_runtime.SESSION_FIELDS)
        self.assertEqual(
            loom_runtime.PreparedInvocation.from_dict(data).prepared_hash,
            prepared.prepared_hash)
        with self.assertRaises((AttributeError, TypeError)):
            prepared.intent = "close"
        with self.assertRaises(TypeError):
            prepared.route_contract["blocked"] = True
        self.assertIsInstance(prepared.domains, tuple)
        serialized = json.dumps(data, sort_keys=True)
        self.assertNotRegex(serialized.casefold(), r"capability|secret|token")
        self.assertNotIn(str(self.repo), serialized)

    def test_unknown_missing_and_hash_mutation_fail(self):
        clean = self.prepare().to_dict()
        for mutation in ("missing", "unknown", "hash"):
            data = json.loads(json.dumps(clean))
            if mutation == "missing":
                data.pop("intent")
            elif mutation == "unknown":
                data["private_surprise"] = True
            else:
                data["intent"] = "close"
            with self.assertRaises(loom_runtime.RuntimeError):
                loom_runtime.PreparedInvocation.from_dict(data)

    def test_schema_type_and_nested_route_forgery_fail(self):
        clean = self.prepare().to_dict()
        mutations = (
            ("instance_id", 12345678901234567890123456789012),
            ("domains", [1]),
            ("schema_version", True),
            ("prepared_at", "2026-07-13T12:00:00"),
        )
        for field, value in mutations:
            data = json.loads(json.dumps(clean))
            data[field] = value
            with self.subTest(field=field), self.assertRaises(loom_runtime.RuntimeError):
                loom_runtime.PreparedInvocation.from_dict(data)
        data = json.loads(json.dumps(clean))
        data["route_contract"]["private_surprise"] = True
        with self.assertRaisesRegex(loom_runtime.RuntimeError, "route contract fields"):
            loom_runtime.PreparedInvocation.from_dict(data)
        data = json.loads(json.dumps(clean))
        data["route_contract"]["target_mutation_count"] = 1
        with self.assertRaisesRegex(loom_runtime.RuntimeError, "side effect"):
            loom_runtime.PreparedInvocation.from_dict(data)

    def test_re_signed_raw_hard_stop_and_retry_forgery_fail(self):
        clean = self.prepare().to_dict()
        raw_stops = (
            "Use sk-private123456789 for C:\\Users\\Owner",
            "Read /etc/shadow before continuing",
            "Slack token " + "xox" + "b-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
            "private identifier Owner-Private-9472",
            "Authorization: " + "Bear" + "er " + "ey" + "Jabcdefghijklmnop.abcdefgh.abcdefghijkl",
            "database pass" + "word is hunter2",
        )
        for mutation in (*raw_stops, "retry"):
            data = json.loads(json.dumps(clean))
            if mutation == "retry":
                data["retry_key"] = "0" * 64
            else:
                data["hard_stops"].append(mutation)
            data.pop("prepared_hash")
            data["prepared_hash"] = loom_runtime._sha(
                loom_runtime._canonical_json(data))
            with self.subTest(mutation=mutation), self.assertRaises(
                    loom_runtime.RuntimeError):
                loom_runtime.PreparedInvocation.from_dict(data)


class NoConfigDefaultTests(RuntimeFixture):
    def test_absent_config_is_safe_zero_question_default(self):
        with mock.patch.object(Path, "home", side_effect=AssertionError("real home read")):
            prepared = self.prepare(owner_home=None)
        route = prepared.route_contract
        self.assertEqual(prepared.config_source, "builtin-safe-default")
        self.assertEqual(route["routine_question_count"], 0)
        for key in loom_runtime.EFFECT_COUNT_FIELDS:
            self.assertEqual(route[key], 0)

    def test_high_consequence_uncertainty_blocks_once(self):
        prepared = self.prepare("Deploy it and delete the old production data")
        route = prepared.route_contract
        self.assertTrue(route["blocked"])
        self.assertTrue(route["needs_owner"])
        self.assertEqual(route["code"], "HIGH_CONSEQUENCE_UNCERTAIN")
        self.assertIsInstance(route["recommendation"], str)
        self.assertTrue(route["recommendation"])
        self.assertEqual(route["target_mutation_count"], 0)

    def test_invalid_config_blocks_instead_of_falling_through(self):
        self.owner_home.mkdir()
        owner_config = json.loads(json.dumps(loom_runtime.DEFAULT_CONFIG))
        owner_config["loom_version"] = "owner"
        (self.owner_home / "loom.config.json").write_text(
            json.dumps(owner_config), encoding="utf-8")
        (self.repo / "loom.config.json").write_text(
            json.dumps({"use_profile": "yes", "unknown": True}), encoding="utf-8")
        prepared = self.prepare()
        self.assertEqual(prepared.config_source, "repository")
        self.assertTrue(prepared.route_contract["blocked"])
        self.assertEqual(prepared.route_contract["code"], "INVALID_CONFIG")

    def test_secret_or_path_shaped_hard_stop_is_not_copied_to_prepared_state(self):
        for unsafe in (
                "Use sk-private123456789",
                "Read C:\\Users\\Owner\\secret.txt",
                "Read /etc/shadow before continuing",
                "Slack token " + "xox" + "b-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
                "private identifier Owner-Private-9472",
                "Authorization: " + "Bear" + "er " + "ey" + "Jabcdefghijklmnop.abcdefgh.abcdefghijkl",
                "database pass" + "word is hunter2"):
            config = json.loads(json.dumps(loom_runtime.DEFAULT_CONFIG))
            config["hard_stops_extra"] = [unsafe]
            with self.subTest(unsafe=unsafe):
                prepared = self.prepare(explicit_config=config)
                self.assertNotIn(unsafe, json.dumps(prepared.to_dict()))
                self.assertTrue(all(
                    stop in loom_runtime.BASE_HARD_STOPS
                    or loom_runtime.CUSTOM_HARD_STOP_RE.fullmatch(stop)
                    for stop in prepared.hard_stops))

    def test_config_precedence_is_explicit_then_repository_then_owner(self):
        self.owner_home.mkdir()
        owner = json.loads(json.dumps(loom_runtime.DEFAULT_CONFIG))
        owner.update({"loom_version": "owner", "language": "fr"})
        (self.owner_home / "loom.config.json").write_text(
            json.dumps(owner), encoding="utf-8")
        self.assertEqual(self.prepare().config_source, "owner")

        repository = json.loads(json.dumps(owner))
        repository.update({"loom_version": "repository", "language": "de"})
        (self.repo / "loom.config.json").write_text(
            json.dumps(repository), encoding="utf-8")
        self.assertEqual(self.prepare().config_source, "repository")

        explicit = json.loads(json.dumps(repository))
        explicit.update({"loom_version": "explicit", "language": "en"})
        self.assertEqual(
            self.prepare(explicit_config=explicit).config_source, "explicit")


class UncertainRouteTests(unittest.TestCase):
    def test_ambiguous_intent_returns_one_recommended_checkpoint(self):
        decision = loom_runtime.resolve_intent(
            "Close this and build the next part", {"pack_exists": True, "terminal": True})
        self.assertTrue(decision["blocked"])
        self.assertTrue(decision["needs_owner"])
        self.assertEqual(decision["code"], "INTENT_AMBIGUOUS")
        self.assertTrue(decision["recommendation"])
        self.assertEqual(decision["target_mutation_count"], 0)

    def test_negated_action_is_not_silently_treated_as_positive(self):
        decision = loom_runtime.resolve_intent(
            "Do not close this; keep going", {"pack_exists": True})
        self.assertTrue(decision["blocked"])
        self.assertEqual(decision["code"], "INTENT_NEGATED")
        self.assertNotEqual(decision["intent"], "close")

    def test_lifecycle_negations_block_but_safety_preferences_are_remembered(self):
        for request in ("Never review this", "Don't keep going", "Do not build it"):
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, {})
                self.assertTrue(decision["blocked"])
                self.assertEqual(decision["code"], "INTENT_NEGATED")
        for request in (
                "Remember that I never want you to deploy without asking",
                "Never deploy", "Deploy nothing"):
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, {})
                self.assertEqual(decision["intent"], "remember")
                self.assertFalse(decision["blocked"])
        self.assertEqual(
            loom_runtime.resolve_intent(
                "Don't remember that I never want you to deploy", {})["intent"],
            "forget")
        scoped = loom_runtime.resolve_intent(
            "Remember that I don't want you to review automatically", {})
        self.assertEqual(scoped["intent"], "remember")
        self.assertFalse(scoped["blocked"])

    def test_memory_plus_separate_action_is_one_blocked_checkpoint(self):
        state = {
            "pack_exists": True, "authorized": True, "active_frontier": True,
        }
        for request in (
                "Remember never deploy, then build it",
                "Remember that I never want you to deploy, and continue"):
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, state)
                self.assertTrue(decision["blocked"])
                self.assertEqual(decision["code"], "INTENT_AMBIGUOUS")
                self.assertEqual(decision["target_mutation_count"], 0)

    def test_negated_forget_never_authorizes_deletion(self):
        for request in (
                "Don't forget that I prefer careful review",
                "I don't want you to forget that I prefer careful review",
                "Forget nothing", "Forget none of my rules",
                "Do not forget anything", "Never forget anything"):
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, {})
                self.assertTrue(decision["blocked"])
                self.assertEqual(decision["code"], "INTENT_NEGATED")
                self.assertNotEqual(decision["intent"], "forget")


class InvalidWorldStateTests(RuntimeFixture):
    def test_freshness_boundary_is_current_through_day_14_and_stale_on_day_15(self):
        pack = self.authorize_fixture_pack()
        current = loom_survey.repo_state(
            self.repo, exclude_prefixes=("plans",))
        verified = dt.date.today()

        current_state = loom_runtime._inspect_lifecycle(
            pack, current.state_hash, today=verified + dt.timedelta(days=14))
        stale_state = loom_runtime._inspect_lifecycle(
            pack, current.state_hash, today=verified + dt.timedelta(days=15))

        self.assertTrue(current_state["authorized"])
        self.assertNotIn("state_error", current_state)
        self.assertFalse(stale_state["authorized"])
        self.assertEqual("STALE_TIME", stale_state["state_error"])

    def test_invalid_lifecycle_blocks_instead_of_routing_through(self):
        pack = self.repo / "plans"
        pack.mkdir()
        (pack / "MANIFEST.md").write_text("# pack\n", encoding="utf-8")
        (pack / "lifecycle.json").write_text("{not-json", encoding="utf-8")
        prepared = self.prepare("Continue")
        self.assertTrue(prepared.route_contract["blocked"])
        self.assertEqual(prepared.route_contract["code"], "INVALID_LIFECYCLE")
        self.assertEqual(prepared.route_contract["target_mutation_count"], 0)

    def test_drift_routes_to_internal_selective_regate_then_execution(self):
        pack = self.authorize_fixture_pack()
        (pack / "plan-dependencies.json").write_text(json.dumps({
            "schema_version": 1,
            "sections": [
                {"id": "architecture", "target_patterns": ["src/ui.py", "src/**"]},
                {"id": "testing", "target_patterns": ["src/**"]},
                {"id": "docs", "target_patterns": ["README.md"]},
            ],
        }), encoding="utf-8")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "runtime.py").write_text(
            "VALUE = 1\n", encoding="utf-8")

        stale = self.prepare("Continue")
        self.assertEqual(stale.intent, "repair")
        self.assertEqual(stale.route_contract["code"], "AUTO_REGATE_REQUIRED")
        self.assertFalse(stale.route_contract["blocked"])
        self.assertFalse(stale.route_contract["needs_owner"])

        verified = []
        result = loom_lifecycle.reconcile(
            pack, self.repo,
            lambda section, changed: verified.append((section, changed)) or {
                "passed": True, "medium": "cli-process",
                "evidence_id": f"regate-{section}",
            })
        self.assertEqual(result["regate_scope"], "selective")
        self.assertEqual(
            [item[0] for item in verified], ["architecture", "testing"])

        current = self.prepare("Continue")
        self.assertEqual(current.intent, "execute")
        self.assertFalse(current.route_contract["blocked"])

        receipt_path = pack / loom_lifecycle.REGATE_FILE
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["verification"][0]["medium"] = "self-report"
        receipt["receipt_hash"] = loom_lifecycle._digest({
            key: value for key, value in receipt.items() if key != "receipt_hash"})
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        rejected = self.prepare("Continue")
        self.assertEqual(rejected.intent, "repair")
        self.assertEqual(rejected.route_contract["code"], "AUTO_REGATE_REQUIRED")

    def test_missing_lifecycle_and_ceremonial_status_text_cannot_close(self):
        for name, content in (
                ("WO-not-valid.md", "status: done\n"),
                ("WO-001-body-only.md", "# prose\nstatus: done\n"),
                ("WO-001-shaped.md", (
                    "---\nid: WO-001\ntitle: Test state\nstatus: done\n"
                    "depends_on: []\nblocks: []\nrouting: strong-coding\nsize: S\n"
                    "touches: [x]\nlast_verified: 2026-07-13\n---\n")),
        ):
            with self.subTest(name=name):
                pack = self.repo / "plans"
                if pack.exists():
                    for child in pack.rglob("*"):
                        if child.is_file():
                            child.unlink()
                orders = pack / "work-orders"
                orders.mkdir(parents=True, exist_ok=True)
                (orders / name).write_text(content, encoding="utf-8")
                prepared = self.prepare("Continue")
                self.assertTrue(prepared.route_contract["blocked"])
                self.assertEqual(
                    prepared.route_contract["code"], "INVALID_LIFECYCLE")
                self.assertNotEqual(prepared.intent, "close")

    def test_indeterminate_survey_is_a_typed_block(self):
        with mock.patch.object(
                loom_runtime.loom_survey, "repo_state",
                side_effect=loom_runtime.loom_survey.SurveyError("seeded survey failure")):
            with self.assertRaisesRegex(
                    loom_runtime.RuntimeBlocked, "PROJECT_INDETERMINATE"):
                self.prepare()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_special_pack_entry_fails_closed(self):
        pack = self.repo / "plans"
        pack.mkdir()
        fifo = pack / "special.fifo"
        os.mkfifo(fifo)
        try:
            with self.assertRaisesRegex(
                    loom_runtime.RuntimeBlocked, "PROJECT_INDETERMINATE"):
                self.prepare()
        finally:
            fifo.unlink(missing_ok=True)

    def test_in_progress_spelling_is_recognized_as_active_frontier(self):
        pack = self.authorize_fixture_pack()
        work_order = pack / "work-orders" / "WO-001-build-ui.md"
        work_order.write_text(
            work_order.read_text(encoding="utf-8").replace(
                "status: ready", "status: in-progress"),
            encoding="utf-8")
        manifest = pack / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "| WO-001 | ready |", "| WO-001 | in-progress |"),
            encoding="utf-8")
        current = loom_survey.repo_state(
            self.repo, exclude_prefixes=("plans",))
        state = loom_runtime._inspect_lifecycle(pack, current.state_hash)
        self.assertTrue(state["active_frontier"])
        self.assertTrue(state["authorized"])
        prepared = self.prepare("Build the next part")
        self.assertEqual(prepared.intent, "execute")
        self.assertFalse(prepared.route_contract["blocked"])

    def test_re_signed_unknown_lifecycle_fields_block_real_prepare(self):
        pack = self.authorize_fixture_pack()
        path = pack / "lifecycle.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["events"][2]["unknown_private_field"] = "owner-secret-marker"
        data["events"][2]["event_hash"] = loom_gate._event_hash(data["events"][2])
        path.write_text(json.dumps(data), encoding="utf-8")
        prepared = self.prepare("Continue")
        self.assertTrue(prepared.route_contract["blocked"])
        self.assertEqual(prepared.route_contract["code"], "INVALID_LIFECYCLE")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_non_git_target_special_entry_blocks_real_prepare(self):
        plain = self.root / "plain-project"
        plain.mkdir()
        baseline = self.prepare(explicit_target=plain, cwd=plain)
        fifo = plain / "target.fifo"
        os.mkfifo(fifo)
        try:
            with self.assertRaisesRegex(
                    loom_runtime.RuntimeBlocked, "PROJECT_INDETERMINATE"):
                self.prepare(explicit_target=plain, cwd=plain)
        finally:
            fifo.unlink(missing_ok=True)
        self.assertRegex(baseline.world_fingerprint, r"^[0-9a-f]{64}$")


class DecisionBoundaryTests(RuntimeFixture):
    def test_prepare_has_no_network_write_contribution_or_real_home_effect(self):
        with mock.patch.object(loom_survey.subprocess, "run",
                               wraps=subprocess.run) as processes, \
                mock.patch.object(Path, "write_text") as write_text, \
                mock.patch.object(Path, "write_bytes") as write_bytes, \
                mock.patch.object(loom_memory, "contribute") as contribute, \
                mock.patch.object(Path, "home", side_effect=AssertionError("real home")):
            prepared = self.prepare(owner_home=None)
        self.assertTrue(processes.call_args_list)
        self.assertTrue(all(call.args[0][0] == "git"
                            for call in processes.call_args_list))
        write_text.assert_not_called()
        write_bytes.assert_not_called()
        contribute.assert_not_called()
        for key in loom_runtime.EFFECT_COUNT_FIELDS:
            self.assertEqual(prepared.route_contract[key], 0)

    def test_prepare_never_executes_git_driver_or_writes_ambient_trace(self):
        sentinel = self.root / "forbidden-driver-effect.txt"
        trace = self.root / "forbidden-git-trace.txt"
        helper = self.root / "driver_probe.py"
        helper.write_text(
            "from pathlib import Path\n"
            f"Path({str(sentinel)!r}).write_text('executed', encoding='utf-8')\n",
            encoding="utf-8")
        command = f'"{sys.executable}" "{helper}"'
        git(self.repo, "config", "diff.external", command)
        git(self.repo, "config", "diff.probe.textconv", command)
        git(self.repo, "config", "filter.probe.clean", command)
        git(self.repo, "config", "filter.probe.smudge", command)
        git(self.repo, "config", "filter.probe.process", command)
        git(self.repo, "config", "filter.probe.required", "true")
        (self.repo / ".gitattributes").write_text(
            "README.md diff=probe filter=probe\n", encoding="utf-8")
        (self.repo / "README.md").write_text("changed\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"GIT_TRACE": str(trace)}, clear=False):
            self.prepare()
        self.assertFalse(sentinel.exists())
        self.assertFalse(trace.exists())


if __name__ == "__main__":
    unittest.main()
