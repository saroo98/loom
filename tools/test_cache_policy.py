#!/usr/bin/env python3

import unittest

import loom_cache_policy


def _sources(**overrides):
    value = {name: name + "-1" for name in loom_cache_policy.SOURCE_FIELDS}
    value.update(overrides)
    return value


class CachePolicyTests(unittest.TestCase):
    def test_exact_dependency_subtrees_invalidate(self):
        registry = loom_cache_policy.build_registry(_sources())
        expected = {
            "runtime-generation": {"static-guidance", "provider-prefix"},
            "host-adapter-generation": {"host-adapter", "provider-prefix"},
            "project-state-generation": {
                "project-routing", "domain-authority", "owner-selection"},
            "request-generation": {
                "project-routing", "domain-authority", "owner-selection"},
            "domain-facts-generation": {"domain-authority", "owner-selection"},
            "vault-generation": {"owner-selection"},
            "provider-semantics-generation": {"provider-prefix"},
        }
        for source, classes in expected.items():
            with self.subTest(source=source):
                result = loom_cache_policy.invalidate(registry, {source})
                self.assertEqual(classes, set(result["invalidated_classes"]))
                self.assertFalse(result["authorizes_execution"])

    def test_generation_change_mutates_only_exact_subtree(self):
        before = loom_cache_policy.build_registry(_sources())
        after = loom_cache_policy.build_registry(
            _sources(**{"vault-generation": "vault-2"}))
        changed = {name for name in before["classes"]
                   if before["classes"][name]["generation"]
                   != after["classes"][name]["generation"]}
        self.assertEqual({"owner-selection"}, changed)

    def test_replay_is_idempotent_and_never_authorizes(self):
        registry = loom_cache_policy.build_registry(_sources())
        self.assertEqual(registry, loom_cache_policy.build_registry(_sources()))
        self.assertFalse(registry["authorizes_execution"])
        self.assertEqual(registry, loom_cache_policy.validate_registry(registry))

    def test_unknown_or_empty_invalidation_fails_closed(self):
        registry = loom_cache_policy.build_registry(_sources())
        for changed in (set(), {"unknown"}):
            with self.subTest(changed=changed):
                with self.assertRaises(loom_cache_policy.CachePolicyError):
                    loom_cache_policy.invalidate(registry, changed)


if __name__ == "__main__":
    unittest.main()
