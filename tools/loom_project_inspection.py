#!/usr/bin/env python3
"""Typed, bounded project-structure evidence derived from one frozen world snapshot."""

import hashlib
import json
import os
import re
import time
from pathlib import Path, PurePosixPath


SCHEMA_VERSION = 1
POLICY_VERSION = "project-inspection-v1"
STATES = {
    "complete", "partial-safe", "partial-requires-discovery",
    "blocked-unsafe", "unsupported",
}
TIER_ORDER = {"S": 0, "M": 1, "L": 2, "XL": 3}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TARGET_RE = re.compile(r"^target-sha256:[0-9a-f]{64}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_NAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "cargo.toml",
    "manifest.json", "build.gradle", "build.gradle.kts", "setup.py",
}
class InspectionError(RuntimeError):
    """Project inspection evidence is malformed, unsafe, or contradictory."""


def _canonical_bytes(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise InspectionError(f"inspection evidence is not canonical JSON: {exc}") from exc


def _digest(value):
    value = dict(value)
    if isinstance(value.get("counters"), dict) and "elapsed_ms" in value["counters"]:
        value["counters"] = {**value["counters"], "elapsed_ms": 0}
    return "sha256:" + hashlib.sha256(
        b"loom-project-inspection-v1\0" + _canonical_bytes(value)).hexdigest()


def _safe_relative(value):
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value:
        raise InspectionError("inspection path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) \
            or re.match(r"^[A-Za-z]:", value):
        raise InspectionError("inspection path is unsafe")
    return value


def _policy_path(root=None):
    base = Path(root) if root is not None else Path(__file__).parent.parent
    return base / "contracts" / "project-inspection-policy-v1.json"


def load_policy(root=None):
    path = _policy_path(root)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InspectionError(f"project inspection policy is unavailable: {exc}") from exc
    expected = {"schema_version", "policy_version", "budgets", "generated_rules",
                "trust_authority_names"}
    budgets = {"detailed_facts", "fact_characters", "generated_exclusions",
               "manifest_bytes", "partitions", "unresolved_roots"}
    if not isinstance(value, dict) or set(value) != expected \
            or value["schema_version"] != SCHEMA_VERSION \
            or value["policy_version"] != POLICY_VERSION \
            or not isinstance(value["budgets"], dict) \
            or set(value["budgets"]) != budgets \
            or any(type(item) is not int or item < 1 for item in value["budgets"].values()) \
            or not isinstance(value["generated_rules"], list) \
            or not value["generated_rules"] \
            or not isinstance(value["trust_authority_names"], list) \
            or not value["trust_authority_names"] \
            or len(value["trust_authority_names"]) \
            != len(set(value["trust_authority_names"])) \
            or not all(isinstance(item, str) and 0 < len(item) <= 128
                       and "/" not in item and "\\" not in item
                       for item in value["trust_authority_names"]):
        raise InspectionError("project inspection policy fields are invalid")
    seen = set()
    for rule in value["generated_rules"]:
        fields = {"id", "basenames", "ancestor_markers", "ignored_required_in_git"}
        if not isinstance(rule, dict) or set(rule) != fields \
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", str(rule.get("id", ""))) \
                or rule["id"] in seen \
                or not isinstance(rule["basenames"], list) or not rule["basenames"] \
                or not isinstance(rule["ancestor_markers"], list) \
                or type(rule["ignored_required_in_git"]) is not bool:
            raise InspectionError("generated-output policy rule is invalid")
        for values in (rule["basenames"], rule["ancestor_markers"]):
            if len(values) != len(set(values)) or not all(
                    isinstance(item, str) and 0 < len(item) <= 128 and "/" not in item
                    and "\\" not in item for item in values):
                raise InspectionError("generated-output policy names are invalid")
        seen.add(rule["id"])
    return value


def _rule_map(policy):
    result = {}
    for rule in policy["generated_rules"]:
        for basename in rule["basenames"]:
            result.setdefault(basename.casefold(), []).append(rule)
    return result


def _under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def _ancestor_has_marker(root, candidate, markers):
    current = (root / PurePosixPath(candidate)).parent
    while True:
        if any((current / marker).is_file() for marker in markers):
            return True
        if current == root:
            return False
        try:
            current.relative_to(root)
        except ValueError:
            return False
        current = current.parent


def _ignored_roots(snapshot):
    if not snapshot.state.is_git:
        return ()
    try:
        result = snapshot.git_query(
            "ls-files", "--others", "--ignored", "--exclude-standard",
            "--directory", "--no-empty-directory", "-z", binary=True)
    except Exception as exc:
        raise InspectionError(f"cannot summarize ignored structure: {exc}") from exc
    if not isinstance(result.stdout, bytes):
        raise InspectionError("ignored structure query did not return bytes")
    roots = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        value = raw.decode("utf-8", errors="backslashreplace").rstrip("/")
        roots.append(_safe_relative(value))
    return tuple(sorted(set(roots), key=lambda item: os.fsencode(item)))


def classify_generated(snapshot, *, policy_root=None, touch_paths=()):
    """Classify generated roots once from the frozen census and Git evidence.

    The result is safe to use as a content-hash exclusion only because every accepted
    root is policy anchored, ignored, untracked, unchanged, outside the requested
    touch scope, and free of known trust-authority entries in the complete census.
    """
    policy = load_policy(policy_root)
    budgets = policy["budgets"]
    state = snapshot.state
    entries = tuple(snapshot.entries)
    tracked = set(snapshot.tracked)
    changed = set(state.staged + state.unstaged + state.untracked)
    touches = {_safe_relative(str(item).replace("\\", "/").strip("/"))
               for item in touch_paths}
    rules = _rule_map(policy)
    authority_names = {item.casefold() for item in policy["trust_authority_names"]}
    ignored = _ignored_roots(snapshot)

    candidate_dirs = []
    for entry in entries:
        if entry.kind == "directory" and PurePosixPath(entry.rel).name.casefold() in rules:
            if not any(_under(entry.rel, parent) for parent in candidate_dirs):
                candidate_dirs.append(entry.rel)
    candidate_dirs = sorted(candidate_dirs, key=lambda item: os.fsencode(item))

    exclusions = []
    unresolved = []
    accepted_roots = set()
    for candidate in candidate_dirs:
        if len(exclusions) >= budgets["generated_exclusions"]:
            if len(unresolved) < budgets["unresolved_roots"]:
                unresolved.append({"path": candidate, "reason": "partition-budget",
                                   "potential_authorities": ["generated-policy"]})
            continue
        basename = PurePosixPath(candidate).name.casefold()
        accepted = None
        for rule in rules[basename]:
            marker = _ancestor_has_marker(snapshot.root, candidate,
                                          rule["ancestor_markers"])
            ignored_by_git = state.is_git and any(
                _under(candidate, root_value) or _under(root_value, candidate)
                for root_value in ignored)
            tracked_descendant = any(_under(path, candidate) for path in tracked)
            changed_descendant = any(_under(path, candidate) for path in changed)
            touched = any(_under(path, candidate) or _under(candidate, path)
                          for path in touches)
            authority_descendant = any(
                _under(entry.rel, candidate)
                and PurePosixPath(entry.rel).name.casefold() in authority_names
                for entry in entries)
            if marker and not tracked_descendant and not changed_descendant and not touched \
                    and not authority_descendant \
                    and (ignored_by_git or not rule["ignored_required_in_git"]):
                accepted = (rule, ignored_by_git)
                break
        if accepted is not None:
            rule, accepted_ignored = accepted
            evidence = [f"policy:{POLICY_VERSION}", f"owner-marker:{rule['id']}",
                        "no-tracked-descendant", "no-current-change",
                        "no-trust-authority", "outside-touch-scope"]
            if accepted_ignored:
                evidence.append("git-ignored")
            exclusions.append({"path": candidate, "rule_id": rule["id"],
                               "evidence": sorted(evidence)})
            accepted_roots.add(candidate)
        elif not state.is_git and len(unresolved) < budgets["unresolved_roots"]:
            unresolved.append({"path": candidate,
                               "reason": "non-git-generated-uncertain",
                               "potential_authorities": ["source", "tool-output"]})

    for ignored_root in ignored:
        if any(_under(ignored_root, root_value) or _under(root_value, ignored_root)
               for root_value in accepted_roots):
            continue
        if len(unresolved) < budgets["unresolved_roots"]:
            unresolved.append({"path": ignored_root, "reason": "ignored-unclassified",
                               "potential_authorities": ["source", "configuration"]})

    unresolved = sorted(
        {(_safe_relative(item["path"]), item["reason"],
          tuple(sorted(item["potential_authorities"]))): {
              **item,
              "potential_authorities": sorted(item["potential_authorities"]),
          }
         for item in unresolved}.values(),
        key=lambda item: (os.fsencode(item["path"]), item["reason"]))
    return {
        "policy_version": POLICY_VERSION,
        "exclusions": tuple(sorted(exclusions,
                                   key=lambda item: os.fsencode(item["path"]))),
        "unresolved": tuple(unresolved),
        "ignored_roots": ignored,
    }


def _manifest_dependencies(name, raw):
    low = name.casefold()
    text = raw.decode("utf-8", errors="strict").casefold()
    dependencies = set()
    if low in {"package.json", "manifest.json"}:
        value = json.loads(text)
        if low == "package.json" and isinstance(value, dict):
            for field in ("dependencies", "devdependencies", "peerdependencies"):
                if isinstance(value.get(field), dict):
                    dependencies.update(str(item).casefold() for item in value[field])
            if isinstance(value.get("bin"), (dict, str)):
                dependencies.add("package-bin")
        elif isinstance(value, dict) and type(value.get("manifest_version")) is int:
            dependencies.add("webextension-manifest")
    elif low in {"build.gradle", "build.gradle.kts"}:
        if "com.android.application" in text:
            dependencies.add("com.android.application")
    else:
        for token in re.findall(r"(?m)^\s*([a-z0-9_.@/-]+)", text):
            dependencies.add(re.split(r"[<>=!~\[]", token)[0])
    return dependencies


def _bounded_append(values, value, maximum, character_budget, character_usage, *,
                    maximum_text=512):
    if value in values:
        return True
    if len(value) > maximum_text or len(values) >= maximum \
            or character_usage[0] + len(value) > character_budget:
        return False
    values.add(value)
    character_usage[0] += len(value)
    return True


def inspect(snapshot, *, target_identity, policy_root=None):
    """Derive one typed receipt without performing another filesystem census."""
    started = time.monotonic_ns()
    if not TARGET_RE.fullmatch(str(target_identity)):
        raise InspectionError("target identity is invalid")
    state = snapshot.state
    if not HASH_RE.fullmatch(str(state.state_hash)):
        raise InspectionError("snapshot survey hash is invalid")
    policy = load_policy(policy_root)
    budgets = policy["budgets"]
    root = snapshot.root
    entries = tuple(snapshot.entries)
    redirected = next((entry for entry in entries if entry.kind == "symlink"), None)
    if redirected is not None:
        raise InspectionError(
            f"workspace contains an unsafe symlink: {redirected.rel}")
    tracked = tuple(snapshot.tracked)
    changed = tuple(sorted(set(state.staged + state.unstaged + state.untracked)))
    tracked_set = set(tracked)
    changed_set = set(changed)
    untracked_set = set(state.untracked)
    frozen = getattr(snapshot, "generated_classification", None)
    if not isinstance(frozen, dict) or frozen.get("policy_version") != POLICY_VERSION:
        frozen = classify_generated(snapshot, policy_root=policy_root)
    exclusions = list(frozen["exclusions"])
    unresolved = list(frozen["unresolved"])
    ignored = tuple(frozen["ignored_roots"])
    excluded_roots = {item["path"] for item in exclusions}

    if len(untracked_set) > budgets["detailed_facts"]:
        untracked_roots = sorted({
            (path.split("/", 1)[0] if "/" in path else path)
            for path in untracked_set
        }, key=os.fsencode)
        for untracked_root in untracked_roots:
            if len(unresolved) >= budgets["unresolved_roots"]:
                break
            unresolved.append({
                "path": untracked_root,
                "reason": "untracked-volume",
                "potential_authorities": ["source", "configuration", "migration"],
            })

    file_names, extensions, dependencies, manifests = set(), set(), set(), set()
    fact_character_usage = [0]
    manifest_bytes = 0
    detail_budget_saturated = False
    relevant_files = relevant_directories = 0
    partition_counts = {}
    relevant_paths = tracked_set | changed_set
    if not state.is_git:
        relevant_paths = {entry.rel for entry in entries
                          if not any(_under(entry.rel, item) for item in excluded_roots)}
    for entry in entries:
        if any(_under(entry.rel, item) for item in excluded_roots):
            classification = "generated"
        elif entry.rel in relevant_paths or any(
                _under(path, entry.rel) for path in relevant_paths):
            classification = "relevant"
        else:
            classification = "unknown"
        partition = (entry.rel.split("/", 1)[0]
                     if "/" in entry.rel else "(root-files)")
        counts = partition_counts.setdefault(
            partition, {"files": 0, "directories": 0, "classes": set()})
        counts["directories" if entry.kind == "directory" else "files"] += 1
        counts["classes"].add(classification)
        if classification != "relevant":
            continue
        if entry.kind == "directory":
            relevant_directories += 1
            continue
        relevant_files += 1
        name = PurePosixPath(entry.rel).name.casefold()
        suffix = PurePosixPath(entry.rel).suffix.casefold()
        detail_budget_saturated |= not _bounded_append(
            file_names, name, budgets["detailed_facts"],
            budgets["fact_characters"], fact_character_usage, maximum_text=200)
        if suffix:
            detail_budget_saturated |= not _bounded_append(
                extensions, suffix, budgets["detailed_facts"],
                budgets["fact_characters"], fact_character_usage, maximum_text=200)
        if name in MANIFEST_NAMES:
            if len(manifests) >= budgets["detailed_facts"]:
                detail_budget_saturated = True
                continue
            path = root / PurePosixPath(entry.rel)
            if entry.size > budgets["manifest_bytes"] \
                    or manifest_bytes + entry.size > budgets["manifest_bytes"]:
                if len(unresolved) < budgets["unresolved_roots"]:
                    unresolved.append({"path": entry.rel, "reason": "manifest-oversized",
                                       "potential_authorities": ["manifest"]})
                continue
            try:
                before = path.stat()
                raw = path.read_bytes()
                after = path.stat()
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) \
                        or len(raw) != entry.size:
                    raise InspectionError(f"manifest changed during inspection: {entry.rel}")
                for dependency in sorted(_manifest_dependencies(name, raw)):
                    detail_budget_saturated |= not _bounded_append(
                        dependencies, dependency, budgets["detailed_facts"],
                        budgets["fact_characters"], fact_character_usage,
                        maximum_text=200)
                manifest_bytes += len(raw)
                detail_budget_saturated |= not _bounded_append(
                    manifests, entry.rel, budgets["detailed_facts"],
                    budgets["fact_characters"], fact_character_usage)
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                if len(unresolved) < budgets["unresolved_roots"]:
                    unresolved.append({"path": entry.rel, "reason": "manifest-invalid",
                                       "potential_authorities": ["manifest"]})
                if isinstance(exc, OSError):
                    raise InspectionError(f"cannot read dependency manifest: {exc}") from exc
    partitions = []
    for name in sorted(partition_counts, key=lambda item: os.fsencode(item)):
        if len(partitions) >= budgets["partitions"]:
            if len(unresolved) < budgets["unresolved_roots"]:
                unresolved.append({"path": name, "reason": "partition-budget",
                                   "potential_authorities": ["source"]})
            break
        value = partition_counts[name]
        classes = value.pop("classes")
        classification = ("unknown" if "unknown" in classes else
                          "relevant" if "relevant" in classes else "generated")
        partitions.append({"path": name, "files": value["files"],
                           "directories": value["directories"],
                           "classification": classification})

    unresolved = sorted(
        {(_safe_relative(item["path"]), item["reason"],
          tuple(sorted(item["potential_authorities"]))): {
              **item,
              "potential_authorities": sorted(item["potential_authorities"]),
          }
         for item in unresolved}.values(),
        key=lambda item: (os.fsencode(item["path"]), item["reason"]))
    # Detailed fact saturation is an intentional summary transition, not missing
    # structural coverage.  The receipt still accounts for every relevant entry in
    # counters and bounded ownership partitions.
    complete = not unresolved
    state_value = "complete" if complete else "partial-requires-discovery"
    source_complete = "complete"
    source_partial = "partial-requires-discovery" if not complete else "complete"
    body = {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "target_identity": target_identity,
        "survey_hash": state.state_hash,
        "state": state_value,
        "source_states": {
            "filesystem_safety": source_complete,
            "tracked": source_complete if state.is_git else "unsupported",
            "staged": source_complete if state.is_git else "unsupported",
            "unstaged": source_complete if state.is_git else "unsupported",
            "untracked": source_complete,
            "ignored_generated": source_partial,
            "manifests": source_partial,
        },
        "counters": {
            "entries_seen": len(entries),
            "tracked_paths_seen": len(tracked),
            "changed_paths_seen": len(changed_set),
            "untracked_paths_seen": len(untracked_set),
            "ignored_candidate_roots_seen": len(ignored),
            "relevant_files_inspected": relevant_files,
            "relevant_directories_inspected": relevant_directories,
            "manifest_bytes_read": manifest_bytes,
            "generated_subtrees_excluded": len(exclusions),
            "unknown_subtrees_summarized": len(unresolved),
            "partitions_summarized": len(partitions),
            "detailed_facts_saturated": int(detail_budget_saturated),
            "elapsed_ms": min(120000, int((time.monotonic_ns() - started) / 1_000_000)),
        },
        "facts": {
            "file_names": sorted(file_names),
            "extensions": sorted(extensions),
            "dependencies": sorted(dependencies),
            "manifests": sorted(manifests),
        },
        "partitions": partitions,
        "generated_exclusions": sorted(exclusions, key=lambda item: os.fsencode(item["path"])),
        "unresolved_roots": unresolved,
        "relevant_coverage_complete": complete,
        "routing_eligible": True,
        "draft_planning_eligible": True,
        "g1_eligible": complete,
        "implementation_eligible": complete,
        "tier_floor": "S" if complete else "L",
    }
    value = {**body, "receipt_digest": _digest(body)}
    validate(value)
    return value


def validate(value):
    required = {
        "schema_version", "policy_version", "target_identity", "survey_hash", "state",
        "source_states", "counters", "facts", "partitions", "generated_exclusions",
        "unresolved_roots", "relevant_coverage_complete", "routing_eligible",
        "draft_planning_eligible", "g1_eligible", "implementation_eligible", "tier_floor",
        "receipt_digest",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value["schema_version"] != SCHEMA_VERSION \
            or value["policy_version"] != POLICY_VERSION \
            or not TARGET_RE.fullmatch(str(value["target_identity"])) \
            or not HASH_RE.fullmatch(str(value["survey_hash"])) \
            or value["state"] not in STATES or value["tier_floor"] not in TIER_ORDER:
        raise InspectionError("project inspection receipt identity is invalid")
    booleans = {"relevant_coverage_complete", "routing_eligible",
                "draft_planning_eligible", "g1_eligible", "implementation_eligible"}
    if any(type(value[name]) is not bool for name in booleans):
        raise InspectionError("project inspection eligibility fields are invalid")
    if (value["g1_eligible"] or value["implementation_eligible"]) \
            and (not value["relevant_coverage_complete"] or value["state"] != "complete"):
        raise InspectionError("partial inspection cannot authorize G1 or implementation")
    if value["implementation_eligible"] and not value["g1_eligible"]:
        raise InspectionError("implementation eligibility requires G1 eligibility")
    if value["g1_eligible"] and not value["draft_planning_eligible"] \
            or value["draft_planning_eligible"] and not value["routing_eligible"]:
        raise InspectionError("project inspection eligibility chain is invalid")
    if value["state"] == "complete":
        if not value["relevant_coverage_complete"] or not value["g1_eligible"] \
                or not value["implementation_eligible"] or value["unresolved_roots"]:
            raise InspectionError("complete inspection has contradictory gates")
    elif value["state"] in {"partial-safe", "partial-requires-discovery"}:
        if value["relevant_coverage_complete"] or value["g1_eligible"] \
                or value["implementation_eligible"] or not value["unresolved_roots"]:
            raise InspectionError("partial inspection has contradictory coverage")
    elif value["routing_eligible"] or value["draft_planning_eligible"]:
        raise InspectionError("unsafe or unsupported inspection cannot route")
    source_keys = {"filesystem_safety", "tracked", "staged", "unstaged", "untracked",
                   "ignored_generated", "manifests"}
    if not isinstance(value["source_states"], dict) \
            or set(value["source_states"]) != source_keys \
            or any(item not in STATES for item in value["source_states"].values()):
        raise InspectionError("project inspection source states are invalid")
    policy = load_policy()
    budgets = policy["budgets"]
    counter_keys = {
        "entries_seen", "tracked_paths_seen", "changed_paths_seen",
        "untracked_paths_seen", "ignored_candidate_roots_seen",
        "relevant_files_inspected", "relevant_directories_inspected",
        "manifest_bytes_read", "generated_subtrees_excluded",
        "unknown_subtrees_summarized", "partitions_summarized",
        "detailed_facts_saturated",
        "elapsed_ms",
    }
    if not isinstance(value["counters"], dict) \
            or set(value["counters"]) != counter_keys \
            or any(type(item) is not int or item < 0
                   for item in value["counters"].values()) \
            or value["counters"]["entries_seen"] > 100000 \
            or value["counters"]["tracked_paths_seen"] > 100000 \
            or value["counters"]["changed_paths_seen"] > 100000 \
            or value["counters"]["untracked_paths_seen"] > 100000 \
            or value["counters"]["ignored_candidate_roots_seen"] > 100000 \
            or value["counters"]["relevant_files_inspected"] > 100000 \
            or value["counters"]["relevant_directories_inspected"] > 100000 \
            or value["counters"]["manifest_bytes_read"] > budgets["manifest_bytes"] \
            or value["counters"]["generated_subtrees_excluded"] \
            > budgets["generated_exclusions"] \
            or value["counters"]["unknown_subtrees_summarized"] \
            > budgets["unresolved_roots"] \
            or value["counters"]["partitions_summarized"] > budgets["partitions"] \
            or value["counters"]["detailed_facts_saturated"] not in {0, 1} \
            or value["counters"]["elapsed_ms"] > 120000:
        raise InspectionError("project inspection counters are invalid")
    if not isinstance(value["generated_exclusions"], list) \
            or len(value["generated_exclusions"]) > budgets["generated_exclusions"] \
            or not isinstance(value["unresolved_roots"], list) \
            or len(value["unresolved_roots"]) > budgets["unresolved_roots"] \
            or not isinstance(value["partitions"], list) \
            or len(value["partitions"]) > budgets["partitions"]:
        raise InspectionError("project inspection collections exceed their bounds")
    for collection in (value["generated_exclusions"], value["unresolved_roots"],
                       value["partitions"]):
        paths = []
        for item in collection:
            if not isinstance(item, dict) or "path" not in item:
                raise InspectionError("project inspection path record is invalid")
            _safe_relative(item["path"])
            paths.append(item["path"])
        if paths != sorted(paths, key=lambda item: os.fsencode(item)) \
                or len(paths) != len(set(paths)):
            raise InspectionError("project inspection paths are duplicate or noncanonical")
    rule_ids = {rule["id"] for rule in policy["generated_rules"]}
    for item in value["generated_exclusions"]:
        if set(item) != {"path", "rule_id", "evidence"} \
                or item["rule_id"] not in rule_ids \
                or not isinstance(item["evidence"], list) \
                or not 3 <= len(item["evidence"]) <= 8 \
                or item["evidence"] != sorted(item["evidence"]) \
                or len(item["evidence"]) != len(set(item["evidence"])) \
                or not all(isinstance(evidence, str) and 0 < len(evidence) <= 128
                           for evidence in item["evidence"]):
            raise InspectionError("generated exclusion evidence is invalid")
    unresolved_reasons = {
        "detailed-budget", "ignored-unclassified", "manifest-oversized",
        "manifest-invalid", "non-git-generated-uncertain", "partition-budget",
        "untracked-volume",
    }
    for item in value["unresolved_roots"]:
        if set(item) != {"path", "reason", "potential_authorities"} \
                or item["reason"] not in unresolved_reasons \
                or not isinstance(item["potential_authorities"], list) \
                or len(item["potential_authorities"]) > 8 \
                or item["potential_authorities"] != sorted(
                    item["potential_authorities"]) \
                or len(item["potential_authorities"]) \
                != len(set(item["potential_authorities"])) \
                or not all(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", str(name))
                           for name in item["potential_authorities"]):
            raise InspectionError("unresolved inspection evidence is invalid")
    for item in value["partitions"]:
        if set(item) != {"path", "files", "directories", "classification"} \
                or type(item["files"]) is not int or not 0 <= item["files"] <= 100000 \
                or type(item["directories"]) is not int \
                or not 0 <= item["directories"] <= 100000 \
                or item["classification"] not in {"relevant", "generated", "unknown"}:
            raise InspectionError("inspection partition is invalid")
    if value["counters"]["generated_subtrees_excluded"] \
            != len(value["generated_exclusions"]) \
            or value["counters"]["unknown_subtrees_summarized"] \
            != len(value["unresolved_roots"]) \
            or value["counters"]["partitions_summarized"] != len(value["partitions"]):
        raise InspectionError("inspection counters do not match their records")
    fact_keys = {"file_names", "extensions", "dependencies", "manifests"}
    if not isinstance(value["facts"], dict) or set(value["facts"]) != fact_keys:
        raise InspectionError("project inspection facts are invalid")
    for items in value["facts"].values():
        if not isinstance(items, list) or len(items) > budgets["detailed_facts"] \
                or len(items) != len(set(items)) or items != sorted(items) \
                or not all(isinstance(item, str) and 0 < len(item) <= 512
                           for item in items):
            raise InspectionError("project inspection facts exceed their bound")
    if sum(len(item) for items in value["facts"].values() for item in items) \
            > budgets["fact_characters"]:
        raise InspectionError("project inspection fact text exceeds its bound")
    for path in value["facts"]["manifests"]:
        _safe_relative(path)
    body = dict(value)
    claimed = body.pop("receipt_digest")
    if not DIGEST_RE.fullmatch(str(claimed)) or claimed != _digest(body):
        raise InspectionError("project inspection receipt digest mismatch")
    return value


def facts(value):
    validate(value)
    return {key: list(value["facts"][key])
            for key in ("file_names", "extensions", "dependencies")}


def capsule(value):
    validate(value)
    body = {
        "schema_version": 1,
        "state": value["state"],
        "receipt_digest": value["receipt_digest"],
        "relevant_coverage_complete": value["relevant_coverage_complete"],
        "routing_eligible": value["routing_eligible"],
        "draft_planning_eligible": value["draft_planning_eligible"],
        "g1_eligible": value["g1_eligible"],
        "implementation_eligible": value["implementation_eligible"],
        "tier_floor": value["tier_floor"],
        "counts": {
            key: value["counters"][key] for key in (
                "entries_seen", "tracked_paths_seen", "changed_paths_seen",
                "untracked_paths_seen", "generated_subtrees_excluded",
                "unknown_subtrees_summarized")},
        "generated_rule_ids": sorted({item["rule_id"]
                                      for item in value["generated_exclusions"]})[:8],
        "unresolved_roots": [item["path"] for item in value["unresolved_roots"][:8]],
    }
    if len(_canonical_bytes(body)) > 2048:
        raise InspectionError("project inspection capsule exceeds 2 KB")
    return body


def capsule_from_capsule(value):
    """Validate and return a detached compact capsule without needing the full receipt."""
    fields = {
        "schema_version", "state", "receipt_digest", "relevant_coverage_complete",
        "routing_eligible", "draft_planning_eligible", "g1_eligible",
        "implementation_eligible", "tier_floor", "counts", "generated_rule_ids",
        "unresolved_roots",
    }
    count_fields = {
        "entries_seen", "tracked_paths_seen", "changed_paths_seen",
        "untracked_paths_seen", "generated_subtrees_excluded",
        "unknown_subtrees_summarized",
    }
    boolean_fields = {
        "relevant_coverage_complete", "routing_eligible", "draft_planning_eligible",
        "g1_eligible", "implementation_eligible",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 or value.get("state") not in STATES \
            or not DIGEST_RE.fullmatch(str(value.get("receipt_digest"))) \
            or value.get("tier_floor") not in TIER_ORDER \
            or any(type(value.get(field)) is not bool for field in boolean_fields) \
            or not isinstance(value.get("counts"), dict) \
            or set(value["counts"]) != count_fields \
            or any(type(item) is not int or not 0 <= item <= 100000
                   for item in value["counts"].values()) \
            or value["counts"]["generated_subtrees_excluded"] > 128 \
            or value["counts"]["unknown_subtrees_summarized"] > 32 \
            or not isinstance(value.get("generated_rule_ids"), list) \
            or len(value["generated_rule_ids"]) > 8 \
            or value["generated_rule_ids"] != sorted(value["generated_rule_ids"]) \
            or len(value["generated_rule_ids"]) != len(set(value["generated_rule_ids"])) \
            or not all(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", str(item))
                       for item in value["generated_rule_ids"]) \
            or not isinstance(value.get("unresolved_roots"), list) \
            or len(value["unresolved_roots"]) > 8 \
            or value["unresolved_roots"] != sorted(
                value["unresolved_roots"], key=lambda item: os.fsencode(item)) \
            or len(value["unresolved_roots"]) != len(set(value["unresolved_roots"])):
        raise InspectionError("project inspection capsule is invalid")
    for path in value["unresolved_roots"]:
        _safe_relative(path)
    if (value["g1_eligible"] or value["implementation_eligible"]) \
            and (not value["relevant_coverage_complete"] or value["state"] != "complete"):
        raise InspectionError("partial inspection capsule cannot authorize execution")
    if value["implementation_eligible"] and not value["g1_eligible"] \
            or value["g1_eligible"] and not value["draft_planning_eligible"] \
            or value["draft_planning_eligible"] and not value["routing_eligible"]:
        raise InspectionError("project inspection capsule eligibility chain is invalid")
    if value["state"] == "complete" and (
            not value["relevant_coverage_complete"] or not value["g1_eligible"]
            or value["unresolved_roots"]):
        raise InspectionError("complete inspection capsule is contradictory")
    if value["state"] in {"partial-safe", "partial-requires-discovery"} and (
            value["relevant_coverage_complete"] or value["g1_eligible"]
            or not value["unresolved_roots"]):
        raise InspectionError("partial inspection capsule is contradictory")
    return value
