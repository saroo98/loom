#!/usr/bin/env python3
"""Automatic lifecycle preflight, selective regating, and real-medium evidence."""

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
import sys

import loom_survey
import loom_privacy


SCHEMA_VERSION = 1
ACCEPTANCE_SCHEMA_VERSION = 3
REPAIR_EVIDENCE_SCHEMA_VERSION = 1
EVIDENCE_DIR = "evidence"
REGATE_FILE = ".loom-regate.json"
DEPENDENCY_FILE = "plan-dependencies.json"
RELEASE_FILE = "release-exposure.json"
MAX_TRANSCRIPT_BYTES = 256 * 1024
MAX_PERSISTED_TRANSCRIPT_CHARS = 4096
MAX_COMMAND_ITEMS = 32
MAX_SECTIONS = 128
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
WO_ID = re.compile(r"^WO-[0-9]{3,}$")
GENERIC_MEDIA = {"checklist", "generic", "unknown", "document-review", "self-report"}


class LifecycleError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _stamp(value=None):
    instant = value or dt.datetime.now(dt.timezone.utc)
    if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
        raise LifecycleError("timestamp must be timezone-aware")
    return instant.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat() \
        .replace("+00:00", "Z")


def _parse_stamp(value):
    if not isinstance(value, str):
        raise LifecycleError("timestamp must be UTC text")
    try:
        instant = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LifecycleError("timestamp is invalid") from exc
    if instant.tzinfo is None or instant.utcoffset() != dt.timedelta(0):
        raise LifecycleError("timestamp must be UTC")
    return instant


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise LifecycleError(f"JSON duplicates key {key!r}")
        value[key] = item
    return value


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.exists() and path.is_symlink():
        raise LifecycleError("lifecycle output path is unsafe")
    payload = _canonical(value) + b"\n"
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise LifecycleError(f"cannot commit lifecycle evidence: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _pack_relative(repo, pack):
    repo, pack = Path(repo).absolute(), Path(pack).absolute()
    try:
        return pack.relative_to(repo).as_posix()
    except ValueError:
        return None


def _repo_state(repo, pack):
    relative = _pack_relative(repo, pack)
    return loom_survey.repo_state(
        Path(repo).absolute(), exclude_prefixes=((relative,) if relative else ()))


def inspect_world(repo, pack):
    state = _repo_state(repo, pack)
    return {"mode": state.mode, "is_git": state.is_git, "head": state.head,
            "branch": state.branch, "staged_count": len(state.staged),
            "unstaged_count": len(state.unstaged),
            "untracked_count": len(state.untracked), "dirty": state.dirty,
            "state_hash": state.state_hash}


def _validate_medium(medium):
    if not isinstance(medium, str) or not SAFE_ID.fullmatch(medium) \
            or medium.casefold() in GENERIC_MEDIA:
        raise LifecycleError("acceptance evidence requires a named real medium")


def _validate_command(command):
    if not isinstance(command, list) or not 1 <= len(command) <= MAX_COMMAND_ITEMS \
            or not all(isinstance(item, str) and 0 < len(item) <= 1000
                       and "\x00" not in item for item in command):
        raise LifecycleError("verification command is invalid")


def _run_bounded(command, cwd, timeout):
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=stdout_file,
                                       stderr=stderr_file, shell=False)
        except OSError as exc:
            raise LifecycleError(f"verification command could not start: {exc}") from exc
        deadline = time.monotonic() + timeout
        exceeded = False
        while process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise LifecycleError("verification command timed out")
            if os.fstat(stdout_file.fileno()).st_size > MAX_TRANSCRIPT_BYTES \
                    or os.fstat(stderr_file.fileno()).st_size > MAX_TRANSCRIPT_BYTES:
                exceeded = True
                process.kill()
                process.wait()
                break
            time.sleep(0.02)
        if exceeded:
            raise LifecycleError("verification transcript exceeds its safety bound")
        stdout_file.seek(0); stderr_file.seek(0)
        stdout = stdout_file.read(MAX_TRANSCRIPT_BYTES + 1)
        stderr = stderr_file.read(MAX_TRANSCRIPT_BYTES + 1)
        if len(stdout) > MAX_TRANSCRIPT_BYTES or len(stderr) > MAX_TRANSCRIPT_BYTES:
            raise LifecycleError("verification transcript exceeds its safety bound")
        return process.returncode, stdout, stderr


def _copy_verification_snapshot(source, destination, excluded):
    """Copy regular target content without links into a disposable verification tree."""
    source, destination = Path(source), Path(destination)
    excluded = Path(excluded) if excluded is not None else None
    destination.mkdir(parents=True)
    pending = [(source, destination)]
    while pending:
        current, output = pending.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise LifecycleError(f"verification snapshot cannot enumerate target: {exc}") \
                from exc
        for entry in entries:
            path = Path(entry.path)
            if excluded is not None and (path == excluded or excluded in path.parents):
                continue
            if entry.is_symlink() or loom_privacy._is_redirect(path):
                raise LifecycleError(
                    f"verification snapshot refuses symlink or reparse entry: {path}")
            target = output / entry.name
            try:
                if entry.is_dir(follow_symlinks=False):
                    target.mkdir()
                    pending.append((path, target))
                elif entry.is_file(follow_symlinks=False):
                    shutil.copy2(path, target)
                else:
                    raise LifecycleError(
                        f"verification snapshot refuses non-regular entry: {path}")
            except OSError as exc:
                raise LifecycleError(f"verification snapshot copy failed: {exc}") from exc


def _capture_real_medium(pack, repo, *, medium, command, timeout, now):
    pack, repo = Path(pack).absolute(), Path(repo).absolute()
    _validate_medium(medium)
    _validate_command(command)
    if type(timeout) not in (int, float) or not 0 < timeout <= 300:
        raise LifecycleError("verification timeout is invalid")
    before = _repo_state(repo, pack)
    started = _stamp(now)
    relative_pack = _pack_relative(repo, pack)
    snapshot_parent = None
    with tempfile.TemporaryDirectory(prefix="loom-verification-") as temporary:
        snapshot_parent = Path(temporary)
        snapshot_root = snapshot_parent / "target"
        excluded = repo / relative_pack if relative_pack else None
        _copy_verification_snapshot(repo, snapshot_root, excluded)
        excluded_snapshot_pack = snapshot_root / ".loom-pack-excluded"
        snapshot_before = _repo_state(snapshot_root, excluded_snapshot_pack)
        exit_code, stdout, stderr = _run_bounded(command, snapshot_root, timeout)
        snapshot_after = _repo_state(snapshot_root, excluded_snapshot_pack)
        if snapshot_before.state_hash != snapshot_after.state_hash:
            raise LifecycleError("verification command changed its disposable target snapshot")
    completed = _stamp()
    after = _repo_state(repo, pack)
    if exit_code != 0:
        raise LifecycleError(f"verification command failed with exit code {exit_code}")
    if before.state_hash != after.state_hash:
        raise LifecycleError("verification command changed the target world")
    try:
        stdout_text = stdout.decode("utf-8")
        stderr_text = stderr.decode("utf-8")
    except UnicodeError as exc:
        raise LifecycleError("verification transcript is not UTF-8") from exc
    roots = [repo, snapshot_parent, Path.home()]
    stdout_minimized = loom_privacy.minimize_evidence(
        stdout_text, roots=roots, max_chars=MAX_PERSISTED_TRANSCRIPT_CHARS)
    stderr_minimized = loom_privacy.minimize_evidence(
        stderr_text, roots=roots, max_chars=MAX_PERSISTED_TRANSCRIPT_CHARS)
    command_minimized = [loom_privacy.minimize_evidence(
        item, roots=roots, max_chars=1000) for item in command]
    return {"medium": medium, "command": command_minimized, "started_at": started,
        "completed_at": completed, "exit_code": exit_code,
        "stdout": stdout_minimized, "stderr": stderr_minimized,
        "stdout_sha256": hashlib.sha256(stdout_minimized.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr_minimized.encode("utf-8")).hexdigest(),
        "raw_stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "raw_stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "transcript_minimized": True,
        "execution_isolation": "disposable-target-snapshot",
        "repo_state_before": before.state_hash,
        "repo_state_after": after.state_hash}


def _seal_content_evidence(evidence):
    evidence_hash = _digest(evidence)
    return {**evidence, "evidence_id": "sha256-" + evidence_hash,
            "evidence_hash": evidence_hash}


def capture_acceptance(pack, repo, work_order, *, medium, command,
                       timeout=120, now=None):
    pack = Path(pack).absolute()
    if not WO_ID.fullmatch(str(work_order)):
        raise LifecycleError("work-order id is invalid")
    evidence = _seal_content_evidence({
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "work_order": str(work_order),
        **_capture_real_medium(
            pack, repo, medium=medium, command=command, timeout=timeout, now=now),
    })
    _atomic_json(pack / EVIDENCE_DIR / f"{work_order}.json", evidence)
    return json.loads(json.dumps(evidence))


def capture_repair_verification(pack, repo, section, *, medium, command,
                                timeout=120, now=None):
    if not isinstance(section, str) or not SAFE_ID.fullmatch(section):
        raise LifecycleError("repair section identity is invalid")
    evidence = _seal_content_evidence({
        "schema_version": REPAIR_EVIDENCE_SCHEMA_VERSION,
        "section": section,
        **_capture_real_medium(
            pack, repo, medium=medium, command=command, timeout=timeout, now=now),
    })
    return json.loads(json.dumps(evidence))


def validate_acceptance_evidence(pack, work_order, repo=None, *,
                                 require_current=False, expected_state_hash=None):
    if not WO_ID.fullmatch(str(work_order)):
        raise LifecycleError("work-order id is invalid")
    path = Path(pack).absolute() / EVIDENCE_DIR / f"{work_order}.json"
    if path.is_symlink() or not path.is_file():
        raise LifecycleError("real-medium acceptance evidence is missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"acceptance evidence is invalid: {exc}") from exc
    fields = {"schema_version", "evidence_id", "work_order", "medium", "command",
        "started_at", "completed_at", "exit_code", "stdout", "stderr",
        "stdout_sha256", "stderr_sha256", "raw_stdout_sha256", "raw_stderr_sha256",
        "transcript_minimized", "execution_isolation", "repo_state_before", "repo_state_after",
        "evidence_hash"}
    body = {key: item for key, item in value.items()
            if key not in {"evidence_id", "evidence_hash"}} \
        if isinstance(value, dict) else {}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != ACCEPTANCE_SCHEMA_VERSION \
            or value.get("work_order") != work_order \
            or value.get("evidence_id") != "sha256-" + _digest(body) \
            or value.get("exit_code") != 0 \
            or not isinstance(value.get("stdout"), str) \
            or not isinstance(value.get("stderr"), str) \
            or len(value.get("stdout", "")) > MAX_PERSISTED_TRANSCRIPT_CHARS \
            or len(value.get("stderr", "")) > MAX_PERSISTED_TRANSCRIPT_CHARS \
            or value.get("transcript_minimized") is not True \
            or value.get("execution_isolation") != "disposable-target-snapshot" \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("raw_stdout_sha256", ""))) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("raw_stderr_sha256", ""))) \
            or not isinstance(value.get("repo_state_before"), str) \
            or not re.fullmatch(r"[0-9a-f]{64}", value["repo_state_before"]) \
            or not isinstance(value.get("repo_state_after"), str) \
            or not re.fullmatch(r"[0-9a-f]{64}", value["repo_state_after"]) \
            or value.get("repo_state_before") != value.get("repo_state_after") \
            or value.get("evidence_hash") != _digest(body) \
            or hashlib.sha256(str(value.get("stdout", "")).encode("utf-8")).hexdigest() \
            != value.get("stdout_sha256") \
            or hashlib.sha256(str(value.get("stderr", "")).encode("utf-8")).hexdigest() \
            != value.get("stderr_sha256"):
        raise LifecycleError("acceptance evidence contract or hash is invalid")
    try:
        started = _parse_stamp(value["started_at"])
        completed = _parse_stamp(value["completed_at"])
    except (ValueError, AttributeError) as exc:
        raise LifecycleError("acceptance evidence identity is invalid") from exc
    if completed < started:
        raise LifecycleError("acceptance evidence completes before it starts")
    _validate_medium(value["medium"])
    _validate_command(value["command"])
    if expected_state_hash is not None and value["repo_state_after"] != expected_state_hash:
        raise LifecycleError("acceptance evidence does not bind the expected world")
    if require_current:
        if repo is None:
            raise LifecycleError("current-world validation requires the repository")
        current = _repo_state(repo, pack)
        if current.state_hash != value["repo_state_after"]:
            raise LifecycleError("world changed after acceptance evidence was captured")
    return value


def _safe_pattern(value):
    return isinstance(value, str) and value and len(value) <= 300 \
        and not value.startswith(("/", "\\")) and ".." not in value.split("/")


def plan_regate(baseline_files, current_files, dependency_map):
    if not isinstance(baseline_files, dict) or not isinstance(current_files, dict) \
            or not isinstance(dependency_map, dict) \
            or set(dependency_map) != {"schema_version", "sections"} \
            or dependency_map["schema_version"] != SCHEMA_VERSION \
            or not isinstance(dependency_map["sections"], list) \
            or not 1 <= len(dependency_map["sections"]) <= MAX_SECTIONS:
        raise LifecycleError("plan dependency map is invalid")
    sections = []
    for item in dependency_map["sections"]:
        if not isinstance(item, dict) or set(item) != {"id", "target_patterns"} \
                or not isinstance(item["id"], str) or not SAFE_ID.fullmatch(item["id"]) \
                or not isinstance(item["target_patterns"], list) \
                or not item["target_patterns"] \
                or not all(_safe_pattern(pattern) for pattern in item["target_patterns"]):
            raise LifecycleError("plan dependency section is invalid")
        sections.append(item)
    if len({item["id"] for item in sections}) != len(sections):
        raise LifecycleError("plan dependency section ids must be unique")
    changed = sorted(path for path in set(baseline_files) | set(current_files)
                     if baseline_files.get(path) != current_files.get(path))
    affected, mapped = set(), set()
    for path in changed:
        for item in sections:
            if any(fnmatch.fnmatchcase(path, pattern)
                   or pattern.endswith("/**") and path.startswith(
                       pattern[:-3].rstrip("/") + "/")
                   for pattern in item["target_patterns"]):
                affected.add(item["id"]); mapped.add(path)
    if not changed:
        scope, result = "none", []
    elif set(changed) - mapped:
        scope, result = "full", ["full-pack"]
    else:
        scope, result = "selective", sorted(affected)
    return {"changed_paths": changed, "affected_plan_sections": result,
            "regate_scope": scope}


def validate_regate_receipt(pack, current_state_hash, prior_state_hash):
    path = Path(pack) / REGATE_FILE
    if path.is_symlink() or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, LifecycleError):
        return None
    fields = {"schema_version", "prior_state_hash", "current_state_hash",
              "changed_paths", "affected_plan_sections", "regate_scope",
              "verification", "sealed_at", "receipt_hash"}
    body = {key: item for key, item in value.items() if key != "receipt_hash"} \
        if isinstance(value, dict) else {}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("prior_state_hash") != prior_state_hash \
            or value.get("current_state_hash") != current_state_hash \
            or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)
                       for item in (prior_state_hash, current_state_hash)) \
            or value.get("receipt_hash") != _digest(body):
        return None
    changed = value.get("changed_paths")
    sections = value.get("affected_plan_sections")
    verification = value.get("verification")
    scope = value.get("regate_scope")
    if not isinstance(changed, list) or changed != sorted(set(changed)) \
            or not all(_safe_pattern(item) for item in changed) \
            or not isinstance(sections, list) or sections != sorted(set(sections)) \
            or not all(isinstance(item, str) and SAFE_ID.fullmatch(item)
                       for item in sections) \
            or scope not in {"none", "selective", "full"} \
            or (scope == "none" and (changed or sections)) \
            or (scope == "selective" and (not changed or not sections)) \
            or (scope == "full" and sections != ["full-pack"]) \
            or not isinstance(verification, list) \
            or len(verification) != len(sections):
        return None
    for expected, item in zip(sections, verification):
        if not isinstance(item, dict) or set(item) != {
                "passed", "medium", "evidence_id", "section"} \
                or item.get("passed") is not True or item.get("section") != expected \
                or not isinstance(item.get("evidence_id"), str) \
                or not SAFE_ID.fullmatch(item["evidence_id"]):
            return None
        try:
            _validate_medium(item.get("medium"))
        except LifecycleError:
            return None
    try:
        _parse_stamp(value.get("sealed_at"))
    except LifecycleError:
        return None
    return value


def preview_regate(pack, repo, *, force_full=False):
    """Return the exact world-bound repair scope without mutating the pack."""
    if type(force_full) is not bool:
        raise LifecycleError("force_full must be boolean")
    pack, repo = Path(pack).absolute(), Path(repo).absolute()
    try:
        lifecycle = json.loads((pack / "lifecycle.json").read_text(encoding="utf-8"),
                               object_pairs_hook=_strict_object)
        dependencies = json.loads((pack / DEPENDENCY_FILE).read_text(encoding="utf-8"),
                                  object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, LifecycleError) as exc:
        raise LifecycleError(f"cannot load selective-regate inputs: {exc}") from exc
    events = lifecycle.get("events", [])
    completions = lifecycle.get("work_order_completions", [])
    if not events:
        raise LifecycleError("lifecycle has no checkpoint")
    checkpoint = completions[-1] if completions else events[-1]
    prior_hash = checkpoint.get("repo_state_hash")
    reference = dict(lifecycle.get("baseline_files", {}))
    for completion in completions:
        reference.update(completion.get("after_hashes", {}))
    import loom_gate
    current_state, current_files = loom_gate._stable_snapshot(repo, pack)
    plan = plan_regate(reference, current_files, dependencies)
    if force_full:
        plan = dict(plan, affected_plan_sections=["full-pack"], regate_scope="full")
    return {
        **plan, "prior_state_hash": prior_hash,
        "current_state_hash": current_state.state_hash,
    }


def reconcile(pack, repo, verifier, *, now=None, force_full=False, expected_plan=None):
    """Regate exactly the affected sections through a trusted real-medium callback."""
    if not callable(verifier):
        raise LifecycleError("regate verifier must be callable")
    pack, repo = Path(pack).absolute(), Path(repo).absolute()
    plan = preview_regate(pack, repo, force_full=force_full)
    if expected_plan is not None and plan != expected_plan:
        raise LifecycleError("repair scope changed after it was sealed")
    verification = []
    for section in plan["affected_plan_sections"]:
        result = verifier(section, tuple(plan["changed_paths"]))
        if not isinstance(result, dict) or set(result) != {"passed", "medium", "evidence_id"} \
                or type(result["passed"]) is not bool \
                or not isinstance(result["evidence_id"], str) \
                or not SAFE_ID.fullmatch(result["evidence_id"]):
            raise LifecycleError("regate verifier returned an invalid result")
        _validate_medium(result["medium"])
        if not result["passed"]:
            return {"status": "blocked", "code": "REGATE_FAILED",
                    "needs_owner": False, **plan}
        verification.append(dict(result, section=section))
    receipt = {"schema_version": SCHEMA_VERSION,
        "prior_state_hash": plan["prior_state_hash"],
        "current_state_hash": plan["current_state_hash"],
        "changed_paths": plan["changed_paths"],
        "affected_plan_sections": plan["affected_plan_sections"],
        "regate_scope": plan["regate_scope"], "verification": verification,
        "sealed_at": _stamp(now)}
    receipt["receipt_hash"] = _digest(receipt)
    _atomic_json(pack / REGATE_FILE, receipt)
    return {"status": "ready", "code": "REGATE_SEALED", "needs_owner": False,
            **plan, "receipt_hash": receipt["receipt_hash"]}


def release_policy(*, external_users, irreversible, data_migration, regulated):
    if type(external_users) is not int or external_users < 0 \
            or any(type(item) is not bool for item in (
                irreversible, data_migration, regulated)):
        raise LifecycleError("release exposure inputs are invalid")
    if irreversible or data_migration or regulated:
        return {"level": "controlled", "requirements": [
            "staged rollout", "independent approval", "tested rollback",
            "audit evidence", "post-release verification"]}
    if external_users > 0:
        return {"level": "staged", "requirements": [
            "bounded rollout", "documented rollback", "release verification"]}
    return {"level": "none", "requirements": ["local acceptance evidence"]}


def seal_release_policy(pack, *, external_users, irreversible, data_migration,
                        regulated):
    inputs = {"external_users": external_users, "irreversible": irreversible,
              "data_migration": data_migration, "regulated": regulated}
    policy = release_policy(**inputs)
    record = {"schema_version": SCHEMA_VERSION, "inputs": inputs, **policy}
    record["policy_hash"] = _digest(record)
    _atomic_json(Path(pack) / RELEASE_FILE, record)
    return record


def validate_release_policy(pack):
    path = Path(pack) / RELEASE_FILE
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, LifecycleError) as exc:
        raise LifecycleError(f"release exposure record is invalid: {exc}") from exc
    fields = {"schema_version", "inputs", "level", "requirements", "policy_hash"}
    body = {key: item for key, item in value.items() if key != "policy_hash"} \
        if isinstance(value, dict) else {}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != SCHEMA_VERSION \
            or not isinstance(value.get("inputs"), dict) \
            or set(value["inputs"]) != {
                "external_users", "irreversible", "data_migration", "regulated"} \
            or value.get("policy_hash") != _digest(body):
        raise LifecycleError("release exposure contract or hash is invalid")
    expected = release_policy(**value["inputs"])
    if value.get("level") != expected["level"] \
            or value.get("requirements") != expected["requirements"]:
        raise LifecycleError("release exposure policy understates the measured exposure")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    world = commands.add_parser("world", help="inspect the complete target state")
    world.add_argument("--repo", required=True)
    world.add_argument("--pack", required=True)
    capture = commands.add_parser(
        "capture", help="run and seal real-medium work-order acceptance evidence")
    capture.add_argument("--repo", required=True)
    capture.add_argument("--pack", required=True)
    capture.add_argument("--wo", required=True)
    capture.add_argument("--medium", required=True)
    capture.add_argument("--timeout", type=float, default=120)
    capture.add_argument("verification_command", nargs=argparse.REMAINDER)
    policy = commands.add_parser(
        "release-policy", help="derive release and rollback rigor from exposure")
    policy.add_argument("--external-users", type=int, required=True)
    policy.add_argument("--irreversible", action="store_true")
    policy.add_argument("--data-migration", action="store_true")
    policy.add_argument("--regulated", action="store_true")
    policy.add_argument("--pack", help="seal the derived policy into this private pack")
    args = parser.parse_args(argv)
    try:
        if args.command == "world":
            result = inspect_world(args.repo, args.pack)
        elif args.command == "capture":
            command = list(args.verification_command)
            if command[:1] == ["--"]:
                command = command[1:]
            result = capture_acceptance(
                args.pack, args.repo, args.wo, medium=args.medium,
                command=command, timeout=args.timeout)
        else:
            inputs = dict(
                external_users=args.external_users,
                irreversible=args.irreversible,
                data_migration=args.data_migration,
                regulated=args.regulated)
            result = (seal_release_policy(args.pack, **inputs) if args.pack
                      else release_policy(**inputs))
    except (LifecycleError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "ok", "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
