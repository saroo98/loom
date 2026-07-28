#!/usr/bin/env python3
"""Typed Loom subjects and bounded Git/generated inventories.

Observed subjects may be produced by candidate code. Expected subjects are accepted
only from a verified stable-controller or CI expectation receipt.
"""

import base64
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import uuid
from pathlib import Path, PurePosixPath


REPOSITORY = "https://github.com/saroo98/loom"
SUBJECT_KINDS = {
    "main-source", "candidate-source", "release-tag", "plugin-zip",
    "native-helper", "installed-runtime",
}
PLATFORMS = {
    "windows-x64", "windows-arm64", "macos-x64", "macos-arm64",
    "linux-x64", "linux-arm64",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$")
MAX_GIT_ENTRIES = 8192
MAX_GIT_BLOB_BYTES = 512 * 1024 * 1024
MAX_GIT_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_OVERLAY_ENTRIES = 1024
MAX_OVERLAY_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_GENERATED_OUTPUTS = 256
MAX_GENERATED_FILE_BYTES = 64 * 1024 * 1024
MAX_GENERATED_TOTAL_BYTES = 256 * 1024 * 1024
EMPTY_OVERLAY_SHA256 = hashlib.sha256(b"loom-empty-overlay-v1\0").hexdigest()


class SubjectIdentityError(RuntimeError):
    pass


class VerifiedExpectedSubjects(dict):
    """Marker returned only after controller or CI authority verification."""


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _subject_digest(value):
    return digest({key: item for key, item in value.items()
                   if key != "subject_digest"})


def _instant(value, label):
    if not isinstance(value, str):
        raise SubjectIdentityError(f"{label} is not a timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SubjectIdentityError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise SubjectIdentityError(f"{label} lacks a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _safe_relative(value):
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise SubjectIdentityError("inventory path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SubjectIdentityError("inventory path is unsafe")
    return path.as_posix()


def _run_git(root, *args, binary=False, input_bytes=None):
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotePath=false", *args],
            cwd=str(root), input=input_bytes, capture_output=True,
            text=not binary, check=False, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SubjectIdentityError(f"Git inventory failed: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr if not binary else result.stderr.decode(
            "utf-8", errors="replace")
        raise SubjectIdentityError(
            "Git inventory failed: " + (message.strip() or "unknown error"))
    return result.stdout


def _read_git_blobs(root, rows):
    process = None
    try:
        process = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            cwd=str(root), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        result = {}
        total = 0
        for row in rows:
            process.stdin.write(row["object"].encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline()
            fields = header.rstrip(b"\n").split(b" ")
            if len(fields) != 3 or fields[0].decode("ascii") != row["object"] \
                    or fields[1] != b"blob":
                raise SubjectIdentityError("Git object is missing or is not a blob")
            try:
                size = int(fields[2])
            except ValueError as exc:
                raise SubjectIdentityError("Git blob size is invalid") from exc
            if size != row["bytes"] or size > MAX_GIT_BLOB_BYTES:
                raise SubjectIdentityError("Git blob exceeds or disagrees with inventory")
            total += size
            if total > MAX_GIT_TOTAL_BYTES:
                raise SubjectIdentityError("Git tree exceeds the aggregate byte bound")
            raw = process.stdout.read(size)
            trailer = process.stdout.read(1)
            if len(raw) != size or trailer != b"\n":
                raise SubjectIdentityError("Git blob changed or was truncated")
            result[row["object"]] = hashlib.sha256(raw).hexdigest()
        process.stdin.close()
        if process.wait(timeout=30) != 0:
            raise SubjectIdentityError("Git object reader failed")
        return result
    except (OSError, subprocess.SubprocessError) as exc:
        raise SubjectIdentityError(f"Git object reader failed: {exc}") from exc
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def git_tree_inventory(root, commit):
    """Hash one exact committed tree without recursively inspecting the worktree."""
    root = Path(root).resolve()
    if not root.is_dir() or not isinstance(commit, str) or HEX40.fullmatch(commit) is None:
        raise SubjectIdentityError("Git tree root or commit is invalid")
    raw = _run_git(
        root, "ls-tree", "-r", "-z", "--full-tree", "--long", commit,
        binary=True)
    rows, seen = [], set()
    for record in (item for item in raw.split(b"\0") if item):
        if b"\t" not in record:
            raise SubjectIdentityError("Git tree record is malformed")
        metadata, raw_path = record.split(b"\t", 1)
        fields = metadata.split()
        if len(fields) != 4 or fields[1] != b"blob":
            raise SubjectIdentityError("Git tree contains an unsupported object")
        try:
            mode = fields[0].decode("ascii")
            object_id = fields[2].decode("ascii")
            size = int(fields[3])
            path = _safe_relative(raw_path.decode("utf-8", errors="strict"))
        except (UnicodeError, ValueError) as exc:
            raise SubjectIdentityError("Git tree record is invalid") from exc
        if mode not in {"100644", "100755"} \
                or HEX40.fullmatch(object_id) is None or size < 0 \
                or size > MAX_GIT_BLOB_BYTES or path.casefold() in seen:
            raise SubjectIdentityError("Git tree entry is unsafe")
        seen.add(path.casefold())
        rows.append({"path": path, "mode": mode, "object": object_id, "bytes": size})
        if len(rows) > MAX_GIT_ENTRIES:
            raise SubjectIdentityError("Git tree exceeds the entry bound")
    if not rows:
        raise SubjectIdentityError("Git tree is empty")
    blobs = _read_git_blobs(root, rows)
    normalized = [
        {**row, "sha256": blobs[row["object"]]} for row in
        sorted(rows, key=lambda item: item["path"].encode("utf-8"))
    ]
    body = {"schema_version": 1, "commit": commit, "entries": normalized}
    return {**body, "tree_sha256": digest(body)}


def overlay_digest(rows):
    """Digest only a controller-declared dirty overlay, never an ambient walk."""
    if rows is None:
        rows = []
    if not isinstance(rows, list) or len(rows) > MAX_OVERLAY_ENTRIES:
        raise SubjectIdentityError("candidate overlay inventory is invalid")
    normalized, seen, total = [], set(), 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise SubjectIdentityError("candidate overlay entry is invalid")
        path = _safe_relative(row["path"])
        if path.casefold() in seen or type(row["bytes"]) is not int \
                or row["bytes"] < 0 or not isinstance(row["sha256"], str) \
                or HEX64.fullmatch(row["sha256"]) is None:
            raise SubjectIdentityError("candidate overlay entry is unsafe")
        seen.add(path.casefold())
        total += row["bytes"]
        if total > MAX_OVERLAY_TOTAL_BYTES:
            raise SubjectIdentityError("candidate overlay exceeds the aggregate byte bound")
        normalized.append({"path": path, "bytes": row["bytes"], "sha256": row["sha256"]})
    if not normalized:
        return EMPTY_OVERLAY_SHA256
    return digest({"schema_version": 1, "entries": sorted(
        normalized, key=lambda item: item["path"].encode("utf-8"))})


def generated_inventory(root, registry):
    """Read only exact generated paths declared by the authority registry."""
    if not isinstance(registry, dict) or not isinstance(
            registry.get("generated_outputs"), list) \
            or len(registry["generated_outputs"]) > MAX_GENERATED_OUTPUTS:
        raise SubjectIdentityError("declared generated inventory is invalid")
    root = Path(root).resolve()
    rows, total, seen = [], 0, set()
    for declaration in registry["generated_outputs"]:
        if not isinstance(declaration, dict) or "path" not in declaration:
            raise SubjectIdentityError("generated output declaration is invalid")
        relative = _safe_relative(declaration["path"])
        if relative.casefold() in seen:
            raise SubjectIdentityError("generated output is declared more than once")
        seen.add(relative.casefold())
        path = root.joinpath(*PurePosixPath(relative).parts)
        try:
            if path.resolve(strict=True) != path.absolute():
                raise SubjectIdentityError(
                    f"declared generated output is redirected: {relative}")
            path.relative_to(root)
            info = path.lstat()
        except (OSError, ValueError) as exc:
            raise SubjectIdentityError(
                f"declared generated output is unavailable: {relative}") from exc
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() \
                or info.st_size > MAX_GENERATED_FILE_BYTES:
            raise SubjectIdentityError(
                f"declared generated output is unsafe: {relative}")
        raw = path.read_bytes()
        if len(raw) != info.st_size:
            raise SubjectIdentityError(
                f"declared generated output changed while reading: {relative}")
        total += len(raw)
        if total > MAX_GENERATED_TOTAL_BYTES:
            raise SubjectIdentityError("declared generated outputs exceed byte bound")
        rows.append({"path": relative, "bytes": len(raw),
                     "sha256": hashlib.sha256(raw).hexdigest()})
    body = {"schema_version": 1, "outputs": sorted(
        rows, key=lambda item: item["path"].encode("utf-8"))}
    return {**body, "inventory_sha256": digest(body)}


def seal_subject(value):
    if not isinstance(value, dict) or "subject_digest" in value:
        raise SubjectIdentityError("unsealed subject fields are invalid")
    sealed = {**value, "subject_digest": _subject_digest(value)}
    return validate_subject(sealed)


def validate_subject(value):
    if not isinstance(value, dict) or value.get("schema_version") != 1 \
            or value.get("kind") not in SUBJECT_KINDS \
            or not isinstance(value.get("subject_id"), str) \
            or not isinstance(value.get("subject_digest"), str) \
            or HEX64.fullmatch(value["subject_digest"]) is None \
            or value["subject_digest"] != _subject_digest(value):
        raise SubjectIdentityError("subject identity is invalid")
    common = {"schema_version", "kind", "subject_id", "subject_digest"}
    kind = value["kind"]
    if kind == "main-source":
        fields = common | {"repository", "commit", "tree_sha256"}
        valid = value.get("subject_id") == "main" \
            and value.get("repository") == REPOSITORY \
            and HEX40.fullmatch(str(value.get("commit", ""))) is not None \
            and HEX64.fullmatch(str(value.get("tree_sha256", ""))) is not None
    elif kind == "candidate-source":
        fields = common | {
            "repository", "base_commit", "commit", "tree_sha256",
            "overlay_sha256", "dirty",
        }
        commit = value.get("commit")
        valid = value.get("subject_id") == "candidate" \
            and value.get("repository") == REPOSITORY \
            and HEX40.fullmatch(str(value.get("base_commit", ""))) is not None \
            and (commit is None or HEX40.fullmatch(str(commit)) is not None) \
            and HEX64.fullmatch(str(value.get("tree_sha256", ""))) is not None \
            and HEX64.fullmatch(str(value.get("overlay_sha256", ""))) is not None \
            and type(value.get("dirty")) is bool \
            and value["dirty"] == (value["overlay_sha256"] != EMPTY_OVERLAY_SHA256)
    elif kind == "release-tag":
        fields = common | {
            "repository", "tag", "tag_object_id", "tag_object_sha256",
            "peeled_commit", "signature_state",
        }
        valid = value.get("repository") == REPOSITORY \
            and value.get("subject_id") == value.get("tag") \
            and TAG.fullmatch(str(value.get("tag", ""))) is not None \
            and HEX40.fullmatch(str(value.get("tag_object_id", ""))) is not None \
            and HEX64.fullmatch(str(value.get("tag_object_sha256", ""))) is not None \
            and HEX40.fullmatch(str(value.get("peeled_commit", ""))) is not None \
            and value.get("signature_state") in {
                "verified", "unverified", "invalid", "unsigned"}
    elif kind == "plugin-zip":
        fields = common | {"filename", "bytes", "sha256"}
        valid = value.get("subject_id") == value.get("filename") \
            and isinstance(value.get("filename"), str) \
            and value["filename"].endswith(".zip") \
            and Path(value["filename"]).name == value["filename"] \
            and type(value.get("bytes")) is int and value["bytes"] > 0 \
            and HEX64.fullmatch(str(value.get("sha256", ""))) is not None
    elif kind == "native-helper":
        fields = common | {
            "platform", "filename", "bytes", "sha256",
            "sbom_sha256", "provenance_sha256",
        }
        valid = value.get("platform") in PLATFORMS \
            and value.get("subject_id") == value.get("platform") \
            and value.get("filename") in {"loom-vault", "loom-vault.exe"} \
            and type(value.get("bytes")) is int and value["bytes"] > 0 \
            and all(HEX64.fullmatch(str(value.get(field, ""))) is not None
                    for field in ("sha256", "sbom_sha256", "provenance_sha256"))
    else:
        fields = common | {
            "version", "release_sequence", "payload_sha256",
            "install_receipt_sha256", "activation_receipt_sha256",
        }
        valid = value.get("subject_id") == value.get("version") \
            and VERSION.fullmatch(str(value.get("version", ""))) is not None \
            and type(value.get("release_sequence")) is int \
            and value["release_sequence"] >= 1 \
            and all(HEX64.fullmatch(str(value.get(field, ""))) is not None
                    for field in (
                        "payload_sha256", "install_receipt_sha256",
                        "activation_receipt_sha256"))
    if set(value) != fields or not valid:
        raise SubjectIdentityError(f"{kind} subject fields are invalid")
    return value


def main_source(root, commit):
    tree = git_tree_inventory(root, commit)
    return seal_subject({
        "schema_version": 1, "kind": "main-source", "subject_id": "main",
        "repository": REPOSITORY, "commit": commit,
        "tree_sha256": tree["tree_sha256"],
    })


def candidate_source(root, *, base_commit, commit=None, overlay=()):
    effective = commit or base_commit
    tree = git_tree_inventory(root, effective)
    overlay_sha256 = overlay_digest(list(overlay))
    return seal_subject({
        "schema_version": 1, "kind": "candidate-source",
        "subject_id": "candidate", "repository": REPOSITORY,
        "base_commit": base_commit, "commit": commit,
        "tree_sha256": tree["tree_sha256"],
        "overlay_sha256": overlay_sha256,
        "dirty": overlay_sha256 != EMPTY_OVERLAY_SHA256,
    })


def release_tag(root, tag, *, signature_state="unverified"):
    if not isinstance(tag, str) or TAG.fullmatch(tag) is None:
        raise SubjectIdentityError("release tag is invalid")
    object_id = _run_git(root, "rev-parse", f"refs/tags/{tag}").strip()
    if HEX40.fullmatch(object_id) is None:
        raise SubjectIdentityError("release tag object identity is invalid")
    object_type = _run_git(root, "cat-file", "-t", object_id).strip()
    if object_type != "tag":
        raise SubjectIdentityError("release tag must be annotated")
    raw = _run_git(root, "cat-file", "-p", object_id, binary=True)
    peeled = _run_git(root, "rev-parse", f"refs/tags/{tag}^{{}}").strip()
    if HEX40.fullmatch(peeled) is None:
        raise SubjectIdentityError("release tag peeled commit is invalid")
    return seal_subject({
        "schema_version": 1, "kind": "release-tag", "subject_id": tag,
        "repository": REPOSITORY, "tag": tag, "tag_object_id": object_id,
        "tag_object_sha256": hashlib.sha256(raw).hexdigest(),
        "peeled_commit": peeled, "signature_state": signature_state,
    })


def artifact_subject(kind, path, *, subject_id=None, **metadata):
    path = Path(path).absolute()
    try:
        if path.resolve(strict=True) != path:
            raise SubjectIdentityError("artifact subject is redirected")
        info = path.lstat()
    except OSError as exc:
        raise SubjectIdentityError("artifact subject is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size <= 0:
        raise SubjectIdentityError("artifact subject is unsafe")
    raw = path.read_bytes()
    if len(raw) != info.st_size:
        raise SubjectIdentityError("artifact subject changed while reading")
    filename = path.name
    body = {
        "schema_version": 1, "kind": kind,
        "subject_id": subject_id or filename, "filename": filename,
        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        **metadata,
    }
    return seal_subject(body)


def installed_runtime(*, version, release_sequence, payload_sha256,
                      install_receipt_sha256, activation_receipt_sha256):
    return seal_subject({
        "schema_version": 1, "kind": "installed-runtime",
        "subject_id": version, "version": version,
        "release_sequence": release_sequence, "payload_sha256": payload_sha256,
        "install_receipt_sha256": install_receipt_sha256,
        "activation_receipt_sha256": activation_receipt_sha256,
    })


def subject_map(subjects):
    if not isinstance(subjects, list) or len(subjects) > 64:
        raise SubjectIdentityError("subject set is invalid")
    result = {}
    for subject in subjects:
        validate_subject(subject)
        key = (subject["kind"], subject["subject_id"])
        if key in result:
            raise SubjectIdentityError("subject identity is duplicated")
        result[key] = subject
    return result


def match_expected(expected, observed, *, required=()):
    expected_map = subject_map(expected)
    observed_map = subject_map(observed)
    findings = []
    for key in sorted(set(required)):
        if key not in expected_map:
            findings.append({"kind": key[0], "subject_id": key[1],
                             "reason": "EXPECTED_SUBJECT_UNAVAILABLE"})
        elif key not in observed_map or observed_map[key]["subject_digest"] \
                != expected_map[key]["subject_digest"]:
            findings.append({"kind": key[0], "subject_id": key[1],
                             "reason": "WRONG_SUBJECT"})
    return findings


def _expectation_hash(value):
    return digest({key: item for key, item in value.items()
                   if key not in {"authority", "expectation_sha256"}})


def _expectation_payload(value):
    return canonical({key: item for key, item in value.items()
                      if key not in {"authority", "expectation_sha256"}})


def validate_expected_subjects(
        value, *, now=None, trusted_controller_keys=None,
        signature_verifier=None, ci_attestation_verifier=None):
    fields = {
        "schema_version", "expectation_id", "issuer_kind", "issuer_id",
        "repository", "run_id", "job_id", "workflow_digest", "base_commit",
        "candidate_commit", "issued_at", "expires_at", "evaluation_epoch",
        "subjects", "authority", "expectation_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("issuer_kind") not in {"stable-controller", "ci"} \
            or value.get("repository") != REPOSITORY \
            or not isinstance(value.get("issuer_id"), str) \
            or SAFE_ID.fullmatch(value["issuer_id"]) is None \
            or not isinstance(value.get("run_id"), str) or not value["run_id"] \
            or not isinstance(value.get("job_id"), str) \
            or SAFE_ID.fullmatch(value["job_id"]) is None \
            or HEX64.fullmatch(str(value.get("workflow_digest", ""))) is None \
            or HEX40.fullmatch(str(value.get("base_commit", ""))) is None \
            or value.get("candidate_commit") is not None \
            and HEX40.fullmatch(str(value["candidate_commit"])) is None \
            or value.get("issuer_kind") == "ci" \
            and value.get("candidate_commit") is None \
            or value.get("expectation_sha256") != _expectation_hash(value):
        raise SubjectIdentityError("expected-subject receipt is invalid")
    try:
        if str(uuid.UUID(value["expectation_id"])) != value["expectation_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise SubjectIdentityError("expected-subject receipt identity is invalid") from exc
    subject_map(value["subjects"])
    issued = _instant(value["issued_at"], "issued_at")
    expires = _instant(value["expires_at"], "expires_at")
    evaluated = _instant(value["evaluation_epoch"], "evaluation_epoch")
    if not issued <= evaluated < expires or expires - issued > dt.timedelta(days=30):
        raise SubjectIdentityError("expected-subject receipt lifetime is invalid")
    if now is not None and not issued <= _instant(now, "now") < expires:
        raise SubjectIdentityError("expected-subject receipt is expired")
    authority = value.get("authority")
    if value["issuer_kind"] == "stable-controller":
        if not isinstance(authority, dict) or set(authority) != {
                "kind", "key_id", "public_key", "signature"} \
                or authority.get("kind") != "stable-controller-ed25519" \
                or not isinstance(trusted_controller_keys, dict) \
                or trusted_controller_keys.get(authority.get("key_id")) \
                != authority.get("public_key") \
                or not callable(signature_verifier):
            raise SubjectIdentityError("stable-controller expectation authority is unavailable")
        try:
            public = base64.b64decode(authority["public_key"], validate=True)
            signature = base64.b64decode(authority["signature"], validate=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise SubjectIdentityError("stable-controller expectation signature is invalid") from exc
        if len(public) != 32 or len(signature) != 64 \
                or signature_verifier(
                    _expectation_payload(value), authority["signature"],
                    authority["public_key"]) is not True:
            raise SubjectIdentityError("stable-controller expectation signature is invalid")
    else:
        if not isinstance(authority, dict) or set(authority) != {
                "kind", "attestation_sha256"} \
                or authority.get("kind") != "ci-attestation" \
                or HEX64.fullmatch(str(authority.get("attestation_sha256", ""))) is None \
                or not callable(ci_attestation_verifier) \
                or ci_attestation_verifier(value) is not True:
            raise SubjectIdentityError("CI expectation attestation is unavailable")
    return VerifiedExpectedSubjects(value)
