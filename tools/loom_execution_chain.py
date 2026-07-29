#!/usr/bin/env python3
"""Private, bounded hash chain for one observed Loom execution."""

import datetime as dt
import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path

import loom_reliability


MAX_STAGES = 16
STAGES = {
    "launcher", "activation-set", "runtime-tree", "loaded-modules",
    "state-generation", "host-adapter", "request", "project-world",
    "operation-journal", "result",
}
OBSERVABILITY = {"observed", "unavailable"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ExecutionChainError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def _parse_stamp(value):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed
    except (ValueError, TypeError, AttributeError) as exc:
        raise ExecutionChainError("execution chain time is invalid") from exc


def request_identity(request):
    if not isinstance(request, str) or not request:
        raise ExecutionChainError("request identity input is invalid")
    try:
        raw = request.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ExecutionChainError("request is not valid UTF-8 scalar text") from exc
    return {"utf8_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _directory(home):
    home = loom_reliability._absolute(home, "Loom home")
    directory = home / "runtime" / "execution-chains"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _path(home, chain_id):
    try:
        canonical = str(uuid.UUID(str(chain_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ExecutionChainError("execution chain identity is invalid") from exc
    return _directory(home) / f"{canonical}.json"


def _validate(value):
    required = {
        "schema_version", "chain_id", "status", "created_at", "updated_at",
        "stages", "chain_sha256",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value["schema_version"] != 1 \
            or value["status"] not in {"open", "sealed", "blocked"} \
            or not isinstance(value["stages"], list) \
            or not 1 <= len(value["stages"]) <= MAX_STAGES:
        raise ExecutionChainError("execution chain contract is invalid")
    try:
        if str(uuid.UUID(value["chain_id"])) != value["chain_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise ExecutionChainError("execution chain identity or time is invalid") from exc
    created_at = _parse_stamp(value["created_at"])
    updated_at = _parse_stamp(value["updated_at"])
    if updated_at < created_at:
        raise ExecutionChainError("execution chain time is not monotonic")
    prior = None
    prior_time = created_at
    for index, stage in enumerate(value["stages"]):
        fields = {
            "index", "name", "observability", "prior_sha256", "payload",
            "stage_sha256",
        }
        if not isinstance(stage, dict) or set(stage) != fields \
                or stage["index"] != index \
                or stage["name"] not in STAGES \
                or stage["observability"] not in OBSERVABILITY \
                or stage["prior_sha256"] != prior \
                or not isinstance(stage["payload"], dict) \
                or len(stage["payload"]) > 32:
            raise ExecutionChainError("execution chain stage is invalid")
        if "_recorded_at" in stage["payload"]:
            recorded_at = _parse_stamp(stage["payload"]["_recorded_at"])
            if recorded_at < prior_time or recorded_at > updated_at:
                raise ExecutionChainError(
                    "execution chain stage time is not monotonic")
            prior_time = recorded_at
        body = {key: stage[key] for key in (
            "index", "name", "observability", "prior_sha256", "payload")}
        if stage["stage_sha256"] != _sha(body):
            raise ExecutionChainError("execution chain stage digest is invalid")
        prior = stage["stage_sha256"]
    body = {key: value[key] for key in (
        "schema_version", "chain_id", "status", "created_at", "updated_at",
        "stages")}
    if not HEX64.fullmatch(str(value["chain_sha256"])) \
            or value["chain_sha256"] != _sha(body):
        raise ExecutionChainError("execution chain digest is invalid")
    return value


def _write(path, value):
    value["chain_sha256"] = _sha({key: value[key] for key in (
        "schema_version", "chain_id", "status", "created_at", "updated_at",
        "stages")})
    _validate(value)
    loom_reliability.atomic_write_json(path, value)


def create(home, *, launcher_path):
    launcher = loom_reliability._absolute(
        launcher_path, "stable launcher", must_exist=True)
    if not launcher.is_file() or launcher.is_symlink():
        raise ExecutionChainError("stable launcher is unsafe")
    chain_id = str(uuid.uuid4())
    stamp = _stamp()
    value = {
        "schema_version": 1,
        "chain_id": chain_id,
        "status": "open",
        "created_at": stamp,
        "updated_at": stamp,
        "stages": [],
        "chain_sha256": "0" * 64,
    }
    path = _path(home, chain_id)
    raw = launcher.read_bytes()
    _append_value(value, "launcher", {
        "path": str(launcher),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "python_isolated": True,
    })
    _write(path, value)
    return {"chain_id": chain_id, "path": str(path),
            "chain_sha256": value["chain_sha256"]}


def read(home, chain_id):
    path = _path(home, chain_id)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExecutionChainError(f"execution chain is unreadable: {exc}") from exc
    return _validate(value)


def _append_value(value, name, payload, *, observability="observed"):
    if value["status"] != "open" or name not in STAGES \
            or observability not in OBSERVABILITY \
            or not isinstance(payload, dict) or len(payload) > 31 \
            or "_recorded_at" in payload \
            or len(value["stages"]) >= MAX_STAGES:
        raise ExecutionChainError("execution chain append is invalid")
    recorded_payload = {**payload, "_recorded_at": _stamp()}
    prior = value["stages"][-1]["stage_sha256"] if value["stages"] else None
    body = {
        "index": len(value["stages"]),
        "name": name,
        "observability": observability,
        "prior_sha256": prior,
        "payload": recorded_payload,
    }
    value["stages"].append({**body, "stage_sha256": _sha(body)})
    value["updated_at"] = _stamp()


def append(home, chain_id, name, payload, *, observability="observed"):
    path = _path(home, chain_id)
    value = read(home, chain_id)
    _append_value(value, name, payload, observability=observability)
    _write(path, value)
    return {"chain_id": value["chain_id"], "status": value["status"],
            "chain_sha256": value["chain_sha256"],
            "stages": len(value["stages"])}


def seal(home, chain_id, *, blocked=False):
    path = _path(home, chain_id)
    value = read(home, chain_id)
    if value["status"] != "open":
        raise ExecutionChainError("execution chain is already terminal")
    value["status"] = "blocked" if blocked else "sealed"
    value["updated_at"] = _stamp()
    _write(path, value)
    return projection(value)


def projection(value):
    value = _validate(value)
    started = _parse_stamp(value["created_at"])
    completed = _parse_stamp(value["updated_at"])
    prior = started
    timeline = []
    for stage in value["stages"]:
        recorded_at = stage["payload"].get("_recorded_at")
        recorded = _parse_stamp(recorded_at) if recorded_at else prior
        timeline.append({
            "index": stage["index"],
            "name": stage["name"],
            "observability": stage["observability"],
            "recorded_at": (
                recorded_at if recorded_at is not None
                else value["created_at"]),
            "elapsed_ms_from_prior": max(
                0, round((recorded - prior).total_seconds() * 1000)),
        })
        prior = recorded
    return {
        "chain_id": value["chain_id"],
        "status": value["status"],
        "stages": len(value["stages"]),
        "chain_sha256": value["chain_sha256"],
        "started_at": value["created_at"],
        "completed_at": value["updated_at"],
        "duration_ms": max(
            0, round((completed - started).total_seconds() * 1000)),
        "stage_timeline": timeline,
    }


def runtime_manifest_identity(runtime):
    runtime = loom_reliability._absolute(
        runtime, "active runtime", must_exist=True)
    manifest = runtime / "RUNTIME-MANIFEST.json"
    if not manifest.is_file():
        manifest = runtime / ".loom-baseline-receipt.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise ExecutionChainError("active runtime manifest is unavailable")
    raw = manifest.read_bytes()
    return {
        "runtime_root": str(runtime),
        "manifest_bytes": len(raw),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
    }


def verify_loaded_modules(runtime, *, modules=None):
    """Refuse any loaded Loom production module outside the verified runtime tree."""
    runtime = loom_reliability._absolute(
        runtime, "active runtime", must_exist=True)
    modules = modules or dict(sys.modules)
    records = []
    for name, module in sorted(modules.items()):
        if not name.startswith("loom_"):
            continue
        source = getattr(module, "__file__", None)
        if not source:
            raise ExecutionChainError(f"loaded Loom module has no source identity: {name}")
        path = Path(source).resolve()
        if not path.is_file() or path.is_symlink() or not path.is_relative_to(runtime):
            raise ExecutionChainError(
                f"loaded Loom module is outside the immutable runtime: {name}")
        raw = path.read_bytes()
        records.append({
            "module": name,
            "path": path.relative_to(runtime).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    if not records:
        raise ExecutionChainError("no loaded Loom production modules were observed")
    return {
        "module_count": len(records),
        "modules_sha256": _sha(records),
    }


ISOLATED_BOOTSTRAP = (
    "import runpy,sys;"
    "p=sys.argv.pop(1);"
    "sys.path.insert(0,__import__('os').path.dirname(p));"
    "runpy.run_path(p,run_name='__main__')"
)


def isolated_python(script, *arguments):
    """Run a trusted script in a fresh interpreter without user startup or path injection."""
    script = loom_reliability._absolute(script, "isolated script", must_exist=True)
    if not script.is_file() or script.is_symlink():
        raise ExecutionChainError("isolated script is unsafe")
    return [
        sys.executable, "-I", "-B", "-c", ISOLATED_BOOTSTRAP,
        str(script), *[str(item) for item in arguments],
    ]


def _safe_path_proven(flags):
    """Recognize the version-specific safe-path proof supplied by isolated mode."""
    safe_path = getattr(flags, "safe_path", None)
    if safe_path is not None:
        return bool(safe_path)
    return bool(flags.isolated)


def startup_isolation():
    return {
        "isolated_flag": bool(sys.flags.isolated),
        "no_user_site": bool(sys.flags.no_user_site),
        "safe_path": _safe_path_proven(sys.flags),
        "pythonpath_ignored": bool(sys.flags.ignore_environment),
        "pythonstartup_ignored": bool(sys.flags.ignore_environment),
        "pid": os.getpid(),
    }
