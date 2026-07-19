#!/usr/bin/env python3
"""Subprocess crash probes for Loom's durable atomic-write boundary."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class FaultError(RuntimeError):
    pass


ORCHESTRATION_CRASH_CODES = {
    "after-active-pointer": 101,
    "after-initializing-action": 102,
    "after-seed-stage": 103,
    "after-prepared-action": 104,
    "after-pack-install": 105,
    "after-installed-action": 106,
    "after-quarantine-move": 108,
    "after-recovery-action-write": 111,
    "after-pointer-clear": 112,
}
MAX_CHILD_PAYLOAD_BYTES = 256 * 1024


def disposable_environment(home):
    """Return a child environment whose user-scoped paths stay below ``home``."""
    home = Path(home).resolve()
    # The legacy test backend additionally proves that ``home`` is below the process
    # temporary root. Point temp APIs at the disposable case root, never the real profile.
    temporary = home.parent
    temporary.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("LOOM_"):
            environment.pop(name, None)
    environment.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "LOOM_HOME": str(home / ".loom"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "LOOM_TEST_ALLOW_LEGACY_BACKEND": "1",
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "TMPDIR": str(temporary),
    })
    return environment


def _child_command(root):
    harness = Path(root).resolve() / "tools" / "loom_fault_harness.py"
    return [sys.executable, "-B", str(harness), "orchestrator-child"]


def start_orchestrator_process(root, payload):
    """Start one isolated invoke/cancel child and deliver its bounded JSON payload."""
    home = Path(payload["home"]).resolve()
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_CHILD_PAYLOAD_BYTES:
        raise FaultError("orchestrator child payload exceeds its hard bound")
    process = subprocess.Popen(
        _child_command(root), cwd=Path(root).resolve() / "tools",
        env=disposable_environment(home), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        process.stdin.write(raw)
        process.stdin.close()
        process.stdin = None
    except BaseException:
        process.kill()
        process.wait(timeout=10)
        raise
    return process


def finish_orchestrator_process(process, *, timeout=90):
    stdout, stderr = process.communicate(timeout=timeout)
    return subprocess.CompletedProcess(
        process.args, process.returncode, stdout=stdout, stderr=stderr)


def run_orchestrator_process(root, payload, *, timeout=90):
    return finish_orchestrator_process(
        start_orchestrator_process(root, payload), timeout=timeout)


def _bounded_child_payload():
    raw = sys.stdin.buffer.read(MAX_CHILD_PAYLOAD_BYTES + 1)
    if len(raw) > MAX_CHILD_PAYLOAD_BYTES:
        raise FaultError("orchestrator child payload exceeds its hard bound")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FaultError(f"orchestrator child payload is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise FaultError("orchestrator child payload must be an object")
    return value


def _assert_disposable_environment(payload):
    expected = Path(payload["home"]).resolve()
    for name in ("HOME", "USERPROFILE", "CODEX_HOME", "LOOM_HOME"):
        value = Path(os.environ.get(name, "")).resolve()
        if value != expected and not value.is_relative_to(expected):
            raise FaultError(f"{name} escaped the disposable owner home")


def _wait_at_barrier(payload, point):
    if payload.get("hold") != point:
        return
    marker = Path(payload["marker"])
    release = Path(payload["release"])
    marker.write_text("ready\n", encoding="utf-8")
    deadline = time.monotonic() + 20
    while not release.exists():
        if time.monotonic() >= deadline:
            raise FaultError(f"orchestrator child barrier timed out: {point}")
        time.sleep(0.02)


def _install_invoke_faults(payload):
    import loom_orchestrator

    boundary = payload.get("boundary")
    if boundary is not None and boundary not in ORCHESTRATION_CRASH_CODES:
        raise FaultError("unknown orchestration crash boundary")
    crash_code = ORCHESTRATION_CRASH_CODES.get(boundary)
    state = {"action_writes": 0, "terminal_written": False}

    original_reconcile = loom_orchestrator._reconcile_active_action
    def reconcile(**kwargs):
        _wait_at_barrier(payload, "invoke-after-lock")
        return original_reconcile(**kwargs)
    loom_orchestrator._reconcile_active_action = reconcile

    original_write_action = loom_orchestrator._write_action
    def write_action(path, value, security=None):
        state["action_writes"] += 1
        result = original_write_action(path, value, security)
        if boundary == "after-initializing-action" \
                and value.get("status") == "initializing":
            os._exit(crash_code)
        if boundary == "after-prepared-action" \
                and value.get("pack_seed", {}).get("state") == "prepared":
            os._exit(crash_code)
        if boundary == "after-installed-action" \
                and value.get("pack_seed", {}).get("state") == "installed" \
                and value.get("status") == "pending":
            os._exit(crash_code)
        if value.get("recovery_receipt") is not None \
                and value.get("status") in {"abandoned", "expired", "superseded"}:
            state["terminal_written"] = True
            if boundary == "after-recovery-action-write":
                os._exit(crash_code)
        return result
    loom_orchestrator._write_action = write_action

    original_write_pointer = loom_orchestrator._write_active_pointer
    def write_pointer(*args, **kwargs):
        result = original_write_pointer(*args, **kwargs)
        if boundary == "after-active-pointer":
            os._exit(crash_code)
        return result
    loom_orchestrator._write_active_pointer = write_pointer

    original_seed_stage = loom_orchestrator._seed_stage
    def seed_stage(*args, **kwargs):
        result = original_seed_stage(*args, **kwargs)
        if boundary == "after-seed-stage":
            os._exit(crash_code)
        return result
    loom_orchestrator._seed_stage = seed_stage

    original_copy_seed = loom_orchestrator._copy_seed_stage
    def copy_seed(*args, **kwargs):
        result = original_copy_seed(*args, **kwargs)
        if boundary == "after-pack-install":
            os._exit(crash_code)
        return result
    loom_orchestrator._copy_seed_stage = copy_seed

    original_quarantine = loom_orchestrator._atomic_quarantine_tree
    def quarantine(*args, **kwargs):
        result = original_quarantine(*args, **kwargs)
        if boundary == "after-quarantine-move" and result:
            os._exit(crash_code)
        return result
    loom_orchestrator._atomic_quarantine_tree = quarantine

    original_clear_pointer = loom_orchestrator._clear_active_pointer
    def clear_pointer(*args, **kwargs):
        result = original_clear_pointer(*args, **kwargs)
        if boundary == "after-pointer-clear" and state["terminal_written"]:
            os._exit(crash_code)
        return result
    loom_orchestrator._clear_active_pointer = clear_pointer
    return loom_orchestrator


def _orchestrator_child(payload):
    _assert_disposable_environment(payload)
    operation = payload.get("operation")
    if operation == "invoke":
        loom_orchestrator = _install_invoke_faults(payload)
        try:
            result = loom_orchestrator.invoke(
                request=payload["request"], cwd=payload["cwd"],
                home=payload["home"], install_root=payload["install_root"],
                explicit_target=payload.get("target"))
        except loom_orchestrator.OrchestratorError as exc:
            print(json.dumps({
                "status": exc.status, "code": exc.code, "error": exc.message,
            }, sort_keys=True), flush=True)
            return 2
    elif operation == "cancel":
        import loom_orchestrator
        original_cancel = loom_orchestrator._cancel_under_lock
        def cancel_under_lock(*args, **kwargs):
            _wait_at_barrier(payload, "cancel-after-lock")
            return original_cancel(*args, **kwargs)
        loom_orchestrator._cancel_under_lock = cancel_under_lock
        try:
            result = loom_orchestrator.cancel(
                payload["action_path"], owner_home=payload["home"],
                install_root=payload["install_root"])
        except loom_orchestrator.OrchestratorError as exc:
            print(json.dumps({
                "status": exc.status, "code": exc.code, "error": exc.message,
            }, sort_keys=True), flush=True)
            return 2
    else:
        raise FaultError("orchestrator child operation is invalid")
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


def atomic_pointer_probe(root):
    root = Path(root).resolve()
    tools = root / "tools"
    with tempfile.TemporaryDirectory(prefix="loom-fault-") as temporary:
        target = Path(temporary) / "pointer.json"
        target.write_text('{"generation":"old"}\n', encoding="utf-8")
        script = (
            "import os,sys; from pathlib import Path; import loom_reliability; "
            "target=Path(sys.argv[1]); original=os.replace; "
            "os.replace=lambda a,b: os._exit(91); "
            "loom_reliability.atomic_write_json(target, {'generation':'new'})")
        crashed = subprocess.run(
            [sys.executable, "-B", "-c", script, str(target)], cwd=tools,
            capture_output=True, timeout=10, check=False)
        if crashed.returncode != 91 \
                or json.loads(target.read_text(encoding="utf-8"))["generation"] != "old":
            raise FaultError("pre-replace process death damaged the old pointer")
        completed = subprocess.run(
            [sys.executable, "-B", "-c",
             "import os,sys; from pathlib import Path; import loom_reliability; "
             "loom_reliability.atomic_write_json(Path(sys.argv[1]), {'generation':'new'}); "
             "os._exit(92)", str(target)], cwd=tools,
            capture_output=True, timeout=10, check=False)
        if completed.returncode != 92 \
                or json.loads(target.read_text(encoding="utf-8"))["generation"] != "new":
            raise FaultError("post-replace process death did not preserve the new pointer")
    return {"status": "passed", "boundaries": ["before-replace", "after-replace"],
            "process_exit_codes": [91, 92]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("atomic-pointer", "orchestrator-child"),
                        default="atomic-pointer")
    args = parser.parse_args(argv)
    if args.command == "orchestrator-child":
        try:
            return _orchestrator_child(_bounded_child_payload())
        except (FaultError, KeyError, OSError, subprocess.SubprocessError) as exc:
            print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True),
                  flush=True)
            return 1
    try:
        result = atomic_pointer_probe(Path(__file__).resolve().parents[1])
    except (FaultError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
