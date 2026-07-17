#!/usr/bin/env python3
"""Run bounded disposable-profile conformance for Loom's simulated host adapters."""

import argparse
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import loom_adapter_protocol
import loom_adapters
import loom_host_registry
import loom_update


def _capabilities():
    return {key: key in {"invoke", "complete", "cancel", "status", "markdown"}
            for key in loom_adapter_protocol.CAPABILITY_KEYS}


def _frames(raw):
    source = io.BytesIO(raw)
    result = []
    while True:
        value = loom_adapter_protocol.read_frame(source)
        if value is None:
            return result
        result.append(value)


def _bridge(launcher, loom_home, host_id, host_version):
    initialize = {
        "schema_version": 2, "message_type": "initialize",
        "request_id": f"init-{host_id}",
        "protocol": {"minimum": 2, "maximum": 2},
        "adapter": {"id": host_id, "version": loom_adapter_protocol.ADAPTER_VERSION},
        "host": {"id": host_id, "version": host_version},
        "capabilities": _capabilities(),
    }
    status = {"schema_version": 2, "message_type": "status",
              "request_id": f"status-{host_id}"}
    source = io.BytesIO()
    loom_adapter_protocol.write_frame(source, initialize)
    loom_adapter_protocol.write_frame(source, status)
    process = subprocess.run(
        [sys.executable, "-B", str(launcher), "--home", str(loom_home), "bridge"],
        input=source.getvalue(), capture_output=True, timeout=30, check=False)
    if process.returncode != 0 or process.stderr:
        raise RuntimeError(f"{host_id} bridge failed")
    values = _frames(process.stdout)
    if len(values) != 2 or values[0]["message_type"] != "initialize-result" \
            or values[1]["message_type"] != "result" \
            or values[1]["returncode"] != 0:
        raise RuntimeError(f"{host_id} bridge transcript is invalid")
    return values


def run(root):
    root = Path(root).resolve()
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    with tempfile.TemporaryDirectory(prefix="loom-adapter-conformance-") as raw:
        temporary = Path(raw).resolve()
        user_home = temporary / "user"
        project = temporary / "project"
        user_home.mkdir()
        project.mkdir()
        (project / "sentinel.txt").write_text("unchanged\n", encoding="utf-8")
        before = (project / "sentinel.txt").read_bytes()
        connectable = [host_id for host_id, contract in loom_host_registry.HOSTS.items()
                       if contract["evidence_status"] == "simulated-conformant"]
        for host_id in connectable:
            marker = loom_host_registry.HOSTS[host_id]["config_markers"][0]
            user_home.joinpath(*Path(marker).parts).mkdir(parents=True, exist_ok=True)
        loom_home = user_home / ".loom"
        runtime = loom_update.SharedRuntime(loom_home, plugin_roots=[root])
        runtime.install_baseline(version, b"conformance-runtime", release_sequence=1)
        installed = loom_adapters.install_launcher(
            loom_home, root / "tools" / "loom_launcher.py")
        versions = {host_id: "fixture-1" for host_id in connectable}
        connected = loom_adapters.connect_all(
            user_home, loom_home, approved=True, which=lambda _name: None,
            versions=versions)
        if sorted(connected["eligible"]) != sorted(connectable):
            raise RuntimeError("connectable host set changed during conformance")
        hosts = []
        for host_id in sorted(connectable):
            transcript = _bridge(
                Path(installed["python_launcher"]), loom_home, host_id,
                versions[host_id])
            initialize, status = transcript
            receipt = loom_adapters._receipt_path(loom_home, host_id)
            value = json.loads(receipt.read_text(encoding="utf-8"))
            hosts.append({
                "id": host_id, "initialize": "passed", "status": "passed",
                "same_runtime": initialize["runtime_version"] == version
                and status["payload"].get("version") == version,
                "same_protocol": initialize["protocol_version"] == 2
                and status["payload"].get("protocol_version") == 2,
                "adapter_receipt": value.get("schema_version") == 2
                and value.get("evidence_status") == "simulated-conformant",
            })
        untouched = (project / "sentinel.txt").read_bytes() == before \
            and sorted(path.name for path in project.iterdir()) == ["sentinel.txt"]
        passed = untouched and all(
            item["same_runtime"] and item["same_protocol"] and item["adapter_receipt"]
            for item in hosts)
        return {
            "schema_version": 1, "status": "passed" if passed else "failed",
            "evidence_status": "simulated-conformant", "runtime_version": version,
            "protocol_version": 2, "hosts": hosts, "project_untouched": untouched,
            "network_listener": False,
            "limitations": [
                "fixture profiles do not certify a real installed third-party host",
                "provider usage and response identity are not available in simulation"],
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    report = run(args.root)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
