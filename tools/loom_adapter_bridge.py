#!/usr/bin/env python3
"""Local JSON-over-stdio bridge from thin host adapters to the stable launcher."""

import json
import subprocess
import sys
from pathlib import Path

import loom_adapter_protocol


class BridgeError(RuntimeError):
    pass


def _payload(stdout):
    if isinstance(stdout, bytes):
        try:
            stdout = stdout.decode("utf-8")
        except UnicodeError as exc:
            raise BridgeError("launcher returned non-UTF-8 output") from exc
    text = stdout.strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BridgeError("launcher returned non-JSON output") from exc
    if not isinstance(value, dict) or len(value) > 128:
        raise BridgeError("launcher returned an invalid payload")
    return value


def _run(launcher, arguments, *, timeout=120):
    try:
        result = subprocess.run(
            [sys.executable, "-B", str(launcher), *arguments],
            capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise loom_adapter_protocol.ProtocolError(
            "TIMEOUT", "stable launcher operation exceeded its timeout") from exc
    return result.returncode, _payload(result.stdout)


def _run_request(launcher, home, envelope, *, timeout=120):
    """Forward owner text only as one bounded protocol-v2 stdin frame."""
    frame = loom_adapter_protocol.canonical_bytes(envelope) + b"\n"
    try:
        result = subprocess.run(
            [sys.executable, "-B", str(launcher), "--home", str(home),
             "invoke-stdio"],
            input=frame, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise loom_adapter_protocol.ProtocolError(
            "TIMEOUT", "stable launcher request exceeded its timeout") from exc
    return result.returncode, _payload(result.stdout)


def dispatch(message, *, home, launcher, session):
    loom_adapter_protocol.validate_message(message)
    request_id = message["request_id"]
    kind = message["message_type"]
    if kind == "initialize":
        selected = loom_adapter_protocol.negotiate(message["protocol"])
        code, payload = _run(launcher, [
            "--home", str(home), "adapter-probe",
            "--protocol-min", str(selected), "--protocol-max", str(selected)])
        if code != 0 or payload.get("status") != "ready":
            raise loom_adapter_protocol.ProtocolError(
                "RUNTIME_BLOCKED", "stable launcher failed its adapter probe")
        session.clear()
        session.update({
            "host": message["host"], "adapter": message["adapter"],
            "capabilities": message["capabilities"], "protocol_version": selected})
        result = {
            "schema_version": 2, "message_type": "initialize-result",
            "request_id": request_id, "protocol_version": selected,
            "runtime_version": payload["version"],
            "release_sequence": payload["release_sequence"],
            "capabilities": {
                "invoke": True, "complete": True, "cancel": True, "status": True,
                "markdown": True, "usage_receipt": False,
                "response_identity": False, "latency_events": False},
            "limitations": [
                "provider usage and response identity depend on host evidence"],
        }
        return loom_adapter_protocol.validate_message(result)
    if not session:
        raise loom_adapter_protocol.ProtocolError(
            "PROTOCOL_INCOMPATIBLE", "adapter must initialize before another operation")
    if kind not in {"invoke", "complete", "cancel", "status"}:
        raise loom_adapter_protocol.ProtocolError(
            "MESSAGE_INVALID", "adapter request is not a bridge operation")
    if not session["capabilities"].get(kind, False):
        raise loom_adapter_protocol.ProtocolError(
            "CAPABILITY_MISSING", f"host did not declare the {kind} capability")
    host = session["host"]
    if kind == "invoke":
        envelope = loom_adapter_protocol.request_envelope(
            message, host, adapter=session["adapter"],
            capabilities=session["capabilities"])
        code, payload = _run_request(launcher, home, envelope)
    elif kind == "complete":
        arguments = ["--home", str(home), "complete", "--action", message["action"]]
        if message["usage"] is not None:
            arguments.extend(["--usage", message["usage"]])
        if message["result"] is not None:
            arguments.extend(["--result", message["result"]])
    elif kind == "cancel":
        arguments = ["--home", str(home), "cancel", "--action", message["action"]]
    else:
        arguments = [
            "--home", str(home), "adapter-probe", "--protocol-min", "2",
            "--protocol-max", "2"]
    if kind != "invoke":
        code, payload = _run(launcher, arguments)
    result = {"schema_version": 2, "message_type": "result",
              "request_id": request_id, "returncode": code, "payload": payload}
    return loom_adapter_protocol.validate_message(result)


def serve(home, launcher, *, input_stream=None, output_stream=None):
    source = input_stream or sys.stdin.buffer
    target = output_stream or sys.stdout.buffer
    session = {}
    while True:
        message = None
        try:
            message = loom_adapter_protocol.read_frame(source)
            if message is None:
                return 0
            response = dispatch(
                message, home=Path(home).resolve(), launcher=Path(launcher).resolve(),
                session=session)
        except loom_adapter_protocol.ProtocolError as exc:
            request_id = "bridge-error"
            if isinstance(message, dict) \
                    and isinstance(message.get("request_id"), str):
                request_id = message["request_id"]
            response = {
                "schema_version": 2, "message_type": "error",
                "request_id": request_id, "code": exc.code,
                "message": str(exc)[:512], "retryable": exc.code in {"TIMEOUT"},
            }
        except (BridgeError, OSError, ValueError) as exc:
            response = {
                "schema_version": 2, "message_type": "error",
                "request_id": "bridge-error", "code": "RUNTIME_FAILED",
                "message": str(exc)[:512], "retryable": False,
            }
        loom_adapter_protocol.write_frame(target, response)
