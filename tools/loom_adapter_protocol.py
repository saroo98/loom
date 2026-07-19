#!/usr/bin/env python3
"""Closed, bounded protocol for stateless Loom host adapters."""

import hashlib
import io
import json
import re


PROTOCOL_VERSION = 2
ADAPTER_VERSION = "2.1.0"
MAX_MESSAGE_BYTES = 65536
MAX_DEPTH = 16
MAX_REQUEST_CHARACTERS = 32768
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
CAPABILITY_KEYS = {
    "invoke", "complete", "cancel", "status", "markdown", "usage_receipt",
    "response_identity", "latency_events",
}
ERROR_CODES = {
    "PROTOCOL_INCOMPATIBLE", "MESSAGE_INVALID", "MESSAGE_TOO_LARGE",
    "CAPABILITY_MISSING", "HOST_UNVERIFIED", "RUNTIME_BLOCKED",
    "RUNTIME_FAILED", "TIMEOUT", "CANCELLED",
}


class ProtocolError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _depth(value, level=0):
    if level > MAX_DEPTH:
        raise ProtocolError("MESSAGE_INVALID", "adapter message nesting exceeds its bound")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError("MESSAGE_INVALID", "adapter message key is not text")
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise ProtocolError("MESSAGE_INVALID", "adapter message contains an unsupported value")


def canonical_bytes(value):
    validate_message(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def request_identity(request):
    """Identify the exact UTF-8 bytes of the decoded owner request."""
    _text(request, "request", 1, MAX_REQUEST_CHARACTERS)
    try:
        raw = request.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProtocolError(
            "MESSAGE_INVALID", "request is not valid Unicode scalar text") from exc
    return {"utf8_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def request_envelope(invoke_message, host):
    """Seal one validated invoke message for internal process forwarding."""
    validate_message(invoke_message)
    if invoke_message["message_type"] != "invoke":
        raise ProtocolError("MESSAGE_INVALID", "request envelope source is not invoke")
    value = {
        "schema_version": PROTOCOL_VERSION,
        "message_type": "request-envelope",
        "request_id": invoke_message["request_id"],
        "request": invoke_message["request"],
        "cwd": invoke_message["cwd"],
        "host": dict(host),
        "request_identity": request_identity(invoke_message["request"]),
    }
    return validate_message(value)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ProtocolError("MESSAGE_INVALID", f"{label} fields are unknown or missing")


def _identifier(value, label):
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ProtocolError("MESSAGE_INVALID", f"{label} is invalid")


def _text(value, label, minimum, maximum):
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ProtocolError("MESSAGE_INVALID", f"{label} is invalid")


def _capabilities(value):
    _exact(value, CAPABILITY_KEYS, "adapter capabilities")
    if any(type(item) is not bool for item in value.values()):
        raise ProtocolError("MESSAGE_INVALID", "adapter capabilities are invalid")


def validate_message(value):
    _depth(value)
    if not isinstance(value, dict):
        raise ProtocolError("MESSAGE_INVALID", "adapter message is not an object")
    message_type = value.get("message_type")
    common = {"schema_version", "message_type", "request_id"}
    if value.get("schema_version") != 2:
        raise ProtocolError("PROTOCOL_INCOMPATIBLE", "adapter schema version is unsupported")
    _identifier(value.get("request_id"), "request ID")
    if message_type == "initialize":
        _exact(value, common | {"protocol", "adapter", "host", "capabilities"}, "initialize")
        protocol = value["protocol"]
        _exact(protocol, {"minimum", "maximum"}, "protocol range")
        if type(protocol["minimum"]) is not int or type(protocol["maximum"]) is not int \
                or not 1 <= protocol["minimum"] <= protocol["maximum"] <= 255:
            raise ProtocolError("MESSAGE_INVALID", "protocol range is invalid")
        for field in ("adapter", "host"):
            _exact(value[field], {"id", "version"}, field)
            _identifier(value[field]["id"], f"{field} ID")
            _text(value[field]["version"], f"{field} version", 1, 128)
        if not VERSION_RE.fullmatch(value["adapter"]["version"]):
            raise ProtocolError("MESSAGE_INVALID", "adapter version is invalid")
        _capabilities(value["capabilities"])
    elif message_type == "initialize-result":
        _exact(value, common | {"protocol_version", "runtime_version", "release_sequence",
                                "capabilities", "limitations"}, "initialize result")
        if value["protocol_version"] != PROTOCOL_VERSION \
                or not isinstance(value["runtime_version"], str) \
                or not VERSION_RE.fullmatch(value["runtime_version"]) \
                or type(value["release_sequence"]) is not int \
                or value["release_sequence"] < 1:
            raise ProtocolError("MESSAGE_INVALID", "initialize result identity is invalid")
        _capabilities(value["capabilities"])
        limitations = value["limitations"]
        if not isinstance(limitations, list) or len(limitations) > 16 \
                or len(limitations) != len(set(limitations)) \
                or any(not isinstance(item, str) or not 1 <= len(item) <= 256
                       for item in limitations):
            raise ProtocolError("MESSAGE_INVALID", "initialize limitations are invalid")
    elif message_type == "invoke":
        _exact(value, common | {"request", "cwd"}, "invoke")
        _text(value["request"], "request", 1, MAX_REQUEST_CHARACTERS)
        _text(value["cwd"], "project path", 1, 4096)
    elif message_type == "request-envelope":
        _exact(value, common | {"request", "cwd", "host", "request_identity"},
               "request envelope")
        _text(value["request"], "request", 1, MAX_REQUEST_CHARACTERS)
        _text(value["cwd"], "project path", 1, 4096)
        _exact(value["host"], {"id", "version"}, "request host")
        _identifier(value["host"]["id"], "request host ID")
        _text(value["host"]["version"], "request host version", 1, 128)
        identity = value["request_identity"]
        _exact(identity, {"utf8_bytes", "sha256"}, "request identity")
        expected = request_identity(value["request"])
        if type(identity["utf8_bytes"]) is not int \
                or identity["utf8_bytes"] != expected["utf8_bytes"] \
                or not isinstance(identity["sha256"], str) \
                or identity["sha256"] != expected["sha256"]:
            raise ProtocolError(
                "MESSAGE_INVALID", "request identity does not match exact UTF-8 bytes")
    elif message_type == "complete":
        _exact(value, common | {"action", "usage", "result"}, "complete")
        _text(value["action"], "action path", 1, 4096)
        for field in ("usage", "result"):
            if value[field] is not None:
                _text(value[field], f"{field} path", 1, 4096)
    elif message_type == "cancel":
        _exact(value, common | {"action"}, "cancel")
        _text(value["action"], "action path", 1, 4096)
    elif message_type == "status":
        _exact(value, common, "status")
    elif message_type == "result":
        _exact(value, common | {"returncode", "payload"}, "result")
        if type(value["returncode"]) is not int or not 0 <= value["returncode"] <= 255 \
                or not isinstance(value["payload"], dict) or len(value["payload"]) > 128:
            raise ProtocolError("MESSAGE_INVALID", "result payload is invalid")
    elif message_type == "error":
        _exact(value, common | {"code", "message", "retryable"}, "error")
        if value["code"] not in ERROR_CODES or type(value["retryable"]) is not bool:
            raise ProtocolError("MESSAGE_INVALID", "error identity is invalid")
        _text(value["message"], "error message", 1, 512)
    else:
        raise ProtocolError("MESSAGE_INVALID", "adapter message type is unsupported")
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProtocolError(
            "MESSAGE_INVALID", "adapter message is not valid Unicode scalar text") from exc
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ProtocolError("MESSAGE_TOO_LARGE", "adapter message exceeds its byte bound")
    return value


def negotiate(protocol_range):
    _exact(protocol_range, {"minimum", "maximum"}, "protocol range")
    minimum = protocol_range["minimum"]
    maximum = protocol_range["maximum"]
    if type(minimum) is not int or type(maximum) is not int \
            or minimum > maximum or not minimum <= PROTOCOL_VERSION <= maximum:
        raise ProtocolError("PROTOCOL_INCOMPATIBLE", "adapter protocol ranges do not overlap")
    return PROTOCOL_VERSION


def read_frame(stream):
    raw = stream.readline(MAX_MESSAGE_BYTES + 2)
    if raw == b"":
        return None
    if len(raw) > MAX_MESSAGE_BYTES + 1 or not raw.endswith(b"\n"):
        raise ProtocolError("MESSAGE_TOO_LARGE", "adapter frame is incomplete or oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("MESSAGE_INVALID", "adapter frame is not valid UTF-8 JSON") from exc
    return validate_message(value)


def read_single_frame(stream, *, message_type):
    """Read one bounded internal frame and require EOF after its newline."""
    value = read_frame(stream)
    if value is None:
        raise ProtocolError("MESSAGE_INVALID", "request frame is missing")
    if value["message_type"] != message_type:
        raise ProtocolError("MESSAGE_INVALID", "request frame type is invalid")
    if stream.read(1) != b"":
        raise ProtocolError("MESSAGE_INVALID", "request transport contains trailing data")
    return value


def write_frame(stream, value):
    raw = canonical_bytes(value) + b"\n"
    if len(raw) > MAX_MESSAGE_BYTES + 1:
        raise ProtocolError("MESSAGE_TOO_LARGE", "adapter frame exceeds its byte bound")
    stream.write(raw)
    stream.flush()


def round_trip(value):
    stream = io.BytesIO()
    write_frame(stream, value)
    stream.seek(0)
    return read_frame(stream)
