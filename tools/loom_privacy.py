#!/usr/bin/env python3
"""Fail-closed publication firewall and local-only sovereign-state utilities."""

import argparse
import ast
import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

import loom_memory


MAX_SCAN_FILE_BYTES = 64 * 1024 * 1024
MAX_EXPORT_BYTES = 64 * 1024 * 1024
SAFE_RECEIVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TOKEN_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be")
TRANSPARENT_TEXT_SUFFIXES = {
    ".bat", ".cfg", ".cmd", ".css", ".csv", ".env", ".htm", ".html",
    ".ini", ".js", ".json", ".md", ".ps1", ".py", ".rst", ".sh",
    ".svg", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml",
}
NETWORK_MODULES = {
    "aiohttp", "ftplib", "http", "httpx", "requests", "smtplib", "socket",
    "telnetlib", "urllib", "websockets",
}
NETWORK_EXECUTABLES = {
    "curl", "ftp", "nc", "ncat", "scp", "sftp", "ssh", "telnet", "wget",
}
NETWORK_GIT_SUBCOMMANDS = {
    "clone", "fetch", "ls-remote", "pull", "push", "remote-update", "submodule",
}
SUBPROCESS_CALLS = {"call", "check_call", "check_output", "Popen", "run"}
SECRET_PATTERNS = (
    ("private-key", re.compile(br"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.I)),
    ("github-token", re.compile(br"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("openai-token", re.compile(
        br"\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,255}\b")),
    ("google-api-key", re.compile(br"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("stripe-secret", re.compile(
        br"\b(?:(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,255}|"
        br"whsec_[A-Za-z0-9]{20,255})\b")),
    ("aws-access-key", re.compile(br"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(br"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b")),
    ("jwt", re.compile(br"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer-credential", re.compile(br"\bBearer\s+[A-Za-z0-9._~+/-]{16,}\b", re.I)),
    ("credential-url", re.compile(
        br"\b[a-z][a-z0-9+.-]{1,15}://[^\s/:@]{1,128}:[^\s/@]{4,128}@", re.I)),
    ("assigned-secret", re.compile(
        br"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)"
        br"\s*[:=]\s*[\"']?(?!REDACTED\b|CHANGEME\b|EXAMPLE\b)[^\s\"',;]{8,}", re.I)),
    ("high-entropy-credential", re.compile(
        br"\b[A-Za-z0-9_.-]*(?:(?i:credential|api[_-]?key|access[_-]?token|"
        br"auth[_-]?token|secret|password|passwd))[A-Za-z0-9_.-]*\s*[:=]\s*[\"']?"
        br"(?=[A-Za-z0-9_~+/=-]{24,})(?=[A-Za-z0-9_~+/=-]*[A-Z])"
        br"(?=[A-Za-z0-9_~+/=-]*[a-z])(?=[A-Za-z0-9_~+/=-]*[0-9])"
        br"(?=[A-Za-z0-9_~+/=-]*[_~+/=-])[A-Za-z0-9_~+/=-]{24,}")),
)


class PrivacyError(RuntimeError):
    pass


def _is_redirect(path):
    path = Path(path)
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        if junction and junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PrivacyError(f"cannot inspect path safely: {path}: {exc}") from exc


def _safe_absolute(path, label, *, must_exist=False):
    try:
        value = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise PrivacyError(f"{label} is invalid: {exc}") from exc
    if must_exist and not value.exists():
        raise PrivacyError(f"{label} does not exist: {value}")
    for component in [*reversed(value.parents), value]:
        if _is_redirect(component):
            raise PrivacyError(f"{label} must not traverse a symlink or reparse point: {component}")
    return value


def _iter_regular_files(root):
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise PrivacyError(f"cannot enumerate publication tree: {directory}: {exc}") from exc
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink() or _is_redirect(path):
                raise PrivacyError(f"publication contains a symlink or reparse point: {path}")
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    yield path
                else:
                    raise PrivacyError(f"publication contains a non-regular entry: {path}")
            except OSError as exc:
                raise PrivacyError(f"cannot inspect publication entry: {path}: {exc}") from exc


def _scan_views(content):
    """Return raw bytes plus normalized text views for supported public encodings."""
    views = [content]
    texts = []
    encodings = ["utf-8-sig"]
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings.append("utf-16")
    elif len(content) % 2 == 0 and content:
        pairs = len(content) // 2
        even_nuls = content[0::2].count(0) / pairs
        odd_nuls = content[1::2].count(0) / pairs
        if max(even_nuls, odd_nuls) >= 0.20:
            encodings.extend(("utf-16-le", "utf-16-be"))
    for encoding in encodings:
        try:
            text = content.decode(encoding)
            normalized = text.encode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            continue
        if text not in texts:
            texts.append(text)
        if normalized not in views:
            views.append(normalized)
    return tuple(views), tuple(texts)


def scan_publication(root, *, forbidden_tokens, require_owner_tokens=False):
    """Scan every regular file byte and every relative filename without extension filters."""
    root = _safe_absolute(root, "publication root", must_exist=True)
    if not root.is_dir():
        raise PrivacyError("publication root must be a directory")
    if not isinstance(forbidden_tokens, (list, tuple)) or any(
            not isinstance(item, str) for item in forbidden_tokens):
        raise PrivacyError("forbidden tokens must be a list of strings")
    tokens = [item.strip() for item in forbidden_tokens if item.strip()]
    if require_owner_tokens and not tokens:
        raise PrivacyError("private/owner publication requires real owner tokens")
    folded_tokens = [
        (item, tuple({form for encoding in TOKEN_ENCODINGS for form in (
            item.encode(encoding), item.encode(encoding).lower(),
            item.casefold().encode(encoding),
        )}))
        for item in tokens
    ]
    findings = []
    files_scanned = 0
    bytes_scanned = 0
    for path in _iter_regular_files(root):
        relative = path.relative_to(root).as_posix()
        for token, _encoded_forms in folded_tokens:
            if token.casefold() in relative.casefold():
                findings.append({"kind": "forbidden-filename", "path": relative,
                                 "rule": hashlib.sha256(token.encode()).hexdigest()[:12]})
                break
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(relative.encode("utf-8")):
                findings.append({"kind": "secret-filename", "path": relative,
                                 "rule": label})
                break
        try:
            size = path.stat().st_size
            if size > MAX_SCAN_FILE_BYTES:
                raise PrivacyError(
                    f"publication file exceeds safe scan limit ({MAX_SCAN_FILE_BYTES} bytes): {relative}")
            content = path.read_bytes()
        except OSError as exc:
            raise PrivacyError(f"cannot read publication file: {relative}: {exc}") from exc
        if len(content) != size:
            raise PrivacyError(f"publication file changed while scanning: {relative}")
        files_scanned += 1
        bytes_scanned += len(content)
        folded = content.lower()
        scan_views, decoded_texts = _scan_views(content)
        token_match = next((
            token for token, encoded_forms in folded_tokens
            if any(encoded in content or encoded in folded
                   for encoded in encoded_forms)
            or any(token.casefold() in text.casefold() for text in decoded_texts)
        ), None)
        if token_match is not None:
            findings.append({"kind": "forbidden-content", "path": relative,
                             "rule": hashlib.sha256(token_match.encode()).hexdigest()[:12]})
        secret_match = None
        for label, pattern in SECRET_PATTERNS:
            if any(pattern.search(view) for view in scan_views):
                findings.append({"kind": "secret-signature", "path": relative,
                                 "rule": label})
                secret_match = label
                break
        transparent_name = not path.suffix or path.suffix.lower() in TRANSPARENT_TEXT_SUFFIXES
        if token_match is None and secret_match is None \
                and (not decoded_texts or not transparent_name):
            findings.append({"kind": "opaque-content", "path": relative,
                             "rule": "unsupported-binary"})
    return {"clean": not findings, "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned, "findings": findings}


def minimize_evidence(text, *, roots=(), max_chars=4096):
    """Keep a bounded diagnostic excerpt while removing known secrets and owner paths."""
    if not isinstance(text, str) or type(max_chars) is not int or not 64 <= max_chars <= 65536:
        raise PrivacyError("evidence minimization inputs are invalid")
    value = text
    for label, pattern in SECRET_PATTERNS:
        value = pattern.sub(f"[REDACTED:{label}]".encode(), value.encode("utf-8")) \
            .decode("utf-8", errors="replace")
    for root in roots:
        raw = os.fspath(root)
        for candidate in {raw, raw.replace("\\", "/")}:
            if candidate:
                value = re.sub(re.escape(candidate), "[LOCAL_ROOT]", value, flags=re.I)
    if len(value) <= max_chars:
        return value
    marker = "\n...[TRUNCATED]...\n"
    head = (max_chars - len(marker)) // 2
    tail = max_chars - len(marker) - head
    return value[:head] + marker + value[-tail:]


def _literal_command_parts(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        values = []
        for item in node.elts:
            if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                return []
            values.append(item.value)
        return values
    return []


def _network_command(parts):
    if not parts:
        return None
    flattened = " ".join(parts).lower()
    executable = re.split(r"[\\/]", parts[0].strip().lower())[-1]
    executable = executable.removesuffix(".exe")
    if executable in NETWORK_EXECUTABLES:
        return executable
    words = set(re.findall(r"[a-z0-9_.-]+", flattened))
    if executable == "git" and words & NETWORK_GIT_SUBCOMMANDS:
        return "git"
    if executable in {"powershell", "pwsh"} and words & {
            "invoke-restmethod", "invoke-webrequest", "start-bitstransfer"}:
        return executable
    if re.search(r"\b(?:https?|ftp)://", flattened):
        return executable or "subprocess"
    return None


def audit_offline_modules(tools_root):
    """Audit direct network imports and literal network subprocess commands."""
    root = _safe_absolute(tools_root, "tools root", must_exist=True)
    findings = []
    scanned = 0
    for path in sorted(root.glob("loom_*.py")):
        scanned += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise PrivacyError(f"cannot audit offline module {path.name}: {exc}") from exc
        subprocess_aliases = {"subprocess"}
        os_aliases = {"os"}
        importlib_aliases = {"importlib"}
        subprocess_functions = set()
        system_functions = set()
        import_module_functions = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        subprocess_aliases.add(alias.asname or alias.name)
                    elif alias.name == "os":
                        os_aliases.add(alias.asname or alias.name)
                    elif alias.name == "importlib":
                        importlib_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                for alias in node.names:
                    if alias.name in SUBPROCESS_CALLS:
                        subprocess_functions.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "os":
                for alias in node.names:
                    if alias.name == "system":
                        system_functions.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        import_module_functions.add(alias.asname or alias.name)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in NETWORK_MODULES:
                    findings.append({"path": path.name, "line": node.lineno,
                                     "module": name})
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            is_dynamic_import = (
                isinstance(function, ast.Name)
                and function.id in ({"__import__"} | import_module_functions)
            ) or (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id in importlib_aliases
                and function.attr == "import_module"
            )
            if is_dynamic_import and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                module = node.args[0].value.split(".")[0]
                if module in NETWORK_MODULES:
                    findings.append({"path": path.name, "line": node.lineno,
                                     "module": module})
            is_subprocess = (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id in subprocess_aliases
                and function.attr in SUBPROCESS_CALLS
            ) or (isinstance(function, ast.Name)
                  and function.id in subprocess_functions)
            is_system = (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id in os_aliases and function.attr == "system"
            ) or (isinstance(function, ast.Name)
                  and function.id in system_functions)
            if is_subprocess or is_system:
                command = _network_command(_literal_command_parts(node.args[0]))
                if command:
                    findings.append({"path": path.name, "line": node.lineno,
                                     "kind": "network-subprocess",
                                     "command": command})
    return {"offline": not findings, "modules_scanned": scanned, "findings": findings}


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _atomic_json(path, value):
    path = _safe_absolute(path, "export destination")
    path.parent.mkdir(parents=True, exist_ok=True)
    _safe_absolute(path.parent, "export destination parent", must_exist=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp",
                                     dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def export_private_state(home, instance_id, destination, *, receiver_id):
    """Explicitly export one validated instance into a receiver-bound local envelope."""
    if not isinstance(receiver_id, str) or not SAFE_RECEIVER.fullmatch(receiver_id):
        raise PrivacyError("receiver_id must be an explicit safe local identifier")
    loom_memory.validate_instance(home, instance_id)
    home = _safe_absolute(home, "Loom home", must_exist=True)
    directory = _safe_absolute(home / "instances" / instance_id, "instance", must_exist=True)
    files = {}
    total = 0
    for path in _iter_regular_files(directory):
        if path.name == ".lock":
            continue
        raw = path.read_bytes()
        total += len(raw)
        if total > MAX_EXPORT_BYTES:
            raise PrivacyError("private export exceeds bounded size")
        files[path.relative_to(directory).as_posix()] = base64.b64encode(raw).decode("ascii")
    body = {"schema_version": 1, "kind": "loom-private-state-export",
            "instance_id": instance_id, "receiver_id": receiver_id,
            "files": files}
    _atomic_json(destination, body)
    return {"destination": str(Path(destination).resolve()), "receiver_id": receiver_id,
            "files_exported": len(files), "bytes_exported": total,
            "sha256": file_sha256(destination)}


def _erase_children(directory, *, root_lock):
    entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
    directories = []
    for entry in entries:
        path = Path(entry.path)
        if path == root_lock:
            continue
        if entry.is_symlink() or _is_redirect(path):
            raise PrivacyError(f"refusing to erase redirected state entry: {path}")
        if entry.is_dir(follow_symlinks=False):
            _erase_children(path, root_lock=root_lock)
            directories.append(path)
        elif entry.is_file(follow_symlinks=False):
            path.unlink()
        else:
            raise PrivacyError(f"refusing to erase non-regular state entry: {path}")
    for path in reversed(directories):
        path.rmdir()


def erase_private_state(home, instance_id, *, confirmation):
    """Erase exactly one marker-proven instance after an exact UUID confirmation."""
    if confirmation != instance_id:
        raise PrivacyError("erase confirmation must exactly match the instance id")
    loom_memory.validate_instance(home, instance_id)
    home = _safe_absolute(home, "Loom home", must_exist=True)
    expected_parent = _safe_absolute(home / "instances", "instances root", must_exist=True)
    directory = _safe_absolute(expected_parent / instance_id, "instance", must_exist=True)
    if directory.parent != expected_parent:
        raise PrivacyError("instance erase target escaped its proven parent")
    metadata = json.loads((directory / "instance.json").read_text(encoding="utf-8"))
    if metadata.get("instance_id") != instance_id:
        raise PrivacyError("instance ownership marker does not match erase target")
    lock_path = directory / ".lock"
    with loom_memory.FileLock(lock_path):
        _erase_children(directory, root_lock=lock_path)
    try:
        directory.rmdir()
    except OSError as exc:
        raise PrivacyError(
            "instance changed during erase; remaining state was left intact") from exc
    return {"erased": True, "instance_id": instance_id,
            "scope": "single-proven-instance"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("root")
    scan.add_argument("--forbid", action="append", default=[])
    scan.add_argument("--require-owner-tokens", action="store_true")
    offline = sub.add_parser("offline-audit")
    offline.add_argument("tools_root")
    args = parser.parse_args(argv)
    result = (scan_publication(args.root, forbidden_tokens=args.forbid,
                               require_owner_tokens=args.require_owner_tokens)
              if args.command == "scan" else audit_offline_modules(args.tools_root))
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("clean", result.get("offline", False)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
