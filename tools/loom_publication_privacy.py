#!/usr/bin/env python3
"""Product-independent, fail-closed public evidence secret scanning."""

import argparse
import ast
import atexit
import hashlib
import os
import queue
import re
import stat
import subprocess
import sys
import threading
from pathlib import Path

from loom_reliability import _is_trusted_os_alias


MAX_QUALIFICATION_SCAN_BYTES = 95_000_000
MAX_SCAN_FILE_BYTES = 64 * 1024 * 1024
QUALIFICATION_CONTRACT_PATH = \
    "contracts/release-mechanism-qualification-v2.json"
QUALIFICATION_CONTRACT_PATHS = frozenset({
    "contracts/release-suite-qualification-v1.json",
    QUALIFICATION_CONTRACT_PATH,
})
TOKEN_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be")
TRANSPARENT_TEXT_SUFFIXES = {
    ".bat", ".cfg", ".cmd", ".css", ".csv", ".env", ".htm", ".html",
    ".ini", ".js", ".json", ".md", ".ps1", ".py", ".rst", ".sh",
    ".rs", ".svg", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml",
    ".yml", ".lock",
}
NETWORK_MODULES = {
    "aiohttp", "ftplib", "http", "httpx", "requests", "smtplib", "socket",
    "telnetlib", "urllib", "websockets",
}
NETWORK_EXECUTABLES = {
    "curl", "ftp", "nc", "ncat", "scp", "sftp", "ssh", "telnet", "wget",
}
NETWORK_GIT_SUBCOMMANDS = {
    "clone", "fetch", "ls-remote", "pull", "push", "remote-update",
    "submodule",
}
SUBPROCESS_CALLS = {"call", "check_call", "check_output", "Popen", "run"}
SECRET_PATTERNS = (
    ("private-key", re.compile(
        br"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.I)),
    ("github-token", re.compile(
        br"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|"
        br"github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("openai-token", re.compile(
        br"\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,255}\b")),
    ("google-api-key", re.compile(br"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("stripe-secret", re.compile(
        br"\b(?:(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,255}|"
        br"whsec_[A-Za-z0-9]{20,255})\b")),
    ("aws-access-key", re.compile(br"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(
        br"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b")),
    ("jwt", re.compile(
        br"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
        br"[A-Za-z0-9_-]{8,}\b")),
    ("bearer-credential", re.compile(
        br"\bBearer\s+[A-Za-z0-9._~+/-]{16,}\b", re.I)),
    ("credential-url", re.compile(
        br"\b[a-z][a-z0-9+.-]{1,15}://[^\s/:@]{1,128}:"
        br"[^\s/@]{4,128}@", re.I)),
    ("assigned-secret", re.compile(
        br"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
        br"client[_-]?secret|password|passwd)\s*[:=]\s*[\"']?"
        br"(?!REDACTED\b|CHANGEME\b|EXAMPLE\b)[^\s\"',;]{8,}", re.I)),
    ("high-entropy-credential", re.compile(
        br"\b[A-Za-z0-9_.-]*(?:(?i:credential|api[_-]?key|"
        br"access[_-]?token|auth[_-]?token|secret|password|passwd))"
        br"[A-Za-z0-9_.-]*\s*[:=]\s*[\"']?"
        br"(?=[A-Za-z0-9_~+/=-]{24,})(?=[A-Za-z0-9_~+/=-]*[A-Z])"
        br"(?=[A-Za-z0-9_~+/=-]*[a-z])(?=[A-Za-z0-9_~+/=-]*[0-9])"
        br"(?=[A-Za-z0-9_~+/=-]*[_~+/=-])[A-Za-z0-9_~+/=-]{24,}")),
)


class PrivacyError(RuntimeError):
    pass


def _scan_views(content):
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


def _publication_file_scan_limit(relative):
    return (MAX_QUALIFICATION_SCAN_BYTES
            if relative in QUALIFICATION_CONTRACT_PATHS
            else MAX_SCAN_FILE_BYTES)


def _is_redirect(path):
    path = Path(path)
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        if junction and junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PrivacyError("cannot inspect path safely") from exc


def _safe_absolute(path, label, *, must_exist=False):
    try:
        value = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise PrivacyError(f"{label} is invalid") from exc
    if must_exist and not value.exists():
        raise PrivacyError(f"{label} does not exist")
    for component in [*reversed(value.parents), value]:
        if _is_redirect(component) and not _is_trusted_os_alias(component):
            raise PrivacyError(f"{label} traverses a redirected path")
    return value


def _iter_regular_files(root):
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(
                os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise PrivacyError("cannot enumerate publication tree") from exc
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink() or _is_redirect(path):
                raise PrivacyError(
                    "publication contains a redirected entry")
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    yield path
                else:
                    raise PrivacyError(
                        "publication contains a non-regular entry")
            except OSError as exc:
                raise PrivacyError(
                    "cannot inspect publication entry") from exc


def _forbidden_token_match(content, folded, decoded_texts, folded_tokens):
    for token, encoded_forms in folded_tokens:
        for encoded in encoded_forms:
            if encoded in content or encoded in folded:
                return token
        folded_token = token.casefold()
        for text in decoded_texts:
            if folded_token in text.casefold():
                return token
    return None


def _secret_signature_match(scan_views):
    for label, pattern in SECRET_PATTERNS:
        for view in scan_views:
            if pattern.search(view) is not None:
                return label
    return None


class _SecretScanWorker:
    def __init__(self):
        self.process = None
        self.responses = None
        self.reader = None

    @staticmethod
    def _read_responses(stdout, responses):
        while True:
            response = stdout.readline()
            responses.put(response)
            if not response:
                return

    def _start(self):
        self.process = subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).resolve()),
             "_secret-worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0)
        self.responses = queue.Queue()
        self.reader = threading.Thread(
            target=self._read_responses,
            args=(self.process.stdout, self.responses),
            name="loom-public-secret-scan-reader", daemon=True)
        self.reader.start()

    def _stop(self):
        process, self.process = self.process, None
        self.responses = None
        self.reader = None
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.stdout is not None:
                process.stdout.close()

    def close(self):
        self._stop()

    def scan(self, content):
        if not isinstance(content, bytes) \
                or len(content) > MAX_QUALIFICATION_SCAN_BYTES:
            raise PrivacyError("isolated secret scan input is invalid or oversized")
        for _attempt in range(3):
            if self.process is None or self.process.poll() is not None:
                self._stop()
                try:
                    self._start()
                except OSError:
                    continue
            try:
                self.process.stdin.write(len(content).to_bytes(8, "big"))
                self.process.stdin.write(content)
                self.process.stdin.flush()
                try:
                    response = self.responses.get(timeout=30)
                except queue.Empty as exc:
                    raise TimeoutError("secret scan worker timed out") from exc
                if not response.endswith(b"\n"):
                    raise BrokenPipeError(
                        "secret scan worker stopped before its receipt")
                label = response[:-1].decode("ascii")
                labels = {item[0] for item in SECRET_PATTERNS}
                if label and label not in labels:
                    raise ValueError("secret scan worker returned an unknown rule")
                return label or None
            except (
                    BrokenPipeError, OSError, TimeoutError,
                    UnicodeDecodeError, ValueError):
                self._stop()
        raise PrivacyError(
            "isolated secret scan failed closed after three attempts")


_SECRET_SCAN_WORKER = None


def _isolated_secret_signature_match(content):
    global _SECRET_SCAN_WORKER
    if _SECRET_SCAN_WORKER is None:
        _SECRET_SCAN_WORKER = _SecretScanWorker()
    return _SECRET_SCAN_WORKER.scan(content)


def _close_secret_scan_worker():
    if _SECRET_SCAN_WORKER is not None:
        _SECRET_SCAN_WORKER.close()


atexit.register(_close_secret_scan_worker)


def scan_publication(root, *, forbidden_tokens, require_owner_tokens=False,
                     verified_opaque_hashes=()):
    root = _safe_absolute(root, "publication root", must_exist=True)
    if not root.is_dir():
        raise PrivacyError("publication root must be a directory")
    if not isinstance(forbidden_tokens, (list, tuple)) or any(
            not isinstance(item, str) for item in forbidden_tokens):
        raise PrivacyError("forbidden tokens must be a list of strings")
    tokens = [item.strip() for item in forbidden_tokens if item.strip()]
    if require_owner_tokens and not tokens:
        raise PrivacyError(
            "private/owner publication requires real owner tokens")
    if not isinstance(verified_opaque_hashes, (
            list, tuple, set, frozenset)) or any(
                not isinstance(item, str)
                or re.fullmatch(r"[0-9a-f]{64}", item) is None
                for item in verified_opaque_hashes):
        raise PrivacyError(
            "verified opaque hashes must be explicit SHA-256 values")
    verified_opaque_hashes = set(verified_opaque_hashes)
    folded_tokens = [
        (item, tuple({
            form for encoding in TOKEN_ENCODINGS for form in (
                item.encode(encoding), item.encode(encoding).lower(),
                item.casefold().encode(encoding))}))
        for item in tokens
    ]
    findings = []
    files_scanned = 0
    bytes_scanned = 0
    for path in _iter_regular_files(root):
        relative = path.relative_to(root).as_posix()
        for token, _encoded_forms in folded_tokens:
            if token.casefold() in relative.casefold():
                findings.append({
                    "kind": "forbidden-filename", "path": relative,
                    "rule": hashlib.sha256(token.encode()).hexdigest()[:12],
                })
                break
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(relative.encode("utf-8")):
                findings.append({
                    "kind": "secret-filename", "path": relative,
                    "rule": label,
                })
                break
        try:
            size = path.stat().st_size
            scan_limit = _publication_file_scan_limit(relative)
            if size > scan_limit:
                raise PrivacyError(
                    f"publication file exceeds safe scan limit "
                    f"({scan_limit} bytes): {relative}")
            content = path.read_bytes()
        except OSError as exc:
            raise PrivacyError(
                f"cannot read publication file: {relative}") from exc
        if len(content) != size:
            raise PrivacyError(
                f"publication file changed while scanning: {relative}")
        files_scanned += 1
        bytes_scanned += len(content)
        folded = content.lower()
        scan_views, decoded_texts = _scan_views(content)
        token_match = _forbidden_token_match(
            content, folded, decoded_texts, folded_tokens)
        if token_match is not None:
            findings.append({
                "kind": "forbidden-content", "path": relative,
                "rule": hashlib.sha256(
                    token_match.encode()).hexdigest()[:12],
            })
        secret_match = _isolated_secret_signature_match(content)
        if secret_match is not None:
            findings.append({
                "kind": "secret-signature", "path": relative,
                "rule": secret_match,
            })
        transparent = not path.suffix \
            or path.suffix.lower() in TRANSPARENT_TEXT_SUFFIXES
        opaque_verified = hashlib.sha256(
            content).hexdigest() in verified_opaque_hashes
        if token_match is None and secret_match is None and not opaque_verified \
                and (not decoded_texts or not transparent):
            findings.append({
                "kind": "opaque-content", "path": relative,
                "rule": "unsupported-binary",
            })
    return {
        "clean": not findings,
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "findings": findings,
    }


def minimize_evidence(text, *, roots=(), max_chars=4096):
    if not isinstance(text, str) or type(max_chars) is not int \
            or not 64 <= max_chars <= 65536:
        raise PrivacyError("evidence minimization inputs are invalid")
    value = text
    for label, pattern in SECRET_PATTERNS:
        value = pattern.sub(
            f"[REDACTED:{label}]".encode(), value.encode("utf-8")
        ).decode("utf-8", errors="replace")
    for root in roots:
        raw = os.fspath(root)
        for candidate in {raw, raw.replace("\\", "/")}:
            if candidate:
                value = re.sub(
                    re.escape(candidate), "[LOCAL_ROOT]", value, flags=re.I)
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
            if not isinstance(item, ast.Constant) \
                    or not isinstance(item.value, str):
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
    root = _safe_absolute(tools_root, "tools root", must_exist=True)
    findings = []
    scanned = 0
    for path in sorted(root.glob("loom_*.py")):
        scanned += 1
        try:
            tree = ast.parse(
                path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise PrivacyError(
                f"cannot audit offline module {path.name}") from exc
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
            elif isinstance(node, ast.ImportFrom) \
                    and node.module == "subprocess":
                subprocess_functions.update(
                    alias.asname or alias.name for alias in node.names
                    if alias.name in SUBPROCESS_CALLS)
            elif isinstance(node, ast.ImportFrom) and node.module == "os":
                system_functions.update(
                    alias.asname or alias.name for alias in node.names
                    if alias.name == "system")
            elif isinstance(node, ast.ImportFrom) \
                    and node.module == "importlib":
                import_module_functions.update(
                    alias.asname or alias.name for alias in node.names
                    if alias.name == "import_module")
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in NETWORK_MODULES:
                    findings.append({
                        "path": path.name, "line": node.lineno,
                        "module": name,
                    })
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            dynamic_import = (
                isinstance(function, ast.Name)
                and function.id in ({"__import__"} | import_module_functions)
            ) or (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id in importlib_aliases
                and function.attr == "import_module")
            if dynamic_import and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                module = node.args[0].value.split(".")[0]
                if module in NETWORK_MODULES:
                    findings.append({
                        "path": path.name, "line": node.lineno,
                        "module": module,
                    })
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
                and function.value.id in os_aliases
                and function.attr == "system"
            ) or (isinstance(function, ast.Name)
                  and function.id in system_functions)
            if is_subprocess or is_system:
                command = _network_command(
                    _literal_command_parts(node.args[0]))
                if command:
                    findings.append({
                        "path": path.name, "line": node.lineno,
                        "kind": "network-subprocess", "command": command,
                    })
    return {
        "offline": not findings,
        "modules_scanned": scanned,
        "findings": findings,
    }


def _worker():
    stream = sys.stdin.buffer
    while True:
        header = stream.read(8)
        if not header:
            return 0
        if len(header) != 8:
            return 2
        size = int.from_bytes(header, "big")
        if size > MAX_QUALIFICATION_SCAN_BYTES:
            return 2
        chunks = []
        remaining = size
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                return 2
            chunks.append(chunk)
            remaining -= len(chunk)
        label = _secret_signature_match(_scan_views(b"".join(chunks))[0])
        sys.stdout.buffer.write((label or "").encode("ascii") + b"\n")
        sys.stdout.buffer.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("_secret-worker",))
    args = parser.parse_args(argv)
    return _worker() if args.command == "_secret-worker" else 2


if __name__ == "__main__":
    raise SystemExit(main())
