#!/usr/bin/env python3
"""loom_audit — executable-source network/telemetry policy audit.

This tool checks the current shipped source tree for known network/process paths. It does
not claim to audit the host agent, editor, operating system, Git remote, or future files:

  1. AST-parses every Python file under tools/ and flags any import of a network
     or IPC-capable module (socket, urllib, http.client, requests, …).
  2. Inspects every subprocess invocation. Runtime tools may launch only `git` or the
     running Python interpreter; installer regression tests may launch only the local
     checked installer scripts through their platform shell.
  3. Recursively scans shell/workflow executable text for download primitives (curl, wget,
     Invoke-WebRequest, …).
  4. Scans shipped browser-executable HTML/SVG/JavaScript/CSS for active remote resources
     and browser network APIs. Inert hyperlinks and metadata URLs are not network execution.

Exit 0 = PASS (no findings). Exit 1 = FAIL with a findings list. Run it yourself:

    python tools/loom_audit.py

Anyone can run this on any Loom tree. Exit 0 means no policy violation was detected by
these checks; it is not a proof about uninspected external processes.
"""

import argparse
import ast
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

FORBIDDEN_MODULES = {
    "socket", "ssl", "select", "selectors", "asyncio",
    "urllib", "http", "requests", "httpx", "aiohttp", "websocket", "websockets",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "nntplib",
    "xmlrpc", "socketserver", "wsgiref",
}

ALLOWED_SUBPROCESS = {"git"}  # plus the running interpreter (sys.executable)
INSTALL_TEST_SHELLS = {"powershell", "powershell.exe", "pwsh", "pwsh.exe", "bash"}
SUBPROCESS_CALLS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
    "subprocess.getoutput", "subprocess.getstatusoutput",
}
SHELL_PROCESS_CALLS = {
    "os.system", "os.popen", "os.spawnl", "os.spawnle", "os.spawnlp",
    "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
}

SHELL_NET_RE = re.compile(
    r"(?i)\b(curl|wget|invoke-webrequest|invoke-restmethod|start-bitstransfer"
    r"|downloadfile|downloadstring|net\.webclient)\b")
WORKFLOW_USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.IGNORECASE)
ALLOWED_WORKFLOW_ACTIONS = {
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
}
WEB_SUFFIXES = {".html", ".htm", ".svg", ".css", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
RENDERED_TEXT_SUFFIXES = {".md"}
WEB_NET_RE = re.compile(
    r"(?i)(?:\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\(|"
    r"\bEventSource\s*\(|\bsendBeacon\s*\(|\bimportScripts\s*\()")
CSS_REMOTE_RE = re.compile(
    r"(?i)(?:url\(\s*['\"]?\s*(https?:)?//|@import\s+(?:url\()?\s*['\"]?\s*(https?:)?//)")
MD_REMOTE_IMAGE_RE = re.compile(
    r"!\[[^\]]*\]\(\s*<?(?:https?:)?//", re.IGNORECASE)


def _remote_url(value):
    value = str(value or "").strip().lower()
    return value.startswith(("http://", "https://", "//"))


class _ActiveResourceParser(HTMLParser):
    ACTIVE = {
        "script": {"src"}, "img": {"src", "srcset"}, "iframe": {"src"},
        "video": {"src", "poster"}, "audio": {"src"}, "source": {"src", "srcset"},
        "track": {"src"}, "embed": {"src"}, "object": {"data"},
        "input": {"src"}, "image": {"href", "xlink:href"},
        "use": {"href", "xlink:href"}, "form": {"action"},
    }
    NETWORK_LINK_RELS = {
        "stylesheet", "preload", "modulepreload", "prefetch", "dns-prefetch",
        "preconnect", "icon", "manifest",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.findings = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = {str(key).lower(): value for key, value in attrs if key}
        line, _ = self.getpos()
        active = set(self.ACTIVE.get(tag, set()))
        if tag == "link":
            rels = set(str(values.get("rel", "")).lower().split())
            if rels & self.NETWORK_LINK_RELS:
                active.add("href")
        if tag == "meta" and str(values.get("http-equiv", "")).lower() == "refresh":
            content = str(values.get("content", ""))
            match = re.search(r"(?i)url\s*=\s*(.+)$", content)
            if match and _remote_url(match.group(1).strip(" '\"")):
                self.findings.append((line, "remote meta refresh"))
        for key in active:
            raw = values.get(key)
            if not raw:
                continue
            candidates = [item.strip().split()[0] for item in str(raw).split(",")]
            if any(_remote_url(item) for item in candidates):
                self.findings.append((line, f"remote active {tag}[{key}] resource"))
        if CSS_REMOTE_RE.search(str(values.get("style", ""))):
            self.findings.append((line, "remote CSS resource in style attribute"))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def module_root(name):
    return (name or "").split(".")[0]


def _qualified_name(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _resolve_expression(arg, assignments):
    seen = set()
    while isinstance(arg, ast.Name) and arg.id in assignments and arg.id not in seen:
        seen.add(arg.id)
        arg = assignments[arg.id]
    return arg


def _program_head(arg, assignments):
    arg = _resolve_expression(arg, assignments)
    if isinstance(arg, ast.BinOp):
        arg = _resolve_expression(arg.left, assignments)
    if isinstance(arg, ast.BinOp) and isinstance(arg.left, (ast.List, ast.Tuple)):
        arg = arg.left
    elems = arg.elts if isinstance(arg, (ast.List, ast.Tuple)) else [arg]
    return elems[0] if elems else None


def _literal_strings(node, assignments):
    node = _resolve_expression(node, assignments)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    values = []
    for child in ast.iter_child_nodes(node):
        values.extend(_literal_strings(child, assignments))
    return values


def audit_python(path, findings):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"),
                         filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        findings.append(f"{path}: cannot audit Python source: {exc}")
        return
    aliases = {}
    assignments = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or module_root(a.name)] = a.name
                if module_root(a.name) in FORBIDDEN_MODULES:
                    findings.append(f"{path}:{node.lineno} imports "
                                    f"network-capable module '{a.name}'")
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
            if module_root(node.module) in FORBIDDEN_MODULES:
                findings.append(f"{path}:{node.lineno} imports from "
                                f"network-capable module '{node.module}'")
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = value

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _qualified_name(node.func, aliases)
        if name in {"__import__", "builtins.__import__", "importlib.import_module"}:
            arg = node.args[0] if node.args else None
            if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                findings.append(f"{path}:{node.lineno} non-literal dynamic import")
            elif module_root(arg.value) in FORBIDDEN_MODULES:
                findings.append(f"{path}:{node.lineno} dynamically imports "
                                f"network-capable module '{arg.value}'")
        if name in SHELL_PROCESS_CALLS:
            findings.append(f"{path}:{node.lineno} uses shell process API '{name}'")
            continue
        if name not in SUBPROCESS_CALLS:
            continue
        if not node.args:
            findings.append(f"{path}:{node.lineno} subprocess has no program argument")
            continue
        if any(k.arg == "shell" and isinstance(k.value, ast.Constant)
               and k.value.value is True for k in node.keywords):
            findings.append(f"{path}:{node.lineno} subprocess enables shell=True")
        head = _program_head(node.args[0], assignments)
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            prog = Path(head.value).name.lower()
            if prog in INSTALL_TEST_SHELLS and path.name == "test_loom_install.py":
                strings = _literal_strings(node.args[0], assignments)
                script = "install.ps1" if prog in {
                    "powershell", "powershell.exe", "pwsh", "pwsh.exe"} else "install.sh"
                forbidden_flags = {"-command", "-c", "-lc"}
                if script not in strings or forbidden_flags & {item.lower() for item in strings}:
                    findings.append(
                        f"{path}:{node.lineno} installer-test shell is not bound to {script}")
            elif prog not in ALLOWED_SUBPROCESS:
                findings.append(f"{path}:{node.lineno} subprocess runs '{head.value}' "
                                "(allowed: git, the Python interpreter)")
        elif _qualified_name(head, aliases) == "sys.executable":
            pass
        else:
            findings.append(f"{path}:{node.lineno} subprocess with a non-literal "
                            "program — inspect by hand")


def audit_web(path, root, findings):
    rel = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        findings.append(f"{rel}: cannot audit browser source: {exc}")
        return
    if path.suffix.lower() in WEB_SUFFIXES:
        for match in WEB_NET_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{rel}:{line} browser network API: {match.group(0).strip()}")
    if path.suffix.lower() in RENDERED_TEXT_SUFFIXES:
        for match in MD_REMOTE_IMAGE_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{rel}:{line} remote rendered Markdown image")
    if path.suffix.lower() in {".css", ".html", ".htm", ".svg"}:
        for match in CSS_REMOTE_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{rel}:{line} remote CSS resource")
    if path.suffix.lower() in {".html", ".htm", ".svg", ".md"}:
        parser = _ActiveResourceParser()
        try:
            parser.feed(text)
        except Exception as exc:  # HTMLParser extension hooks can raise on malformed input
            findings.append(f"{rel}: cannot parse browser markup: {exc}")
        else:
            for line, message in parser.findings:
                findings.append(f"{rel}:{line} {message}")


def audit(root):
    root = Path(root).resolve()
    findings, scanned = [], 0
    excluded = {".git", "dist", "__pycache__"}
    python_files = [
        path for path in root.rglob("*.py")
        if not any(part in excluded for part in path.relative_to(root).parts)
    ] if root.is_dir() else []
    for py in sorted(python_files):
        scanned += 1
        audit_python(py, findings)
    executable_text = [
        path for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".sh", ".ps1", ".bat", ".cmd", ".yml", ".yaml"}
        and not any(part in excluded for part in path.relative_to(root).parts)
    ] if root.is_dir() else []
    for file in sorted(executable_text):
        scanned += 1
        rel = file.relative_to(root).as_posix()
        try:
            lines = file.read_text(encoding="utf-8", errors="strict").splitlines()
        except (OSError, UnicodeError) as exc:
            findings.append(f"{rel}: cannot audit executable text: {exc}")
            continue
        for n, line in enumerate(lines, 1):
            if SHELL_NET_RE.search(line):
                findings.append(f"{rel}:{n} shell download primitive: "
                                f"{line.strip()[:60]}")
            action = WORKFLOW_USES_RE.match(line)
            if file.suffix.lower() in {".yml", ".yaml"} and action \
                    and action.group(1) not in ALLOWED_WORKFLOW_ACTIONS:
                findings.append(
                    f"{rel}:{n} workflow action is not allowlisted: {action.group(1)}")
    web_files = [
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in WEB_SUFFIXES | RENDERED_TEXT_SUFFIXES
        and not any(part in excluded for part in path.relative_to(root).parts)
    ] if root.is_dir() else []
    for file in sorted(web_files):
        scanned += 1
        audit_web(file, root, findings)
    return scanned, findings


def main(argv=None):
    ap = argparse.ArgumentParser(description="No-network audit of a Loom tree")
    ap.add_argument("root", nargs="?",
                    default=str(Path(__file__).resolve().parent.parent),
                    help="Loom tree to audit (default: this repo)")
    args = ap.parse_args(argv)
    scanned, findings = audit(args.root)
    for x in findings:
        print(f"FINDING  {x}")
    verdict = "FAIL" if findings else "PASS"
    print(f"loom_audit: {verdict} — {scanned} files scanned, "
          f"{len(findings)} finding(s). Network-capable imports: forbidden; "
          "runtime subprocess restricted to git + Python; installer-test shells "
          "must target local installer scripts; workflow actions are immutable-pinned "
          "and allowlisted; "
          "browser network APIs/active remote resources are forbidden.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
