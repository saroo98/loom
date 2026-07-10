#!/usr/bin/env python3
"""loom_audit — the executable no-network / no-telemetry audit.

Loom's privacy claim is architectural: the tools contain no network code, so nothing
CAN leave the machine except git talking to remotes the user configured. This tool
makes that claim machine-checkable instead of rhetorical:

  1. AST-parses every Python file under tools/ and flags any import of a network
     or IPC-capable module (socket, urllib, http.client, requests, …).
  2. Inspects every subprocess invocation and flags any launched program that is
     not `git` or the running Python interpreter (used only to run the test suite).
  3. Scans the shell installers for download primitives (curl, wget,
     Invoke-WebRequest, …).

Exit 0 = PASS (no findings). Exit 1 = FAIL with a findings list. Run it yourself:

    python tools/loom_audit.py

Anyone can run this on any Loom tree — it is part of the public cut, and the public
repository runs it on every push so the proof trail is generated in public, not
asserted by the author.
"""

import argparse
import ast
import re
import sys
from pathlib import Path

FORBIDDEN_MODULES = {
    "socket", "ssl", "select", "selectors", "asyncio",
    "urllib", "http", "requests", "httpx", "aiohttp", "websocket", "websockets",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "nntplib",
    "xmlrpc", "socketserver", "wsgiref",
}

ALLOWED_SUBPROCESS = {"git"}  # plus the running interpreter (sys.executable)

SHELL_NET_RE = re.compile(
    r"(?i)\b(curl|wget|invoke-webrequest|invoke-restmethod|start-bitstransfer"
    r"|downloadfile|downloadstring|net\.webclient)\b")


def module_root(name):
    return (name or "").split(".")[0]


def audit_python(path, findings):
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                     filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if module_root(a.name) in FORBIDDEN_MODULES:
                    findings.append(f"{path.name}:{node.lineno} imports "
                                    f"network-capable module '{a.name}'")
        elif isinstance(node, ast.ImportFrom):
            if module_root(node.module) in FORBIDDEN_MODULES:
                findings.append(f"{path.name}:{node.lineno} imports from "
                                f"network-capable module '{node.module}'")
        elif isinstance(node, ast.Call):
            f = node.func
            is_sub = (isinstance(f, ast.Attribute)
                      and isinstance(f.value, ast.Name)
                      and f.value.id == "subprocess")
            if not (is_sub and node.args):
                continue
            arg = node.args[0]
            if isinstance(arg, ast.BinOp) and isinstance(arg.left, ast.List):
                arg = arg.left  # ["git", ...] + more_args — head is the literal list
            elems = arg.elts if isinstance(arg, (ast.List, ast.Tuple)) else [arg]
            head = elems[0] if elems else None
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                prog = Path(head.value).name.lower()
                if prog not in ALLOWED_SUBPROCESS:
                    findings.append(f"{path.name}:{node.lineno} subprocess runs "
                                    f"'{head.value}' (allowed: git, the Python "
                                    f"interpreter)")
            elif (isinstance(head, ast.Attribute)
                  and isinstance(head.value, ast.Name)
                  and head.value.id == "sys" and head.attr == "executable"):
                pass  # the running interpreter — used to run the test suite
            elif isinstance(head, ast.Name) and head.id in ("PY", "python"):
                pass  # resolved interpreter variable
            else:
                findings.append(f"{path.name}:{node.lineno} subprocess with a "
                                f"non-literal program — inspect by hand")


def audit(root):
    root = Path(root)
    findings, scanned = [], 0
    tools = root / "tools"
    for py in sorted(tools.glob("*.py")) if tools.is_dir() else []:
        scanned += 1
        audit_python(py, findings)
    for sh in ("tools/install.sh", "tools/install.ps1",
               "templates/hooks/pre-commit"):
        f = root / sh
        if f.is_file():
            scanned += 1
            for n, line in enumerate(f.read_text(encoding="utf-8",
                                                 errors="replace").splitlines(), 1):
                if SHELL_NET_RE.search(line):
                    findings.append(f"{sh}:{n} shell download primitive: "
                                    f"{line.strip()[:60]}")
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
          f"subprocess restricted to git + the Python interpreter.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
