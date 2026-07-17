#!/usr/bin/env python3
"""Truthful host registry for Loom's thin local adapters."""

import shutil
from pathlib import Path


HOSTS = {
    "codex": {
        "adapter_path": ".codex/skills/loom/SKILL.md",
        "config_markers": [".codex"], "executables": ["codex"],
        "adapter_kind": "agent-skill", "evidence_status": "simulated-conformant",
        "official_source": "https://learn.chatgpt.com/docs/non-interactive-mode",
        "headless_command": ["codex", "exec"], "contract_status": "documented"},
    "claude-code": {
        "adapter_path": ".claude/skills/loom/SKILL.md",
        "config_markers": [".claude"], "executables": ["claude"],
        "adapter_kind": "agent-skill", "evidence_status": "simulated-conformant",
        "official_source": None, "headless_command": None, "contract_status": "unverified"},
    "gemini-cli": {
        "adapter_path": ".gemini/skills/loom/SKILL.md",
        "config_markers": [".gemini"], "executables": ["gemini"],
        "adapter_kind": "agent-skill", "evidence_status": "simulated-conformant",
        "official_source": None, "headless_command": None, "contract_status": "unverified"},
    "opencode": {
        "adapter_path": ".config/opencode/skills/loom/SKILL.md",
        "config_markers": [".config/opencode"], "executables": ["opencode"],
        "adapter_kind": "agent-skill", "evidence_status": "simulated-conformant",
        "official_source": None, "headless_command": None, "contract_status": "unverified"},
    "copilot": {
        "adapter_path": ".copilot/skills/loom/SKILL.md",
        "config_markers": [".copilot"], "executables": ["copilot", "gh"],
        "adapter_kind": "agent-skill", "evidence_status": "simulated-conformant",
        "official_source": None, "headless_command": None, "contract_status": "unverified"},
    "cursor": {
        "adapter_path": ".cursor/skills/loom/SKILL.md",
        "config_markers": [".cursor"], "executables": ["cursor"],
        "adapter_kind": "agent-skill", "evidence_status": "experimental",
        "official_source": None, "headless_command": None, "contract_status": "unverified"},
    "factory-droid": {
        "adapter_path": ".factory/skills/loom/SKILL.md",
        "config_markers": [".factory"], "executables": ["droid"],
        "adapter_kind": "agent-skill", "evidence_status": "unsupported",
        "official_source": None, "headless_command": None, "contract_status": "unverified"},
    "generic-agent-skills": {
        "adapter_path": ".agents/skills/loom/SKILL.md",
        "config_markers": [".agents"], "executables": [],
        "adapter_kind": "agent-skill", "evidence_status": "experimental",
        "official_source": None, "headless_command": None, "contract_status": "unverified"},
}


def contract(host_id):
    """Return public host facts without turning them into conformance evidence."""
    value = HOSTS.get(host_id)
    if value is None:
        raise KeyError(host_id)
    return {key: value[key] for key in (
        "adapter_path", "adapter_kind", "evidence_status", "official_source",
        "headless_command", "contract_status")}

CONNECTABLE = {"simulated-conformant", "real-host-verified"}


def detect(user_home, *, which=None, versions=None):
    root = Path(user_home).resolve()
    finder = which or shutil.which
    versions = versions or {}
    results = []
    for host_id, contract in HOSTS.items():
        markers = [marker for marker in contract["config_markers"]
                   if root.joinpath(*Path(marker).parts).exists()]
        executable = next((name for name in contract["executables"] if finder(name)), None)
        if not markers and executable is None:
            continue
        results.append({
            "id": host_id,
            "version": versions.get(host_id),
            "adapter_kind": contract["adapter_kind"],
            "adapter_path": contract["adapter_path"],
            "evidence_status": contract["evidence_status"],
            "connectable": contract["evidence_status"] in CONNECTABLE,
            "detection_evidence": sorted(
                [f"config:{item}" for item in markers]
                + ([f"executable:{executable}"] if executable else [])),
        })
    return results
