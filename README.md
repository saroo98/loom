# Loom 1.0.0

Loom is a local-first planning runtime for agents. Give it one request:

```text
/loom <request>
```

Loom surveys the real project, chooses planning depth from consequence and uncertainty, discovers
domain invariants, produces only artifacts with a consumer, blocks stale or unsafe execution,
records evidence, and returns a compact receipt. Small work stays small. Accounting, real-time 3D,
firmware, research, data, mobile, desktop, and unfamiliar domains receive different invariants and
verification media. Unknown coverage blocks the gate until those invariants have evidence.

## Install Once

From a clean checkout, install Loom as a Codex skill:

```powershell
python tools/loom_install.py install . "$HOME/.codex/skills/loom"
```

The installer accepts only a new target, records every owned file hash, and immediately verifies
the result, including a unique receipt-owned installation identity. Check it later with
`python tools/loom_install.py check <install-path>`. Uninstall needs the exact installation ID and
refuses the entire removal if any owned file changed. The installed skill invokes the production
orchestrator internally with bytecode writes disabled, so a documented run remains receipt-clean
and reversible. Normal use still has one surface: `/loom <request>`.

## Automatic local adaptation

Each completed run may update bounded owner memory when there is evidence. General judgment,
domain knowledge, project state, and installation state remain separate. Dormant project and
domain material leaves active context automatically; useful material can return when relevant.
Default domain retirement accelerates for harmful or unused rules and retains repeatedly helpful
rules longer; session housekeeping performs it without another owner command.
Forgetting is durable, and the latest reversible adaptation can be undone. Learning stays on the
owner's machine and is never a contribution or publication. Improvement is not inferred from
record count: Loom requires an exact-domain early/recent comparison, 8 paired memory-on/off replays,
at least 16 longitudinal samples, and an independently reproducible evidence bundle. General
calibration is reported separately from domain behavior.

Contributing changes to Loom is a separate, explicit source-control action. Loom never uploads
owner memory or project content by itself.

## Trust boundary

Loom fails closed when repository state, lifecycle state, identity, freshness, or memory integrity
cannot be proven. Mechanical and advisory capabilities are distinguished in
[the capability registry](docs/capabilities.json). Live inventory counts are generated in
[the evidence report](docs/generated-evidence.json), not typed into this page.

Production certification is intentionally fail-closed. Local tests cannot substitute for a real
cross-platform CI run, an unfamiliar-person usability study, an independent hostile review,
provider-attested production performance, or independently reproduced production memory replay.
See [current limitations](docs/limitations.md); Loom never labels itself 100 without all five
signed evidence records.

Agents start with [START-HERE.md](START-HERE.md). Maintainers can read the
[advanced architecture](docs/architecture.md).
