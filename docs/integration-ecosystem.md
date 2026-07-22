# Loom integration ecosystem

Loom has one engine, one owner vault, and one public action: `/loom <request>`. Agent integrations
are intentionally small. They route a request to `~/.loom/bin/loom.py`; they do not copy Loom's engine,
read its vault, select memory, migrate state, or keep host-specific policy.

## What is mechanically proven

- Adapter protocol v2 has a closed message vocabulary, exact fields, a 64 KiB frame limit, a
  16-level nesting limit, explicit protocol negotiation, bounded errors, and canonical hashing.
- Connected adapters and capability receipts are bound to exact bytes. Changed or unowned files
  block update and uninstall.
- Launcher installation, adapter connection, upgrade, and removal share an OS-locked transaction
  generation. A failed or interrupted write restores prior launcher, adapter, capability, and
  receipt bytes before the next writer proceeds.
- An unowned host-local Loom adapter blocks connection because host precedence could otherwise
  route requests around the shared runtime.
- The bridge is a local JSON-over-stdio process. It creates no network listener.
- Codex Standard mode uses the plugin's local stdio MCP server. The plugin bootstrap replaces
  itself with the receipt-owned stable launcher before accepting Loom tools. It opens no network
  listener and needs no hook trust.
- Codex Verified mode is a separate, explicit user-hook installation. It preserves unrelated
  hooks, refuses unowned Loom-like entries, owns exact entry hashes, and can be removed without
  removing the vault. `UserPromptSubmit` forwards only explicit `/loom` or Loom-skill requests;
  ordinary prompts are ignored without starting Loom.
- Request text remains bounded UTF-8 JSON across both subprocess boundaries. Ingress records its
  exact decoded UTF-8 byte length and SHA-256; the launcher and orchestrator reject any mismatch.
  The Windows command wrapper is not an invocation surface and refuses instead of forwarding `%*`.
- Disposable simulated profiles prove that all four current eligible adapter templates select one runtime
  and protocol, produce ownership receipts, and leave the project directory unchanged.

These proofs do not show that a real third-party host parsed or invoked the adapter. The conformance
receipt therefore uses the literal status `simulated-conformant`; its schema cannot encode that
result as real-host verification.

## Current support matrix

| Host | Adapter location | Current evidence | Connection policy |
| --- | --- | --- | --- |
| Codex | plugin skill plus local MCP; optional user hooks | source-tested; clean installed-host invocation pending | plugin installation; one-time hook trust only for Verified mode |
| Claude Code | `~/.claude/skills/loom/SKILL.md` | simulated-conformant | eligible after detection and owner approval |
| Gemini CLI | `~/.gemini/skills/loom/SKILL.md` | stale | detected, not connected during host transition |
| OpenCode | `~/.config/opencode/skills/loom/SKILL.md` | simulated-conformant | eligible after detection and owner approval |
| GitHub Copilot | `~/.copilot/skills/loom/SKILL.md` | simulated-conformant | eligible after detection and owner approval |
| Cursor | `~/.cursor/skills/loom/SKILL.md` | experimental | detected, not connected |
| Generic Agent Skills host | `~/.agents/skills/loom/SKILL.md` | unsupported format-only contract | detected, not connected |
| Factory Droid | `~/.factory/skills/loom/SKILL.md` | unsupported | detected, not connected |

Detection records the observed configuration marker and executable separately. A directory name,
installed executable, or generated adapter is never presented as evidence that the host actually
used Loom. Canonical roots, alternate roots, project shadows, precedence, version/headless probes,
proof TTLs, and update/removal behavior come from `contracts/host-contracts-v2.json`; stale or
unsupported contracts cannot become connectable through detection alone.

## Capability receipt

Each installed host gets a private capability receipt containing the host identity and observed
version, protocol and adapter versions, runtime version, detection evidence, evidence status, and
which optional telemetry fields the host supplied. Empty usage, response-identity, cache, and
latency capabilities stay false. The ownership receipt hashes the capability receipt, so changing
the capability story without changing the adapter blocks the next update or removal.

## Promotion to real-host verified

A host/version can move from simulated to real-host verified only when a disposable clean profile
proves all of the following against the exact release:

1. the real host discovers the documented adapter location;
2. `/loom <request>` reaches the receipt-owned Python bridge through a host process API that writes
   JSON directly to stdin, not a shell command, argv, environment variable, or temporary file;
3. initialization negotiates protocol 2 and reports the pinned runtime generation;
4. invoke, status, completion, cancellation, timeout, malformed input, and protocol mismatch follow
   the same contract;
5. the project is unchanged except for work explicitly authorized by the Loom action;
6. uninstall removes only unchanged Loom-owned files;
7. any provider usage, response identity, cache, or latency claim is backed by content-bound host
   evidence rather than inferred from local behavior.

Until that matrix exists, Loom makes no universal-host, live-provider, or MCP-conformance claim.
The source tests prove the Windows process boundaries themselves; they do not prove that every
third-party host exposes a safe direct-stdin process API.
