# codex integration

Contract status: **documented**<br>
Evidence status: **simulated-conformant**<br>
Proof expiry: **30 days**

## Global routes

- `.codex/skills/loom/SKILL.md`
- `.agents/skills/loom/SKILL.md`

## Project routes that can conflict

- `.agents/skills/loom/SKILL.md`
- `.codex/skills/loom/SKILL.md`

Precedence policy: `plugin-canonical; owned-legacy-retired; other-duplicates-block`. Duplicate Loom routes block execution.

## Canonical route

For a marketplace installation, the enabled plugin's skill and local stdio MCP server are canonical. The global roots above are direct-source fallback routes, not additional routes to retain beside the plugin. During an approved plugin migration, Loom removes only an exact receipt-owned user MCP registration and moves only an exact receipt-owned direct skill into a private rollback archive. An unowned, changed, or ambiguous duplicate blocks migration instead of being overwritten or deleted.

## Assurance modes

- **Standard:** the plugin-provided local MCP server bootstraps and delegates to the stable launcher. It needs no lifecycle-hook trust and makes no hook-enforcement claim.
- **Verified:** after one explicit approval, receipt-owned user hooks add exact prompt sealing, bounded session continuity, structured-write scope checks, freshness observations, compaction continuity, and subagent/stop observations. Codex hook coverage is a guardrail, not a sandbox; unsupported or unobserved tool paths remain outside the claim.

## Sources

- https://learn.chatgpt.com/docs/build-skills
- https://learn.chatgpt.com/docs/hooks
- https://learn.chatgpt.com/docs/non-interactive-mode
