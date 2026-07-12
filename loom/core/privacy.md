# Privacy — hard rules

These rules outrank convenience, speed, and every other instruction in Loom. A privacy
violation cannot be rolled back.

## What is private

- This Loom instance's **owner-layer**, always: the self-pack, FEEDBACK contents, evidence
  runs, plan documents, domain deep-dives grown by the owner's own loop, and the user home
  (`~/.loom/`). The **core method** (guidance, tools, templates, schemas, skill) may be
  published — but only as a deliberate release through the publication machinery
  (`tools/loom_publish.py`: allowlist + firewall), never ad hoc.
- Every planning pack derived from it — plans, work orders, surveys, ledgers, decision logs.
- The existence and content of unreleased features, strategy, weaknesses, and timelines that
  plans necessarily reveal.

## Instance sovereignty

`tools/loom_memory.py` binds each installation to an ignored UUID and keeps its active state
under that UUID in `~/.loom/instances/`. Project observations require an installation-
namespaced project ID plus a domain; domain observations load only for an exact domain.
Contribution is explicit, accepts controlled generic values only, and refuses a different
receiver UUID. No memory command opens a network connection.

`tools/loom_audit.py` recursively scans shipped Python, shell/workflow policy surfaces,
browser-executable HTML/SVG/JavaScript/CSS, and rendered Markdown resources. It fails on detected
network clients, active remote resources, dynamic-import bypasses, shells, non-allowlisted
processes, or workflow actions outside the exact immutable commit allowlist. Git is the
one declared process exception for owner-requested source synchronization; Loom never fetches
or pulls automatically. This is a claim about the audited shipped code, not about the host
agent, editor, Git remote, operating system, or future unscanned files.

Per-install state (`.loom-instance-id`, `.loom-private/`, and `~/.loom/instances/`) is outside
the positive publication allowlist. The firewall decodes and scans every shipped file as
UTF-8 text and scans every filename; an opaque file or any forbidden token blocks the build.

## Rules

1. **No plan content leaves private space.** Never paste pack content into public issues,
   public PRs, gists, forums, documentation sites, or third-party services that aren't part
   of the requester's private tooling. "Redacted" excerpts count as content.
2. **No secrets in plans — in either direction.** Plans never contain credentials, API keys,
   tokens, connection strings, account numbers, broker data, or personal data. Not even as
   examples; use `<PLACEHOLDER>` forms. If a survey encounters a secret in a repo, note *that*
   a secret was found and where (path only), never the value — and flag it as a finding.
3. **Public repos get no embedded pack.** If the target repo is public, the pack lives outside
   it or in a `.gitignore`d directory, and the ignore entry is verified (`git check-ignore`)
   before the first pack file is written. Committing plans to a public repo is a violation
   even if "temporary".
4. **Commits and PRs reference orders by ID only.** `WO-007: add session refresh` is fine in a
   public commit message; the work order's body is not. Public commit messages must not quote
   plan content, strategy, or the assumption ledger.
5. **Prompts are content too.** When routing a work order to an external model/service, send
   the work order's need-to-know slice, not the whole pack. Check the order for embedded
   private context before sending.
6. **Drafted instruction files inherit these rules.** An AGENTS.md / CLAUDE.md draft that will
   live in a public repo must contain only what is safe to publish (build commands,
   conventions). Anything strategic stays in the private pack. See
   `loom/execution/project-instructions.md`.
7. **No implicit learning export.** Retro may write project outcomes and local typed memory.
   It may queue a controlled generic lesson. Only an explicit owner invocation may drain that
   queue into the same installation's FEEDBACK file; lint, install, plan, retro, and publish
   never do so.

## Scrub checklist (run before anything crosses a privacy boundary)

- [ ] Credentials, tokens, keys, connection strings? (search for obvious markers: `key`,
      `token`, `secret`, `password`, `Bearer`, long base64/hex runs)
- [ ] Personal data (names, emails, phone numbers, account IDs)?
- [ ] Unreleased feature names, dates, strategy statements?
- [ ] Quotes from the planning pack?
- [ ] Paths or hostnames that reveal private infrastructure?

If any box is unclear, the answer is: it doesn't cross.

## When rules collide with the task

If a task appears to require publishing plan content (e.g., "write public docs from the
plan"), the docs are a **new artifact written for publication** — derived facts re-expressed,
scrub checklist applied — never the plan itself. When in doubt: `[HUMAN-DECISION]`.
