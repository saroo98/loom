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

## Instance sovereignty (D-012)

Every Loom install is owner-operated, and the learning loop closes inside it: retro writes
to the owner's `~/.loom/` and to the FEEDBACK queue of the repo `$LOOM` points at — *their*
Loom. There is no central queue, no upstream contribution channel, and no telemetry; the
channel does not exist, provably — the tools contain no network code except git against the
user's own remotes. Instances diverge by design: each accretes its owner's domain chapters,
and upstream releases are optional imports, never required updates. If an owner chooses to
make their Loom repo public, rules 1–6 below and the anonymization gates protect what their
loop writes.

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
