# User cheatsheet — the short prompts

For the human driving projects across many chats. Agents: these are requester-side
conventions; the skill and bootstrap prompts remain your entry points.

## Universal append-tag (attach to anything, any project)

```
Use Loom (/loom). Pack lives in this repo's plans/. A2: decide reversible things yourself, batch my decisions with recommendations. Lint before gates. Repo conventions win.
```

Everything in it is already skill-enforced — the tag exists so no agent ever skips the
skill, in any harness.

## Start a project (first message of a chat)

```
/loom plan — <name>: <one sentence what it is>. For: <who uses it>. Done = <observable finish line>. Constraints: <platform / don't-touch / budget — or "none">. Repo: <path|URL|none>.
```

The two load-bearing clauses are **Done =** (intake's finish line — saves the agent an
inference the requester then has to confirm) and **Constraints** (hard stops in, ghost
requirements out). Everything else Loom derives from the repo.

## During the project

| Moment | Prompt |
|---|---|
| Execute next work | `/loom wo WO-00X` (or "execute the frontier") |
| Returning after a break / other agents touched the repo | `/loom resume` |
| Check pack health | `/loom lint` |
| SEE the pack (one HTML page: DAG, ledger, live lint) | `/loom report` |
| Gate a milestone | `/loom gate G4` |
| Milestone shipped / project done | automatic — bare `/loom` runs retro + contribute at the natural end (manual: `/loom retro`) |
| Teach/correct a preference | `/loom profile set <key> <value>` — or just say "remember that I…" |
| Force-send queued lessons now | `/loom contribute` (normally automatic, D-010) |

## The loop back to Loom

Bare `/loom` auto-closes each run: retro fills that project's `plans/outcomes.md`, teaches
`~/.loom/`, and contributes compact anonymized patterns to Loom's `FEEDBACK.md` — no extra
typing. In Loom's home chat: **"aggregate"** / **"retro aggregate"** harvests and triages
everything; **"score Loom"** runs the independent scorecard when evidence has accumulated.
