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
| Milestone shipped / project done | bare `/loom` runs retro at the natural end (manual: `/loom retro`) |
| Teach/correct a preference | `/loom profile set <key> <value>` — or just say "remember that I…" |
| Explicitly merge controlled queued lessons into this Loom install | `/loom contribute` |

## The loop back to Loom

Bare `/loom` auto-closes each run with retro: it fills that project's `plans/outcomes.md`,
records bounded numeric calibration, and may queue a controlled generic pattern locally.
Nothing drains that queue without the explicit `/loom contribute` command. In Loom's home
chat: **"aggregate"** / **"retro aggregate"** compacts and triages the local queue;
**"score Loom"** runs the independent scorecard when evidence has accumulated.
