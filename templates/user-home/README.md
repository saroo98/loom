# User-home state is generated, not copied

Do not create flat profile, calibration, project-index, or outbox Markdown files. They cannot
express installation/domain/project scope and are therefore quarantined as legacy input.

Initialize typed state with:

```text
python <loom>/tools/loom_memory.py init --loom-root <loom>
```

The tool creates schema-versioned state under `~/.loom/instances/<installation UUID>/` and
enforces isolation, expiration, compaction, hard size limits, atomic writes, and explicit
contribution. See `loom/core/user-memory.md` for the full contract.
