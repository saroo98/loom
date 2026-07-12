# Privacy and sovereignty — exact guarantees

## What the shipped Loom code guarantees

1. `tools/loom_memory.py` performs local standard-library file IO only. It stores active
   state under `~/.loom/instances/<installation UUID>/`; every record/outcome/outbox is
   validated against that UUID.
2. Arbitrary observations require an exact domain; project observations additionally require
   an installation-namespaced opaque project ID. Global active memory accepts only typed,
   explicitly stated general preferences. Raw/other-scope history is never selected.
3. Active memory, selected context, outcomes, summary partitions, tombstones, and the
   contribution outbox have hard bounds. Tool-generated FEEDBACK contributions compact to 100
   active entries in the same command; direct manual edits require `compact-feedback` to
   reapply that bound. FEEDBACK is not loaded during planning. Inactive archives are never
   loaded into planning context.
4. Contribution is never automatic. The command accepts controlled generic pattern/action
   values only and refuses a receiver with another installation UUID. It is a local write to
   that same Loom root, not a network transfer.
5. Per-install state and planning packs are absent from the positive public allowlist.
   Publication scans every shipped UTF-8 file and filename for forbidden owner tokens and
   secret patterns; opaque files block.

## Executable-source audit: scope, not mythology

Run:

```text
python tools/loom_audit.py
```

It recursively parses shipped Python, resolves import/subprocess aliases and dynamic imports,
scans shell/workflow executable text, and checks browser-executable HTML/SVG/JavaScript/CSS for
network APIs or active remote resources; rendered Markdown remote resources are checked too.
Detected network-capable imports, browser network paths, shell bypasses, download primitives,
non-allowlisted processes, or workflow actions outside exact immutable commit pins fail. Runtime
subprocess is limited to Git and Python; installer regression tests may invoke only the checked
local installer scripts. Inert external hyperlinks and metadata URLs are reported as content,
not falsely classified as automatic network execution.

Exit 0 means these checks found no violation in the files scanned. It does **not** audit or
make promises about the host agent/model provider, editor, operating system, Git server,
plugins, future files, or commands the owner runs separately.

Git is the one declared external-process exception. Loom never fetches or pulls merely because
the skill loaded. A network Git operation occurs only after an explicit owner request.

## Planning-pack privacy

Planning packs expose strategy and must stay private. Public target repositories keep packs
outside the repo or in a verified ignored location. Plans contain no credentials, account
data, connection strings, personal data, or secret values—even as examples. Need-to-know work
orders, not whole packs, are routed to external agent services.

## Publishing a Loom cut

`loom_publish.py` builds a versioned, ownership-marked output through a positive allowlist.
It refuses dangerous paths, symlinks, unmarked existing directories, modified/foreign marked
directories, owner-layer builds with zero configured forbidden tokens, any undecodable shipped
file, every firewall/secret hit, broken supported local reference, source/public version drift,
and a failing staged suite. The previous valid output remains untouched when staging fails.

No scanner can prove that arbitrary prose contains no sensitive idea. The mechanical guarantee
is precise: only allowlisted sources can ship; every shipped byte must decode as UTF-8 text;
every configured forbidden token and implemented secret pattern is checked. Human review is
still required for semantic confidentiality.
