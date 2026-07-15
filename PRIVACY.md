# Privacy and Sovereignty

Loom's production Python modules are standard-library-only. The offline audit rejects direct and
literal dynamic network imports plus literal network subprocess commands; it does not claim an OS
network sandbox for dynamically constructed or owner-selected verification commands. Current Loom
source contains no built-in telemetry transport. Owner state is local, instance-scoped, and absent
from the positive public allowlist. General judgment, domain learning, project state, and
installation identity remain separate. Selection is bounded and exact-scope; forgetting writes a
durable content-erased tombstone.

Private-owner publication requires explicit owner-token inputs and proves that at least one token
is grounded in source material outside the positive public allowlist. A nonblank dummy token cannot
produce a clean private build. Public-release verification uses an explicit scan-only classification
and reports `protection_claimed: false`; it never pretends those inputs prove private-source
grounding. Grounding proves the policy would protect something, not that a human supplied every
possible sensitive idea or identifier.

The firewall scans every regular output filename and raw byte stream, normalizes UTF-8 and UTF-16
text, and checks configured private tokens plus implemented secret signatures. Transparent text
formats and extensionless decoded text may ship; unsupported opaque binary or container formats are
rejected instead of being declared clean. Symlinks, reparse points, non-regular entries, oversized
files, changed-during-scan files, and a private build whose token policy would protect nothing also
fail closed.
Artifact verification rejects every undeclared post-build file, runs tests with Python bytecode
disabled, and repeats the firewall after tests so validation cannot silently contaminate a clean cut.

These guarantees cover shipped Loom source and Loom-managed state. They do not claim control over
the host agent provider, editor, operating system, plugins, Git server, or commands a person runs
outside Loom. No scanner can prove arbitrary prose contains no sensitive idea, so semantic review
remains a release responsibility in addition to the mechanical firewall.
