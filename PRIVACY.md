# Privacy and Sovereignty

Loom's production Python modules are standard-library-only and are mechanically audited for
network-capable imports. Owner state is local, instance-scoped, and absent from the positive public
allowlist. General judgment, domain learning, project state, and installation identity remain
separate. Selection is bounded and exact-scope; forgetting writes a durable content-erased
tombstone.

Publication requires explicit owner-token inputs. The firewall scans every regular output file and
relative filename without extension filters for configured private tokens and implemented secret
signatures. Symlinks, reparse points, non-regular entries, oversized files, changed-during-scan
files, and a private build with no owner tokens fail closed.

These guarantees cover shipped Loom source and Loom-managed state. They do not claim control over
the host agent provider, editor, operating system, plugins, Git server, or commands a person runs
outside Loom. No scanner can prove arbitrary prose contains no sensitive idea, so semantic review
remains a release responsibility in addition to the mechanical firewall.
