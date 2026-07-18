# Private diagnostics and support bundles

Loom diagnostics are local and body-free. They may report runtime versions, state schema and
generation, SQLite integrity, adapter ownership status, pending updates, session counts, and
bounded reason codes. They never include memory bodies, prompts, absolute paths, stable owner or
device identifiers, credentials, or telemetry.

An encrypted support bundle is created only after an explicit request:

```text
python -B tools/loom_diagnostics.py support-bundle \
  --home ~/.loom --helper <verified-loom-vault-helper> --output loom-support.loom-encrypted
```

The command asks twice for a passphrase and writes an encrypted local file. Loom has no upload
path. The owner decides whether and how to share it. Physical secure deletion is not claimed on
copy-on-write filesystems or SSDs; encryption and bounded plaintext exposure are the guarantees.
