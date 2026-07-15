# Loom 1.0.0 Limitations

Loom fails closed around evidence it does not possess.

- Cross-platform behavior is **[UNVERIFIED]** until the current revision passes the complete CI
  matrix on Windows, macOS, and Linux. A workflow definition is not a successful run.
- Fresh-install usability is **[UNVERIFIED]** until at least 1 person unfamiliar with Loom installs
  it from the public cut and completes a real request without maintainer coaching.
- Independent hostile review is **[UNVERIFIED]** until a reviewer independent of the implementation
  reports 0 Critical and 0 High findings against the exact release candidate.
- Improvement claims remain unavailable for a metric/domain pair until it has at least 16 ordered
  observations and 8 controlled memory-enabled versus memory-disabled replay pairs.
- Domain guidance is not current legal, tax, medical, safety, or regulatory advice. Loom must verify
  present rules and target-environment facts before those claims become load-bearing.
- Verification commands run in a disposable target snapshot, but the Python standard library does
  not provide a portable host-level filesystem/network sandbox. Loom protects the original target
  from relative-path mutation and detects target drift; command authority outside that snapshot is
  **[UNVERIFIED]** until an OS sandbox provider is configured and certified.

`tools/loom_release.py certify` enforces the first 3 evidence contracts. Certification requires a
separate trust policy whose independently provisioned RSA public keys authorize each evidence type;
unsigned, self-asserted, duplicated, expired, irrelevant, tampered, or wrong-commit evidence fails.
Missing evidence blocks production certification and the 100 score; documentation cannot override
that result.
