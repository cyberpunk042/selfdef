# Sigma rules

Vendor-neutral detection rules in [Sigma](https://sigmahq.io/) format.

Each rule:
- Lives in a subdirectory by tactic (e.g. `credential-access/`, `persistence/`).
- Maps to one or more MITRE ATT&CK technique IDs in its frontmatter.
- Is unit-tested against `tests/replay/` corpora in CI (M7).

Loaded by the correlator from `/etc/selfdef/rules/sigma/` at startup and on SIGHUP.
