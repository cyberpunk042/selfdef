# Replay corpora

Captured event streams used to test rules and collectors deterministically.

Layout (populated in M7):
- `replay/<source>/<scenario>.jsonl` — one JSON event per line, in the
  `Event` envelope shape defined by `selfdef-core`.
- `replay/<source>/<scenario>.expected.yaml` — rule-IDs expected to fire,
  with timing tolerances.

CI runs every rule against every applicable corpus and asserts the expected
match set. This is the regression net for detection engineering.
