# Adversary emulation tests

Each technique gets a directory keyed by MITRE ATT&CK ID. Two files inside:

- `atomic.yaml` — the [Atomic Red Team](https://atomicredteam.io/) invocation
  in YAML. Format mirrors ART's official `*.yaml` shape so the official runner
  works against it as-is.
- `expected.yaml` — what selfdef should observe. Rule IDs that should fire,
  acceptable latency, ordering hints.

## Layout

```
tests/adversary/
├── README.md
└── T<id>-<short-slug>/
    ├── atomic.yaml
    └── expected.yaml
```

## Current state

The infrastructure is in place; the **runner** itself is not yet automated.
Running ART techniques safely requires an isolated environment (container or
VM) with the right tooling installed, which is out of scope for the basic
`cargo test` flow.

Two ways to use this directory today:

1. **Manual**: pick a technique, run the ART invocation on a host running
   `selfdefd`, watch `selfdefctl events alerts` for the expected rule IDs.
2. **Documentation**: each expected.yaml is a contract — "this rule claims to
   detect this technique." A future milestone wires a CI job that spins a
   VM, runs the technique, and asserts.

## Adding a technique

1. Pick the ATT&CK technique you want covered, e.g. `T1110.001` (Password
   Guessing).
2. Create `tests/adversary/T1110.001-password-guessing/`.
3. Drop in `atomic.yaml` from
   <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics> (or
   write your own).
4. Write `expected.yaml` listing the selfdef rule IDs you expect to fire.
5. Run the technique manually; iterate until expected ⇄ observed match.
6. Commit. CI lint at minimum verifies the YAML parses.
