# SDD-079 — Tetragon metric-name contract (observability hardening)

**Status:** implemented
**Author:** selfdef IPS authority chain
**Closes:** F-2026-052 (findings ledger — *was M-007*) — "Hardcoded
Tetragon metric name without an upstream-version pin."
**Owner:** the `observability` module (it renders the panels, so it
owns the contract for the series those panels depend on).
**Stems from:** MS027 E0275 ("Tetragon metric-name pin"), R06323
(non-negotiable), F03190. The README's "Tetragon metric-name pin"
section documented the v1.x assumption in prose; this SDD upgrades
that prose into an enforced, machine-checkable contract.
**Last updated:** 2026-06-08.

## Problem

The shipped Grafana dashboard
(`modules/observability/assets/dashboards/selfdef.json.template`)
renders four panels off upstream Tetragon's built-in Prometheus
exporter:

| Panel | Series |
|---|---|
| Tetragon events / second | `tetragon_events_total` |
| Tetragon kills by policy | `tetragon_msg_sigkill_total` |
| Process cache utilization | `tetragon_process_cache_size` |
| Map operation errors | `tetragon_map_errors_total` |

These series names are hard-coded in the dashboard JSON. The failure
mode (F-2026-052): if a Tetragon release **renames** any of them, the
matching panel renders **flat** — no error, no log line, no alert.
The operator stares at an empty graph and may not notice for weeks
that their kill-by-policy visibility silently went dark. That is the
worst class of observability failure: a monitor that fails *open* and
*quiet*.

Prior partial close: a README section documented the v1.x assumption.
Prose in a README does not fail a build and does not page an operator.
This SDD adds the missing enforcement.

## Goals

1. **Pin** the four series in one declarative, machine-checkable place.
2. **Lock** dashboard ↔ contract ↔ SDD in lockstep so drift on any of
   the three fails CI (prevention/detection).
3. **Probe** the live endpoint so a rename in production surfaces as a
   loud, actionable `check.sh` warning instead of a silent flat panel
   (operability).
4. **Document** the verified upstream version window so an operator
   bumping Tetragon has an explicit compatibility gate.

## Non-goals

- **Auto-enforcing** the Tetragon binary version range from the
  `tetragon` module's `requires` block. That needs a binary-version
  probe the tetragon module does not have today; it is the remaining
  Phase-3 follow-up (see § Open questions D-1). This SDD ships the
  *declared* version window + the *runtime series probe*, which is the
  load-bearing half of the gate.
- Renaming or restructuring the dashboard panels themselves.
- Pinning the selfdef-daemon-side series (those are owned by this repo
  and covered by the m060 + four-watchdog dashboard contract tests;
  the risk this SDD addresses is specifically the *upstream* Tetragon
  surface we do not control).

## Design

### The contract asset

`modules/observability/assets/contracts/tetragon-metrics.toml` is the
single source of truth. It declares:

- `schema_version`
- `verified_tetragon_version` — semver range window (`>=1.0.0, <2.0.0`)
- `canonical_source` — the upstream page publishing the names
- four `[[series]]` entries, each with `name` (bare series), `panel`
  (dashboard title), `promql` (the EXACT dashboard expression).

The observability module owns this file because it owns the dashboard.
The `tetragon` module owns the *substrate* (the exporter endpoint);
the boundary is deliberate — observability is the consumer of the
metrics-endpoint surface tetragon `provides`.

### Three lines of defense

1. **Prevention / detection (CI).**
   `tests/observability/test_tetragon_metric_name_contract.py` asserts:
   - the contract parses and declares exactly the four series;
   - each contract `promql` equals the dashboard panel's `expr`
     character-for-character;
   - the dashboard contains **no other** `tetragon_*` panel series
     beyond the four (adding a fifth Tetragon panel is then a
     deliberate decision that must extend the contract);
   - SDD-079 (this file) documents all four series + the version pin;
   - the README cross-references the contract file.

   Drift on the dashboard, the contract, the SDD, or the README fails
   the build.

2. **Operability (runtime probe).**
   `check.sh` gains an opt-in, warn-only Tetragon-series presence probe
   (`SELFDEF_OBSERVABILITY_PROBE_TETRAGON=1`). When enabled and `curl`
   is available, it scrapes the Tetragon metrics endpoint
   (`SELFDEF_TETRAGON_METRICS_URL`, default
   `http://127.0.0.1:2112/metrics`) and emits a `warn` line per
   contract series **absent** from the live exposition. It never
   `die`s — Tetragon being down is the operator's problem, not the
   module's (the module's existing doctrine), and a warn keeps
   `check.sh`'s exit-0-on-rendered-files-present contract intact while
   making a rename loud.

3. **Documentation (version window).**
   `verified_tetragon_version` records the validated window so an
   operator bumping Tetragon major versions has an explicit re-check
   gate, and the README points at the contract instead of restating
   the names (single source of truth).

## Verification

```
$ pytest -xq tests/observability/test_tetragon_metric_name_contract.py
# locks dashboard <-> contract <-> SDD-079 <-> README

# operability probe against a live Tetragon endpoint (host with the
# tetragon module applied):
$ SELFDEF_OBSERVABILITY_PROBE_TETRAGON=1 \
  SELFDEF_OBSERVABILITY_CONFIG=/etc/selfdef/modules/observability.toml \
  bash modules/observability/install/check.sh
# warns: "tetragon series absent from live exposition: <name>" per gap
```

## Open questions

- **D-1**: Should the `tetragon` module's `requires` block gain a
  `{ kind = "binary-version", value = "tetragon >=1.0.0,<2.0.0" }`
  entry that the apply path enforces fail-closed? **Recommendation:**
  yes, as a Phase-3 follow-up once the module runner grows a
  binary-version probe (today `requires` only checks binary
  *presence*). The `verified_tetragon_version` field in the contract
  is the declarative half that the future probe will read, so the
  contract is forward-compatible with that enforcement.

- **D-2**: Should the probe `die` (fail-closed) instead of `warn`?
  **Recommendation:** no — keep warn-only. `check.sh`'s established
  contract is "rendered files present → ok"; an unreachable upstream
  Tetragon is explicitly out of the module's responsibility per the
  existing check.sh header comment. A warn surfaces the gap without
  breaking the module-health contract that other tooling depends on.
