# Crate audit

> Scope: `crates/*` — public surface, daemon wiring, config wiring,
> dead code, schema drift. Per-area ids prefix `C-`.

The good news first: every crate that exists is reachable from
`selfdef-daemon` at runtime — no orphan collectors, no
unreachable modules. Wiring is mostly clean. The findings cluster
around three patterns: **dead config knobs** (typed but never
read), **a duplicated constant** (drift risk), and **a single
`deny` vs `forbid`** difference in one binary that's
intentionally documented but worth flagging.

---

## Per-crate notes

### selfdef-api

- `/metrics` is fully wired end-to-end: route at
  `crates/selfdef-api/src/lib.rs:75`, handler at
  `crates/selfdef-api/src/handlers.rs:82-94`, `Arc<Metrics>`
  field on `ApiState` (`state.rs:35`, initialized at line 41,
  overridable via `with_metrics`).
- Daemon spawns the ingest task at
  `crates/selfdef-daemon/src/main.rs:151-162` only when the API
  is enabled — correct, no counters bumped when nothing scrapes.
- The metrics field is `Arc<Metrics>`, not `Option<Arc<Metrics>>`.
  Always present even when ingest doesn't run. Negligibly wasteful;
  not a finding.

### selfdef-bus

- `BusConfig::backend` (`selfdef-config/src/lib.rs`) defaults to
  `"inproc"` and is never branched on in the daemon. Documented as
  "backend selector" but there is one backend. **(C-001)**

### selfdef-cli

- Binary only; no library surface.
- Subcommand handlers are all reachable from `Cli::command`
  match arms.

### selfdef-collector-*

All seven collectors are conditionally spawned in
`selfdef-daemon/src/main.rs:218-363`:

| Collector | Spawn site | Behind config flag |
| --- | --- | --- |
| auditd | lines 218-233 | `cfg.collectors.auditd.enabled` |
| journald | lines 235-262 | `cfg.collectors.journald.enabled` |
| tetragon | lines 264-280 | `cfg.collectors.tetragon.enabled` |
| suricata | lines 282-298 | `cfg.collectors.suricata.enabled` |
| canary | lines 300-318 | `cfg.collectors.canary.enabled` |
| eventstream | lines 320-337 | `cfg.collectors.eventstream.enabled` |
| ebpf | lines 339-363 | `cfg.collectors.ebpf.enabled` |

No orphans. All seven are also re-exported / referenced by the
daemon's import block.

### selfdef-config

Three dead knobs:

- `BusConfig::backend` — see C-001.
- `CorrelatorConfig::window_secs` (default 60) and
  `CorrelatorConfig::threshold` (default 3). Documented in the
  struct as "Default time window/threshold for built-in rules" but
  the correlator is constructed at
  `selfdef-daemon/src/main.rs:82-86` taking only `rules_dir`.
  Sigma rules carry their own windows/thresholds; the daemon-level
  defaults are unused. **(C-002)**
- `StoreConfig::hot_retention_days` — exposed in config but
  `selfdef-store` has no retention sweeper that reads it. **(C-003)**

### selfdef-core

No findings. `SCHEMA_VERSION` is a single source of truth here
(see C-005 about its duplicate elsewhere).

### selfdef-correlator

- Wired correctly. Cloned into `ApiState` for the `/rules/reload`
  endpoint at `selfdef-daemon/src/main.rs:172-174`.
- The two dead config knobs (window_secs / threshold) belong to
  the config crate, not here, but the correlator should accept
  them if they're supposed to mean something. See C-002.

### selfdef-ebpf-common

No findings. The `unsafe` impls for `bytemuck::Pod` are legitimate
and annotated.

### selfdef-nats

JetStream is fully wired end-to-end:

- `selfdef-config/src/lib.rs:143-153` `NatsJetStreamConfig`
  exposes `enabled`, `stream_name`, `durable_consumer_prefix`,
  `max_age_secs`, `max_bytes`, `max_msgs`.
- `selfdef-daemon/src/main.rs:190-200` translates every field.
- `selfdef-nats/src/lib.rs:200-205` branches on `enabled` and
  drives the durable consumer path.

No knob drift.

### selfdef-notifier

- `selfdef-daemon/src/main.rs:508-535` `build_notifier_chain`
  iterates `cfg.notifier.channels`. Notifiers (`NtfyNotifier`,
  `SignalCliNotifier`) are reachable only via that list.
- An operator who configures `[notifier.ntfy]` but forgets to put
  `"ntfy"` in `channels` gets silent skip. There's a log line
  ("channel skipped — missing config") but only if the channel
  name is in the list with missing config; if the channel name is
  absent entirely, no warning fires. **(C-004)**

### selfdef-responder

Seven actions registered at
`selfdef-daemon/src/main.rs:108-127`. All real implementations
(no `Ok(())` stubs). No findings.

### selfdef-ssh-wrap

Uses `#![deny(unsafe_code)]` instead of the workspace standard
`#![forbid(unsafe_code)]`. Intentional and documented at
`crates/selfdef-ssh-wrap/src/main.rs:18` — the binary needs a
localized `unsafe` block to call the Rust 2024
`std::env::set_var` from a test. Flagged for awareness only; not
a finding.

### selfdef-store

- Local hard-coded `const SCHEMA_VERSION: u32 = 1` at
  `crates/selfdef-store/src/sqlite.rs:106` instead of referencing
  `selfdef_core::SCHEMA_VERSION`. Currently coincidentally equal;
  a future bump in core would leave this stale and would only
  surface if a migration check fired. **(C-005)**
- `hot_retention_days` not enforced — see C-003.

### selfdef-daemon

The wiring hub. All subsystems reachable. Shutdown coordination
via a single `CancellationToken` propagates to every task. No
findings specific to the daemon, but it carries the brunt of the
findings rooted in its config and collectors.

---

## Cross-cutting

### Schema-version coherence

Most call sites reference `selfdef_core::SCHEMA_VERSION` directly
(`daemon/main.rs:56`, `api/state.rs:46`, `api/metrics.rs:52`,
the CLI). The one outlier is `selfdef-store/src/sqlite.rs:106`
(C-005).

### `forbid(unsafe_code)` coverage

Every crate carries `#![forbid(unsafe_code)]` *except*
`selfdef-ssh-wrap` (`deny`, documented). `selfdef-ebpf-common`
keeps `forbid` and contains real `unsafe` impls via the
`bytemuck` derive macros which expand under the macro's own
annotations.

---

## Findings raised in this section

| Id | Severity | Surface | Summary |
| --- | --- | --- | --- |
| C-001 | nice | `selfdef-config/src/lib.rs` `BusConfig::backend` | Dead knob — always "inproc", daemon doesn't read it. Either remove or implement the second backend. |
| C-002 | important | `selfdef-config/src/lib.rs` `CorrelatorConfig::window_secs`, `threshold` | Dead knobs — config exposes them but the correlator constructor ignores them. Sigma rules carry their own windows/thresholds; the daemon-level defaults are vestigial. |
| C-003 | important | `selfdef-config/src/lib.rs` `StoreConfig::hot_retention_days` + `selfdef-store` | Dead knob — config exposes a retention horizon but no sweeper enforces it. Either implement retention or remove the knob. |
| C-004 | nice | `selfdef-daemon/src/main.rs build_notifier_chain` | A `[notifier.ntfy]` block with no matching `"ntfy"` entry in `channels` silently disables ntfy without a warning at startup. |
| C-005 | important | `selfdef-store/src/sqlite.rs:106` | `const SCHEMA_VERSION: u32 = 1` duplicates `selfdef_core::SCHEMA_VERSION`. Drift risk on a future schema bump; the store migration check would not fire. Reference the core constant instead. |
