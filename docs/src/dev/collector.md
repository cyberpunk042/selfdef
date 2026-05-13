# Adding a collector

A **collector** is a workspace crate named `selfdef-collector-<name>`
that turns some external event source into `selfdef_core::Event`
values and publishes them onto the in-process bus. Once the bus
has the event, the rest of the system (correlator, responder,
notifier, store, API) handles it uniformly — no per-collector
plumbing past this seam.

## The contract

Every collector exposes:

- A constructor `pub fn new(...) -> Self` taking whatever it
  needs (input path, runtime config, a `selfdef_bus::Publisher`
  handle).
- An async `pub async fn run(&self, shutdown: CancellationToken)
  -> Result<(), CollectorError>` that loops until shutdown,
  publishing events as they appear.

The daemon (`selfdef-daemon/src/main.rs`) spawns each enabled
collector as a `tokio::spawn` task gated on `cfg.collectors.<name>.enabled`.

## Step-by-step

1. **New crate** under `crates/selfdef-collector-<name>` with a
   `Cargo.toml` that depends on `selfdef-core` and `selfdef-bus`.
   Add the crate to the workspace `Cargo.toml`'s `members` list.
2. **Implement parsing** from the source format into
   `selfdef_core::Event`. Keep parsing dumb — translate, don't
   correlate. Severity, attack mappings, and finding promotion
   are the correlator's job, not yours. (See SDD-001 for the
   rationale.)
3. **Preserve the source payload** on `Event.raw` so sigma
   rules can match against the original fields. The `tetragon`
   collector is the canonical example — it pulls structured
   fields out (process, file, network) and keeps the raw JSON
   for rule access.
4. **Add a config block** in `selfdef-config::Config` —
   `[collectors.<name>] enabled = false` plus whatever knobs
   your source needs. Keep the default `enabled = false` so
   `selfdefd` stays safe-off out of the box.
5. **Spawn site** in `selfdef-daemon/src/main.rs` next to the
   other collectors. The pattern: read the config, build the
   collector, `tokio::spawn` its `run()` with a shutdown token
   clone.
6. **Test surface**: the existing collectors' replay corpora
   live under `tests/replay/<source>/*.jsonl`. Drop a corpus
   for your collector and add an integration test that asserts
   the parsed events have the right shape (see
   `crates/selfdef-daemon/tests/m6_collectors.rs` for the
   pattern).

## What a collector does NOT do

- It does not assign findings (`category_uid = 2`). The
  correlator promotes raw events to findings via sigma rules.
- It does not call notifiers or actions directly. The
  responder is the only path to side effects.
- It does not maintain its own retention or rotation. The store
  sink owns that.
- It does not block on slow downstream consumers. Use
  `Publisher::publish_lossy` if your source is a hot loop;
  the bus handles backpressure via subscriber lag detection.

## Reference collectors

| Source | Crate | Notes |
| --- | --- | --- |
| auditd | `selfdef-collector-auditd` | Tails `/var/log/audit/audit.log`; parses key=value records into Process / Authentication events. |
| journald | `selfdef-collector-journald` | Two modes: spawn `journalctl --follow`, or tail a JSONL file. |
| tetragon | `selfdef-collector-tetragon` | Parses Tetragon's native JSON into Process / FileSystem / Network Activity events. |
| suricata | `selfdef-collector-suricata` | Parses EVE JSON. |
| canary | `selfdef-collector-canary` | Watches a list of honeytoken paths; any access publishes a Critical Detection Finding. |
| eventstream | `selfdef-collector-eventstream` | Tails any JSONL of pre-formed selfdef Events. Used by `selfdef-ssh-wrap` and by modules invoking `selfdefctl events emit`. |
| ebpf | `selfdef-collector-ebpf` | Native in-kernel via aya. Requires the BPF object compiled and the systemd ebpf.conf drop-in. |

When in doubt, copy the smallest neighbour and adapt.
