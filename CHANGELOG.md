# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — AI-machine track: `tetragon` + `agent-guard` + `observability` modules
- New `tetragon` module (v0.1.0, hardening, `phase = "pre"`):
  substrate for everything Tetragon-based. Renders
  `/etc/tetragon/tetragon.yaml` byte-stably from the host config,
  owns the TracingPolicy drop directory, exposes the built-in
  Prometheus metrics endpoint, points Tetragon's event JSONL at a
  path the daemon's `eventstream` collector can tail. Refuses to
  apply if `tetragon` / `systemctl` aren't on `PATH`. Restarts the
  service only when the rendered config actually changes bytes —
  re-running apply on a converged host is a true no-op. Provides
  `tetragon-tracing` / `tetragon-policies` / `metrics-endpoint`.
- New `agent-guard` module (v0.1.0, hardening, `depends_on =
  ["tetragon"]`): four TracingPolicies tuned for AI agents running
  in Docker / Podman / containerd containers:
  - `etc-write-guard` — `security_file_open` with write intent
    under `/etc/`.
  - `container-shell-guard` — `execve` of `bash` / `sh` / `dash`
    / `zsh` / `ash`.
  - `egress-guard` — `tcp_connect` to non-allowlisted destinations
    (CSV CIDR allowlist via `egress_allowlist`).
  - `securemessage-guard` — forward-looking stub for a SecureMessage
    endpoint; auto-downgrades to `Post` action whenever the
    endpoint is unset so the placeholder never SIGKILLs anything.
  Two profiles: `audit` (Post-only, the bring-up default) and
  `enforce` (Sigkill). Per-policy `*_action = default | post |
  sigkill` overrides let operators ramp up policies individually.
  Container scope uses Tetragon's `matchNamespaces` to skip the
  host PID namespace — works on every container runtime without
  needing k8s labels.
- New `observability` module (v0.1.0, observability, `phase =
  "post"`, `depends_on = ["tetragon"]`): Prometheus scrape config
  + Grafana dashboard JSON for the selfdef stack. Two profiles:
  `bundled` (drops files under `/etc/prometheus/conf.d/` and
  `/var/lib/grafana/dashboards/selfdef/`, reloads Prometheus) and
  `external` (renders into a staging dir for the operator to sync
  out). Dashboard: four panels — Tetragon events/sec, kills by
  policy, process-cache utilization, BPF map errors.
- 23 new hermetic dry-run smoke tests cover the three modules:
  byte-stable config rendering + idempotent reapply (tetragon),
  per-policy action resolution + egress allowlist splicing +
  SecureMessage stub behaviour + check drift detection +
  uninstall cleanup (agent-guard), bundled vs external rendering +
  scrape target splicing + dashboard JSON validity + idempotent
  reapply + empty-target refusal (observability).
- Roadmap (`docs/src/modules-roadmap.md`) gains rows for the three
  new modules and the "AI-machine track" callout in remaining
  work, with pod-label / GPU device-guard variants + a
  selfdef-daemon `/metrics` endpoint flagged as follow-ups.

### Added — `selfdefctl events emit` + `integrity-sentinel` notifier wiring
- New `selfdefctl events emit` subcommand appends a single OCSF
  Event line to a JSONL stream the daemon's existing `eventstream`
  collector tails. Modules and helper scripts can now surface
  findings onto the bus without hand-rolling the envelope in bash:
  the Rust side builds a real `selfdef_core::Event`, so taxonomy,
  schema version, derived `type_uid`, and metadata are guaranteed
  correct. Args: `--class-uid`, `--activity-id` (default 1),
  `--severity` (informational|low|medium|high|critical|fatal),
  `--source`, `--message`, `--host-tag` (defaults to
  $HOSTNAME / /etc/hostname), `--out <path>` (required).
- `integrity-sentinel` v0.1.1: when `event_stream_path` is set in
  the module's host config, drift now emits a Detection Finding
  (OCSF class 2004) to that JSONL stream. The daemon picks it up,
  the responder routes Findings-category events through the
  notifier chain, and ntfy / Signal fires. Severity defaults to
  `high` for `strict` and `low` for `warn-only`; both are
  overridable via `event_severity_strict` / `event_severity_warn`.
  Leave `event_stream_path` unset to suppress emission — the
  structured-status surface is unaffected. Best-effort: a
  `selfdefctl` not on PATH or a failed emit logs a warning and
  never fails the apply / check run.
- 5 new unit tests for `selfdefctl events emit` (round-trips
  through `Event`, atomic append doesn't clobber prior lines,
  unknown severity / empty source rejected, parent dir is created
  on demand) plus 1 integration test that exercises
  `integrity-sentinel`'s apply path with `event_stream_path` set
  and asserts the resulting JSONL line parses back into a valid
  Findings-category Event.
- Roadmap docs (`docs/src/modules-roadmap.md`) updated to remove
  both shipped items (`modules uninstall`, integrity-sentinel
  notifier wiring) from the remaining-work list and to include the
  `uninstall` row in the lifecycle table.

### Added — `selfdefctl modules uninstall`
- New subcommand drives each active module's `uninstall.sh` in the
  inverse of apply order: dependents come down before the modules
  they depended on, and phases unwind `post → main → pre`.
- Destructive by design — non-dry-run runs require
  `--confirm <hostname>` matching this host (mirrors the `panic`
  subcommand's confirmation pattern). Mismatched or absent
  `--confirm` exits 2 with a clear message.
- `--dry-run` previews the run without `--confirm`, propagating
  `SELFDEF_DRY_RUN=1` so module scripts can short-circuit.
- Standard `--only` / `--except` filters apply, accepting either a
  bare slug or a `slug#instance` form.
- Modules whose manifest never declared an uninstall script (or use
  `kind = "debian-package"`) are reported as `skipped: no uninstall
  script declared` so a host-wide uninstall still produces a useful
  aggregate.
- Refactored the internal lifecycle runner around a small
  `LifecyclePolicy` (reverse order + tolerate-missing-script) to
  share the apply / check / uninstall machinery without forking.
- 3 new unit tests (reverse apply order, reverse phase order,
  missing-script detection) and 6 integration tests in
  `tests/cli_modules_uninstall.rs` cover ordering, the skipped path,
  both confirmation refusals, the matching-confirm happy path, and
  `--only` filtering.

### Added — JetStream durability for the NATS bridge
- New `[bus.nats.jetstream]` config block. When `enabled = true`, the
  bridge:
  - Ensures a JetStream stream (`stream_name`, default
    `selfdef-events`) capturing `<subject_prefix>.>` with operator-
    tunable retention (`max_age_secs` / `max_bytes` / `max_msgs`).
  - Creates a per-host durable pull consumer named
    `<durable_consumer_prefix>-<host_tag>` so each daemon tracks its
    own ack progress and a restart resumes mid-stream.
  - Publishes locally-originated events via `js.publish(...).await`
    and waits for the server ack — outages stall publishes rather
    than silently dropping them.
  - Acks each inbound message after republishing it onto the local
    bus (or recognizing it as a self-echo).
- Same loop-avoidance machinery as Core mode (host_tag check on both
  sides). At-least-once redeliveries are safe because each event
  carries a UUIDv7 and the store sink dedupes by id.
- Public API additions in `selfdef-nats`:
  - `JetStreamConfig` struct + nested in `NatsConfig`.
  - `durable_consumer_name(prefix, host_tag)` helper that sanitizes
    host_tags to the JetStream durable-name grammar (alphanumeric +
    `-` + `_`).
- 3 new unit tests: `durable_consumer_name` builds the expected
  string, sanitizes disallowed chars, and the `JetStreamConfig`
  defaults are conservative (disabled, 7-day retention, unlimited
  size).
- async-nats `jetstream` feature added to the workspace dep flags.
- Docs: `docs/nats.md` gains a "Modes: Core vs JetStream" section
  with a runnable config snippet, retention semantics, and explicit
  notes on at-least-once delivery + the dedupe contract. Example
  config gains the `[bus.nats.jetstream]` block.

### Added — Dashboard control surface
- The bundled PWA in `dashboard/` gains a **Control** panel that wires
  up the M13/M14 write endpoints:
  - **Reload rules** — `POST /rules/reload`. Shows the resulting
    `rules_loaded` count.
  - **Panic** — `POST /panic`. Confirmation requires typing the host
    tag (matches `selfdefctl panic --confirm`) and clicking through a
    second browser-level confirm dialog.
  - **Run action** — `POST /actions/{name}/run`. The action dropdown
    is populated from `GET /actions`. Leaving the event-id field
    blank runs the action against the most-recent finding.
- New `post()` helper in `dashboard/app.js` that parses the JSON body
  from both 2xx and error responses so the dashboard can surface what
  actually went wrong (`{"error": "..."}`).
- Result indicator (`#control-result`) renders ok / error states with
  green / red coloring and the API's own status text.
- Service worker now bypasses every non-`GET` request — control verbs
  pass straight through, no chance of an offline-cached fallback
  swallowing a panic dispatch. `/actions` is also added to the
  always-network list so the action list stays fresh.
- Docs: `docs/api.md`'s Dashboard section describes the new control
  surface and how the read-vs-control token gate is reflected in the
  UI.

### Added — M15 (NATS bridge for multi-host correlation)
- New crate `selfdef-nats` — pumps events between selfdef daemons over
  NATS Core. The local in-proc broadcast stays the source of truth for
  every in-process subscriber (collectors, correlator, responder,
  store sink, API SSE stream); the bridge is a sidecar task with two
  loops:
  - **outbound**: subscribes to the local bus and publishes locally-
    originated events to `<subject_prefix>.<host_tag>`.
  - **inbound**: subscribes to `<subject_prefix>.>` and republishes
    received events onto the local bus, dropping any whose
    `host_tag` matches ours (self-echo loop guard).
- Loop avoidance is two-layered on purpose: outbound filters by
  `event.host_tag == local`, inbound drops the mirror. The host_tag
  check is O(1) and doesn't need the deduper dance UUIDv7 enables.
- `[bus.nats]` config block: `enabled`, `url`, `subject_prefix`.
  Default prefix `selfdef.events`. Disabled by default. Multiple NATS
  servers are comma-separated per the async-nats URL grammar; TLS via
  the `tls://` scheme.
- Daemon wires the bridge as another supervised task next to the API
  and the store sink. SIGTERM/SIGINT cancel propagates through; the
  bridge tears down both child tasks before exiting.
- async-nats 0.48 (latest as of this PR). Picked deliberately over the
  0.37 baseline because that pull also yanked the unmaintained
  `rustls-pemfile` + old `rustls-webpki` transitive deps that fell out
  of `cargo deny check advisories`.
- Unit tests for the bridge cover the subject layout
  (`outbound_subject` / `inbound_subject`), subject sanitization
  (host_tags with `.`, `*`, `>`, whitespace), the local-origin check,
  and JSON round-trip on the wire format.
- Docs: new `docs/nats.md` describes the topology, subject layout,
  loop avoidance, and a one-liner smoke test against `nats-server`.
- Documented non-goals: this is NATS Core only (no JetStream
  durability yet); no built-in auth (operators bring NATS mTLS / NKey
  / JWT as needed).

### Added — M14 (per-token capabilities for the API)
- `[api].control_token_file` — a second, optional bearer token. Read
  endpoints accept either the existing `token_file` or
  `control_token_file`; control endpoints (`/rules/reload`, `/panic`,
  `/actions/{name}/run`) require the control token specifically.
- New `selfdef_api::Capability` (`Read` | `Full`) request extension
  set by the auth layer based on which token matched (or
  unconditionally `Full` for UNIX-socket clients). Control handlers
  pull a `RequireControl` extractor that returns `403 Forbidden` for
  `Read` requests and `401 Unauthorized` for unauthenticated.
- New `selfdef_api::with_full_capability` / `with_capability` helpers.
  Tests use them to stamp a capability onto the request without going
  through bearer auth. The UNIX-socket transport uses `with_capability(_, Full)`
  internally — same primitive, no special cases.
- 6 new integration tests in `crates/selfdef-api/tests/m12_api.rs`
  covering: read-only token on read endpoints (200), read-only token on
  `/actions` discovery (200), read-only token on each control verb
  (403), and the anonymous control-verb path (401). 19 cases total.
- Docs: `docs/api.md` gains a fleshed-out auth-boundary section with
  token mint + rotate recipes. Example config gains the new
  `control_token_file` field with annotated semantics. README adds the
  M14 checkbox.

### Added — M13 (control-plane verbs + TLS/mTLS for the API)
- **Control-plane endpoints** in `selfdef-api` (write side):
  - `POST /rules/reload` — re-reads the rules directory, returns
    `{rules_loaded: N}`. Returns `503` when the daemon hasn't wired a
    correlator handle (e.g. correlator disabled in config).
  - `POST /panic` — body `{confirm, message?}`. Validates `confirm`
    against the daemon's `host_tag` (same safety belt as
    `selfdefctl panic`) and direct-fires the panic action set.
  - `POST /actions/{name}/run` — body `{event}` *or* `{event_id}`.
    Runs a single named action against the supplied / stored event
    via the responder's new `dispatch_single` method. Bypasses the
    allowlist on purpose — the auth boundary is the API token / UNIX
    socket permissions.
  - `GET /actions` — discovery: returns registered action names in
    order so dashboards / scripts can enumerate them.
- **Audit trail.** Every control verb publishes a synthetic event on
  the bus (`source = "selfdef.api"`, class `INCIDENT_FINDING`,
  severity `Informational`) with the action, status, and details. The
  store sink writes it to disk so `selfdefctl events tail` shows who
  poked the daemon.
- **`Responder` gains** `dispatch_single(name, event)` and
  `action_names()`. The bus-driven responder and the API now share
  one `Arc<Responder>` via clone rather than each having its own —
  same action set, one allowlist, one dry-run flag.
- **`ApiState` gains** an optional `ControlHandles` block (correlator,
  responder, publisher). Builder methods (`with_correlator`,
  `with_responder`, `with_publisher`) keep tests able to construct a
  read-only state with no control handles, in which case control
  endpoints return `503 Service Unavailable`.
- **TLS / mTLS for the TCP transport.** New `[api.tls]` block:
  `cert_path`, `key_path`, `client_ca`. With cert+key only: vanilla TLS
  (bearer token still authenticates). Add `client_ca` → mTLS (client
  certificate required and verified). Uses `tokio-rustls` 0.26 with the
  ring provider; the TLS-wrapped accept loop drives hyper directly,
  matching the existing UDS pattern. No CA bundle for client verification
  shipped — operators bring their own.
- New integration tests in `crates/selfdef-api/tests/m12_api.rs`
  covering: `/actions` discovery, `/rules/reload` 503 when correlator
  missing, `/panic` hostname mismatch returns 400, `/panic` happy path,
  `/actions/{name}/run` dry-run, unknown action 404, missing
  body 400. 13 cases total, up from 6.
- Docs: `docs/api.md` extended with the control-endpoint table, the
  auth-boundary note, and a TLS / mTLS section with a self-signed
  recipe. Example config gains `[api.tls]`.

### Added — Milestone 12 (Mobile dashboard / read-only HTTP API)
- New crate `selfdef-api`: axum-based read-only HTTP API. Endpoints:
  - `GET /status` — host_tag, schema_version, crate_version,
    event_count, uptime_secs.
  - `GET /events?n=N` — last N events from the hot store (default 50,
    capped at 1,000).
  - `GET /findings?n=N` — last N events with `category_uid = 2`.
  - `GET /events/stream` — Server-Sent Events live tail. Subscribes a
    fresh bus subscriber per client and forwards each event as a `data:`
    frame; lagged subscribers get a single `event: lagged` frame and
    resume; clients disconnect → forwarder exits on next send.
- Two transports, either or both at once via `[api]` config:
  - **UNIX socket** (default `/run/selfdef.sock`, mode `0660`). Trusted
    via filesystem permissions; no token. Driven via a custom hyper-util
    accept loop because axum 0.7's `axum::serve` is TCP-only.
  - **TCP** (off by default). Requires `Authorization: Bearer <token>`
    matching the contents of `token_file`. CORS is permissive on the
    response side; operators are expected to bind localhost and put a
    reverse proxy in front for TLS termination.
- Vanilla-JS PWA in `dashboard/`: single-file `app.js`, no bundler, no
  `node_modules`. Renders findings + events lists, polls `/status`
  every 5s, and exposes a "live stream" toggle that opens an
  `EventSource` against `/events/stream`. Service-worker shell-caches
  the static assets but never the API responses themselves. Manifest
  JSON makes it installable on iOS/Android.
- Daemon wiring: when `[api] enabled = true`, a new task spins up the
  API alongside the collectors / correlator / responder. Store and bus
  moved behind `Arc` so the API and the existing sink share ownership
  cleanly. New `build_api_config` helper translates the
  string-shaped `[api]` TOML into the typed `selfdef_api::ApiConfig` —
  a malformed `tcp_addr` logs a warning and disables the TCP transport
  rather than crashing the daemon.
- Integration test `crates/selfdef-api/tests/m12_api.rs` exercises the
  router via `tower::ServiceExt::oneshot`: status returns the host tag
  and counters; `/findings` filters by `category_uid = 2`;
  `/events?n=N` honors the page param; an unknown route 404s; the
  event JSON round-trips back to `selfdef_core::Event` envelopes.
- Documentation: new `docs/api.md` covers the transports, endpoints,
  and dashboard wiring; example config gains a documented `[api]`
  section.

### Added — M10 polish (eBPF: argv capture, LSM file_open, do_unlinkat kprobe)
- **argv capture** in the `execve_enter` tracepoint program. Walks the
  userspace `argv` pointer array with `bpf_probe_read_user` plus
  `bpf_probe_read_user_str_bytes`, bounded at 16 entries and 256 bytes
  total. Sets `argv_truncated` when the buffer fills or the entry cap
  is reached without seeing the NULL terminator. The OCSF
  `process.cmdline` now reflects the captured argv (joined by spaces);
  the `raw` payload carries the structured `argv` array and the
  `argv_truncated` flag for rule matching.
- **LSM `file_open` BPF program**. Observe-only (always returns 0, never
  vetoes). Reports pid/uid/comm/flags. Path capture is deferred until
  the project gains generated `vmlinux.rs` bindings — the ring-buffer
  schema already has `path` and `path_len` fields so the path can be
  layered on without touching userspace.
- **`do_unlinkat` kprobe BPF program**. Reports pid/uid/comm. Same
  path-deferral rationale as the LSM hook.
- New userspace API `selfdef_collector_ebpf::EbpfProbes` carries the
  three opt-in flags (`execve`, `lsm_file_open`, `kprobe_unlinkat`)
  from config into the collector. `EbpfCollector::with_probes()`
  selects what to attach; the existing `EbpfCollector::new()` keeps
  the conservative default (execve only).
- Each probe attach is independent and **fail-soft**: missing program
  in the `.bpf.o`, missing kernel BTF, missing `CONFIG_BPF_LSM=y`, or
  a kprobe that points at an inlined symbol all log a warning and
  leave the other probes running. The daemon never aborts on a
  partial attach.
- Daemon wires the three `[collectors.ebpf]` `enable_*` config bits
  into `EbpfProbes`. Example config + `docs/ebpf.md` updated to drop
  the "reserved" / "not yet implemented" notes and describe the
  current capabilities and limitations.
- Unit-test coverage extended in `selfdef-collector-ebpf`:
  `argv_truncated` propagates into the OCSF `raw` payload;
  `FileOpenEvent` and `UnlinkEvent` round-trip into properly classed
  `FILE_SYSTEM_ACTIVITY` events; `EbpfProbes::default()` matches the
  conservative shipping config.

### Added — Milestone 11 (Forensics + Velociraptor integration)
- New responder action `forensics_bundle`: on Critical findings, writes an
  evidence bundle to `forensics_dir/<event-uuid>/` containing the
  triggering event JSON, host metadata (`uname`, `/etc/os-release`,
  `/proc/version`, `/proc/cmdline`, `uptime`, `mounts`, `modules`,
  `passwd`, `group`), network state (`/proc/net/tcp`, `/proc/net/udp`,
  `ss -tnap`), kernel ring buffer tail (`dmesg`, bounded to 2,000
  lines), recent journal (`journalctl -n 2000`), and a per-pid
  snapshot of `/proc/<pid>/{cmdline,environ,status,maps,stat,io}` plus
  `exe_link`, `cwd_link`, and `fd/` listing when the event carries an
  actor pid. A `manifest.txt` records what was captured and what was
  skipped (with the underlying error). Best-effort throughout — missing
  files or unreadable subprocesses don't abort the bundle.
- New responder action `velociraptor_escalate`: invokes a configured
  Velociraptor binary with operator-defined argv. The placeholders
  `{event_id}` and `{host_tag}` are substituted before invocation, so
  the same selfdef config can drive client-side artifact collection,
  server-side hunt creation, or any other Velociraptor workflow. Empty
  args = action runs cleanly with no side effects (useful when the
  action is allowlisted but a particular host has no Velociraptor
  deployment).
- New `[responder]` config fields: `forensics_dir`,
  `velociraptor_binary`, `velociraptor_args`. Defaults are conservative
  — `forensics_dir` lives under `/var/lib/selfdef/forensics`, the
  Velociraptor binary path is set but `velociraptor_args` is empty so
  the action is opt-in even after being added to `allowed_actions`.
- `selfdefctl forensics list` — lists bundle directories in
  `forensics_dir` with per-bundle size.
- `selfdefctl forensics collect <event-id>` — manually triggers a
  forensics bundle for any event already in the hot store. Useful for
  retroactively building evidence on an event that was caught before
  `forensics_bundle` was added to the allowlist.
- Example `config/selfdef.toml.example` extended with both new fields
  and two ready-to-use Velociraptor argv templates (client collect,
  server hunt).
- Integration test `crates/selfdef-daemon/tests/m11_forensics.rs`:
  - **bus → responder → disk**: a synthetic Critical finding published
    onto the bus produces a `forensics_dir/<uuid>/` directory with
    `event.json` (round-trips back to the same event id) and a
    `manifest.txt` that records the `proc/* SKIP` line for the pidless
    event.
  - **dry-run safety**: dry-run on `forensics_bundle` doesn't create
    the target directory.
  - **velociraptor placeholders**: dry-run rendering of
    `velociraptor_escalate` substitutes `{event_id}` and `{host_tag}`
    in every arg.
- Toolchain pin moved from 1.83 to 1.88 to match the edition 2024
  requirement and current dependency MSRVs (notably `time` and the
  `icu_*` chain). The workspace `unsafe_code` lint moved from `forbid`
  to `deny` with a documented carve-out so `selfdef-ebpf-common` can
  still implement `bytemuck::Pod` for ring-buffer record types. The
  ssh-wrap binary added `#![cfg_attr(test, allow(unsafe_code))]` to
  accommodate the Rust 2024 unsafe-`set_var` for its test-only env
  setup.

### Added — Milestone 10 (Custom eBPF programs via aya)
- New crate `selfdef-ebpf-common`: shared `#[repr(C)]` POD types between
  kernel-space BPF programs and the userspace loader. Ships
  `ProcessExecEvent`, `FileOpenEvent`, `UnlinkEvent` with an
  `EventKind` discriminator byte for ring-buffer record dispatch.
  `userspace` feature exposes `bytemuck::Pod` impls and decode helpers
  (`comm_str`, `argv_strings`); `ebpf` feature is `no_std`-compatible
  for the BPF target.
- New crate `selfdef-collector-ebpf`: userspace loader built on aya
  0.13. Loads a precompiled BPF object via `aya::Ebpf::load_file`,
  attaches the `execve_enter` tracepoint to `syscalls/sys_enter_execve`,
  takes ownership of the `EVENTS` ring buffer, wraps it in
  `tokio::io::unix::AsyncFd`, and drains records into OCSF events
  published on the bus.
- **Graceful degradation**: if the BPF object isn't installed at the
  configured `program_path`, the collector logs a warning at startup
  and runs idle. Daemon stays up; other collectors keep working. Same
  daemon binary can ship to hosts with and without eBPF support — config
  drives the difference.
- Kernel-space crate at `bpf/selfdef-bpf/` (intentionally **outside the
  main workspace** with its own `[workspace]` block so
  `cargo build --workspace` never tries to compile it). Ships one
  tracepoint program: `execve_enter`. Captures pid/tgid/ppid/uid/gid/comm
  and emits to a 256 KB ring buffer.
- Build orchestration via `xtask`:
  - `cargo xtask build-bpf [--release]` — compile with nightly
    toolchain, `-Z build-std=core`, target `bpfel-unknown-none`.
  - `cargo xtask install-bpf [<dest>]` — build release + install to
    `/usr/lib/selfdef/selfdef.bpf.o` (or custom path).
- Systemd drop-in `packaging/systemd/selfdefd.service.d/ebpf.conf`:
  grants `CAP_BPF` + `CAP_PERFMON` ambient (no full root needed on
  Linux >= 5.8), raises `LimitMEMLOCK=infinity` for older kernels that
  still account BPF map pages there. Default install keeps the
  capability-light ambient set; you opt-in by installing the drop-in.
- New `[collectors.ebpf]` config section with `enabled`,
  `program_path`, `enable_execve`, `enable_lsm_open` (reserved),
  `enable_kprobe_unlink` (reserved). Daemon wires the collector as a
  task with the same shutdown semantics as the other collectors.
- Documentation `docs/ebpf.md` covering prerequisites (`bpf-linker`,
  nightly toolchain, rust-src), kernel requirements (BTF, ring buffer
  support), capabilities drop-in, troubleshooting, and a clear ledger
  of what's actually shipped versus reserved-for-future-work.
- Integration test `crates/selfdef-daemon/tests/m10_ebpf.rs`:
  - **graceful degradation**: collector runs idle when no BPF object
    exists; shutdown is clean.
  - **event conversion**: `ProcessExecEvent` → OCSF `Event` round-trips
    through the bus into SQLite with correct class/activity/process
    fields. Three synthetic execs (`ls`, `curl`, `sshd`) are decoded,
    published, and asserted. Loading a real BPF program needs CAP_BPF
    + a real kernel + the BPF toolchain — out of scope for `cargo test`
    but documented for manual smoke tests.

### Honest deferrals
- **argv capture from the execve tracepoint.** Reading the user-pointer
  array requires bounded looped `bpf_probe_read_user` calls. The
  infrastructure (buffer in `ProcessExecEvent`, `argv_truncated` flag,
  decode helper, OCSF mapping) is in place; the BPF-side capture lands
  in a follow-up.
- **LSM `file_open` program.** Type reserved in `EventKind::FileOpen`,
  userspace decode path implemented, kernel-side program not yet
  shipped. Requires `CONFIG_BPF_LSM=y` and `bpf` in `CONFIG_LSM`.
- **`kprobe:do_unlinkat` program.** Type reserved as
  `EventKind::Unlink`, userspace decode implemented, kernel-side
  program not yet shipped.
- Stale M1 stub crates (`selfdef-ebpf-types`, `selfdef-ebpf-progs`)
  removed in favor of the M10 layout.

### Added — Milestone 9 (Client-side SSH wrapper)
- New binary crate `selfdef-ssh-wrap` (`selfdef-ssh-wrap`): a drop-in
  replacement for `ssh` that enforces per-host policy and emits OCSF
  events for every session. Designed for fast cold-start (no async
  runtime, no heavy deps).
- argv classifier (`crates/selfdef-ssh-wrap/src/argv.rs`) that
  distinguishes flags, value-taking options (`-o`, `-i`, `-p`, ...),
  attached-value options (`-pPORT`), `--` markers, and positional
  arguments. Extracts the target spec and supports filtering of
  policy-denied flags.
- Policy file (`~/.config/selfdef/ssh-wrap.toml`, override via
  `$SELFDEF_SSH_POLICY`):
  - `[defaults]` with secure baseline: no agent fwd, no X11, no port
    forwarding, `StrictHostKeyChecking=accept-new`,
    `ExitOnForwardFailure=true`, conservative timeouts.
  - `[hosts."<pattern>"]` per-host overrides. Patterns support exact
    match, `*.suffix`, `prefix*`. No regex.
  - Resolved policy is rendered as `-o key=value` ssh args prepended to
    the user's invocation; user-supplied flags conflicting with policy
    are stripped.
- Event emission (`crates/selfdef-ssh-wrap/src/events.rs`): writes OCSF
  events to `~/.local/share/selfdef/ssh-wrap.jsonl` (override via
  `$SELFDEF_SSH_EVENT_LOG`). Three event kinds:
  - **session start** — `SSH_ACTIVITY` / Open, with target, host, port,
    user, and `first_seen` flag (computed via `ssh-keygen -F`).
  - **policy strip** — `DETECTION_FINDING` / Low, lists the args removed
    from the user's invocation.
  - **session end** — `SSH_ACTIVITY` / Close, with duration and exit
    code; status_id reflects success/failure.
- New collector `selfdef-collector-eventstream`: tails a JSONL file of
  pre-formed selfdef events and republishes onto the bus. Used by the
  ssh wrapper and any other producer. Each event must already be a
  well-formed `Event`; malformed lines are logged and skipped.
- `[collectors.eventstream]` config section with `enabled`, `paths`,
  `read_from`.
- Daemon wires N independent eventstream collector tasks (one per path).
- New rule `rules/sigma/defense_evasion/ssh_wrap_policy_strip.yml` +
  tests: catches the wrapper's policy-strip findings as Medium-severity.
  Maps to `attack.defense_evasion`.
- Example policy file `packaging/ssh-wrap-policy.toml.example` with
  annotated defaults and per-host examples.
- Install guide `docs/ssh-wrap-install.md`: PATH-shadowing pattern,
  daemon wiring, caveats (host-key change detection delegated to ssh
  itself, in-session forwarding invisible to the wrapper).
- Integration test `crates/selfdef-daemon/tests/m9_ssh_wrap.rs`
  exercises the JSONL-to-bus-to-SQLite path with three event kinds.

### Added — Milestone 8 (Honeytokens + responder actions)
- New collector `selfdef-collector-canary`: inotify-based watcher that
  emits a `DETECTION_FINDING` with `Severity::Critical` and ATT&CK tag
  `T1552.001` whenever any configured path is read, opened, modified,
  has attributes changed, is deleted, or is moved. Watches are installed
  once at startup; recreating a watched file requires a daemon restart
  (documented limitation).
- Responder rewritten around an [`Action`] trait. Five built-in actions:
  - `notify` — sends through the existing `Notifier` chain.
  - `snapshot_proc` — writes `/proc/<pid>/{cmdline,environ,status,maps,stat,io}`
    plus `exe_link` and `cwd_link` symlink targets to
    `snapshot_dir/<event-uuid>/`. Best-effort: per-file read errors are
    swallowed.
  - `kill_pid` — runs `kill -TERM <pid>`. Pid extracted from
    `event.actor.process.pid` or `event.process.pid`.
  - `lockdown_egress` — invokes a configurable shell script with
    `activate`. Default path `/usr/local/sbin/selfdef-lockdown.sh`. Operator
    owns the nftables logic.
  - `revoke_session` — invokes a configurable script with the user's
    name. Default path `/usr/local/sbin/selfdef-revoke-session.sh`.
- All actions support `dry_run=true` and produce structured `ActionOutcome`
  values (`Success` / `DryRun` / `Skipped`). Failing actions log a warning
  without stopping siblings.
- Responder allowlist: each action's `name()` must appear in
  `responder.allowed_actions` to fire. Default config ships only `notify`
  enabled.
- `selfdefctl panic --confirm <hostname>` is now real:
  - Validates hostname match (prevents accidental fire on the wrong box).
  - Builds a synthetic Critical Finding with `source = "selfdef.panic"`.
  - Dispatches via `Responder::fire` with a 2-action set: `notify` +
    `lockdown_egress`.
  - Respects `responder.dry_run` from config.
- New rule `rules/sigma/credential_access/canary_access.yml` documents
  the canary path in the rule set (and surfaces in ATT&CK coverage).
- New config sections:
  - `[collectors.canary]` with `enabled` and `paths`.
  - `[responder]` extended with `snapshot_dir`, `lockdown_script`,
    `revoke_session_script`.
- Example operator script `packaging/scripts/selfdef-lockdown.sh`
  (annotated nftables-based egress lockdown with lifeline allowlist via
  `$SELFDEF_LIFELINES` env var).
- Integration test `crates/selfdef-daemon/tests/m8_honeytokens.rs`
  exercises the full path: real inotify, real bus, real responder, all
  five actions in dry-run mode. Verifies the canary finding lands in
  SQLite with the expected ATT&CK tag.

### Added — Milestone 7 (Detection-as-code CI)
- Per-rule test files: every rule may have a sibling `<rule>.tests.yaml`
  declaring partial input events and an `expected_findings` count. The
  test runner builds full events from minimal specs, runs each test
  against a single-rule engine, asserts firing counts.
- New crate APIs:
  - `selfdef_correlator::Engine::with_rules(Vec<CompiledRule>)`
    constructor for test isolation.
  - `selfdef_correlator::sigma::AttackCoverage` and
    `Engine::attack_coverage()` — walks loaded rules, returns techniques,
    tactics, and per-tactic rule counts.
  - `selfdef_correlator::lint` module: `lint_rule`, `lint_rules`, `Issue`,
    `Severity`. Checks for missing metadata (description, attack tags,
    technique tag, falsepositives, author), undefined selections in
    conditions, count-by fields that don't look like known event paths,
    duplicate rule IDs across files.
- `Engine::load_dir` now skips `*.tests.yaml` and `*.tests.yml` files
  during rule discovery (those are fixtures, not rules).
- 7 per-rule test files covering the 7 starter rules with 25+ test cases
  total — positive matches, negative matches, logsource gating,
  aggregation thresholds.
- New integration test `crates/selfdef-correlator/tests/rule_tests.rs`
  with three test functions:
  - `every_rule_with_tests_passes` — discovers and runs all per-rule
    fixtures, fails the build on any mismatch.
  - `rule_set_passes_lint` — fails on lint errors, surfaces warnings.
  - `attack_coverage_report` — prints the coverage matrix; fails if zero
    techniques covered.
- `selfdefctl rules lint` — runs lint with exit code 1 on errors.
- `selfdefctl rules coverage` — prints the ATT&CK coverage matrix.
- Adversary emulation directory at `tests/adversary/` with documented
  layout and `T1110.001-password-guessing/` as the first technique
  (atomic.yaml in ART format + expected.yaml contract). Full ART runner
  integration deferred to a future milestone (needs a VM/container
  sandbox to be safe in CI).

### Added — Milestone 6 (Collector fan-out)
- `selfdef-collector-journald`: real implementation. Two input modes
  selected by config (`mode = "journalctl"` or `"file"`):
  - **subprocess** spawns `journalctl --output=json --follow --no-pager`,
    optionally with `-u <unit>` filters from `collectors.journald.units`.
  - **file** tails a JSON-lines file (for tests / external pipelines).
  Maps `sshd` to `SSH_ACTIVITY`, `sudo` to `AUTHENTICATION`,
  `systemd-logind` to `AUTHORIZE_SESSION`; everything else generic.
  Priority → severity mapping (`PRIORITY=3` → High, `=4` → Medium, etc.).
- `selfdef-collector-tetragon`: real implementation. Tails Tetragon JSON
  output. Recognizes `process_exec` (→ `PROCESS_ACTIVITY`/Launch),
  `process_kprobe` with `security_file_open`-style functions
  (→ `FILE_SYSTEM_ACTIVITY`/Open with `file.path` extracted from kprobe
  args), `process_exit` (→ Terminate). Other event kinds preserve their
  raw payload.
- `selfdef-collector-suricata`: real implementation. Tails Suricata EVE
  JSON. **Alerts become `DETECTION_FINDING` directly** — Suricata is itself
  detection, so its alerts go straight to the responder. Suricata severity
  inverted to OCSF (1→High, 2→Medium, 3→Low). DNS/HTTP/TLS/flow records
  emit as informational network-class events that Sigma rules can match.
- `selfdef-config`: new `[collectors.journald]`, `[collectors.tetragon]`,
  `[collectors.suricata]` sections with typed config.
- `selfdef-daemon`: wires all three new collectors. Each enabled via its
  `enabled` flag in config; each runs as its own task with shared
  `CancellationToken` for graceful shutdown.
- New rules:
  - `rules/sigma/discovery/sshd_publickey_accepted.yml` — uses the journald
    collector; informational baseline for SSH key logins.
  - `rules/sigma/execution/webshell_pattern.yml` — uses the tetragon
    collector; detects shells spawned from nginx/apache/php-fpm parents.
- New replay corpora:
  - `tests/replay/journald/sshd_login.jsonl`
  - `tests/replay/tetragon/sensitive_file.jsonl`
  - `tests/replay/suricata/scan_alert.jsonl`
- Integration test `crates/selfdef-daemon/tests/m6_collectors.rs`:
  - journald file-mode emits classified events
  - tetragon replay emits typed events with the right class_uid
  - suricata alert lands in SQLite as a DETECTION_FINDING

### Deferred to a polish milestone
- Multi-line auditd record grouping (SYSCALL + PATH + EXECVE + EOE). The
  current M3 parser handles each line standalone, which covers the
  user-auth records selfdef cares most about today. Multi-line grouping
  is real parser work that deserves its own milestone.

### Added — Milestone 5 (Sigma engine + hot reload)
- `selfdef-correlator::sigma`: Sigma-subset rule engine. Parses YAML rules
  with metadata (`id`, `title`, `description`, `level`, `tags`, `references`,
  `falsepositives`, `author`, `date`), `logsource`, named `selection_*`
  blocks, optional `timeframe`, and `condition` strings of the form
  `<sel>` or `<sel> | count() by <field> > <N>`.
- Field matchers: equality, `|contains`, `|startswith`, `|endswith`, `|re`
  (regex). List of values within a field = OR. Dot-notation for nested
  fields (`src_endpoint.ip`, `actor.user.name`).
- `Aggregator` for time-windowed counting; clears window on fire to
  prevent re-firing on the same burst.
- ATT&CK overlay: `attack.t1234[.567]` tags → technique IDs;
  `attack.<tactic>` tags → tactic enum; both flow into the emitted finding's
  `attack` array.
- `Correlator` now loads rules from a directory; `load_rules()` is
  idempotent and atomically swaps the engine on success (failure preserves
  the previous ruleset). Backed by `Arc<RwLock<Arc<Engine>>>` so reads
  don't block reloads.
- `selfdef-daemon`: SIGHUP triggers `correlator.load_rules()`. `selfdefd`
  keeps running across reloads; `systemctl reload selfdefd` works (the unit
  already had `ExecReload=/bin/kill -HUP $MAINPID`).
- 5 initial rules in `rules/sigma/`:
  - `credential_access/ssh_bruteforce.yml` — replaces the M4 hardcoded rule.
  - `credential_access/sensitive_file_access.yml` — `/etc/shadow`, `/root/.ssh/`,
    etc. (logsource: tetragon; waits for the tetragon collector).
  - `privilege_escalation/sudo_failure.yml` — failed sudo PAM auth.
  - `persistence/sudoers_tamper.yml` — writes to `/etc/sudoers*`.
  - `persistence/setuid_binary.yml` — new files with setuid/setgid bits.
- Replay corpus: `tests/replay/auditd/ssh_bruteforce.jsonl` (4 events) +
  `ssh_bruteforce.expected.yaml` (expected firings).
- `selfdefctl` implements `rules list`, `rules validate <path>`,
  `rules test --corpus <jsonl>`.
- New integration test `crates/selfdef-daemon/tests/m5_sigma.rs`:
  - engine loads N rules from a directory
  - engine ignores non-YAML files
  - replay corpus produces the expected firing count
  - hot reload picks up new rules in-place
- M4 test updated to use the YAML rule via a tempdir rules directory
  instead of the now-removed `Correlator::new(window, threshold)` API.
- New workspace deps: `serde_yml` (maintained fork of `serde_yaml`), `regex`.

### Added — Milestone 4 (Alert path)
- `selfdef-notifier`: `Notifier` trait, `NtfyNotifier` (HTTP POST to a
  self-hosted ntfy server with optional bearer token, 3-attempt backoff),
  `SignalCliNotifier` (subprocess to `signal-cli`), `NotifierChain` that
  tries channels in order. Severity → ntfy priority mapping. Title/body
  rendering helpers `render_title`/`render_body`. Tags include ATT&CK
  technique IDs.
- `selfdef-correlator`: subscribes to the bus, processes events through a
  built-in `SshBruteforceRule` (≥ N failed auths from the same source IP
  within W seconds → emit a Detection Finding). Configurable window and
  threshold. Loop guard: Findings-class events are never reprocessed.
- `selfdef-responder`: subscribes to the bus, watches for Findings-class
  events, executes the `notify` action through the configured notifier
  chain. Allowlist enforcement (`allowed_actions`) and `dry_run` mode.
- `selfdef-core`: added `ClassUid::SECURITY_FINDING` (2001),
  `DETECTION_FINDING` (2004), `INCIDENT_FINDING` (2005) constants.
- `selfdef-config`: added `[correlator]`, `[notifier]` (with `[notifier.ntfy]`,
  `[notifier.signal]` subsections), and `[responder]` config sections.
- `selfdef-store`: `recent_findings(limit)` helper for the CLI alerts view.
- `selfdef-daemon`: M4 wiring — correlator + responder spawned alongside
  the store sink, each as an independent bus subscriber.
- `selfdef-cli`: `events alerts -n N [--json]` subcommand for tailing
  findings.
- Integration test `crates/selfdef-daemon/tests/m4_alert.rs` proves the
  full path: 3 failed-auth lines → wiremock-mocked ntfy server receives
  exactly one POST with `Priority: 5`.
- Workspace lints: dropped `unwrap_used`, `expect_used`, `panic` from the
  default warn set — too noisy in test code; `clippy::pedantic` still
  catches real issues.

### Added — Milestone 3 (First spine)
- `selfdef-config`: Figment-based layered config loader (defaults → TOML →
  `SELFDEF_*` env vars). Typed `Config`, `DaemonConfig`, `BusConfig`,
  `StoreConfig`, `CollectorsConfig`, `AuditdConfig`.
- `selfdef-bus`: in-proc broadcast bus over `tokio::sync::broadcast`.
  `Bus`, `Publisher` (Clone), `Subscriber`, `BusError`. Tests for
  publish/subscribe ordering, fan-out, and lagged subscriber detection.
- `selfdef-store`: `SqliteStore` with WAL mode, `synchronous=NORMAL`,
  hand-rolled migrations driven by `user_version`. Async API via
  `spawn_blocking`. Operations: `open`, `insert`, `count`, `recent`, `get`.
  Migration `0001_initial.sql` defines the indexed `events` table.
- `selfdef-collector-auditd`: line parser for `USER_AUTH`, `USER_LOGIN`,
  `USER_ACCT` (mapped to `ClassUid::AUTHENTICATION` with correct
  `status_id`, ATT&CK technique tagging on failure). Unknown record types
  emitted as generic events with raw payload preserved. File tailer with
  `ReadFrom::{Start, End}` modes and graceful shutdown via `CancellationToken`.
- `selfdef-daemon`: real entry point — loads config, opens store, builds bus,
  spawns the auditd collector + a store sink task, waits for SIGTERM/SIGINT,
  drains the bus, reports counts on exit.
- `selfdef-cli`: `status` (event count + store path), `events tail [-n N] [--json]`
  reading the SQLite store directly.
- Integration test `crates/selfdef-daemon/tests/m3_pipeline.rs` proves the
  end-to-end loop: 4 canned audit lines → collector → bus → sink → SQLite,
  with assertions on classification, severity, and ATT&CK tagging.

### Added — Milestone 2 (Event envelope)
- `selfdef-core` restructured into focused modules: `envelope`, `category`,
  `activity`, `severity`, `status`, `attack`, `metadata`, `observable/*`,
  `error`, `prelude`.
- OCSF-aligned `Event` envelope with: `schema`, `id` (UUIDv7), `time_dt`
  (RFC3339), `category_uid`, `class_uid`, `activity_id`, `type_uid`,
  `severity_id`, `status_id`, `host_tag`, `source`, `message`, `metadata`,
  `raw`, plus optional typed observables.
- Typed observables: `Actor`, `User`, `Process`, `Session`, `File`,
  `FileType`, `Hash`, `HashAlgorithm`, `Endpoint`, `NetworkConnection`,
  `Direction`.
- MITRE ATT&CK overlay: `Tactic` enum with stable `TA*` IDs,
  `TechniqueRef` with convenience constructors.
- `Metadata` block with `Product`, `logged_time_dt`, `sequence`, `profiles`.
- Builder methods on `Event` (`with_status`, `with_actor`, ...).
- `Event::validate()` invariant check.
- 6 inline unit tests + insta snapshot tests for 4 canonical event shapes
  + proptest properties for round-trip, type_uid, category, validation.
- `SCHEMA_VERSION` bumped from 0 (placeholder) to 1 (first real schema).
- Daemon logs schema version on startup; `selfdefctl version` displays it.

### Added — Milestone 1 (Foundation)
- Cargo workspace with 13 crates.
- Pinned Rust toolchain, lint policy, `cargo-deny` config.
- Hardened systemd unit, AppArmor profile, Debian packaging metadata.
- CI workflow skeleton (fmt, clippy, test, deny, audit, build).
- Documentation skeleton (mdbook), architecture and security threat model.
- Example configuration.
