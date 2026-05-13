# Integration audit — flows across the system

> Scope: every cross-cutting flow where data crosses a crate or
> module boundary. Per-area finding ids prefix `I-`.

This is the audit that surfaced the most severe gaps. The
per-crate review (`20-crate-audit.md`) confirms every crate is
*reachable* — the daemon spawns every collector, every notifier
is config-driven, every API endpoint has a handler. But
**reachable is not the same as integrated**. Several of the
module-side defaults assume a daemon configuration that the
daemon does not ship with, and one collector silently strips the
information another module relies on.

The most serious cluster of findings is around the AI-machine
track (`agent-guard` → `selfdef-collector-tetragon` →
correlator → responder). Read the Flow 4 section carefully — it
documents an end-to-end promise that does not hold today.

---

## Flow 1 — drift event reaches a notifier

`integrity-sentinel`'s apply detects drift → calls
`selfdefctl events emit` → writes a JSON line to a JSONL stream
→ daemon's eventstream collector tails it → publishes onto bus →
responder dispatches → ntfy / Signal fires.

### Boundary 1.1 — module's `event_stream_path` is commented out by default

`modules/integrity-sentinel/profiles/strict.toml` (and the
`warn-only` variant) ship with `event_stream_path` commented:

```
# event_stream_path     = "/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"
```

An operator who copies the profile unmodified gets a module
that detects drift but never emits an event. **(I-001)**

### Boundary 1.2 — daemon's `[collectors.eventstream].paths` defaults to `[]`

`selfdef-config/src/lib.rs:292-298` `EventstreamConfig::default`
ships `paths: Vec<PathBuf>::new()`. Even if the operator
uncomments `event_stream_path`, nothing reads the JSONL file
unless they *also* add the path to the daemon config's
eventstream collector. **(I-002)**

There is no documented coupling between the module's
`event_stream_path` and the daemon's `[collectors.eventstream].paths`.
README mentions the second step in passing; nothing enforces it.

### Boundary 1.3 — `selfdefctl events emit` has no default output path

`crates/selfdef-cli/src/main.rs` declares `--out: PathBuf` as a
required (no-default) argument. Every caller must hard-code the
path. So if the module's default path diverges from the daemon's
configured tail path, events go to a file no collector reads.
**(I-003)**

The downstream of these three boundaries is fine: the collector
parses lines, publishes to the bus, the responder routes
findings (`category_uid == 2`) through `NotifyAction`. The
breakage is entirely in the upstream defaults not aligning.

---

## Flow 2 — Prometheus scrape reaches `/metrics`

Prometheus (scrape config) → daemon API `/metrics` →
`handlers::metrics` → renders counters + live `store.count()`.

### Boundary 2.1 — API disabled by default; observability assumes :8443

- `selfdef-config/src/lib.rs ApiConfig::default`:
  `enabled: false`, `tcp_addr: ""`.
- `modules/observability/profiles/bundled.toml`:
  `scrape_targets = "localhost:2112, localhost:8443"`.

A bundled-profile install renders a Prometheus scrape config
targeting `localhost:8443`, but the daemon never binds that port
unless the operator opts in. **(I-004)**

### Boundary 2.2 — bearer-token auth on TCP is undocumented for Prometheus

`crates/selfdef-api/src/transport.rs:151-166` requires
`Authorization: Bearer <token>` on every TCP request. Prometheus
supports this via `bearer_token` / `bearer_token_file` in scrape
config — but `modules/observability/README.md` doesn't explain
this. A naive operator who enables the API and points Prometheus
at it gets uniform 401s. **(I-005)**

### Boundary 2.3 — `scrape_targets` default disagrees with itself

The drift on `scrape_targets` already flagged as M-005 in the
module audit (README says single target; both profiles + apply.sh
disagree on the default value). Cross-listed here because the
fix lives at the integration layer.

---

## Flow 3 — Tetragon → daemon

`tetragon` module configures Tetragon → Tetragon writes
`/var/log/tetragon/events.json` → daemon ingests.

### Boundary 3.1 — wrong collector named in the module README

`modules/tetragon/README.md` and the default profile's comment
say:

> The selfdef daemon's `[collectors.eventstream]` block should
> include this path so events flow onto the bus.

This is **wrong**. Tetragon's native JSON format is not the
selfdef-Event format; it cannot be parsed by the eventstream
collector. The correct collector is `[collectors.tetragon]`,
backed by `selfdef-collector-tetragon`, which parses Tetragon's
format and translates it into `selfdef_core::Event`.

`selfdef-config/src/lib.rs:249-263` `TetragonConfig::default`
ships `enabled: false, input_path: /var/log/tetragon/events.json`.
So the path is right; the **collector to enable is wrong** in
the module README. **(I-006)**

An operator following the tetragon README adds the path to the
eventstream collector's `paths`, where each line fails serde
parsing as `selfdef_core::Event` and is dropped silently
(`selfdef-collector-eventstream/src/lib.rs:94-95` logs at
`debug` only). The host appears to be running tetragon but no
events reach the daemon's bus.

This is the single most consequential integration defect found in
the audit.

---

## Flow 4 — agent-guard violation reaches the operator

`agent-guard` policy fires (Tetragon Sigkill) → tetragon collector
emits event → bus → correlator → responder if it's a finding →
notifier chain → operator alert.

### Boundary 4.1 — Tetragon collector hardcodes severity = Informational

`crates/selfdef-collector-tetragon/src/lib.rs` builds every
event with `SeverityId::Informational` (multiple call sites:
roughly lines 173, 220, 249, 261 per the agent report). The
policy YAML annotates `selfdef.io/severity: "high"`, but the
collector does **not** read the annotation. Every Tetragon
event — Post or Sigkill, etc-write or egress — surfaces as
`Informational`. **(I-007)**

### Boundary 4.2 — no correlator rule promotes Tetragon → Finding

`rules/sigma/` has rules for several patterns (webshell exec,
ssh brute-force, etc.) but none specifically promote
agent-guard's Tetragon events to findings.
`category_uid` of those events is 1 (System Activity) /
1007 (Process Activity) — the responder's
`category_uid == Findings` (2) filter never matches. **(I-008)**

### End-to-end consequence

The AI-machine track's central operator promise — "the agent
violated the host's policy, you'll get a Signal ping" — is **not
plumbed end-to-end today**. Every step from the kernel to the
bus works; from the bus onward to a notifier there is no path
unless the operator writes a custom sigma rule and the collector
is patched to honour policy severity annotations.

The mitigation work belongs in a Phase-2 design doc. Two parallel
tracks:
- Patch the collector to honour Tetragon event metadata
  (`severity`, `attack`, `policy_name`) and produce
  `class_uid = DETECTION_FINDING` for matched policies.
- OR ship a sigma rule under `rules/sigma/hardening/` that
  promotes any Tetragon event with `source = "agent-guard:*"`
  to a High-severity Detection Finding.

Either is fine; both is better. Neither exists today.

---

## Flow 5 — NATS multi-host

Host A publishes → broker → host B subscribes → bus → responder.

The crate audit (C-section) and the integration agent both
verified that:

- `selfdef-config/src/lib.rs:143-153` exposes every JetStream
  knob (`enabled`, `stream_name`, `durable_consumer_prefix`,
  `max_age_secs`, `max_bytes`, `max_msgs`).
- `selfdef-daemon/src/main.rs:190-200` translates every field
  one-to-one into `selfdef_nats::JetStreamConfig`.
- `selfdef-nats/src/lib.rs:200-205` branches on `enabled` and
  drives durable consumer creation.
- Loop avoidance (inbound `host_tag` filter) operates on every
  republished message.

No findings on this flow.

---

## Flow 6 — `selfdefctl modules apply`

CLI resolves catalog + host config → topo sort by phase +
`depends_on` → spawn each module's `apply.sh` → aggregate
structured-status.

The crate audit (C-section) confirmed the topo sort, phase
ordering, dry-run propagation (`SELFDEF_DRY_RUN`), and instance
suffix logic all behave. The module audit (`30-`) flagged the
vpn-bridge multi-instance corruption (M-008) — that is a module
defect, not a lifecycle-runner defect. No new findings here.

---

## Cross-flow systemic issues

### Default-config alignment

The daemon defaults to *every collector disabled* (`enabled =
false` across the board). Modules ship defaults that *assume the
daemon has certain collectors and the API turned on*:

- `integrity-sentinel` assumes `[collectors.eventstream]` is
  enabled with its path in `.paths`.
- `tetragon` assumes `[collectors.tetragon]` is enabled (and
  README points at the wrong collector — see I-006).
- `observability` assumes `[api] enabled = true, tcp_addr =
  "127.0.0.1:8443"`.

There is **no bundled `selfdef.toml` template** that an operator
can copy to `/etc/selfdef/selfdef.toml` to get a working
three-module deployment. The `packaging/` dir ships a default
config (probably — needs Phase-2 verification) but the modules
that depend on its content have no automated check. **(I-009)**

### Auth coherence

Module READMEs do not consistently document which surfaces are
auth-gated. Observability assumes Prometheus can scrape without
auth, but the daemon API requires bearer tokens. Either the
default scrape target should be a UNIX socket (which Prometheus
can reach with a sidecar), or the README must walk the operator
through the token setup. **(I-005, restated)**

### Schema coherence

The `Event` envelope is referenced via `selfdef_core::Event`
everywhere except `selfdef-store/sqlite.rs:106` which hardcodes
`const SCHEMA_VERSION: u32 = 1`. The store-level value
coincidentally matches the core value today; a future bump in
core would leave the store's migration check stale and silent.
Cross-listed from C-005.

---

## Findings raised in this section

| Id | Severity | Surface | Summary |
| --- | --- | --- | --- |
| I-001 | important | `modules/integrity-sentinel/profiles/*.toml` | `event_stream_path` commented out in the shipped profile — drift events are silent until an operator hand-edits the host config. |
| I-002 | blocker | `selfdef-config EventstreamConfig::default` | Daemon's eventstream `paths` defaults to `[]`. Any JSON written by a module emitter (integrity-sentinel today, future emitters tomorrow) is never tailed unless the operator manually wires both sides. |
| I-003 | nice | `selfdefctl events emit` | `--out` has no default. Callers must know the daemon's config to choose a path. Reasonable for a one-shot CLI; tracked for a future "agree on a default per-module emission directory" SDD. |
| I-004 | blocker | `selfdef-config ApiConfig::default` vs `modules/observability/profiles/bundled.toml` | Observability scrape config targets `localhost:8443`; daemon API defaults to disabled with empty `tcp_addr`. Out-of-the-box, Prometheus cannot reach the daemon. |
| I-005 | important | `modules/observability/README.md` | Bearer-token auth on TCP `/metrics` is required by the API but undocumented in the observability operator guide. Scrapes will 401. |
| I-006 | blocker | `modules/tetragon/README.md` + `modules/tetragon/profiles/default.toml` (comment) | README tells the operator to add Tetragon's `events.json` to `[collectors.eventstream]`, which silently drops every line. The correct collector is `[collectors.tetragon]`. |
| I-007 | blocker | `crates/selfdef-collector-tetragon/src/lib.rs` | Every Tetragon-derived event surfaces as `SeverityId::Informational`. The policy YAML's `selfdef.io/severity` annotation is ignored. Agent-guard `enforce` profile produces Sigkill on the kernel side but the daemon sees an Informational Process Activity event. |
| I-008 | blocker | `rules/sigma/` | No sigma rule promotes Tetragon agent-guard violations to `category_uid = 2 (Findings)`. The responder therefore never runs `NotifyAction` for them; the operator never gets the alert the module README promises. |
| I-009 | important | repo-wide (`packaging/` + module READMEs) | No bundled `selfdef.toml` template covers the "three modules with sane defaults" scenario. Operators stitch together collectors / API / eventstream paths manually. |
