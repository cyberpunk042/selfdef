# SDD-001 — AI-machine track, end-to-end

> Status: draft
> Owner: audit team
> Last updated: 2026-05-13
> Closes findings: F-2026-001, F-2026-002, F-2026-003, F-2026-006

## Problem

The AI-machine track (`tetragon` substrate + `agent-guard`
policies + `observability` dashboard) ships with a documented
operator promise: "when an agent in a container violates
host policy, the operator gets an alert through the existing
notifier chain (ntfy / Signal)." That promise is **not
plumbed end-to-end today**.

Three breakages, each a Phase 1 blocker:

- **F-2026-001** — `selfdef-collector-tetragon` hard-codes
  `SeverityId::Informational` for every Tetragon-derived event
  (`crates/selfdef-collector-tetragon/src/lib.rs:173, 220, 249,
  261`). The policy YAML annotation `selfdef.io/severity:
  "high"` is silently ignored.
- **F-2026-002** — `rules/sigma/` carries no rule that
  promotes Tetragon agent-guard events to `category_uid =
  Findings (2)`. The responder filters on `category_uid ==
  Findings` (`crates/selfdef-responder/src/lib.rs:122`), so a
  Tetragon event with `class_uid = 1007 (Process Activity)` or
  `class_uid = 1001 (File System Activity)` never reaches
  `NotifyAction`.
- **F-2026-003** — `modules/tetragon/README.md` and the default
  profile's comment tell the operator to add Tetragon's
  `events.json` to the `[collectors.eventstream]` paths list,
  which silently fails to parse it as `selfdef_core::Event`.
  The correct collector is `[collectors.tetragon]`.

The end-to-end impact: an agent-guard policy with `action:
Sigkill` does terminate the offending process kernel-side
(Tetragon's eBPF half works). The corresponding event reaches
the daemon's bus (when the correct collector is enabled), but
it surfaces as an `Informational` `Process Activity` event,
the correlator never tags it as a finding, the responder never
runs `NotifyAction`, and the operator never gets a ping.

The Phase-1 audit also flagged **F-2026-006**: no daemon-side
integration test would have caught any of the three above.
Phase 3 implementations must close this gap too, so a future
regression on the same axis is impossible to silently land.

## Goals

1. A Tetragon TracingPolicy violation (Sigkill or Post) from an
   `agent-guard` policy surfaces as a Detection Finding
   (`category_uid = 2`, `class_uid = 2004`) on the daemon's
   bus, with severity derived from the policy's
   `selfdef.io/severity` annotation.
2. The responder's existing notifier-chain dispatch fires
   without modification when the finding lands.
3. The contract between the policy YAML (severity, attack id,
   policy_name convention) and the correlator / collector is
   written down and testable. Operators authoring new policies
   know what the contract gives them.
4. `modules/tetragon/README.md` correctly names
   `[collectors.tetragon]`, with a config snippet that an
   operator can paste into `/etc/selfdef/selfdef.toml`.
5. One daemon integration test fires a Tetragon-shaped event,
   asserts a finding lands in the store with severity High,
   asserts the responder dispatched `NotifyAction`.

## Non-goals

- No changes to Tetragon's own configuration grammar. The
  policy YAML annotations we rely on are already shipped.
- No new collector. The existing
  `selfdef-collector-tetragon` is the implementation surface.
- No new responder action. The existing notifier chain is the
  output surface.
- No multi-host coverage. NATS bridge propagation works today
  for findings — it'll work for these findings too without
  changes.
- No GPU / k8s-specific design beyond what `agent-guard`
  already ships. Pod-label scope and GPU device guard are
  already in the bundle; this SDD makes them *useful*, not
  more capable.
- No backport to old policy YAMLs. The annotation contract is
  forward-only: agent-guard's shipped policies already use it.

## Glossary

- **TracingPolicy** — a Cilium / Tetragon YAML rule loaded into
  the kernel via Tetragon's policy directory.
- **policy annotation** — a `metadata.annotations.<key>: <value>`
  field on a TracingPolicy. Tetragon copies these into the
  event JSON it emits.
- **selfdef-Event** — the OCSF-aligned envelope defined in
  `selfdef-core::Event`. The format every collector translates
  *into*.
- **finding** — a selfdef-Event with `category_uid = 2`
  (Findings). The responder's notifier dispatch is gated on
  this filter.
- **severity mapping** — the function from a Tetragon policy
  annotation to a `selfdef_core::severity::SeverityId`.

## Current state

### 1. Tetragon emits the data we need

A `process_kprobe` event from a TracingPolicy carries:

```json
{
  "process_kprobe": {
    "policy_name": "selfdef-agent-etc-write-guard",
    "policy_namespace": "",
    "function_name": "security_file_open",
    "action": "Sigkill",
    "args": [...],
    "process": {...}
  },
  "node_name": "...",
  "time": "..."
}
```

The `policy_name` is the value of `metadata.name` in the
TracingPolicy YAML (`agent-guard` ships the
`selfdef-agent-<policy-slug>` naming convention). The `action`
field reflects what Tetragon actually took. **The
`metadata.annotations` block is NOT echoed into the event
JSON** by upstream Tetragon today; operators have to either
encode severity in `policy_name` or look it up server-side.

### 2. The collector parses what it sees

`crates/selfdef-collector-tetragon/src/lib.rs:183-243` builds a
selfdef-Event from a `process_kprobe`:

- `function_name` chooses `(class_uid, activity_id)`:
  file_open / inode → File System Activity (1001) Open (14);
  socket / connect → Network Activity (4001) Open (1);
  else → Kernel Activity (1003) Unknown (0).
- `file_arg.path` lands on `Event.file`.
- `process` lands on `Event.process`.
- `severity_id` is hard-coded `Informational`.
- The whole Tetragon JSON is preserved on `Event.raw`.

`policy_name` and `action` are present in `Event.raw` but
nowhere structured.

### 3. The responder routes on category_uid

`crates/selfdef-responder/src/lib.rs:122`:

```rust
Ok(event) if event.category_uid == CategoryUid::Findings => {
    self.handle_finding(&event).await;
}
```

Only category-2 events dispatch actions. Process / Filesystem
/ Network / Kernel Activity events (categories 1 / 4) pass
through, are written to the store via the sink task, and
that's it.

### 4. Sigma rules can promote, but none does

The correlator (`crates/selfdef-correlator/src/lib.rs:93-107`)
runs every event through the Sigma engine and publishes any
findings back onto the bus. The shipped sigma rules
(`rules/sigma/<tactic>/*.yml`) match on `raw.<field>` paths
into the event payload (the SSH rule in
`rules/sigma/credential_access/ssh_bruteforce.yml` is the
canonical example). There's no rule today scoped to
`tetragon`-source events promoting them to findings.

### 5. The README points at the wrong collector

`modules/tetragon/README.md` includes:

> The selfdef daemon's `[collectors.eventstream]` block should
> include this path so events flow onto the bus.

`crates/selfdef-config/src/lib.rs` exposes both
`[collectors.tetragon]` (`TetragonConfig`, defaults to
disabled, with `input_path = /var/log/tetragon/events.json`)
and `[collectors.eventstream]` (`EventstreamConfig`, defaults
to disabled with `paths = []`). The eventstream collector
parses lines as `selfdef_core::Event` and logs at debug if
they don't deserialize; a Tetragon-format line drops silently.

## Design alternatives considered

### Alternative A — Severity mapping in the collector

Have `selfdef-collector-tetragon` read the on-disk
TracingPolicy YAML files at startup, build a map from
`policy_name` → `(severity, attack_id, class_uid_override)`,
and apply it when building events. Promote events from
`agent-guard` policies to `class_uid = 2004 (Detection
Finding)` directly.

**Pros**

- Single place to change. Operators don't need to also touch
  the correlator rule set.
- The collector already has structured context; severity is
  derivable per event.
- No new bus traffic — the event arrives once, fully shaped.

**Cons**

- The collector takes on a *meaning* responsibility ("this is a
  finding"). Up to now collectors are dumb translators.
  Crossing that line spreads correlation logic into multiple
  places.
- The collector must reload the policy map on TracingPolicy
  directory changes (Tetragon already watches the dir; the
  collector would need its own watcher or a SIGHUP).
- If a policy YAML is malformed, the collector silently
  drops the mapping for that policy. Failure modes spread.
- Doesn't generalise: tomorrow's `host-hardening-guard` would
  need the same code path.

### Alternative B — Severity mapping in a sigma rule

Ship a sigma rule under `rules/sigma/hardening/` that matches
Tetragon `process_kprobe` events whose
`raw.process_kprobe.policy_name` matches a `selfdef-agent-*`
prefix (or carries the annotations encoded in `policy_name`).
The rule emits a Detection Finding with the configured
severity.

**Pros**

- Correlation logic lives in one place (sigma rules + the
  correlator). The collector stays dumb.
- Operators authoring new policy bundles ship a sigma rule
  alongside; the contract is uniform across modules.
- Sigma rules are reload-safe via SIGHUP today.
- A single rule covers every `agent-guard` policy (and any
  future `selfdef-agent-*`).

**Cons**

- The Tetragon event's `policy_name` carries the
  annotation-encoded severity only if `agent-guard` puts it
  there. Pure naming convention is brittle.
- Sigma matching on substrings + raw-path syntax requires
  careful regex / startswith authorship.
- Severity must be encoded somewhere visible to the rule —
  either the `policy_name` itself or a runtime lookup. We
  haven't built the runtime lookup.

### Alternative C — Hybrid (annotation passthrough + sigma promotion)

Two-stage:

1. Patch the collector to copy the Tetragon event's
   `process_kprobe.action`, `process_kprobe.policy_name`, and
   (if/when upstream supports it) `process_kprobe.annotations`
   into structured fields on the selfdef-Event. The Event
   still has `class_uid = 1001 (File System Activity)` etc;
   severity stays Informational at the collector layer.
2. Ship a sigma rule keyed on `raw.process_kprobe.policy_name`
   matching `selfdef-agent-*`, emitting a Detection Finding
   with severity derived either from the policy_name encoding
   or from a per-rule literal.

**Pros**

- Collector responsibility stays narrow: parse JSON, extract
  fields, no meaning.
- Promotion logic stays in sigma rules — operator-editable,
  reload-safe.
- A future server-side severity lookup (read the YAML from
  disk) can land as a sigma-rule modifier without touching the
  collector.

**Cons**

- Two PRs, not one. Collector PR + sigma rule PR.
- Without upstream annotation passthrough, encoding severity
  via `policy_name` substrings is still a convention the
  policy author maintains by hand.

## Recommended design

**Alternative C** — hybrid. Collector becomes more structured;
correlator decides what's a finding. Reasoning:

- Keeps the existing "collectors are dumb translators"
  invariant (a virtue the audit captured under SDD-debt:
  collectors that take on meaning duplicate correlator work).
- Promotion lives where reload is already solved (SIGHUP rule
  reload).
- The same pattern serves future Tetragon-using modules
  (`host-hardening-guard`, k8s-admin-guard) without churning
  the collector.

## Detailed design

### D-1 Collector field extraction

Patch `selfdef-collector-tetragon` to attach structured
Tetragon-specific fields onto every event built from a
`process_kprobe`. Today the only structured destinations are
`Event.process`, `Event.file`, `Event.network`. Tetragon
fields go on a new optional struct on the Event envelope.

**Decision**: do **not** add a new top-level field to
`selfdef_core::Event` (that's a schema bump). Instead, add a
flat helper `Event::with_label(key, value)` semantically
equivalent to attaching a (key, value) pair to a future
`Event.labels: BTreeMap<String, String>` field.

Wait — that *is* a schema bump. Two options without bumping
schema:

- **Sub-option D-1a**: Use the existing `Event.attack: Vec<TechniqueRef>`
  field. `TechniqueRef` is already present and carries a
  string. Tetragon's annotation `selfdef.io/attack:
  "T1565.001"` lands as a `TechniqueRef`. **Severity** is the
  field we still can't carry without a schema bump unless we
  encode it in the policy_name.
- **Sub-option D-1b**: Stuff structured Tetragon fields into
  the `Event.raw` blob, with a stable shape:
  `Event.raw.tetragon = { policy_name, action, severity, ... }`.
  The sigma rule reads `raw.tetragon.policy_name` etc. This is
  what the existing sigma rules already do (`raw.<field>`
  matching), so the syntax is familiar.

**Recommendation for D-1**: D-1b. No schema change. The
collector adds a `tetragon` key under `Event.raw`:

```json
"raw": {
  "tetragon": {
    "policy_name": "selfdef-agent-etc-write-guard",
    "policy_namespace": "",
    "action": "Sigkill",
    "function_name": "security_file_open"
  },
  ... (original Tetragon JSON also preserved)
}
```

Implementation: in
`crates/selfdef-collector-tetragon/src/lib.rs build_process_kprobe`,
after building the `Event`, attach a `tetragon` key to the
`raw` value via `with_raw(modified_value)`. Keep
`severity_id = Informational` at the collector layer;
promotion is the correlator's job.

The schema version stays at `1`. Sigma rules access the new
fields via dot-notation as they do today.

Future extension (when upstream Tetragon passes annotations in
events): `raw.tetragon.severity` becomes populated server-side
and the sigma rule can match on it directly. Until then,
severity is encoded by the rule.

### D-2 Sigma rule for promotion

Ship a new rule:
`rules/sigma/hardening/agent_guard_violation.yml`

Skeleton:

```yaml
title: agent-guard policy violation
id: <new-uuid>
status: stable
description: |
  Promotes Tetragon TracingPolicy violations from the
  `agent-guard` module bundle into Detection Findings.
  Severity follows the policy_name convention: any policy
  whose name starts with `selfdef-agent-` is treated as High;
  a future rule can split by specific policy_name for finer
  severity control.
references:
  - https://tetragon.io/docs/concepts/tracing-policy/
  - SDD-001
author: selfdef
date: 2026-05-13
tags:
  - attack.t1565.001
logsource:
  service: tetragon
detection:
  agent_guard_action:
    raw.tetragon.policy_name|startswith: "selfdef-agent-"
    raw.tetragon.action|in:
      - "Sigkill"
      - "Override"
      - "NotifyKiller"
  condition: agent_guard_action
level: high
falsepositives:
  - Operator manually testing agent-guard policies during
    bring-up. Use `audit` profile (action = Post) to suppress.
```

`action|in` includes `Sigkill`, `Override`, `NotifyKiller`
(the action types Tetragon supports that imply the policy
intervened). `Post` (the audit-profile default) is
intentionally NOT in the list — audit-profile applications
should not page operators.

A second rule, `agent_guard_observed.yml`, scopes
`action: Post` to `Informational` if we want a visible
audit-mode signal at all. **Open question A** below covers
whether to ship it.

The correlator's sigma engine handles the rest: matching
events are republished as findings (category 2), the
responder dispatches `NotifyAction` (and any other allowed
actions per config), the notifier chain fires.

### D-3 README / collector documentation fix

Two textual changes:

1. `modules/tetragon/README.md`: replace the
   "[collectors.eventstream]" reference with
   "[collectors.tetragon]" and include a paste-ready config
   snippet:

   ```toml
   # /etc/selfdef/selfdef.toml
   [collectors.tetragon]
   enabled    = true
   input_path = "/var/log/tetragon/events.json"
   read_from  = "end"
   ```

2. `modules/tetragon/profiles/default.toml`: rewrite the
   `event_log_path` comment to make the eventstream-vs-tetragon
   distinction explicit.

Both are doc-only, but they close F-2026-003 and remove the
class of operator confusion that I-006 documented.

### D-4 Integration test

`crates/selfdef-daemon/tests/m_ai_machine.rs` — a new daemon
integration test that:

1. Sets up an in-process daemon with a tetragon collector
   reading from a tempfile, a correlator loaded with the new
   `agent_guard_violation.yml` rule, a responder with a
   counting (no-op) NotifyAction, and a store.
2. Writes a synthetic Tetragon `process_kprobe` JSON line to
   the tempfile, structured to match the
   `selfdef-agent-etc-write-guard` policy with `action:
   Sigkill`.
3. Waits for the event to traverse the pipeline (bus event
   ingest → correlator promotion → responder dispatch).
4. Asserts the store now carries a Detection Finding with
   `severity_id = High` and the responder's NotifyAction was
   invoked exactly once.

The synthetic event JSON should be checked into
`tests/replay/tetragon/agent_guard_etc_write_kill.jsonl` so
the corpus stays canonical. A second corpus
`agent_guard_audit_post.jsonl` with `action: Post` asserts
the rule does **NOT** fire (negative case).

### D-5 Ledger linkage

When this SDD reaches `implemented`, append a back-reference
to `docs/review/99-findings-ledger.md` next to F-2026-001,
-002, -003, -006: "Closed by SDD-001, PR #NN."

## Test plan (implementation PR must satisfy)

1. Unit test in `selfdef-collector-tetragon`: `build_process_kprobe`
   on a known policy_name produces an Event whose `raw` carries a
   `tetragon` subobject with `policy_name`, `action`, `function_name`.
2. Sigma rule test under `rules/sigma/hardening/`: a
   `.tests.yaml` corpus containing one Sigkill event (expect
   finding, severity high) and one Post event (expect no
   finding).
3. Daemon integration test (D-4 above).
4. Documentation snippet from D-3 is verbatim-pasteable: an
   adversarial reading should not produce ambiguity.

CI green is necessary, not sufficient. The implementation PR
must include the corpus, the sigma rule, the README fix, and
the daemon test in one diff so a reviewer can verify the
end-to-end claim from a single PR.

## Rollout / migration

- Existing deployments running with `agent-guard` v0.x and
  `tetragon` v0.1.0 will start seeing findings the moment the
  new sigma rule is loaded (SIGHUP-reload-safe). Operators in
  bring-up should either:
  - Pin `agent-guard.profile = "audit"` (no Sigkill, no
    rule fires) until the rule's signal/noise is acceptable
    on their host, OR
  - Disable the rule via `selfdefctl rules ...` (future
    knob; today the rule directory itself is the surface).
- No schema-version bump. Old hosts can be NATS peers of new
  hosts without breakage; the `raw.tetragon` subobject is just
  an additional JSON field old peers ignore.
- The README change clarifies which collector to enable. Hosts
  that *had* (incorrectly) added the path to
  `[collectors.eventstream]` will see silent log noise in
  debug; switching to `[collectors.tetragon]` is a one-line
  config change.

## Risks

- **Risk R-1 — false-positive load from a noisy policy.**
  Mitigated by per-policy `*_action` overrides in
  `agent-guard.toml`. An operator can drop a single rule
  back to Post (audit-only) without disabling the whole
  bundle. Tracked.
- **Risk R-2 — `policy_name` convention drift.** If a future
  agent-guard policy is misnamed (no `selfdef-agent-` prefix),
  the rule won't promote it. The rule should be authored to
  match the prefix exactly; a CI check that audits the
  agent-guard YAML namespace would reduce risk. Not in this
  SDD's scope.
- **Risk R-3 — upstream Tetragon changes the event shape.**
  The collector parses `process_kprobe.policy_name` and
  `process_kprobe.action` today. A Tetragon version that
  renames either field breaks the contract. Mitigated by
  pinning a tested Tetragon version range in the
  `tetragon` module's README and by D-1's principle of
  keeping the structured raw field stable across
  Tetragon-version changes (the collector adapts; the rule
  doesn't).

## Open questions

- **Q-A** — Do we ship the `agent_guard_observed.yml`
  Post-mode rule alongside? Pro: full audit-mode visibility.
  Con: every audit-mode policy fire creates an `Informational`
  finding, which clutters the store. Defaulting to "no" for
  the first cut; revisit after operator feedback.
- **Q-B** — Should the sigma rule's `level` be a literal
  `high`, or should it map per-policy from the YAML's
  `selfdef.io/severity` annotation? D-1's recommendation is
  literal-`high` because annotations aren't in the event
  today; D-1b leaves room for per-policy mapping once
  upstream Tetragon exposes annotations.
- **Q-C** — Do we wire the responder's `KillPidAction` to
  agent-guard findings (i.e. "the kernel killed the process;
  the responder reaps the cgroup")? Out of scope for this
  SDD; the kernel already killed via Tetragon. KillPidAction
  is for cases where the correlator promotes and *then* asks
  user-space to kill. Belongs to a separate SDD if desired.
- **Q-D** — Does the integration test (D-4) need a real NATS
  broker to also assert multi-host propagation? Out of scope
  here; SDD-001 stays single-host.

## Appendix — alternatives in detail

(omitted; see "Design alternatives considered" above. Future
edits can flesh out the cons of A and B if a reviewer asks.)
