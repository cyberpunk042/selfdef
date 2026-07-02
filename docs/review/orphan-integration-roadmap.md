# Orphan-integration roadmap — full 467-crate triage (2026-07-02)

> Answers the operator's directive: *"lets continue developping selfdef, it was
> much more than what it currently do. lets investigate what is up with that."*
>
> Extends `crate-wiring-analysis.md` (which measured the 16%-wired headline and
> classified 3 families by hand) into a **complete per-crate triage of all 467
> orphans**, so integration can be steered from the full map instead of
> crate-by-crate. Method: 9 parallel classifiers each read the actual crate
> `lib.rs` + the real daemon integration points (responder, correlator, api
> router, grants/quarantine handlers, collectors, bus, store, notifier), plus a
> mechanical pass over the data-structure primitives. Every verdict is grounded
> in code read this session, not the crate name.

## Headline (recomputed 2026-07-02)

| Metric | Count |
|---|---|
| Workspace `selfdef-*` crates | 558 |
| Wired (reachable from selfdefd / selfdefctl / ssh-wrap) | 91 |
| Orphaned | 467 |

The 467 orphans triage into **five dispositions**:

| Disposition | ~Count | Meaning |
|---|---:|---|
| **GENUINE_GAP — wireable now** | ~34 | Real missing discipline over an **already-wired** verb; fail-safe, default-off, follows the proven pattern. The actionable backlog. |
| **SUBSYSTEM** | ~110 | Coherent, designed-together capability with **no wired entry point**. Needs the subsystem's entry point built first, then assembled as a unit — not per-crate. |
| **SIMULATION_BLOCKED** | ~25 | Real logic, but wiring is blocked on an **execution/metering backend that doesn't exist yet** (the MS5a substrate). |
| **REDUNDANT / ALTERNATIVE** | ~90 | The daemon already provides this (often stronger), or it's a duplicate/parallel model. **Do not wire.** |
| **PRIMITIVE_UTILITY** | ~208 | Generic building blocks (data structures, math, hashing, taxonomies) — deps of the policy crates, not directly wireable capabilities. |

The core truth from `crate-wiring-analysis.md` holds and sharpens: **the verbs
are wired; the discipline is orphaned** — but "build it out" is emphatically
*not* "wire 467 crates." Roughly **half the orphans should never be wired**
(redundant, alternative, or primitive), a quarter are **one entry point away**
(subsystems), and only **~34 are the real, safe, do-it-now backlog.**

---

## The keystone: the decision-emit spine (unlocks three families at once)

The single most leveraged finding. Three independent classifiers — **policy**,
**decision**, and **audit-forensics** — converged on the *same* missing piece:

> The responder fires containment actions but **emits no coordinated decision
> object.** The daemon's own doctrine (in `selfdef-policy-decision`) states
> *"every action MUST have a policy decision object,"* yet the wired path emits
> none.

`selfdef-event-emitter` is literally designed to emit the 4-tuple
`PolicyDecision + TraceSpan + AuditRecord + DispatchPlan` per decision. Wiring
that spine **emit-only (Shadow mode, zero behavior change)** at the responder's
dispatch point lights up, as clean follow-ons, the highest-value gaps of three
families:

- **policy**: `policy-decision` (keystone) → then `policy-bus`,
  `policy-conflict-detector`, `policy-conflict-resolver`.
- **decision**: the `PolicyDecision` vocabulary the whole `decision-*` lattice
  speaks becomes real, so `decision-explainer` / `-reason-codes` / `-causation-chain`
  gain a producer.
- **audit-forensics**: `trace-span` (13-field, "emitted when decided") +
  `evidence-ledger` (the durable trace-indexed sink the responder already
  *asserts* it needs but lacks) + `replay-divergence-detector`.

**Recommendation: build the decision-emit spine first** (`policy-decision` +
`event-emitter` + `trace-span`, emit-only). It is itself a P1 zero-behavior-change
increment and it is the assembly point subsystem #2 below grows from.

---

## Tier 1 — standalone P1 increments on already-wired verbs (do these now)

Each is a self-contained, fail-safe-directional, default-off wiring onto a verb
that is *already* running — the exact pattern proven by the shipped responder
circuit-breaker and grant overlap/cooldown gates. No subsystem required.

| # | Crate | Wired verb / integration point | Why it's a genuine gap |
|---|---|---|---|
| 1 | `selfdef-collector-staleness-policy` | the 7 wired collectors → freshness budget + metric/alert | **`main.rs` itself documents the bug**: a collector that panics mid-run leaves "events silently lost while the daemon ran," noticed only at shutdown. Nothing detects a silently-dead source today. |
| 2 | `selfdef-quarantine-release-policy` | `POST /v1/quarantine/release` | The wired release handler checks **only the operator signature** — it ignores reviewer-count / minimum-age / operator-signoff gates that operate on metadata already present. Hardens the sole escape hatch from quarantine, no backend. |
| 3 | `selfdef-grant-revocation-cascade` | `POST /v1/grants/revoke` | Revoke a parent grant → cascade-revoke its children. Revoking *more* only narrows access → fail-safe. Mirror of the shipped overlap gate, on the revoke verb. |
| 4 | `selfdef-grant-revocation-log` | `POST /v1/grants/revoke` | Append-only revocation audit on the same wired verb. Additive, pairs with cascade. |
| 5 | `selfdef-decision-budget` | responder destructive path (beside the rate-cap) | Long-horizon (daily/weekly/monthly) cap on destructive actions. The shipped 60s rate-cap is **blind to a slow drip** across hours/days. Keys on `Profile` (already wired). |
| 6 | `selfdef-secret-redaction-policy` (+ `secret-detection`, `output-channel-allowlist`) | notifier egress (`NtfyNotifier` / `SignalCliNotifier` / NATS — all wired) | Finding text is built from raw log/audit lines and egresses to third-party services; a finding can carry an AWS key / JWT / `sk-*` straight out. Redact-before-dispatch is purely subtractive. **A real credential-leak surface.** |
| 7 | `selfdef-recovery-snapshot-authority` | responder `snapshot_dir` / `forensics_dir` pruning | Those dirs grow **unbounded** today (same class as the store's SDD-081 fix). Min-kept-per-class retention. |
| 8 | `selfdef-collector-budget-guard` | collector→bus publish (EPS ceiling) | Nothing caps a runaway or compromised collector flooding the in-proc bus. |
| 9 | `selfdef-concurrent-action-limiter` | responder action dispatch | Per-actor **concurrency** cap — a distinct dimension from the shipped rate-cap (concurrency ≠ rate). |

Secondary same-shape P2s: `collector-coalescing`, `ingest-admission-gate`,
`actor-registry` + `actor-suspension-policy` (validate `req.actor` on
`/v1/grants/issue`, today trusted unchecked), `quarantine-cause-taxonomy`,
`sandbox-dispatcher` (derive the MS036 tier instead of trusting the caller's on
`/v1/sandboxes/allocate`), `decision-trace-export-policy` (DLP over the forensic
export surface), `policy-cooldown-window` (duplicate-alert suppression over the
wired notifier).

## Tier 2 — action-identity discipline (a small subsystem on the responder)

The responder models an action's *repeat/flood* (shipped) but not its *identity
and journey*. A cohesive mini-subsystem, best wired together:
`action-lifecycle` (Requested→…→Completed/Failed state machine; dispatch is
fire-and-forget today) + `action-precondition-checker` (declarative pre-dispatch
gates) + `kill-switch-registry` (an operator **runtime** kill switch with
dual-control re-arm; today's only "off" is static config / `dry_run`) +
`action-outcome-ledger` + `blast-radius-classifier` → `action-confirmation-tier`
(graded human-gating replacing the flat `is_destructive` boolean).

## Tier 3 — boot-integrity gate (wireable now, data already at boot)

`substrate-readiness` + `substrate-self-test` + `substrate-fingerprint`:
refuse-boot-unless-pass against the loaded rule packs / doctrine, all known at
startup. A clean, self-contained hardening.

---

## The big unassembled subsystems (need an entry point / backend, scoped separately)

These are **not** per-crate wiring gaps. Each is a coherent product surface that
selfdef clearly intends but has not assembled; wiring individual member crates
before the entry point exists produces dead code.

| Subsystem | ~Crates | Status & the entry point it needs | Scope call |
|---|---:|---|---|
| **PolicyDecision authorization + provenance engine** | policy-* core + decision-* + emit spine | Partially unlocked by the **decision-emit spine** above. Grow from `policy-decision` emit-only. | In scope — highest leverage. |
| **AI-agent-governance / MCP-tool firewall** | 37 (llm/prompt/tool/mcp) | `/v1/tool-authority` + `/v1/mcp` are **static schema stubs** naming these crates as strings without executing them. Needs the **planned `selfdef-mcp-server` + an SDD-050 tool-gate-pipeline runner** built first, then the `prompt-injection-classifier` + 8 tool-* gates assemble onto it. | A real intended product surface. Needs a build decision. |
| **Execution / metering substrate (MS5a)** | ~25 (substrate quotas + isolation + the simulated destructive effectors + the prevention layer) | All `SIMULATION_BLOCKED`: pure in-memory accounting with **no producer of real cpu/disk/fd/syscall usage** and no enforcement point. Blocked on a **process-runner-under-Profile that meters real usage** — the same backend that blocks the simulated quarantine/netns/freeze effectors and the connect/spawn-time prevention layer (`network-egress-decision`, `process-launch-policy`, dns/clipboard egress). | Backend *implementation* depth, not glue. The biggest effort. |
| **Agent-runtime / execution-mode governance** | ~11 | Shares a `Profile / ExecutionMode / TaskClass / SideEffectClass` vocabulary and governs an **agent runtime the IPS daemon does not host** (execution-mode-history, mode-pre-flight, session-lifetime, routing-decision-authority, eval-gate, task-priority/deadline, emergency-stop, source-attribution…). | **Likely belongs to sovereign-os, not selfdefd.** Flag for a scope decision before any wiring. |
| **Authority lattice** | ~8 | `high-risk-triple-gate`, `autonomous-gates`, `mode-transition-authority`, `toggle-audit-authority`, `config-personalization-bounds`, `quorum-approval`, `denial-appeal` — several depend on the orphan `eval-gate-policy` / `policy-decision`. Assembles after the decision spine. | In scope, after Tier 1. |
| **Collector-fabric lifecycle** | ~4 | `collector-arming-state` + `collector-quarantine-ledger` (share `collector-source-taxonomy`). Needs a lifecycle manager; `staleness` + `coalescing` + `budget-guard` are individually wireable now (Tier 1). | In scope. |
| **Trust-cohort** | ~3 | `subject-cohort` + `promotion-throttle` feeding orphan `trust-promotion/decay`. Note: the **wired** trust registry is a *different* crate (`selfdef-trust-score-registry`), so much of this family is redundant with it. | Low priority. |

---

## Do-not-wire (≈½ of the orphans)

- **REDUNDANT (~25)** — the daemon already provides this, often stronger. Named
  examples: `action-denylist` (default-allow, dominated by the wired default-deny
  `allowed_actions`); `decision-cache/throttle/watchdog` (= the shipped
  burst-dedup / rate-cap / `action_deadline`); `circuit-breaker-policy` (= the
  wired responder rate-cap); `retention-policy` (= store SDD-081);
  `evidence-chain-link` + `evidence-merkle-chain` (weaker FNV dups of the wired
  OCSF SHA-256 chains); `alert-escalation-policy` (= the wired notifier
  `EscalationEngine`); `capability-token-store` / `trust-score-history` /
  `trust-decay-policy` (dups of the wired `capability-registry` /
  `trust-score-registry`).
- **ALTERNATIVE (~40+)** — parallel models of a wired capability, or internally
  duplicative: three enforcement toggles (`shadow-mode` / `dry-run` /
  `feature-flag`), two rollout selectors (`rollout-stage` / `traffic-ramp`), two
  validators (`spec-validator` / `shape-checker`), the whole connect/spawn-time
  **prevention layer** (blocked on effectors that don't exist), the
  **bus-governance cluster** (models a 9-subscriber topology the in-proc
  broadcast bus never adopted; NATS JetStream already DLQs).
- **PRIMITIVE_UTILITY (~208)** — data structures (bloom/cuckoo/lru/ring/prefix-sum/
  union-find/consistent-hash), math (linear-regression/EMA/quantile-sketch),
  hashing, id issuers, generic stores, taxonomies. These are the **dependencies**
  the policy crates compose; they are healthy building blocks, not integration
  targets.
- **N/A** — multi-tenant crates (`tenant-*`, `policy-namespace-*`) in a
  single-box, single-operator IPS; `blue-green-deploy` (the daemon deploys no
  services).

---

## Recommended sequence

1. **Decision-emit spine** (`policy-decision` + `event-emitter` + `trace-span`,
   emit-only/Shadow) — zero behavior change, unlocks 3 families.
2. **Tier 1** (the 9 standalone P1s) — each a clean, independent, fail-safe
   session, highest operational value first: collector-staleness → quarantine-release
   → grant-revocation pair → decision-budget → notifier DLP → snapshot pruning.
3. **Tier 2** action-identity subsystem on the responder.
4. **Tier 3** boot-integrity gate.
5. **Scope decision** on the agent-runtime governance family (selfdef vs
   sovereign-os) and on committing to the **AI-agent-governance subsystem** and
   the **MS5a execution substrate** — the two large builds that would take
   selfdef from an IPS-with-discipline to the full catalogued vision.

Everything in Tiers 1–3 follows the already-proven, test-locked, default-off
integration pattern; none of it changes default behavior until an operator opts
in. The two large subsystems (AI-agent governance, MS5a substrate) are where
"much more than it currently does" mostly lives — and both are build decisions,
not glue.

## Provenance

Per-crate verdicts (class · priority · integration point · rationale for all
467) are in the session triage notes; this document is the synthesized roadmap.
Classifiers cross-checked every "gap" against the wired surface before calling
it genuine, so the backlog above is what survived that adversarial filter — the
"84% orphaned" headline overstates missing capability, and this roadmap is the
corrected, steerable map.
