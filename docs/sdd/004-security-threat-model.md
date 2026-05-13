# SDD-004 — Security threat-model rewrite

> Status: implemented
> Owner: audit team
> Last updated: 2026-05-13
> Closes findings: F-2026-023, F-2026-024, F-2026-025, F-2026-026

## Implementation status

Shipped in the SDD-004 implementation PR. SECURITY.md and its
mdbook mirror were rewritten in lockstep — `docs/src/security.md`
is now a symlink to `../../SECURITY.md` per D-6, eliminating the
drift surface.

- **D-1 — Assets table**: three new rows. `/metrics` endpoint,
  Tetragon TracingPolicy directory (`/etc/tetragon/tetragon.tp.d/`),
  and eventstream JSONL paths (default
  `/var/lib/selfdef/eventstream/`). Total: 10 rows. Closes
  F-2026-023, F-2026-024, F-2026-026 at the inventory level.
- **D-2 — Adversaries table**: new class 6, *Cluster-tenant
  attacker* — has Pod-label `PATCH` rights on the cluster.
  Closes F-2026-025 at the adversary level.
- **D-3 — Mitigations**: two new layers added under
  "Mitigations by layer". *API surface* covers UNIX vs TCP
  transports, the bearer-token model, `/metrics` read-cap
  parity, and the uptime side channel. *Policy surface*
  covers TracingPolicy directory ownership, agent-guard
  pod-label scope dependency on cluster RBAC, and the
  eventstream JSONL trust boundary.
- **D-4 — Known gaps**: extended with three new follow-up
  entries — TracingPolicy signing (F-2026-024 follow-up),
  metrics-token rotation (F-2026-023 follow-up), k8s
  label-RBAC posture (F-2026-025 follow-up). Eventstream JSONL
  integrity (F-2026-026 follow-up) was already enumerated by
  PR #36 and stays.
- **D-5 — Hardening checklist**: short copy-paste-able sidebar
  at the end of the Mitigations section enumerating the
  recommended posture for an AI-machine deployment (mode +
  ownership for the four key paths, RBAC restriction for k8s,
  binding posture for `/metrics`).
- **D-6 — Doc mirror**: `docs/src/security.md` is now a
  symlink to `../../SECURITY.md`. Single source of truth;
  mdbook follows symlinks transparently on Linux (the only
  platform the docs are built on).

## Open questions resolution

- **Q-A** (worked example block): not added in this PR. Per-module
  READMEs already carry the concrete examples; SECURITY.md stays
  declarative.
- **Q-B** (cluster control plane in trust assumptions): added.
  The Trust assumptions section now lists "the cluster control
  plane is trusted to enforce RBAC" for k8s deployments.
- **Q-C** (TracingPolicy signing shape): deferred. Tracked as
  the F-2026-024 follow-up known gap; a future SDD scopes the
  shared signing machinery between sigma rules and
  TracingPolicies.

## Problem

`SECURITY.md` (mirrored at `docs/src/security.md`) was
written when the daemon was the entire surface. The post-M15
work introduced four new attack surfaces the threat model
does not acknowledge:

- **F-2026-023** — the `/metrics` Prometheus endpoint
  (PR #23). The endpoint exposes counters that fingerprint
  host activity (events / second by class, findings /
  second by severity, daemon uptime, store size). The
  Assets table doesn't list it; the bearer-token rotation
  story is unspecified; the chained-attack possibility
  (uptime gauge → time a credential-file edit to a daemon
  restart) isn't mentioned.
- **F-2026-024** — the Tetragon TracingPolicy drop directory
  `/etc/tetragon/tetragon.tp.d/` (PR #22). A writable
  directory the kernel reads policy from. An attacker with
  write access can inject Sigkill / Override / NotifyKiller
  policies, mask legitimate detection by replacing
  `agent-guard` policies with permissive variants, or
  disable monitoring outright. Not in the Assets table; no
  mode / ownership / signing requirement documented.
- **F-2026-025** — pod-label scope in `agent-guard` v0.3.0
  (PR #25). Selectors of the form
  `matchPodSelector: matchLabels.<key>=<value>` move the
  policy boundary from "every container on the host" to
  "every pod carrying this label". On Kubernetes, anyone
  with `PATCH` rights on a Pod's labels can either opt
  unrelated pods into agent-guard's policies (denial-of-
  service-of-attention) or opt the actual agent pod out
  (defeat). The Adversaries table doesn't have a
  cluster-RBAC-aware adversary; no guidance on label
  governance.
- **F-2026-026** — the eventstream JSONL trust boundary.
  The daemon's `eventstream` collector parses any JSON line
  in any file at any path it's configured to tail.
  `selfdefctl events emit` makes injecting events
  programmatic. The threat model treats the daemon as
  trusted, but treats the bus as a stream of trusted events
  — when in fact every line in those JSONL files is an
  event-injection vector. No documented ownership / mode
  requirement on the JSONL paths; no integrity check at
  parse time.

The shipped SECURITY.md is otherwise sound. The rewrite is
**additive** — keep the existing material, fold the four
surfaces into the right tables, add a small new section per
surface where the existing structure doesn't fit, and update
the "Known gaps" list.

## Goals

1. Every surface that ships in the catalog has a row in the
   Assets table.
2. Every adversary class that can plausibly act against the
   new surfaces is named in the Adversaries table.
3. Each surface has explicit Mitigation guidance the operator
   can act on (file modes, ownership, scrape-config patterns).
4. The "Known gaps" list explicitly names the four
   not-yet-mitigated items the rewrite reveals (e.g.
   "TracingPolicy directory has no signing requirement
   today; SDD-004-followup tracks").
5. The rewrite stays **operator-readable**. SECURITY.md is
   not an SDD; keep it short, declarative, and useful as a
   threat-model reference.
6. The rewrite lands in **two places** at once: the repo-root
   `SECURITY.md` and the mdbook mirror `docs/src/security.md`.
   The two are byte-equivalent today; they should stay so.

## Non-goals

- Implementing any of the mitigations. This is a documentation
  rewrite; the implementations (signed TracingPolicies,
  integrity-checked eventstream, automatic token rotation)
  are tracked as their own future SDDs.
- Changing the Adversary numbering. The five existing
  adversary classes stay as-is; the rewrite adds a sixth
  ("Cluster-tenant attacker") under k8s-aware deployments.
- Replacing the SECURITY.md style. Tables stay; section
  ordering stays.

## Glossary

- **Asset** — a thing on the host whose tampering /
  exfiltration affects detection. Already used in the
  existing SECURITY.md.
- **Adversary** — a numbered class with a stated capability
  level. Already used.
- **Mitigation by layer** — the existing organization of the
  Mitigations section (build / process / config / storage /
  notification / tamper detection). The rewrite adds two
  layers: **API surface** and **policy surface**.

## Current state

The shipped SECURITY.md has these sections in order:

1. Assets (7 rows: daemon binary / config / rules / hot store /
   cold archive / notification credentials / eBPF programs).
2. Adversaries (5 classes).
3. Trust assumptions.
4. Mitigations by layer (Build / Process / Configuration &
   rules / Storage / Notification / Tamper detection).
5. Known gaps (3 bullets: dm-verity, remote attestation,
   rule signing).
6. Reporting.

Missing from each section per the audit:

- Assets: `/metrics` endpoint, TracingPolicy drop dir,
  eventstream JSONL paths.
- Adversaries: cluster-tenant attacker (k8s).
- Mitigations: API surface (auth, exposure modes), policy
  surface (TracingPolicy ownership, signing — flagged as a
  Known gap if signing isn't implemented).
- Known gaps: TracingPolicy signing, eventstream integrity,
  metrics token rotation, k8s label RBAC dependency.

## Design alternatives considered

### Alternative A — Inline expansion of every existing section

Add the new rows / classes / mitigations directly into the
existing tables and section bodies. No new top-level
sections.

**Pros**
- Smallest diff. Operators reading SECURITY.md see the new
  content in the place they expect to find it.
- No reorganization risk; the existing flow is preserved.

**Cons**
- The Assets table grows from 7 to 10 rows; the table starts
  to feel mixed (binary / config / rules / hot store / cold
  archive / credentials / eBPF / metrics endpoint /
  TracingPolicy dir / eventstream JSONL is a lot of disparate
  things in one table).
- Mitigations sections grow longer without clearer scope.

### Alternative B — New "Module-introduced surfaces" section

Add one new top-level section ("Module-introduced surfaces")
that groups everything the AI-machine track + observability
brought in. The existing daemon-centric tables stay
unchanged.

**Pros**
- Clean separation between "the daemon's threat model" and
  "the threat model the modules add".
- Future modules with new surfaces just append rows here.

**Cons**
- Splits the threat model into two reading passes. An
  operator wanting "everything that's an asset" reads two
  tables.
- Implies the daemon-side and module-side surfaces are
  unrelated, which they aren't — the eventstream JSONL is
  written by modules but parsed by the daemon's collector.

### Alternative C — Hybrid (recommended)

- Expand the existing tables (Assets, Adversaries) inline
  with the new entries. Keep the daemon-centric structure.
- Add **two new layers** to the Mitigations section: "API
  surface" (covering UNIX-socket vs TCP, bearer-token /
  TLS / mTLS, the new `/metrics` exposure considerations)
  and "Policy surface" (covering TracingPolicy ownership,
  the path the `tetragon` module manages,
  agent-guard's pod-label scope dependency on cluster RBAC,
  the eventstream JSONL trust boundary).
- Update Known gaps to enumerate the four not-yet-mitigated
  items.

This combines A's clarity-of-place with B's
clarity-of-grouping for the new mitigation guidance that
doesn't fit existing layers.

## Recommended design

**Alternative C**.

## Detailed design

### D-1 — Assets table: three new rows

```
| /metrics endpoint | UNIX socket /run/selfdef.sock or TCP <bind> | Activity-fingerprint information; chained-attack timing of credential edits to daemon restart. |
| TracingPolicy directory | /etc/tetragon/tetragon.tp.d/ | Writable: malicious YAML loads as kernel-level eBPF policy (Sigkill, Override, NotifyKiller, mask). |
| Eventstream JSONL paths | Varies — see [collectors.eventstream].paths | Event-injection vector. Crafted Findings can fire the notifier chain or pollute the multi-host NATS bridge via host_tag spoofing. |
```

### D-2 — Adversaries table: one new class

```
6. Cluster-tenant attacker — has Pod-label PATCH rights on
   the cluster (k8s only). Trying to defeat agent-guard
   pod-label scoping. *Should be detected via
   matchPodSelector + label-RBAC posture.*
```

Numbered class 6, sequential after the existing five.

### D-3 — Mitigations section: two new layers

#### API surface

- **UNIX socket transport**: filesystem permissions are the
  auth boundary. Default `0660 root:adm`; recommended for
  on-host scrapers (Prometheus on the same host).
- **TCP transport**: bearer-token required on every request.
  `bearer_token_file` in the Prometheus scrape config; mode
  `0600` on the token file; rotate via daemon restart (token
  is read at startup, never re-read from disk per
  Notification mitigation already in §6.3).
- **TLS / mTLS**: opt-in; required when binding outside
  `127.0.0.1`.
- **`/metrics` is read-cap**: the same bearer token grants
  read access to `/status`, `/events`, `/findings`,
  `/events/stream`, `/metrics`. It does NOT grant control-
  verb access (`/rules/reload`, `/panic`, `/actions/*/run`)
  — those need the separate `control_token_file`.
- **Side channel**: `selfdef_uptime_seconds` lets a scraper
  detect a daemon restart. Rotate notifier credentials via
  a deliberate operator action, not through automated
  watchers that key on uptime resets.

#### Policy surface

- **TracingPolicy directory** (`/etc/tetragon/tetragon.tp.d/`):
  the `tetragon` module creates this dir at install. Mode
  recommended `0750 root:root`; only `agent-guard` and any
  other operator-approved policy module should write here.
  An `integrity-sentinel` paths file should baseline this
  directory's contents.
- **Pod-label scope** (`agent-guard` `scope = "pod-label"`):
  the policy boundary is the configured label
  (`pod_label_key=pod_label_value`). Any cluster identity
  with `PATCH` on a Pod's labels can move the boundary.
  Document the required RBAC posture in your cluster's
  `Role` / `RoleBinding` for the namespace agent-guard
  watches.
- **Eventstream JSONL trust**: every line in every path
  listed in `[collectors.eventstream].paths` is an event
  the daemon will treat as if a collector emitted it. The
  daemon-owned dirs (default `/var/lib/selfdef/eventstream/`)
  should be `0750 selfdef:selfdef`. Operator-owned emitters
  (e.g. the user's own `~/.local/share/selfdef/ssh-wrap.jsonl`)
  inherit the user's trust posture — a compromise of that
  user's account is event-injection.

### D-4 — Known gaps: extended

Current list:
- dm-verity
- remote attestation
- rule signing

Add:
- TracingPolicy signing (analogous to rule signing): the
  daemon trusts every YAML in the policy dir as if signed
  by the operator. Future SDD: per-policy cosign + a
  startup-time verifier in `tetragon` apply.sh.
- Eventstream JSONL integrity: every line is trusted by the
  collector. Future SDD: daemon-side ownership / mode
  verification at parse time, plus an optional per-line HMAC.
- Metrics-token rotation: today a daemon restart is the only
  rotation point. Future SDD: a `selfdefctl api rotate-token`
  verb plus daemon SIGUSR2 handling.
- k8s label-RBAC posture: the `pod-label` scope assumes the
  cluster RBAC posture is documented. A `selfdefctl modules
  check` integration that reads the cluster's RBAC and
  warns on overly-permissive PATCH rights is desirable but
  not designed.

### D-5 — Operator-facing guidance: a "Hardening checklist" sidebar

A short bullet list at the end of the Mitigations section:

```
For an AI-machine deployment (tetragon + agent-guard +
observability), the audit-recommended hardening posture is:

- /etc/tetragon/tetragon.tp.d/ : 0750 root:root
- /var/lib/selfdef/eventstream/ : 0750 selfdef:selfdef
- /etc/selfdef/api.token : 0600 root:selfdef (or 0600
  prometheus:prometheus on the scraper host)
- agent-guard pod-label scope: cluster RBAC restricts
  Pod-label PATCH to cluster-admin
- integrity-sentinel paths file includes /etc/tetragon/,
  /etc/selfdef/, /var/lib/selfdef/eventstream/
```

This block is intentionally short — anyone deploying the AI-
machine track should be able to copy-paste it into a
hardening runbook.

### D-6 — Doc mirror

`docs/src/security.md` and the repo-root `SECURITY.md` are
duplicates. Keep them so by either:
- making `docs/src/security.md` a symlink to
  `../../SECURITY.md` (mdbook follows symlinks), or
- editing both files in lockstep.

The implementation PR should pick one. The recommendation
here is **symlink** — fewer drift opportunities. If symlinks
in the docs tree complicate downstream tooling, lockstep
edits with a CI check are the fallback.

## Test plan (implementation PR must satisfy)

This is a doc rewrite, so "tests" are review-style:

1. The Assets table contains exactly 10 rows.
2. The Adversaries table contains exactly 6 classes,
   numbered 1-6.
3. The Mitigations section contains 8 layers: the original 6
   (Build & supply chain / Process / Configuration & rules /
   Storage / Notification / Tamper detection) plus the two
   new ones (API surface / Policy surface).
4. The "Known gaps" list contains exactly 7 bullets (the 3
   original plus the 4 new).
5. The "Hardening checklist" sidebar appears at the end of
   Mitigations.
6. `SECURITY.md` and `docs/src/security.md` are
   byte-equivalent (or one is a symlink to the other).
7. Phase-1 ledger rows F-2026-023, -024, -025, -026 each
   gain a "closed by SDD-004 implementation PR" back-
   reference.

## Rollout / migration

- Pure documentation. No code, no defaults change.
- Existing operators reading SECURITY.md see new asset rows
  + new adversary class + new mitigation guidance. No
  action is *required*; the hardening checklist names what
  *should* be done.
- The four "Known gaps" entries explicitly call out work
  that hasn't shipped yet — the operator knows where to
  look.

## Risks

- **R-1 — operators read the new mitigations as
  prescriptive.** Worded carefully — the section is
  "recommended posture", not "required". Audit-style.
- **R-2 — symlink in docs/src/security.md breaks mdbook on
  some platforms.** Mitigated by the fallback (lockstep
  edits + CI check). Pick during implementation.
- **R-3 — the "Hardening checklist" goes stale as defaults
  change.** Mitigated by linking it to the CHANGELOG entry
  that introduces each change; the doc-sweep PR pattern
  established in PR #30 already touches both surfaces in
  one diff.

## Open questions

- **Q-A** — Should the rewrite include a worked example of
  a Prometheus scrape config with a token, a TracingPolicy
  with `selfdef.io/severity: "high"`, and an
  integrity-sentinel `paths.txt` covering the tetragon
  policy dir? The current design says "no, that belongs in
  per-module READMEs" but operator ergonomics might argue
  for in-line examples in SECURITY.md.
- **Q-B** — Does the cluster-tenant adversary deserve its
  own Trust assumptions section entry? Today TM assumes
  "kernel is trusted, hardware root of trust is trusted".
  A k8s deployment also assumes "cluster control plane is
  trusted". Worth flagging.
- **Q-C** — TracingPolicy signing: same shape as rule
  signing, or different? Rule signing is sigma-rule-specific
  and uses cosign. TracingPolicies could plausibly use the
  same machinery (sign the YAML; verify on apply). Worth a
  shared sub-SDD with the existing rule-signing gap.

## Appendix — interaction with other SDDs

- **SDD-001** (AI-machine end-to-end) defines what an
  agent-guard event looks like once it surfaces as a
  finding. The threat-model rewrite assumes that pipeline is
  in place; the "Hardening checklist" mentions
  integrity-sentinel watching the policy dir, which is
  actionable today regardless of SDD-001.
- **SDD-002** (defaults that work out of the box) introduces
  `[daemon_requires]`. The threat-model rewrite doesn't
  depend on it but mentions the eventstream JSONL trust
  boundary, which SDD-002 makes more discoverable via the
  manifest's `[daemon_requires]` block.
- **SDD-003** (vpn-bridge multi-instance) is unrelated to
  the security rewrite.

## Follow-up findings (F-2027-045)

Phase 2 raised eight findings against this SDD's surface (six
nice, two important; all closed). Listed here so future SDD
readers can trace the lineage from this design doc to the
post-Phase-1 iterations.

### Important

- **F-2027-003** — `selfdef-collector-eventstream`'s
  `read_euid()` returned 0 silently on `/proc/self/status`
  read failure, making the integrity check accidentally
  permissive. Phase 2 first-fixes PR (#56) flipped it to
  `Option<u32>` and falls back strict-safe.
- **F-2027-035** — `check_path_integrity` used
  `std::fs::metadata` (stat, follows symlinks) and then
  `tokio::fs::File::open` (also follows). Phase 2 PR (#67)
  rewrote as `O_NOFOLLOW`-open + fstat-on-FD, closing the
  TOCTOU window and refusing symlinks with a typed
  `IntegritySymlink` variant.

### Nice

- **F-2027-005** — rule-signing verifier hot-rotation via
  SIGUSR2 (PR #58). Pre-fix needed a full daemon restart.
- **F-2027-006** — `selfdefctl keys verify-dir <dir>` batch
  verb replaces the N-spawn `for p in $(find …); do
  selfdefctl keys verify $p` loop in
  `modules/tetragon/install/{apply,check}.sh` (PR #57).
- **F-2027-007** — `selfdefctl rbac check --probe` expanded
  the built-in probe set from 2 to 4 subjects (PR #57).
- **F-2027-014** — `selfdef_api::with_full_capability` was
  documented as test-only but `pub fn` and reachable from
  any caller. Now gated behind the `test-helpers` Cargo
  feature; absent from release builds (PR #61).
- **F-2027-031** — `TokenReloader::reload` didn't validate
  the mode-0600 invariant. Now refuses with a typed
  `LooseTokenMode` variant on `chmod 0644` (PR #69).
- **F-2027-036** — eventstream integrity check runs once at
  startup against the FD; post-startup `logrotate` requires
  a daemon restart. Documented in `docs/dev/first-run.md`
  (PR #67).
