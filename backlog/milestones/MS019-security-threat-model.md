# MS019 — Security threat model

> Parent: `backlog/milestones/INDEX.md` row MS019.
> Source: `docs/sdd/004-security-threat-model.md` (536 lines; status=implemented; owner=audit team; last updated 2026-05-13; closes F-2026-023 + F-2026-024 + F-2026-025 + F-2026-026; ships D-1..D-6 + Hardening checklist + 8 phase-2 follow-ups including 2 important F-2027-003 + F-2027-035) + `SECURITY.md` + `docs/src/security.md` symlink. All entries below extract verbatim. No invention.

## Epics (E0191–E0200)

| Epic ID | Phrase | Source |
|---|---|---|
| E0191 | Mission — SECURITY.md threat-model rewrite (mirrored at docs/src/security.md via symlink); SDD-004 is implemented; closes 4 findings F-2026-023+024+025+026; post-M15 work introduced 4 new attack surfaces existing threat model didn't acknowledge; rewrite is ADDITIVE — keep existing material + fold 4 surfaces into right tables + add small new sections + update Known gaps | SDD-004 § header + § Problem |
| E0192 | F-2026-023 — `/metrics` Prometheus endpoint (PR #23) exposes counters that fingerprint host activity (events/second by class / findings/second by severity / daemon uptime / store size); bearer-token rotation story unspecified; chained-attack possibility (uptime gauge → time credential-file edit to daemon restart) wasn't mentioned | SDD-004 § Problem F-2026-023 |
| E0193 | F-2026-024 — Tetragon TracingPolicy drop directory `/etc/tetragon/tetragon.tp.d/` (PR #22); writable directory kernel reads policy from; attacker with write access can inject Sigkill/Override/NotifyKiller policies, mask legitimate detection by replacing agent-guard policies with permissive variants, or disable monitoring outright; no mode/ownership/signing requirement documented | SDD-004 § Problem F-2026-024 |
| E0194 | F-2026-025 — pod-label scope in agent-guard v0.3.0 (PR #25); selectors `matchPodSelector: matchLabels.<key>=<value>` move policy boundary from "every container on the host" to "every pod carrying this label"; anyone with PATCH rights on a Pod's labels can opt unrelated pods INTO agent-guard's policies (denial-of-service-of-attention) or opt actual agent pod OUT (defeat); Adversaries table didn't have cluster-RBAC-aware adversary; no guidance on label governance | SDD-004 § Problem F-2026-025 |
| E0195 | F-2026-026 — eventstream JSONL trust boundary; daemon's eventstream collector parses any JSON line in any file at any path it's configured to tail; `selfdefctl events emit` makes injecting events programmatic; threat model treated daemon as trusted + bus as stream of trusted events — when in fact every line in those JSONL files is an event-injection vector; no documented ownership/mode requirement; no integrity check at parse time | SDD-004 § Problem F-2026-026 |
| E0196 | 6 Goals — (1) every surface in catalog has row in Assets table; (2) every adversary class that can plausibly act against new surfaces is named; (3) each surface has explicit Mitigation guidance operator can act on (file modes / ownership / scrape-config patterns); (4) "Known gaps" list explicitly names 4 not-yet-mitigated items; (5) SECURITY.md stays operator-readable (NOT an SDD; keep short, declarative); (6) rewrite lands in BOTH places at once (repo-root SECURITY.md + mdbook mirror docs/src/security.md; byte-equivalent or symlink) | SDD-004 § Goals |
| E0197 | 3 Design alternatives — A (inline expansion of every section); B (new "Module-introduced surfaces" section); C (recommended HYBRID — expand Assets + Adversaries inline + add 2 new Mitigations layers API surface + Policy surface + extended Known gaps) | SDD-004 § Design alternatives |
| E0198 | D-1 + D-2 — Assets table: 3 new rows (`/metrics` endpoint / TracingPolicy directory / Eventstream JSONL paths) bringing total to 10 rows; Adversaries table: 1 new class 6 "Cluster-tenant attacker" (Pod-label PATCH rights on cluster, k8s only) | SDD-004 § D-1 + § D-2 |
| E0199 | D-3 — 2 new Mitigations layers: API surface (UNIX-socket vs TCP transport / bearer-token rotation / TLS-mTLS opt-in / read-cap vs control-cap parity / uptime side-channel) + Policy surface (TracingPolicy directory ownership / pod-label scope dependency on cluster RBAC / eventstream JSONL trust boundary) | SDD-004 § D-3 |
| E0200 | D-4 + D-5 + D-6 + Phase-2 follow-ups — D-4 extends Known gaps with 4 shipped opt-in features (TracingPolicy signing via minisign; eventstream JSONL integrity owner-mode verification; metrics-token rotation via SIGUSR2; k8s label-RBAC posture via `selfdefctl rbac check --probe`); D-5 Hardening checklist sidebar (4-line posture: 0750 root:root tetragon dir / 0750 selfdef:selfdef eventstream / 0600 root:selfdef api.token / cluster-admin-only Pod-label PATCH / integrity-sentinel paths file); D-6 docs/src/security.md is symlink to ../../SECURITY.md; 8 Phase-2 follow-ups (2 important F-2027-003 read_euid silent-zero fallback + F-2027-035 O_NOFOLLOW TOCTOU; 6 nice including F-2027-005 SIGUSR2 verifier hot-rotation + F-2027-014 with_full_capability gated behind test-helpers feature) | SDD-004 § D-4 + § D-5 + § D-6 + § Follow-up findings |

## Modules (M00473–M00498)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00473 | F-2026-023 finding — `/metrics` endpoint exposed in threat-model | SDD-004 § Problem F-2026-023 | E0192 |
| M00474 | F-2026-024 finding — TracingPolicy drop directory writable | SDD-004 § Problem F-2026-024 | E0193 |
| M00475 | F-2026-025 finding — agent-guard pod-label scope movable by cluster PATCH | SDD-004 § Problem F-2026-025 | E0194 |
| M00476 | F-2026-026 finding — eventstream JSONL parsed as trusted | SDD-004 § Problem F-2026-026 | E0195 |
| M00477 | Assets row 8 — `/metrics` endpoint (UNIX socket /run/selfdef.sock or TCP <bind>; Activity-fingerprint information; chained-attack timing of credential edits to daemon restart) | SDD-004 § D-1 | E0198 |
| M00478 | Assets row 9 — TracingPolicy directory (/etc/tetragon/tetragon.tp.d/; Writable: malicious YAML loads as kernel-level eBPF policy: Sigkill/Override/NotifyKiller/mask) | SDD-004 § D-1 | E0198 |
| M00479 | Assets row 10 — Eventstream JSONL paths (Varies — see [collectors.eventstream].paths; Event-injection vector; Crafted Findings can fire notifier chain or pollute multi-host NATS bridge via host_tag spoofing) | SDD-004 § D-1 | E0198 |
| M00480 | Adversary class 6 — Cluster-tenant attacker (Pod-label PATCH rights on cluster; k8s only; trying to defeat agent-guard pod-label scoping; "Should be detected via matchPodSelector + label-RBAC posture") | SDD-004 § D-2 | E0198 |
| M00481 | API surface Mitigation — UNIX socket transport (filesystem permissions = auth boundary; default 0660 root:adm; recommended for on-host scrapers) | SDD-004 § D-3 API surface | E0199 |
| M00482 | API surface Mitigation — TCP transport (bearer-token required on every request; `bearer_token_file` in Prometheus scrape config; mode 0600 on token file; rotate via daemon restart per Notification mitigation already in §6.3) | SDD-004 § D-3 API surface | E0199 |
| M00483 | API surface Mitigation — TLS/mTLS opt-in (required when binding outside 127.0.0.1) | SDD-004 § D-3 API surface | E0199 |
| M00484 | API surface Mitigation — `/metrics` is read-cap (same bearer token grants read access to /status, /events, /findings, /events/stream, /metrics; does NOT grant control-verb access /rules/reload, /panic, /actions/*/run — those need separate `control_token_file`) | SDD-004 § D-3 API surface | E0199 |
| M00485 | API surface Mitigation — Side channel `selfdef_uptime_seconds` lets scraper detect daemon restart; rotate notifier credentials via deliberate operator action, not automated watchers that key on uptime resets | SDD-004 § D-3 API surface | E0199 |
| M00486 | Policy surface Mitigation — TracingPolicy directory mode 0750 root:root; only agent-guard and operator-approved policy modules should write; integrity-sentinel paths file should baseline directory contents | SDD-004 § D-3 Policy surface | E0199 |
| M00487 | Policy surface Mitigation — Pod-label scope policy boundary is configured label; any cluster identity with PATCH on Pod labels can move boundary; document required RBAC posture in cluster's Role/RoleBinding for namespace agent-guard watches | SDD-004 § D-3 Policy surface | E0199 |
| M00488 | Policy surface Mitigation — Eventstream JSONL trust; every line in every path in [collectors.eventstream].paths is event daemon treats as if collector emitted it; daemon-owned dirs (default /var/lib/selfdef/eventstream/) should be 0750 selfdef:selfdef; operator-owned emitters inherit user's trust posture | SDD-004 § D-3 Policy surface | E0199 |
| M00489 | Known gap shipped — TracingPolicy signing (F-2026-024 follow-up; minisign filesystem-native; `tetragon` apply.sh + check.sh re-use `selfdefctl keys verify` against .minisig siblings; turn on via `require_signed_policies = true` in /etc/selfdef/modules/tetragon.toml; caveat agent-guard renders policies at runtime + that output isn't pre-signed) | SDD-004 § D-4 + § Q-C answer | E0200 |
| M00490 | Known gap shipped — Eventstream JSONL integrity (F-2026-026 follow-up; opt-in; `[collectors.eventstream].integrity_check = true` refuses to tail any path world-writable OR owned by UID outside {daemon-uid, root} ∪ allowed_owners; per-line HMAC NOT shipped — owner/mode verification was sufficient) | SDD-004 § D-4 | E0200 |
| M00491 | Known gap shipped — Metrics-token rotation (F-2026-023 follow-up; `selfdefctl api rotate-token` generates fresh 32-byte token + writes atomically to [api].token_file + optionally signals running daemon `--pid <pid>` or `--pid auto`; SIGUSR2 triggers re-read under shared Arc<RwLock<>> backing bearer middleware; in-flight requests authenticate against new token without dropping) | SDD-004 § D-4 | E0200 |
| M00492 | Known gap shipped — k8s label-RBAC posture (F-2026-025 follow-up; `selfdefctl rbac check` prints recommended posture + kubectl auth can-i commands; with --probe executes those commands for fixed subject set system:authenticated + system:unauthenticated + operator-supplied --as; exits non-zero if any subject can PATCH pod labels; spot-checking on fixed subject set, not cluster-wide enumeration) | SDD-004 § D-4 | E0200 |
| M00493 | D-5 Hardening checklist — AI-machine deployment audit-recommended posture (5-line copy-paste-able sidebar) | SDD-004 § D-5 | E0200 |
| M00494 | D-6 — `docs/src/security.md` is symlink to `../../SECURITY.md` (single source of truth; mdbook follows symlinks transparently on Linux) | SDD-004 § D-6 + § Implementation status | E0200 |
| M00495 | F-2027-003 important follow-up — read_euid() returned 0 silently on /proc/self/status read failure (integrity check accidentally permissive); Phase 2 PR #56 flipped to Option<u32> + falls back strict-safe | SDD-004 § Follow-up findings Important | E0200 |
| M00496 | F-2027-035 important follow-up — check_path_integrity used std::fs::metadata (stat, follows symlinks) then tokio::fs::File::open (also follows); Phase 2 PR #67 rewrote as O_NOFOLLOW-open + fstat-on-FD; closes TOCTOU window; refuses symlinks with typed IntegritySymlink variant | SDD-004 § Follow-up findings Important | E0200 |
| M00497 | F-2027-005/006/007/014/031/036 nice follow-ups — SIGUSR2 verifier hot-rotation (PR #58) + `selfdefctl keys verify-dir <dir>` batch verb replaces N-spawn loop (PR #57) + `selfdefctl rbac check --probe` 2→4 subjects (PR #57) + `selfdef_api::with_full_capability` gated behind test-helpers Cargo feature absent from release (PR #61) + TokenReloader::reload validates mode-0600 invariant refuses with LooseTokenMode (PR #69) + eventstream integrity check post-startup logrotate caveat documented | SDD-004 § Follow-up findings Nice | E0200 |
| M00498 | Test plan — 7 review-style checks (Assets exactly 10 rows / Adversaries exactly 6 classes 1-6 / Mitigations 8 layers original 6 + 2 new / Known gaps exactly 7 bullets 3 original + 4 new / Hardening checklist sidebar at end of Mitigations / SECURITY.md and docs/src/security.md byte-equivalent or symlink / Phase-1 ledger rows F-2026-023+024+025+026 gain "closed by SDD-004 implementation PR" back-reference) | SDD-004 § Test plan | E0200 |

## Features (F02161–F02280)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F02161 | SDD-004 status = implemented | SDD-004 § header | E0191 | composite | false |
| F02162 | SDD-004 owner = audit team | SDD-004 § header | E0191 | composite | false |
| F02163 | SDD-004 last updated = 2026-05-13 | SDD-004 § header | E0191 | composite | false |
| F02164 | SDD-004 closes findings = F-2026-023, F-2026-024, F-2026-025, F-2026-026 | SDD-004 § header | E0191 | composite | false |
| F02165 | docs/src/security.md is symlink to ../../SECURITY.md (eliminating drift surface) | SDD-004 § Implementation status + § D-6 | M00494 | composite | false |
| F02166 | Problem — SECURITY.md was written when daemon was entire surface | SDD-004 § Problem | E0191 | composite | false |
| F02167 | Post-M15 work introduced 4 new attack surfaces the threat model does not acknowledge | SDD-004 § Problem | E0191 | composite | false |
| F02168 | F-2026-023 — /metrics Prometheus endpoint (PR #23) | SDD-004 § Problem F-2026-023 | M00473 | composite | false |
| F02169 | /metrics exposes counters that fingerprint host activity (events/sec by class, findings/sec by severity, daemon uptime, store size) | SDD-004 § Problem F-2026-023 | M00473 | composite | false |
| F02170 | /metrics — Assets table doesn't list it | SDD-004 § Problem F-2026-023 | M00473 | composite | false |
| F02171 | /metrics — bearer-token rotation story unspecified | SDD-004 § Problem F-2026-023 | M00473 | composite | false |
| F02172 | /metrics — chained-attack possibility (uptime gauge → time credential-file edit to daemon restart) isn't mentioned | SDD-004 § Problem F-2026-023 | M00473 | composite | false |
| F02173 | F-2026-024 — Tetragon TracingPolicy drop directory /etc/tetragon/tetragon.tp.d/ (PR #22) | SDD-004 § Problem F-2026-024 | M00474 | composite | false |
| F02174 | TracingPolicy dir — writable directory kernel reads policy from | SDD-004 § Problem F-2026-024 | M00474 | composite | false |
| F02175 | TracingPolicy dir — attacker with write access can inject Sigkill / Override / NotifyKiller policies | SDD-004 § Problem F-2026-024 | M00474 | composite | false |
| F02176 | TracingPolicy dir — mask legitimate detection by replacing agent-guard policies with permissive variants | SDD-004 § Problem F-2026-024 | M00474 | composite | false |
| F02177 | TracingPolicy dir — disable monitoring outright | SDD-004 § Problem F-2026-024 | M00474 | composite | false |
| F02178 | TracingPolicy dir — not in Assets table; no mode/ownership/signing requirement documented | SDD-004 § Problem F-2026-024 | M00474 | composite | false |
| F02179 | F-2026-025 — pod-label scope in agent-guard v0.3.0 (PR #25) | SDD-004 § Problem F-2026-025 | M00475 | composite | false |
| F02180 | pod-label scope selectors — matchPodSelector matchLabels.<key>=<value> | SDD-004 § Problem F-2026-025 | M00475 | composite | false |
| F02181 | pod-label scope — moves policy boundary from "every container on host" to "every pod carrying this label" | SDD-004 § Problem F-2026-025 | M00475 | composite | false |
| F02182 | pod-label scope — Kubernetes anyone with PATCH rights on Pod labels can opt unrelated pods INTO policies (denial-of-service-of-attention) | SDD-004 § Problem F-2026-025 | M00475 | composite | false |
| F02183 | pod-label scope — or opt actual agent pod OUT (defeat) | SDD-004 § Problem F-2026-025 | M00475 | composite | false |
| F02184 | pod-label scope — Adversaries table doesn't have cluster-RBAC-aware adversary | SDD-004 § Problem F-2026-025 | M00475 | composite | false |
| F02185 | pod-label scope — no guidance on label governance | SDD-004 § Problem F-2026-025 | M00475 | composite | false |
| F02186 | F-2026-026 — eventstream JSONL trust boundary | SDD-004 § Problem F-2026-026 | M00476 | composite | false |
| F02187 | eventstream collector parses any JSON line in any file at any path it's configured to tail | SDD-004 § Problem F-2026-026 | M00476 | composite | false |
| F02188 | `selfdefctl events emit` makes injecting events programmatic | SDD-004 § Problem F-2026-026 | M00476 | composite | false |
| F02189 | Threat model treated daemon as trusted but treats bus as stream of trusted events | SDD-004 § Problem F-2026-026 | M00476 | composite | false |
| F02190 | Reality — every line in those JSONL files is an event-injection vector | SDD-004 § Problem F-2026-026 | M00476 | composite | false |
| F02191 | eventstream JSONL — no documented ownership/mode requirement | SDD-004 § Problem F-2026-026 | M00476 | composite | false |
| F02192 | eventstream JSONL — no integrity check at parse time | SDD-004 § Problem F-2026-026 | M00476 | composite | false |
| F02193 | Rewrite is ADDITIVE — keep existing material + fold 4 surfaces into right tables + add small new sections + update Known gaps | SDD-004 § Problem | E0191 | composite | false |
| F02194 | Goal 1 — every surface that ships in catalog has a row in Assets table | SDD-004 § Goals 1 | E0196 | composite | false |
| F02195 | Goal 2 — every adversary class that can plausibly act against new surfaces is named in Adversaries table | SDD-004 § Goals 2 | E0196 | composite | false |
| F02196 | Goal 3 — each surface has explicit Mitigation guidance operator can act on (file modes / ownership / scrape-config patterns) | SDD-004 § Goals 3 | E0196 | composite | false |
| F02197 | Goal 4 — "Known gaps" list explicitly names the 4 not-yet-mitigated items the rewrite reveals | SDD-004 § Goals 4 | E0196 | composite | false |
| F02198 | Goal 5 — rewrite stays operator-readable (SECURITY.md is NOT an SDD; keep short, declarative, useful) | SDD-004 § Goals 5 | E0196 | composite | false |
| F02199 | Goal 6 — rewrite lands in BOTH places at once (repo-root SECURITY.md + mdbook mirror docs/src/security.md) | SDD-004 § Goals 6 | E0196 | composite | false |
| F02200 | Goal 6 — two places stay byte-equivalent today | SDD-004 § Goals 6 | E0196 | composite | false |
| F02201 | Non-goal — implementing any of the mitigations (this is a documentation rewrite; implementations tracked as future SDDs) | SDD-004 § Non-goals | E0191 | composite | false |
| F02202 | Non-goal — changing Adversary numbering (5 existing classes stay as-is; rewrite adds sixth) | SDD-004 § Non-goals | M00480 | composite | false |
| F02203 | Non-goal — replacing SECURITY.md style (tables stay; section ordering stays) | SDD-004 § Non-goals | E0191 | composite | false |
| F02204 | Alternative A (inline expansion) — Pros: smallest diff; no reorganization risk | SDD-004 § Alternative A | E0197 | composite | false |
| F02205 | Alternative A — Con: Assets table grows from 7 to 10 rows; feels mixed | SDD-004 § Alternative A | E0197 | composite | false |
| F02206 | Alternative B (new "Module-introduced surfaces" section) — Pros: clean separation between daemon's threat model and module-side | SDD-004 § Alternative B | E0197 | composite | false |
| F02207 | Alternative B — Con: splits threat model into two reading passes; implies daemon-side and module-side unrelated (which they aren't — eventstream JSONL written by modules but parsed by daemon's collector) | SDD-004 § Alternative B | E0197 | composite | false |
| F02208 | Alternative C (recommended HYBRID) — expand existing tables inline + add 2 new layers to Mitigations section + update Known gaps to enumerate 4 not-yet-mitigated items | SDD-004 § Alternative C + § Recommended design | E0197 | composite | false |
| F02209 | Alternative C combines A's clarity-of-place with B's clarity-of-grouping for new mitigation guidance that doesn't fit existing layers | SDD-004 § Alternative C | E0197 | composite | false |
| F02210 | D-1 Asset 8 — /metrics endpoint (UNIX socket /run/selfdef.sock or TCP <bind>) | SDD-004 § D-1 | M00477 | composite | true |
| F02211 | D-1 Asset 8 threat — Activity-fingerprint information; chained-attack timing of credential edits to daemon restart | SDD-004 § D-1 | M00477 | composite | false |
| F02212 | D-1 Asset 9 — TracingPolicy directory (/etc/tetragon/tetragon.tp.d/) | SDD-004 § D-1 | M00478 | composite | true |
| F02213 | D-1 Asset 9 threat — Writable: malicious YAML loads as kernel-level eBPF policy (Sigkill / Override / NotifyKiller / mask) | SDD-004 § D-1 | M00478 | composite | false |
| F02214 | D-1 Asset 10 — Eventstream JSONL paths (Varies — see [collectors.eventstream].paths) | SDD-004 § D-1 | M00479 | composite | true |
| F02215 | D-1 Asset 10 threat — Event-injection vector; crafted Findings can fire notifier chain or pollute multi-host NATS bridge via host_tag spoofing | SDD-004 § D-1 | M00479 | composite | false |
| F02216 | Assets table totals 10 rows after SDD-004 | SDD-004 § Test plan 1 + § Implementation status | M00498 | composite | false |
| F02217 | D-2 Adversary class 6 — Cluster-tenant attacker | SDD-004 § D-2 | M00480 | composite | true |
| F02218 | Cluster-tenant attacker capability — Pod-label PATCH rights on cluster (k8s only) | SDD-004 § D-2 | M00480 | composite | false |
| F02219 | Cluster-tenant attacker target — defeat agent-guard pod-label scoping | SDD-004 § D-2 | M00480 | composite | false |
| F02220 | Cluster-tenant attacker detection — matchPodSelector + label-RBAC posture | SDD-004 § D-2 | M00480 | composite | false |
| F02221 | Adversaries table totals 6 classes numbered 1-6 | SDD-004 § Test plan 2 + § Implementation status | M00480 + M00498 | composite | false |
| F02222 | D-3 Mitigations new layer — API surface | SDD-004 § D-3 | E0199 | composite | false |
| F02223 | API surface — UNIX socket transport (filesystem permissions = auth boundary; default 0660 root:adm) | SDD-004 § D-3 API surface | M00481 | composite | true |
| F02224 | UNIX socket transport — recommended for on-host scrapers (Prometheus on same host) | SDD-004 § D-3 API surface | M00481 | composite | false |
| F02225 | API surface — TCP transport (bearer-token required on every request) | SDD-004 § D-3 API surface | M00482 | composite | true |
| F02226 | TCP transport — `bearer_token_file` in Prometheus scrape config | SDD-004 § D-3 API surface | M00482 | composite | false |
| F02227 | TCP transport — mode 0600 on token file | SDD-004 § D-3 API surface | M00482 | composite | false |
| F02228 | TCP transport — rotate via daemon restart (token read at startup, never re-read from disk per Notification mitigation already in §6.3) | SDD-004 § D-3 API surface | M00482 | composite | false |
| F02229 | API surface — TLS/mTLS opt-in (required when binding outside 127.0.0.1) | SDD-004 § D-3 API surface | M00483 | composite | true |
| F02230 | API surface — `/metrics` is read-cap | SDD-004 § D-3 API surface | M00484 | composite | false |
| F02231 | Read-cap — same bearer token grants read access to /status / /events / /findings / /events/stream / /metrics | SDD-004 § D-3 API surface | M00484 | composite | false |
| F02232 | Read-cap — does NOT grant control-verb access (/rules/reload, /panic, /actions/*/run) | SDD-004 § D-3 API surface | M00484 | composite | false |
| F02233 | Control-verb access — needs separate `control_token_file` | SDD-004 § D-3 API surface | M00484 | composite | false |
| F02234 | API surface — Side channel `selfdef_uptime_seconds` lets scraper detect daemon restart | SDD-004 § D-3 API surface | M00485 | composite | false |
| F02235 | Side-channel mitigation — Rotate notifier credentials via deliberate operator action, not automated watchers that key on uptime resets | SDD-004 § D-3 API surface | M00485 | composite | false |
| F02236 | D-3 Mitigations new layer — Policy surface | SDD-004 § D-3 Policy surface | E0199 | composite | false |
| F02237 | Policy surface — TracingPolicy directory mode recommended `0750 root:root` | SDD-004 § D-3 Policy surface | M00486 | composite | true |
| F02238 | Policy surface — only agent-guard + operator-approved policy modules should write to TracingPolicy dir | SDD-004 § D-3 Policy surface | M00486 | composite | false |
| F02239 | Policy surface — integrity-sentinel paths file should baseline TracingPolicy dir contents | SDD-004 § D-3 Policy surface | M00486 | composite | true |
| F02240 | Policy surface — Pod-label scope policy boundary is configured label | SDD-004 § D-3 Policy surface | M00487 | composite | false |
| F02241 | Policy surface — Any cluster identity with PATCH on Pod's labels can move boundary | SDD-004 § D-3 Policy surface | M00487 | composite | false |
| F02242 | Policy surface — document required RBAC posture in cluster's Role/RoleBinding for namespace agent-guard watches | SDD-004 § D-3 Policy surface | M00487 | composite | true |
| F02243 | Policy surface — Eventstream JSONL trust: every line in every path is event daemon will treat as if collector emitted it | SDD-004 § D-3 Policy surface | M00488 | composite | false |
| F02244 | Policy surface — Daemon-owned eventstream dirs (default `/var/lib/selfdef/eventstream/`) should be `0750 selfdef:selfdef` | SDD-004 § D-3 Policy surface | M00488 | composite | true |
| F02245 | Policy surface — Operator-owned emitters (e.g. user's `~/.local/share/selfdef/ssh-wrap.jsonl`) inherit user's trust posture | SDD-004 § D-3 Policy surface | M00488 | composite | false |
| F02246 | Policy surface — compromise of that user's account is event-injection | SDD-004 § D-3 Policy surface | M00488 | composite | false |
| F02247 | D-4 — Known gaps extended with 4 follow-up entries | SDD-004 § D-4 | E0200 | composite | false |
| F02248 | Known gap shipped — TracingPolicy signing (F-2026-024 follow-up via minisign) | SDD-004 § D-4 + § Q-C answer | M00489 | composite | true |
| F02249 | TracingPolicy signing — `tetragon` module's apply.sh + check.sh re-use `selfdefctl keys verify` against `.minisig` siblings | SDD-004 § D-4 | M00489 | composite | true |
| F02250 | TracingPolicy signing — turn on via `require_signed_policies = true` in `/etc/selfdef/modules/tetragon.toml` | SDD-004 § D-4 | M00489 | composite | true |
| F02251 | TracingPolicy signing — caveat: agent-guard renders policies at runtime; that output isn't pre-signed (intentional, documented) | SDD-004 § D-4 | M00489 | composite | false |
| F02252 | TracingPolicy signing — implementation departed from original cosign framing in favor of minisign for filesystem-native distribution | SDD-004 § D-4 | M00489 | composite | false |
| F02253 | Known gap shipped — Eventstream JSONL integrity (F-2026-026 follow-up; opt-in) | SDD-004 § D-4 | M00490 | composite | true |
| F02254 | Eventstream integrity — `[collectors.eventstream].integrity_check = true` | SDD-004 § D-4 | M00490 | composite | true |
| F02255 | Eventstream integrity — daemon refuses to tail any path world-writable OR owned by UID outside {daemon-uid, root} ∪ allowed_owners | SDD-004 § D-4 | M00490 | composite | false |
| F02256 | Eventstream integrity — disabled by default to preserve operator-owned emitters like `~/.local/share/selfdef/ssh-wrap.jsonl` | SDD-004 § D-4 | M00490 | composite | false |
| F02257 | Eventstream integrity — per-line HMAC NOT shipped (owner/mode verification was sufficient for threat profile) | SDD-004 § D-4 | M00490 | composite | false |
| F02258 | Known gap shipped — Metrics-token rotation (F-2026-023 follow-up) | SDD-004 § D-4 | M00491 | composite | true |
| F02259 | Metrics-token rotation — `selfdefctl api rotate-token` ships | SDD-004 § D-4 | M00491 | composite | true |
| F02260 | Metrics-token rotation — generates fresh 32-byte token | SDD-004 § D-4 | M00491 | composite | false |
| F02261 | Metrics-token rotation — writes atomically to `[api].token_file` | SDD-004 § D-4 | M00491 | composite | false |
| F02262 | Metrics-token rotation — optionally signals running daemon (`--pid <pid>` or `--pid auto`) | SDD-004 § D-4 | M00491 | composite | true |
| F02263 | Metrics-token rotation — SIGUSR2 triggers re-read under shared `Arc<RwLock<>>` backing bearer middleware | SDD-004 § D-4 | M00491 | composite | false |
| F02264 | Metrics-token rotation — in-flight requests authenticate against new token without dropping | SDD-004 § D-4 | M00491 | composite | false |
| F02265 | Known gap shipped — k8s label-RBAC posture (F-2026-025 follow-up) | SDD-004 § D-4 | M00492 | composite | true |
| F02266 | k8s RBAC — `selfdefctl rbac check` prints recommended posture + `kubectl auth can-i` commands | SDD-004 § D-4 | M00492 | composite | true |
| F02267 | k8s RBAC — `--probe` executes commands for fixed subject set (`system:authenticated`, `system:unauthenticated`, plus operator-supplied `--as`) | SDD-004 § D-4 | M00492 | composite | true |
| F02268 | k8s RBAC — exits non-zero if any subject can PATCH pod labels | SDD-004 § D-4 | M00492 | composite | false |
| F02269 | k8s RBAC — spot-checking on fixed subject set, NOT cluster-wide enumeration | SDD-004 § D-4 | M00492 | composite | false |
| F02270 | k8s RBAC — operators needing exhaustive analysis run `rbac-tool` or `kubectl-who-can` separately | SDD-004 § D-4 | M00492 | composite | false |
| F02271 | D-5 Hardening checklist — `/etc/tetragon/tetragon.tp.d/`: 0750 root:root | SDD-004 § D-5 | M00493 | composite | true |
| F02272 | D-5 Hardening checklist — `/var/lib/selfdef/eventstream/`: 0750 selfdef:selfdef | SDD-004 § D-5 | M00493 | composite | true |
| F02273 | D-5 Hardening checklist — `/etc/selfdef/api.token`: 0600 root:selfdef (or 0600 prometheus:prometheus on scraper host) | SDD-004 § D-5 | M00493 | composite | true |
| F02274 | D-5 Hardening checklist — agent-guard pod-label scope: cluster RBAC restricts Pod-label PATCH to cluster-admin | SDD-004 § D-5 | M00493 | composite | true |
| F02275 | D-5 Hardening checklist — integrity-sentinel paths file includes /etc/tetragon/, /etc/selfdef/, /var/lib/selfdef/eventstream/ | SDD-004 § D-5 | M00493 | composite | true |
| F02276 | D-5 — block intentionally short; anyone deploying AI-machine track should be able to copy-paste into hardening runbook | SDD-004 § D-5 | M00493 | composite | false |
| F02277 | D-6 doc mirror — symlink chosen (fewer drift opportunities); fallback was lockstep edits with CI check | SDD-004 § D-6 + § Implementation status | M00494 | composite | false |
| F02278 | F-2027-003 important — `selfdef-collector-eventstream`'s `read_euid()` returned 0 silently on /proc/self/status read failure; integrity check accidentally permissive; Phase 2 PR #56 flipped to Option<u32> + falls back strict-safe | SDD-004 § Follow-up findings Important | M00495 | composite | false |
| F02279 | F-2027-035 important — `check_path_integrity` used std::fs::metadata (stat, follows symlinks) then tokio::fs::File::open (also follows); Phase 2 PR #67 rewrote as O_NOFOLLOW-open + fstat-on-FD; closes TOCTOU window; refuses symlinks with typed IntegritySymlink variant | SDD-004 § Follow-up findings Important | M00496 | composite | false |
| F02280 | Composite — SDD-004 ships D-1..D-6 + Hardening checklist + 8 phase-2 follow-ups (2 important + 6 nice); closes F-2026-023+024+025+026 at all 4 audit levels (Assets / Adversaries / Mitigations / Known gaps); SECURITY.md byte-equivalent to docs/src/security.md via symlink; threat model now covers /metrics + TracingPolicy dir + eventstream JSONL + cluster-tenant attacker (k8s); 4 shipped opt-in features (TracingPolicy signing minisign / eventstream integrity owner-mode / metrics-token SIGUSR2 / RBAC posture probe) | SDD-004 entire | E0191 + E0192 + E0193 + E0194 + E0195 + E0196 + E0197 + E0198 + E0199 + E0200 | composite | false |

## Requirements (R04321–R04560)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R04321 | SDD-004 status = implemented | SDD-004 § header | F02161 | non-negotiable | false | 10 |
| R04322 | SDD-004 closes F-2026-023, F-2026-024, F-2026-025, F-2026-026 | SDD-004 § header | F02164 | non-negotiable | false | 10 |
| R04323 | docs/src/security.md is symlink to ../../SECURITY.md per D-6 | SDD-004 § Implementation status + § D-6 | F02165 | non-negotiable | false | 10 |
| R04324 | Symlink eliminates drift surface | SDD-004 § Implementation status | F02165 | non-negotiable | false | 10 |
| R04325 | SECURITY.md was written when daemon was entire surface | SDD-004 § Problem | F02166 | non-negotiable | false | 10 |
| R04326 | Post-M15 work introduced 4 new attack surfaces threat model didn't acknowledge | SDD-004 § Problem | F02167 | non-negotiable | false | 10 |
| R04327 | F-2026-023 — `/metrics` Prometheus endpoint (PR #23) is an attack surface | SDD-004 § Problem F-2026-023 | F02168 | non-negotiable | false | 10 |
| R04328 | /metrics exposes events/sec by class counter | SDD-004 § Problem F-2026-023 | F02169 | non-negotiable | false | 10 |
| R04329 | /metrics exposes findings/sec by severity counter | SDD-004 § Problem F-2026-023 | F02169 | non-negotiable | false | 10 |
| R04330 | /metrics exposes daemon uptime counter | SDD-004 § Problem F-2026-023 | F02169 | non-negotiable | false | 10 |
| R04331 | /metrics exposes store size counter | SDD-004 § Problem F-2026-023 | F02169 | non-negotiable | false | 10 |
| R04332 | F-2026-024 — Tetragon TracingPolicy drop directory `/etc/tetragon/tetragon.tp.d/` (PR #22) is an attack surface | SDD-004 § Problem F-2026-024 | F02173 | non-negotiable | false | 10 |
| R04333 | TracingPolicy dir is writable directory kernel reads policy from | SDD-004 § Problem F-2026-024 | F02174 | non-negotiable | false | 10 |
| R04334 | Attacker can inject Sigkill / Override / NotifyKiller policies | SDD-004 § Problem F-2026-024 | F02175 | non-negotiable | false | 10 |
| R04335 | Attacker can mask legitimate detection by replacing agent-guard policies with permissive variants | SDD-004 § Problem F-2026-024 | F02176 | non-negotiable | false | 10 |
| R04336 | Attacker can disable monitoring outright | SDD-004 § Problem F-2026-024 | F02177 | non-negotiable | false | 10 |
| R04337 | F-2026-025 — pod-label scope in agent-guard v0.3.0 (PR #25) is an attack surface | SDD-004 § Problem F-2026-025 | F02179 | non-negotiable | false | 10 |
| R04338 | pod-label scope selectors — matchPodSelector matchLabels.<key>=<value> | SDD-004 § Problem F-2026-025 | F02180 | non-negotiable | false | 10 |
| R04339 | pod-label scope moves policy boundary from "every container on host" to "every pod carrying this label" | SDD-004 § Problem F-2026-025 | F02181 | non-negotiable | false | 10 |
| R04340 | Anyone with PATCH rights on Pod labels can opt unrelated pods INTO policies (denial-of-service-of-attention) | SDD-004 § Problem F-2026-025 | F02182 | non-negotiable | false | 10 |
| R04341 | Anyone with PATCH rights on Pod labels can opt actual agent pod OUT (defeat) | SDD-004 § Problem F-2026-025 | F02183 | non-negotiable | false | 10 |
| R04342 | F-2026-026 — eventstream JSONL trust boundary is an attack surface | SDD-004 § Problem F-2026-026 | F02186 | non-negotiable | false | 10 |
| R04343 | eventstream collector parses any JSON line in any file at any path configured to tail | SDD-004 § Problem F-2026-026 | F02187 | non-negotiable | false | 10 |
| R04344 | `selfdefctl events emit` makes injecting events programmatic | SDD-004 § Problem F-2026-026 | F02188 | non-negotiable | false | 10 |
| R04345 | Every line in JSONL files is an event-injection vector | SDD-004 § Problem F-2026-026 | F02190 | non-negotiable | false | 10 |
| R04346 | Rewrite is ADDITIVE | SDD-004 § Problem | F02193 | non-negotiable | false | 10 |
| R04347 | Rewrite folds 4 surfaces into right tables | SDD-004 § Problem | F02193 | non-negotiable | false | 10 |
| R04348 | Rewrite adds small new sections per surface where existing structure doesn't fit | SDD-004 § Problem | F02193 | non-negotiable | false | 10 |
| R04349 | Rewrite updates "Known gaps" list | SDD-004 § Problem | F02193 | non-negotiable | false | 10 |
| R04350 | Goal 1 — every surface in catalog has row in Assets table | SDD-004 § Goals 1 | F02194 | non-negotiable | false | 10 |
| R04351 | Goal 2 — every adversary class that can plausibly act against new surfaces is named in Adversaries table | SDD-004 § Goals 2 | F02195 | non-negotiable | false | 10 |
| R04352 | Goal 3 — each surface has explicit Mitigation guidance operator can act on | SDD-004 § Goals 3 | F02196 | non-negotiable | false | 10 |
| R04353 | Goal 4 — Known gaps list explicitly names 4 not-yet-mitigated items | SDD-004 § Goals 4 | F02197 | non-negotiable | false | 10 |
| R04354 | Goal 5 — rewrite stays operator-readable | SDD-004 § Goals 5 | F02198 | non-negotiable | false | 10 |
| R04355 | Goal 5 — SECURITY.md is NOT an SDD; keep short, declarative, useful as threat-model reference | SDD-004 § Goals 5 | F02198 | non-negotiable | false | 10 |
| R04356 | Goal 6 — rewrite lands in BOTH places at once (repo-root SECURITY.md + mdbook mirror docs/src/security.md) | SDD-004 § Goals 6 | F02199 | non-negotiable | false | 10 |
| R04357 | Goal 6 — two files stay byte-equivalent | SDD-004 § Goals 6 | F02200 | non-negotiable | false | 10 |
| R04358 | Non-goal — implementing any of the mitigations | SDD-004 § Non-goals | F02201 | non-negotiable | false | 10 |
| R04359 | Non-goal — implementations (signed TracingPolicies, integrity-checked eventstream, automatic token rotation) tracked as own future SDDs | SDD-004 § Non-goals | F02201 | non-negotiable | false | 10 |
| R04360 | Non-goal — changing Adversary numbering | SDD-004 § Non-goals | F02202 | non-negotiable | false | 10 |
| R04361 | Non-goal — 5 existing adversary classes stay as-is; rewrite adds sixth ("Cluster-tenant attacker") under k8s-aware deployments | SDD-004 § Non-goals | F02202 | non-negotiable | false | 10 |
| R04362 | Non-goal — replacing SECURITY.md style (tables stay; section ordering stays) | SDD-004 § Non-goals | F02203 | non-negotiable | false | 10 |
| R04363 | Glossary — Asset = thing on host whose tampering / exfiltration affects detection | SDD-004 § Glossary | E0191 | non-negotiable | false | 10 |
| R04364 | Glossary — Adversary = numbered class with stated capability level | SDD-004 § Glossary | E0191 | non-negotiable | false | 10 |
| R04365 | Glossary — Mitigation by layer = existing organization of Mitigations section | SDD-004 § Glossary | E0191 | non-negotiable | false | 10 |
| R04366 | Glossary — Rewrite adds 2 layers (API surface + Policy surface) | SDD-004 § Glossary | E0199 | non-negotiable | false | 10 |
| R04367 | Original Assets table has 7 rows (daemon binary / config / rules / hot store / cold archive / notification credentials / eBPF programs) | SDD-004 § Current state | E0191 | non-negotiable | false | 10 |
| R04368 | Original Adversaries table has 5 classes | SDD-004 § Current state | E0191 | non-negotiable | false | 10 |
| R04369 | Original Mitigations has 6 layers (Build / Process / Configuration & rules / Storage / Notification / Tamper detection) | SDD-004 § Current state | E0199 | non-negotiable | false | 10 |
| R04370 | Original Known gaps has 3 bullets (dm-verity / remote attestation / rule signing) | SDD-004 § Current state | E0200 | non-negotiable | false | 10 |
| R04371 | Alternative A — inline expansion of every existing section (rejected: too mixed) | SDD-004 § Alternative A | F02204 | non-negotiable | false | 10 |
| R04372 | Alternative B — new "Module-introduced surfaces" section (rejected: splits reading passes; implies daemon/module surfaces unrelated) | SDD-004 § Alternative B | F02206 | non-negotiable | false | 10 |
| R04373 | Alternative C (recommended) — Hybrid; expand existing tables inline + add 2 new Mitigations layers + extended Known gaps | SDD-004 § Alternative C + § Recommended design | F02208 | non-negotiable | false | 10 |
| R04374 | D-1 — Assets table grows by 3 rows (total 10) | SDD-004 § D-1 + § Implementation status | F02216 | non-negotiable | false | 10 |
| R04375 | Asset row 8 — `/metrics` endpoint | SDD-004 § D-1 | F02210 | non-negotiable | true | 10 |
| R04376 | Asset row 8 location — UNIX socket /run/selfdef.sock or TCP <bind> | SDD-004 § D-1 | F02210 | non-negotiable | false | 10 |
| R04377 | Asset row 8 threat — Activity-fingerprint information; chained-attack timing of credential edits to daemon restart | SDD-004 § D-1 | F02211 | non-negotiable | false | 10 |
| R04378 | Asset row 9 — TracingPolicy directory | SDD-004 § D-1 | F02212 | non-negotiable | true | 10 |
| R04379 | Asset row 9 location — /etc/tetragon/tetragon.tp.d/ | SDD-004 § D-1 | F02212 | non-negotiable | false | 10 |
| R04380 | Asset row 9 threat — Writable: malicious YAML loads as kernel-level eBPF policy (Sigkill / Override / NotifyKiller / mask) | SDD-004 § D-1 | F02213 | non-negotiable | false | 10 |
| R04381 | Asset row 10 — Eventstream JSONL paths | SDD-004 § D-1 | F02214 | non-negotiable | true | 10 |
| R04382 | Asset row 10 location — Varies — see [collectors.eventstream].paths | SDD-004 § D-1 | F02214 | non-negotiable | false | 10 |
| R04383 | Asset row 10 threat — Event-injection vector; Crafted Findings can fire notifier chain or pollute multi-host NATS bridge via host_tag spoofing | SDD-004 § D-1 | F02215 | non-negotiable | false | 10 |
| R04384 | D-2 — Adversaries table grows by 1 class (total 6) | SDD-004 § D-2 + § Implementation status | F02221 | non-negotiable | false | 10 |
| R04385 | Adversary class 6 — Cluster-tenant attacker | SDD-004 § D-2 | F02217 | non-negotiable | true | 10 |
| R04386 | Adversary class 6 capability — Pod-label PATCH rights on cluster (k8s only) | SDD-004 § D-2 | F02218 | non-negotiable | false | 10 |
| R04387 | Adversary class 6 target — defeat agent-guard pod-label scoping | SDD-004 § D-2 | F02219 | non-negotiable | false | 10 |
| R04388 | Adversary class 6 detection — matchPodSelector + label-RBAC posture | SDD-004 § D-2 | F02220 | non-negotiable | false | 10 |
| R04389 | Adversaries numbered class 6 (sequential after 5) | SDD-004 § D-2 | M00480 | non-negotiable | false | 10 |
| R04390 | D-3 — Mitigations grows by 2 new layers | SDD-004 § D-3 + § Implementation status | E0199 | non-negotiable | false | 10 |
| R04391 | Mitigations new layer — API surface | SDD-004 § D-3 API surface | F02222 | non-negotiable | true | 10 |
| R04392 | API surface — UNIX socket transport filesystem permissions are auth boundary | SDD-004 § D-3 API surface | M00481 | non-negotiable | false | 10 |
| R04393 | API surface — UNIX socket default 0660 root:adm | SDD-004 § D-3 API surface | F02223 | non-negotiable | true | 10 |
| R04394 | API surface — UNIX socket recommended for on-host scrapers (Prometheus on same host) | SDD-004 § D-3 API surface | F02224 | non-negotiable | false | 10 |
| R04395 | API surface — TCP transport bearer-token required on every request | SDD-004 § D-3 API surface | F02225 | non-negotiable | false | 10 |
| R04396 | API surface — TCP transport `bearer_token_file` in Prometheus scrape config | SDD-004 § D-3 API surface | F02226 | non-negotiable | true | 10 |
| R04397 | API surface — TCP transport token-file mode 0600 | SDD-004 § D-3 API surface | F02227 | non-negotiable | true | 10 |
| R04398 | API surface — TCP transport rotate via daemon restart (pre-SDD-004 baseline) | SDD-004 § D-3 API surface | F02228 | non-negotiable | false | 10 |
| R04399 | API surface — TCP transport token read at startup, never re-read from disk (per Notification mitigation §6.3) | SDD-004 § D-3 API surface | F02228 | non-negotiable | false | 10 |
| R04400 | API surface — TLS/mTLS opt-in (required when binding outside 127.0.0.1) | SDD-004 § D-3 API surface | F02229 | non-negotiable | true | 10 |
| R04401 | API surface — `/metrics` is read-cap (same bearer token grants /status + /events + /findings + /events/stream + /metrics) | SDD-004 § D-3 API surface | F02230 + F02231 | non-negotiable | false | 10 |
| R04402 | API surface — read-cap does NOT grant control-verb access | SDD-004 § D-3 API surface | F02232 | non-negotiable | false | 10 |
| R04403 | API surface — control-verb access (/rules/reload, /panic, /actions/*/run) needs separate `control_token_file` | SDD-004 § D-3 API surface | F02233 | non-negotiable | false | 10 |
| R04404 | API surface — Side channel `selfdef_uptime_seconds` lets scraper detect daemon restart | SDD-004 § D-3 API surface | F02234 | non-negotiable | false | 10 |
| R04405 | API surface — Rotate notifier credentials via deliberate operator action, not automated watchers that key on uptime resets | SDD-004 § D-3 API surface | F02235 | non-negotiable | false | 10 |
| R04406 | Mitigations new layer — Policy surface | SDD-004 § D-3 Policy surface | F02236 | non-negotiable | true | 10 |
| R04407 | Policy surface — TracingPolicy directory mode recommended `0750 root:root` | SDD-004 § D-3 Policy surface | F02237 | non-negotiable | true | 10 |
| R04408 | Policy surface — only agent-guard + operator-approved policy modules should write to TracingPolicy dir | SDD-004 § D-3 Policy surface | F02238 | non-negotiable | false | 10 |
| R04409 | Policy surface — integrity-sentinel paths file should baseline TracingPolicy dir contents | SDD-004 § D-3 Policy surface | F02239 | non-negotiable | true | 10 |
| R04410 | Policy surface — Pod-label scope policy boundary is configured label (`pod_label_key=pod_label_value`) | SDD-004 § D-3 Policy surface | F02240 | non-negotiable | false | 10 |
| R04411 | Policy surface — Any cluster identity with PATCH on Pod's labels can move boundary | SDD-004 § D-3 Policy surface | F02241 | non-negotiable | false | 10 |
| R04412 | Policy surface — Document required RBAC posture in cluster's Role / RoleBinding for namespace agent-guard watches | SDD-004 § D-3 Policy surface | F02242 | non-negotiable | true | 10 |
| R04413 | Policy surface — Eventstream JSONL trust: every line is event daemon treats as if collector emitted | SDD-004 § D-3 Policy surface | F02243 | non-negotiable | false | 10 |
| R04414 | Policy surface — Daemon-owned eventstream dirs (default `/var/lib/selfdef/eventstream/`) should be `0750 selfdef:selfdef` | SDD-004 § D-3 Policy surface | F02244 | non-negotiable | true | 10 |
| R04415 | Policy surface — Operator-owned emitters inherit user's trust posture | SDD-004 § D-3 Policy surface | F02245 | non-negotiable | false | 10 |
| R04416 | Policy surface — Compromise of user's account is event-injection | SDD-004 § D-3 Policy surface | F02246 | non-negotiable | false | 10 |
| R04417 | D-4 — Known gaps extended with 4 follow-up entries | SDD-004 § D-4 | F02247 | non-negotiable | false | 10 |
| R04418 | Known gap shipped — TracingPolicy signing (F-2026-024 follow-up) | SDD-004 § D-4 + § Q-C answer | F02248 | non-negotiable | true | 10 |
| R04419 | TracingPolicy signing — minisign filesystem-native + offline-capable | SDD-004 § Q-C answer + § D-4 | M00489 | non-negotiable | false | 10 |
| R04420 | TracingPolicy signing — `tetragon` module's apply.sh + check.sh re-use `selfdefctl keys verify` against `.minisig` siblings | SDD-004 § D-4 | F02249 | non-negotiable | true | 10 |
| R04421 | TracingPolicy signing — turn on via `require_signed_policies = true` in `/etc/selfdef/modules/tetragon.toml` | SDD-004 § D-4 | F02250 | non-negotiable | true | 10 |
| R04422 | TracingPolicy signing caveat — agent-guard renders policies at runtime + that output isn't pre-signed (intentional, documented) | SDD-004 § D-4 | F02251 | non-negotiable | false | 10 |
| R04423 | TracingPolicy signing — implementation departed from original cosign framing in favor of minisign for filesystem-native distribution | SDD-004 § D-4 | F02252 | non-negotiable | false | 10 |
| R04424 | Known gap shipped — Eventstream JSONL integrity (F-2026-026 follow-up; opt-in) | SDD-004 § D-4 | F02253 | non-negotiable | true | 10 |
| R04425 | Eventstream integrity — `[collectors.eventstream].integrity_check = true` | SDD-004 § D-4 | F02254 | non-negotiable | true | 10 |
| R04426 | Eventstream integrity — daemon refuses to tail any path world-writable | SDD-004 § D-4 | F02255 | non-negotiable | false | 10 |
| R04427 | Eventstream integrity — daemon refuses to tail any path owned by UID outside {daemon-effective-uid, root} ∪ allowed_owners | SDD-004 § D-4 | F02255 | non-negotiable | false | 10 |
| R04428 | Eventstream integrity — disabled by default to preserve operator-owned emitters | SDD-004 § D-4 | F02256 | non-negotiable | false | 10 |
| R04429 | Eventstream integrity — per-line HMAC NOT shipped (owner/mode verification was sufficient) | SDD-004 § D-4 | F02257 | non-negotiable | false | 10 |
| R04430 | Known gap shipped — Metrics-token rotation (F-2026-023 follow-up) | SDD-004 § D-4 | F02258 | non-negotiable | true | 10 |
| R04431 | Metrics-token rotation — `selfdefctl api rotate-token` ships | SDD-004 § D-4 | F02259 | non-negotiable | true | 10 |
| R04432 | Metrics-token rotation — generates fresh 32-byte token | SDD-004 § D-4 | F02260 | non-negotiable | false | 10 |
| R04433 | Metrics-token rotation — writes atomically to `[api].token_file` | SDD-004 § D-4 | F02261 | non-negotiable | false | 10 |
| R04434 | Metrics-token rotation — optionally signals running daemon `--pid <pid>` or `--pid auto` | SDD-004 § D-4 | F02262 | non-negotiable | true | 10 |
| R04435 | Metrics-token rotation — SIGUSR2 triggers re-read under shared Arc<RwLock<>> backing bearer middleware | SDD-004 § D-4 | F02263 | non-negotiable | false | 10 |
| R04436 | Metrics-token rotation — in-flight requests authenticate against new token without dropping | SDD-004 § D-4 | F02264 | non-negotiable | false | 10 |
| R04437 | Known gap shipped — k8s label-RBAC posture (F-2026-025 follow-up) | SDD-004 § D-4 | F02265 | non-negotiable | true | 10 |
| R04438 | k8s RBAC — `selfdefctl rbac check` prints recommended posture | SDD-004 § D-4 | F02266 | non-negotiable | true | 10 |
| R04439 | k8s RBAC — prints `kubectl auth can-i` commands | SDD-004 § D-4 | F02266 | non-negotiable | true | 10 |
| R04440 | k8s RBAC — `--probe` executes commands for fixed subject set | SDD-004 § D-4 | F02267 | non-negotiable | true | 10 |
| R04441 | k8s RBAC — fixed subject set `system:authenticated` | SDD-004 § D-4 | F02267 | non-negotiable | true | 10 |
| R04442 | k8s RBAC — fixed subject set `system:unauthenticated` | SDD-004 § D-4 | F02267 | non-negotiable | true | 10 |
| R04443 | k8s RBAC — fixed subject set + any operator-supplied `--as` | SDD-004 § D-4 | F02267 | non-negotiable | true | 10 |
| R04444 | k8s RBAC — exits non-zero if any subject can PATCH pod labels | SDD-004 § D-4 | F02268 | non-negotiable | false | 10 |
| R04445 | k8s RBAC — spot-checking on fixed subject set, NOT cluster-wide enumeration | SDD-004 § D-4 | F02269 | non-negotiable | false | 10 |
| R04446 | k8s RBAC — operators needing exhaustive analysis run rbac-tool or kubectl-who-can separately | SDD-004 § D-4 | F02270 | non-negotiable | false | 10 |
| R04447 | D-5 — Hardening checklist sidebar appears at end of Mitigations section | SDD-004 § D-5 + § Test plan 5 | M00498 | non-negotiable | false | 10 |
| R04448 | D-5 — Hardening checklist scoped to AI-machine deployment (tetragon + agent-guard + observability) | SDD-004 § D-5 | M00493 | non-negotiable | false | 10 |
| R04449 | Hardening checklist — `/etc/tetragon/tetragon.tp.d/`: 0750 root:root | SDD-004 § D-5 | F02271 | non-negotiable | true | 10 |
| R04450 | Hardening checklist — `/var/lib/selfdef/eventstream/`: 0750 selfdef:selfdef | SDD-004 § D-5 | F02272 | non-negotiable | true | 10 |
| R04451 | Hardening checklist — `/etc/selfdef/api.token`: 0600 root:selfdef | SDD-004 § D-5 | F02273 | non-negotiable | true | 10 |
| R04452 | Hardening checklist — or `/etc/selfdef/api.token`: 0600 prometheus:prometheus on scraper host | SDD-004 § D-5 | F02273 | non-negotiable | true | 10 |
| R04453 | Hardening checklist — agent-guard pod-label scope: cluster RBAC restricts Pod-label PATCH to cluster-admin | SDD-004 § D-5 | F02274 | non-negotiable | true | 10 |
| R04454 | Hardening checklist — integrity-sentinel paths file includes /etc/tetragon/ | SDD-004 § D-5 | F02275 | non-negotiable | true | 10 |
| R04455 | Hardening checklist — integrity-sentinel paths file includes /etc/selfdef/ | SDD-004 § D-5 | F02275 | non-negotiable | true | 10 |
| R04456 | Hardening checklist — integrity-sentinel paths file includes /var/lib/selfdef/eventstream/ | SDD-004 § D-5 | F02275 | non-negotiable | true | 10 |
| R04457 | Hardening checklist — intentionally short; copy-paste-able into hardening runbook | SDD-004 § D-5 | F02276 | non-negotiable | false | 10 |
| R04458 | D-6 — docs/src/security.md and SECURITY.md are byte-equivalent or symlink | SDD-004 § D-6 + § Test plan 6 | M00494 | non-negotiable | false | 10 |
| R04459 | D-6 — symlink is the chosen implementation (fewer drift opportunities) | SDD-004 § D-6 + § Implementation status | F02277 | non-negotiable | false | 10 |
| R04460 | D-6 — mdbook follows symlinks transparently on Linux (only platform docs are built on) | SDD-004 § Implementation status D-6 | M00494 | non-negotiable | false | 10 |
| R04461 | D-6 fallback — lockstep edits with CI check if symlink complicates downstream tooling | SDD-004 § D-6 | M00494 | non-negotiable | false | 10 |
| R04462 | Test plan — Assets table contains exactly 10 rows | SDD-004 § Test plan 1 | F02216 | non-negotiable | false | 10 |
| R04463 | Test plan — Adversaries table contains exactly 6 classes numbered 1-6 | SDD-004 § Test plan 2 | F02221 | non-negotiable | false | 10 |
| R04464 | Test plan — Mitigations section contains 8 layers (original 6 + 2 new) | SDD-004 § Test plan 3 | M00498 | non-negotiable | false | 10 |
| R04465 | Test plan — Mitigations original 6 layers (Build & supply chain / Process / Configuration & rules / Storage / Notification / Tamper detection) | SDD-004 § Test plan 3 + § Current state | E0199 | non-negotiable | false | 10 |
| R04466 | Test plan — Mitigations 2 new layers (API surface + Policy surface) | SDD-004 § Test plan 3 + § D-3 | E0199 | non-negotiable | false | 10 |
| R04467 | Test plan — Known gaps list contains exactly 7 bullets (3 original + 4 new) | SDD-004 § Test plan 4 | E0200 | non-negotiable | false | 10 |
| R04468 | Test plan — Hardening checklist sidebar appears at end of Mitigations | SDD-004 § Test plan 5 | F02276 | non-negotiable | false | 10 |
| R04469 | Test plan — SECURITY.md and docs/src/security.md are byte-equivalent (or symlink) | SDD-004 § Test plan 6 | M00494 | non-negotiable | false | 10 |
| R04470 | Test plan — Phase-1 ledger rows F-2026-023, -024, -025, -026 each gain "closed by SDD-004 implementation PR" back-reference | SDD-004 § Test plan 7 | E0191 | non-negotiable | false | 10 |
| R04471 | Rollout — Pure documentation; no code, no defaults change | SDD-004 § Rollout / migration | E0191 | non-negotiable | false | 10 |
| R04472 | Rollout — Existing operators see new asset rows + new adversary class + new mitigation guidance | SDD-004 § Rollout / migration | E0191 | non-negotiable | false | 10 |
| R04473 | Rollout — No action is REQUIRED; hardening checklist names what SHOULD be done | SDD-004 § Rollout / migration | F02276 | non-negotiable | false | 10 |
| R04474 | Rollout — 4 "Known gaps" entries explicitly call out work that hasn't shipped yet (operator knows where to look) | SDD-004 § Rollout / migration | E0200 | non-negotiable | false | 10 |
| R04475 | Risk R-1 — operators read new mitigations as prescriptive; mitigated by "recommended posture" wording | SDD-004 § Risks R-1 | E0199 | non-negotiable | false | 10 |
| R04476 | Risk R-2 — symlink breaks mdbook on some platforms; mitigated by lockstep+CI fallback | SDD-004 § Risks R-2 | M00494 | non-negotiable | false | 10 |
| R04477 | Risk R-3 — Hardening checklist goes stale as defaults change; mitigated by doc-sweep PR pattern (PR #30) touching both surfaces in one diff | SDD-004 § Risks R-3 | M00493 | non-negotiable | false | 10 |
| R04478 | Q-A — worked-example block (Prometheus scrape config + TracingPolicy with selfdef.io/severity:"high" + integrity-sentinel paths.txt) — answered: not added in this PR; per-module READMEs already carry concrete examples | SDD-004 § Open questions Q-A | E0196 | non-negotiable | false | 10 |
| R04479 | Q-B — cluster control plane in Trust assumptions — answered: ADDED; Trust assumptions section now lists "the cluster control plane is trusted to enforce RBAC" for k8s deployments | SDD-004 § Open questions Q-B | M00480 | non-negotiable | false | 10 |
| R04480 | Q-C — TracingPolicy signing shape — answered (D-003, 2026-05-15): inline detached signatures + bundled CA (filesystem-native, offline-capable); detailed shape scoped in F-2026-024 follow-up SDD | SDD-004 § Open questions Q-C | M00489 | non-negotiable | false | 10 |
| R04481 | Appendix — SDD-001 (AI-machine end-to-end) defines what agent-guard event looks like once it surfaces as finding | SDD-004 § Appendix | E0191 | non-negotiable | false | 10 |
| R04482 | Appendix — Hardening checklist mentions integrity-sentinel watching policy dir, actionable today regardless of SDD-001 | SDD-004 § Appendix | M00493 | non-negotiable | false | 10 |
| R04483 | Appendix — SDD-002 (defaults that work) introduces `[daemon_requires]`; rewrite doesn't depend on it but mentions eventstream JSONL trust boundary which SDD-002 makes more discoverable via manifest | SDD-004 § Appendix | M00488 | non-negotiable | false | 10 |
| R04484 | Appendix — SDD-003 (vpn-bridge multi-instance) is unrelated to security rewrite | SDD-004 § Appendix | E0191 | non-negotiable | false | 10 |
| R04485 | Phase-2 F-2027-003 important — `read_euid()` returned 0 silently on /proc/self/status read failure; integrity check accidentally permissive; Phase 2 PR #56 flipped to Option<u32> + falls back strict-safe | SDD-004 § Follow-up findings Important | F02278 | non-negotiable | false | 10 |
| R04486 | Phase-2 F-2027-035 important — `check_path_integrity` used std::fs::metadata (follows symlinks) then tokio::fs::File::open (follows); Phase 2 PR #67 rewrote as O_NOFOLLOW-open + fstat-on-FD | SDD-004 § Follow-up findings Important | F02279 | non-negotiable | false | 10 |
| R04487 | Phase-2 F-2027-035 important — closes TOCTOU window | SDD-004 § Follow-up findings Important | F02279 | non-negotiable | false | 10 |
| R04488 | Phase-2 F-2027-035 important — refuses symlinks with typed `IntegritySymlink` variant | SDD-004 § Follow-up findings Important | F02279 | non-negotiable | false | 10 |
| R04489 | Phase-2 F-2027-005 nice — rule-signing verifier hot-rotation via SIGUSR2 (PR #58); pre-fix needed full daemon restart | SDD-004 § Follow-up findings Nice | M00497 | non-negotiable | false | 10 |
| R04490 | Phase-2 F-2027-006 nice — `selfdefctl keys verify-dir <dir>` batch verb replaces N-spawn `for p in $(find …); do selfdefctl keys verify $p` loop in `modules/tetragon/install/{apply,check}.sh` (PR #57) | SDD-004 § Follow-up findings Nice | M00497 | non-negotiable | false | 10 |
| R04491 | Phase-2 F-2027-007 nice — `selfdefctl rbac check --probe` expanded built-in probe set from 2 to 4 subjects (PR #57) | SDD-004 § Follow-up findings Nice | M00497 | non-negotiable | false | 10 |
| R04492 | Phase-2 F-2027-014 nice — `selfdef_api::with_full_capability` documented as test-only but pub fn and reachable from any caller; now gated behind `test-helpers` Cargo feature; absent from release builds (PR #61) | SDD-004 § Follow-up findings Nice | M00497 | non-negotiable | false | 10 |
| R04493 | Phase-2 F-2027-031 nice — `TokenReloader::reload` didn't validate mode-0600 invariant; now refuses with typed `LooseTokenMode` variant on chmod 0644 (PR #69) | SDD-004 § Follow-up findings Nice | M00497 | non-negotiable | false | 10 |
| R04494 | Phase-2 F-2027-036 nice — eventstream integrity check runs once at startup against FD; post-startup logrotate requires daemon restart; documented in docs/dev/first-run.md | SDD-004 § Follow-up findings Nice | M00497 | non-negotiable | false | 10 |
| R04495 | F-2027-045 phase-2 nice-cluster closed — 8 findings (2 important + 6 nice) closed in tree | SDD-004 § Follow-up findings | E0200 | non-negotiable | false | 10 |
| R04496 | Integration with MS001 daemon core — daemon hosts /metrics endpoint + collectors that consume eventstream JSONL | MS001 + SDD-004 § Problem | M00482 | non-negotiable | false | 10 |
| R04497 | Integration with MS002 collector fabric — selfdef-collector-eventstream is the integrity-gated reader | MS002 + SDD-004 § D-4 | M00490 | non-negotiable | false | 10 |
| R04498 | Integration with MS003 correlator + responder — bearer-token gates the control surface | MS003 + SDD-004 § D-3 API surface | M00484 | non-negotiable | false | 10 |
| R04499 | Integration with MS006 — agent-guard module manifests pod-label scope; vpn-bridge module is unrelated | MS006 + SDD-004 § D-2 + § Appendix | M00475 | non-negotiable | false | 10 |
| R04500 | Integration with MS007 typed-mirror crates — threat model contract may be carried as typed-mirror for cross-repo audit | MS007 + SDD-038 | E0191 | non-negotiable | false | 10 |
| R04501 | Integration with MS009 audit cycles — phase-6 80-security-audit covers SDD-004 surfaces + 4 follow-up findings | MS009 phase-6 80-security-audit | E0200 | non-negotiable | false | 10 |
| R04502 | Integration with MS010 hardware-aware modules — `/etc/selfdef/api.token` is part of SAIN-01 deployment hardening | MS010 + SDD-004 § D-5 | F02273 | non-negotiable | false | 10 |
| R04503 | Integration with MS011 operator dashboard — dashboard MCP tab + Hardware tab show /metrics endpoint health + token rotation state | MS011 + SDD-004 § D-3 API surface | M00484 | non-negotiable | false | 10 |
| R04504 | Integration with MS012 perimeter coexistence — agent-guard policy_name prefix discriminator (MS012 § Coverage 5) is the audit-trail mechanism this threat model depends on | MS012 + SDD-004 § D-3 Policy surface | M00487 | non-negotiable | false | 10 |
| R04505 | Integration with MS013 27-SDD charter — SDD-004 is one of the foundational 10 SDDs (per MS013 R03012) | MS013 + SDD-004 | E0191 | non-negotiable | false | 10 |
| R04506 | Integration with MS014 SSH-wrap — ssh-wrap JSONL is operator-owned emitter inheriting user's trust posture per Policy surface | MS014 + SDD-004 § D-3 Policy surface | F02245 | non-negotiable | false | 10 |
| R04507 | Integration with MS015 NATS messaging — bridge may pollute via host_tag spoofing if eventstream integrity disabled per Assets row 10 | MS015 + SDD-004 § D-1 Asset 10 | F02215 | non-negotiable | false | 10 |
| R04508 | Integration with MS016 eBPF + Tetragon — TracingPolicy directory and tetragon module integration | MS016 + SDD-004 § D-3 Policy surface | M00486 | non-negotiable | false | 10 |
| R04509 | Integration with MS017 agent-guard — Adversary class 6 specifically defeats agent-guard pod-label scoping | MS017 + SDD-004 § D-2 | M00480 | non-negotiable | false | 10 |
| R04510 | Integration with MS018 vpn-bridge multi-instance — explicitly unrelated to security rewrite per Appendix | MS018 + SDD-004 § Appendix | F02208 | non-negotiable | false | 10 |
| R04511 | Project boundary — SDD-004 is selfdef-scope; sovereign-os may consume SECURITY.md as reference (NOT crate import) | architecture + MS007 + SDD-038 | E0191 | non-negotiable | false | 10 |
| R04512 | Project boundary — TracingPolicy signing infrastructure (minisign + selfdefctl keys verify) is selfdef-side; sovereign-os signs its own sovereign-kernel-fence policies if needed | MS012 § Coverage 1 + SDD-004 § D-4 | M00489 | non-negotiable | false | 10 |
| R04513 | Project boundary — eventstream JSONL integrity validates within selfdef daemon's UID set; doesn't require sovereign-os participation | SDD-004 § D-4 | M00490 | non-negotiable | false | 10 |
| R04514 | Project boundary — RBAC check verb (`selfdefctl rbac check`) is selfdef-scope; doesn't enumerate sovereign-os cluster roles | SDD-004 § D-4 | M00492 | non-negotiable | false | 10 |
| R04515 | Doctrine — threat model is OPERATOR-READABLE (not an SDD) — short / declarative / useful | SDD-004 § Goals 5 | F02198 | non-negotiable | false | 10 |
| R04516 | Doctrine — additive rewrites preserve existing tables (Assets / Adversaries / Mitigations / Known gaps) | SDD-004 § Problem | F02193 | non-negotiable | false | 10 |
| R04517 | Doctrine — new layers added only where existing layers don't fit | SDD-004 § Alternative C | F02208 | non-negotiable | false | 10 |
| R04518 | Doctrine — Known gaps explicitly track not-yet-mitigated items per finding | SDD-004 § Goals 4 + § D-4 | F02197 | non-negotiable | false | 10 |
| R04519 | Doctrine — Hardening checklist captures operator-actionable defaults | SDD-004 § D-5 | M00493 | non-negotiable | false | 10 |
| R04520 | Doctrine — symlink eliminates drift between SECURITY.md and docs/src/security.md | SDD-004 § D-6 | M00494 | non-negotiable | false | 10 |
| R04521 | Doctrine — Phase-2 nice-cluster follows shipping SDD (operator-ergonomics + defense-in-depth fixes layer on top) | SDD-004 § Follow-up findings | E0200 | non-negotiable | false | 10 |
| R04522 | Doctrine — important Phase-2 findings (F-2027-003 + F-2027-035) close TOCTOU + permissive-default footguns | SDD-004 § Follow-up findings Important | F02278 + F02279 | non-negotiable | false | 10 |
| R04523 | Doctrine — security-feature opt-in default for behavior-changing additions (integrity_check default false) | SDD-004 § D-4 | F02256 | non-negotiable | false | 10 |
| R04524 | Doctrine — security-feature optional for surfaces that may not be deployed (k8s RBAC check is opt-in for k8s deployments) | SDD-004 § D-4 | M00492 | non-negotiable | false | 10 |
| R04525 | Doctrine — clean separation of read-cap vs control-cap token (read = /metrics + /events + /findings + /events/stream + /status; control = /rules/reload + /panic + /actions/*/run) | SDD-004 § D-3 API surface | M00484 | non-negotiable | false | 10 |
| R04526 | Doctrine — bearer-token + TLS + mTLS chain for API surface (filesystem default for UNIX socket; bearer-token mandatory for TCP; TLS/mTLS required when binding outside 127.0.0.1) | SDD-004 § D-3 API surface | M00481 + M00482 + M00483 | non-negotiable | false | 10 |
| R04527 | Doctrine — atomic token rotation (write to tmp + rename + SIGUSR2) preserves in-flight requests | SDD-004 § D-4 metrics-token rotation | F02263 + F02264 | non-negotiable | false | 10 |
| R04528 | Doctrine — minisign over cosign for filesystem-native signing (offline-capable; no centralized PKI required) | SDD-004 § D-4 TracingPolicy signing | F02252 | non-negotiable | false | 10 |
| R04529 | Doctrine — operator-owned emitters explicitly NOT integrity-gated (preserves usability for ssh-wrap JSONL) | SDD-004 § D-4 + § D-3 Policy surface | F02245 + F02256 | non-negotiable | false | 10 |
| R04530 | Doctrine — RBAC posture spot-checked on fixed subject set (not cluster-wide; that's separate tooling) | SDD-004 § D-4 | F02269 | non-negotiable | false | 10 |
| R04531 | Doctrine — chained-attack surface (uptime gauge → daemon restart → credential rotation) is documented; operator MUST rotate via deliberate action | SDD-004 § D-3 API surface | F02234 + F02235 | non-negotiable | false | 10 |
| R04532 | Doctrine — integrity-sentinel module is the baseline mechanism for /etc/tetragon/ + /etc/selfdef/ + /var/lib/selfdef/eventstream/ | SDD-004 § D-5 + § D-3 Policy surface | F02275 | non-negotiable | false | 10 |
| R04533 | Doctrine — cluster-tenant attacker (class 6) explicitly named in Adversaries table when deployment is k8s-aware | SDD-004 § D-2 | M00480 | non-negotiable | false | 10 |
| R04534 | Doctrine — trust assumption "cluster control plane is trusted to enforce RBAC" is explicit for k8s deployments (Q-B answer) | SDD-004 § Q-B answer | M00480 | non-negotiable | false | 10 |
| R04535 | Doctrine — known gaps that ship as opt-in features are still labeled gaps until set ON (operator-discoverable in selfdefctl init checklist) | SDD-004 § D-4 | E0200 | non-negotiable | false | 10 |
| R04536 | Doctrine — TracingPolicy signing caveat: agent-guard renders policies at runtime (NOT pre-signed; intentional + documented) | SDD-004 § D-4 | F02251 | non-negotiable | false | 10 |
| R04537 | Doctrine — eventstream integrity owner-mode verification ≠ per-line HMAC (per-line HMAC NOT shipped) | SDD-004 § D-4 | F02257 | non-negotiable | false | 10 |
| R04538 | Audit-cycle integration — MS009 phase-6 80-security-audit covers all 10 Assets + 6 Adversaries + 8 Mitigations + 7 Known gaps | MS009 phase-6 80-security-audit + SDD-004 § Test plan | M00498 | non-negotiable | false | 10 |
| R04539 | Audit-cycle integration — MS009 phase-7 80-security-audit verifies 4 follow-up shipped features in-tree | MS009 phase-7 80-security-audit + SDD-004 § D-4 | E0200 | non-negotiable | false | 10 |
| R04540 | Audit-cycle integration — F-2026-NNN findings ledger records security-posture violations | MS009 99-findings-ledger | E0191 | non-negotiable | false | 10 |
| R04541 | Audit-cycle integration — F-2027-045 phase-2 cluster (2 important + 6 nice) verified closed in tree | MS009 phase-2 + SDD-004 § Follow-up findings | E0200 | non-negotiable | false | 10 |
| R04542 | Audit-cycle integration — phase-6 60-docs-audit covers SECURITY.md against charter style rules + symlink target | MS009 phase-6 60-docs-audit + SDD-004 § D-6 | M00494 | non-negotiable | false | 10 |
| R04543 | Audit-cycle integration — phase-6 70-tests-audit covers SDD-004 review-style test plan + Phase-2 follow-up tests | MS009 phase-6 70-tests-audit + SDD-004 § Test plan | M00498 | non-negotiable | false | 10 |
| R04544 | Audit-cycle integration — Hardening checklist re-verified on every audit cycle (stale-defaults R-3 risk) | MS009 + SDD-004 § Risks R-3 | M00493 | non-negotiable | false | 10 |
| R04545 | Composite — SDD-004 closes F-2026-023+024+025+026 at Assets + Adversaries + Mitigations + Known-gaps levels | SDD-004 § Implementation status | E0191 | non-negotiable | false | 10 |
| R04546 | Composite — 4 follow-up Known-gap entries shipped as opt-in features per `selfdefctl init checklist` | SDD-004 § D-4 | E0200 | non-negotiable | false | 10 |
| R04547 | Composite — 8 Phase-2 follow-up findings (2 important + 6 nice) closed in tree | SDD-004 § Follow-up findings | E0200 | non-negotiable | false | 10 |
| R04548 | Composite — Hardening checklist is the operator-facing distillation of the new mitigations | SDD-004 § D-5 | M00493 | non-negotiable | false | 10 |
| R04549 | Composite — SDD-004 stays operator-readable; tables stay; section ordering stays | SDD-004 § Goals 5 + § Non-goals | F02198 + F02203 | non-negotiable | false | 10 |
| R04550 | Composite — SDD-004 is implemented + verified + post-shipping followed up; no open work as of 2026-05-15 (D-003 Q-C answer date) | SDD-004 § Implementation status + § Q-C answer | E0191 | non-negotiable | false | 10 |
| R04551 | Composite — SDD-004 is the canonical security threat model for selfdef; operator audits against this document | SDD-004 entire | E0191 | non-negotiable | false | 10 |
| R04552 | Composite — SDD-004 covers the original 7 daemon-scope assets + 3 new module-introduced surfaces in unified table | SDD-004 § Current state + § D-1 | E0198 | non-negotiable | false | 10 |
| R04553 | Composite — SDD-004 introduces cluster-tenant attacker as the only k8s-aware adversary class (class 6) | SDD-004 § D-2 | M00480 | non-negotiable | false | 10 |
| R04554 | Composite — SDD-004 grows Mitigations to 8 layers (Build / Process / Configuration & rules / Storage / Notification / Tamper detection / API surface / Policy surface) | SDD-004 § Test plan 3 + § D-3 | M00498 | non-negotiable | false | 10 |
| R04555 | Composite — SDD-004 Known gaps list grows to 7 bullets (3 original + 4 SDD-004-introduced) | SDD-004 § Test plan 4 + § D-4 | E0200 | non-negotiable | false | 10 |
| R04556 | Composite — SDD-004 ships 4 opt-in mitigations covering all 4 introduced surfaces (TracingPolicy signing / eventstream integrity / metrics-token rotation / RBAC posture) | SDD-004 § D-4 | E0200 | non-negotiable | false | 10 |
| R04557 | Composite — SDD-004 honors operator-ergonomics principle (operator-readable + copy-pasteable + opt-in defaults) | SDD-004 § Goals 5 + § D-5 + § D-4 | F02198 + F02276 | non-negotiable | false | 10 |
| R04558 | Composite — SDD-004 honors selfdef + sovereign-os boundary (selfdef-scope SECURITY.md; no cross-repo crate import; documented file paths + Tetragon merge agent per MS012) | SDD-004 + MS012 + MS007 + SDD-038 | R04511 | non-negotiable | false | 10 |
| R04559 | Composite — SDD-004 closes F-2026-023+024+025+026 + tracks 4 follow-up shipping in opt-in features + closes 8 Phase-2 follow-ups (2 important + 6 nice) — full traceability from Phase 1 finding → SDD design → implementation PR → Phase 2 follow-up → in-tree closure | SDD-004 § Implementation status + § D-4 + § Follow-up findings | E0200 | non-negotiable | false | 10 |
| R04560 | Composite — MS019 covers SDD-004 implementation + 4 opt-in shipped follow-ups + 8 Phase-2 follow-ups + Hardening checklist + symlink doc-mirror + integrates with MS001-MS018 milestones; project boundary preserved (selfdef-scope; cross-repo via NATS + MS007 typed mirrors + documented file contracts only) | INDEX.md MS019 + SDD-004 + MS001-MS018 | E0191 + E0192 + E0193 + E0194 + E0195 + E0196 + E0197 + E0198 + E0199 + E0200 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS018: 25920 + 2400 = 28320 sub-requirements when MS019 lands

## Cross-references

- SDD source: `docs/sdd/004-security-threat-model.md` (536 lines; status=implemented; closes F-2026-023+024+025+026)
- Doc mirror: `docs/src/security.md` → `../../SECURITY.md` (symlink per D-6)
- Phase-1 ledger rows closed: F-2026-023 (`/metrics` endpoint) + F-2026-024 (TracingPolicy dir) + F-2026-025 (pod-label scope) + F-2026-026 (eventstream JSONL trust)
- Phase-2 follow-ups closed: F-2027-003 (read_euid silent-zero) + F-2027-005 (SIGUSR2 verifier hot-rotation) + F-2027-006 (keys verify-dir batch) + F-2027-007 (rbac check --probe 2→4 subjects) + F-2027-014 (with_full_capability test-only feature gate) + F-2027-031 (TokenReloader mode-0600 validation) + F-2027-035 (O_NOFOLLOW TOCTOU) + F-2027-036 (eventstream integrity post-startup logrotate doc)
- Sister milestones: MS001 daemon core (hosts /metrics + eventstream collectors) / MS002 collector fabric (selfdef-collector-eventstream is integrity-gated) / MS003 correlator+responder+store-sink (bearer-token gates control surface) / MS006 agent-guard module / MS009 audit cycles (phase-6+phase-7 80-security-audit) / MS010 hardware-aware (api.token in SAIN-01 hardening) / MS011 operator dashboard (token rotation surface) / MS012 perimeter coexistence (policy_name discriminator) / MS013 27-SDD charter (SDD-004 is foundational 000-009 layer) / MS014 SSH-wrap (operator-owned emitter) / MS015 NATS messaging (host_tag spoofing mitigated by integrity gate) / MS016 eBPF + Tetragon (TracingPolicy directory ownership) / MS017 agent-guard (Adversary class 6 specifically defeats agent-guard pod-label scoping)
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (SDD-004 is selfdef-scope reference document; sovereign-os MAY consume via documented file contracts + NATS subscription with mTLS)
