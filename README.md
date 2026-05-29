# selfdef

Self-defense service for Linux hosts (Debian 13+, Ubuntu 24.04+).
A multi-layered host detection, deception, and response platform aimed at
personal workstations, home servers, public VPSes, and AI-machine hosts
running containerised agents.

> **Status:** All milestones M1–M16 plus the AI-machine track shipped.
> The Phase 1 architecture audit closeout is complete — every Phase-1
> blocker, important, and SDD-debt finding is closed or carries a
> tracked follow-up that's now shipped (see
> [`docs/review/99-findings-ledger.md`](docs/review/99-findings-ledger.md)).
> Nine modules ship in the catalog; six audit-shipped opt-in security
> features (rule signing, TracingPolicy signing, eventstream integrity,
> API token hot-rotation, k8s RBAC posture check, vpn-bridge
> multi-instance honesty) ship behind operator-controlled toggles.

## Goals

1. **Detect** intrusion attempts and post-compromise behavior with high signal,
   low noise, across kernel (Tetragon + custom eBPF), system (auditd, journald),
   and network (Suricata) layers.
2. **Correlate** events across collectors with time-windowed rules. Single
   events are noise; correlated patterns are signal.
3. **Respond** actively: lockdown egress, freeze logins, snapshot state,
   notify, and engage deception layers.
4. **Defend the client side too** — most SSH-defense tooling is server-only.
   This service includes a wrapper that protects you when *you* are the
   client connecting to a possibly-hostile server.
5. **Defend AI-machine hosts.** Tetragon-backed TracingPolicies in the
   `agent-guard` module enforce host-level invariants on AI agents
   running in Docker / Podman / containerd containers (no `/etc/`
   writes, no shell exec inside containers, allowlisted egress,
   GPU device-node allowlist, optional pod-label scoping for k8s).

Explicit non-goal: offensive action against attackers. Active deception
(honeytokens, honey services) is in scope; hacking back is not, ever.

## Operator quick-start

`selfdefctl init` bootstraps a deployment; `selfdefctl doctor`
verifies it.

```sh
# Day 0
sudo selfdefctl init config              # writes /etc/selfdef/selfdef.toml
sudo selfdefctl init modules             # writes /etc/selfdef/modules.toml
sudo systemctl enable --now selfdefd
sudo selfdefctl modules apply
selfdefctl doctor

# Day N
selfdefctl doctor                        # after editing config or rotating keys
```

`selfdefctl init checklist` prints the full 11-step first-run
runbook covering each opt-in security feature. See
[`docs/dev/first-run.md`](docs/dev/first-run.md) for the
walkthrough and [`docs/dev/operator-health-check.md`](docs/dev/operator-health-check.md)
for the doctor reference.

## Module catalog

| Slug | Category | Purpose |
| --- | --- | --- |
| `detect-host` | detection | Wraps the daemon — collectors, correlator, responder, notifier, store, API. |
| `bridge-l2` | network | Transparent L2 bridge + nftables FORWARD policy. Foundation for inline IDS / TLS-tap modules. |
| `suricata` | network | Inline IDS via NFQUEUE or AF_PACKET copy-mode. |
| `polarproxy` | network | TLS termination → PCAP-over-IP for content visibility. |
| `vpn-bridge` | network | Remote-network connectivity: WireGuard relay (multi-instance), Tailscale, Cloudflare Tunnel. Per-profile `instanced` capability honestly declared (SDD-003). |
| `integrity-sentinel` | hardening | SHA256 baseline + drift detection. Optional notifier emission. |
| `tetragon` | hardening | Tetragon (Cilium eBPF) substrate: config, event JSONL, policy dir, `/metrics`. Optional `require_signed_policies = true` gates TracingPolicy loading. |
| `agent-guard` | hardening | TracingPolicies for AI agents in containers (etc-write, shell-exec, egress, SecureMessage stub, GPU device). Pod-label scope honors k8s label RBAC (verify via `selfdefctl rbac check`). |
| `observability` | observability | Prometheus scrape config + Grafana dashboard for the selfdef stack. |

Activate modules in `/etc/selfdef/modules.toml` (or use
`selfdefctl init modules` to scaffold it). Manage with
`selfdefctl modules {list,info,apply,check,status,uninstall,show-requires}`.

## `selfdefctl` reference

Every operator-facing verb:

### Read-only

| Verb | Purpose |
| --- | --- |
| `status` | Daemon status (event count, store path). |
| `events {tail,alerts}` | Recent events / alerts from the hot store. |
| `events follow` | Live SSE tail of the daemon's `/events/stream` over a UNIX socket. F-2027-029 + -030: surfaces `event: shutdown` and `event: lagged` frames as stderr `# …` comments. |
| `events emit` | Inject a hand-crafted event onto the eventstream JSONL (testing). |
| `forensics list` | List forensic bundles. |
| `modules {list,info,check,status,show-requires}` | Inspect modules + their daemon_requires. |
| `version` | Build info. |

### Lifecycle

| Verb | Purpose |
| --- | --- |
| `init {config,modules,checklist}` | First-run bootstrap. Non-destructive (refuse-to-clobber unless `--force`). |
| `modules apply` | Apply every active module's `install/apply.sh` in dependency order. |
| `modules uninstall` | Reverse-order uninstall. Requires `--confirm <hostname>`. |
| `rules {list,validate,test,lint,coverage}` | Detection-rule tooling. |
| `forensics collect` | Manually collect a bundle for an event by id. |
| `panic` | Trigger panic mode (lockdown). Requires `--confirm <hostname>`. |
| `reload` | SIGHUP the daemon (rules reload). |

### Four-watchdog set (IPS spine, MS046+MS047+MS044+MS048)

The package ships four cooperating boundary-enforcement watchdogs that
operate together as the IPS spine. All OFF by default;
`selfdefctl wizard` Step 5 walks the enablement path.

| Layer | Verb | Catalog | Surface |
| --- | --- | --- | --- |
| hardware frame | `friction-audit {show,history,replay} [--json]` | MS046 / SDD-027 | Boot-time PCIe/ZFS/memory gate via `sovereign-guard.service`. |
| kernel syscall | `perimeter {show,history,extend,revoke,check-overlap,status,audit-cycle replay} [--json]` | MS047 / SDD-028 | In-kernel `sys_execve` allowlist via Tetragon `sovereign-perimeter.yaml` (no userspace service). |
| supervisor tier | `guardian {show,history,replay,rollback} [--json]` | MS044 / SDD-029 | Tetragon UNIX-socket consumer + 3-step Responder (SIGKILL / atomic ZFS audit-append / `/dev/console` BEL) via `selfdef-guardian.service`. |
| routing layer | `scheduler {show,history,explain,replay,weights,force,audit-cycle replay} [--json]` | MS048 / SDD-031 | Goldilocks 7-axis objective + 5 backpressure surfaces via `selfdef-scheduler.service`. |

Cross-cutting operator surface:

| Verb | Purpose |
| --- | --- |
| `trio [--json] [--watch N]` | Consolidated four-panel snapshot (CLI analog of the PWA dashboard's main view). |
| `trio-tail [--interval-ms N] [--json]` | Unified live OCSF tail of all four watchdog JSONL logs. |
| `doctor` | The `watchdog-set` category reports per-watchdog deployability (binary present + systemd unit present + ring dir + supporting infrastructure). |

Operator runbooks (20 total, 5 per watchdog) ship in the companion
`devops-solutions-information-hub` repository:
`wiki/runbooks/{friction-audit,perimeter,guardian,scheduler}-*.md`.

### Security opt-ins (audit-shipped)

| Verb | Closes | Purpose |
| --- | --- | --- |
| `keys verify <target>` | original "Rule signing" Known gap | Verify a detached minisign signature against a target file (rule, TracingPolicy). |
| `keys verify-dir <dir>` | F-2027-006 | Batch-verify every `*.yml`/`*.yaml` in a directory in one process. Replaces the N-spawn `for p in $(find …); do selfdefctl keys verify $p` loop in `modules/tetragon/install/{apply,check}.sh`. |
| `api rotate-token` | SDD-004 F-2026-023; F-2027-031 enforces mode-0600 on reload | Generate a fresh 32-byte API bearer token, write atomically to `[api].token_file` at mode 0600, optionally SIGUSR2 the daemon to reload. |
| `rbac check [--probe]` | SDD-004 F-2026-025; F-2027-007 expanded built-in subject set to 4 | Verify k8s RBAC posture for agent-guard's `pod-label` scope. With `--probe`, shells out to `kubectl auth can-i` against `system:authenticated` + `system:unauthenticated` + `system:masters` + `system:serviceaccount:default:default` + operator-supplied `--as`. |
| `doctor [--json]` | post-audit synthesis | Cross-cutting health check: rule signing, API token mode, eventstream integrity, RBAC posture summary. |

**Phase 2 hot-reload surfaces** (all via SIGUSR2; covered in
`docs/dev/signing.md` § "Turn on enforcement"):
- F-2027-005 — rule-signing verifier hot-rotation (no daemon restart).
- F-2027-032 — one-line "tokens=ok verifier=ok rules=ok"
  summary after the SIGUSR2 fan-out completes.
- F-2027-035 — `[collectors.eventstream].integrity_check`
  hardening: `O_NOFOLLOW` + fstat-on-FD; symlinks refused with
  a typed `IntegritySymlink` variant.
- F-2027-014 — `selfdef_api::with_full_capability` test-only
  helper is feature-gated (`test-helpers`), absent from
  release builds.

### Operator runbooks

One-page printable reference + per-feature deep dives:

- [`docs/operator-cheatsheet.md`](docs/operator-cheatsheet.md) — **daily-driver commands one-pager**: trio / doctor / per-watchdog drill-down / modules / HTTP API / PS1 integration. Print this and pin it.
- [`first-run.md`](docs/dev/first-run.md) — `init` family walkthrough.
- [`operator-health-check.md`](docs/dev/operator-health-check.md) — `doctor` reference + systemd-timer integration.
- [`modules.md`](docs/dev/modules.md) — module author contract (`module.toml` schema + `[install]` kinds + lifecycle).
- [`signing.md`](docs/dev/signing.md) — rule + TracingPolicy signing (minisign).
- [`rbac-posture.md`](docs/dev/rbac-posture.md) — k8s pod-label RBAC verification.
- [`module-helpers.md`](docs/dev/module-helpers.md) — shared module-script library (`packaging/lib/module-lib.sh`).
- [`test-contract.md`](docs/dev/test-contract.md) — what "integration-tested" means in this codebase.
- [`m060-cockpit-mirror-producers.md`](docs/operator/m060-cockpit-mirror-producers.md) — selfdef-side **producer** wiring for the 11 cockpit mirrors consumed by sovereign-os (D-02/D-12..D-18 + tui-layout + cli-schema + m060-health). Resident-store paths, producer one-shots (cli-mirror-emit), per-artifact onboarding verbs, failure-mode crib sheet.
- [`ms022-sse-subscriber-quota.md`](docs/operator/ms022-sse-subscriber-quota.md) — MS022 **SSE subscriber quota** operator guide. 6 Prometheus gauges (`selfdef_sse_subscribers_*`) exposed at `/metrics`, the operator-tunable `[api].max_sse_subscribers{,_per_token}` knobs, cap-enforcement semantics (per-token check first, global CAS-loop second per SDD-007 D-6), defaults rationale, raise-vs-leak diagnosis decision tree, failure-mode → log-line crib sheet, project-boundary discipline (R10212). 50 contract tests lock the producer → consumer wire across both repos.

For the 20 watchdog-failure-mode runbooks (5 per watchdog × 4 watchdogs)
+ the UX coherence failures runbook, see the companion info-hub repo's
`wiki/runbooks/` directory.

## Layout

```
crates/                          One workspace, many focused crates.
  selfdef-core/                  Schema, event envelope, errors.
  selfdef-config/                Layered config (TOML + env + CLI).
  selfdef-bus/                   Event bus abstraction.
  selfdef-store/                 SQLite (hot) + DuckDB (warm) storage.
  selfdef-correlator/            Sigma rule engine (opt-in signed-rule verification).
  selfdef-signing/               Minisign-compatible detached signature verification.
  selfdef-notifier/              Legacy notifier-chain ABI; channel implementations now live in selfdef-integration-* (M4 carve, SDD-008 D-2+).
  selfdef-notifier-orchestrator/ `Channel` trait crate (SDD-008 D-2a) — every integration implements it.
  selfdef-notifier-engine/       SDD-008 D-5 — persistent escalation engine (SQLite, WAL, wake task, profiles, mode, ack tokens).
  selfdef-integration-ntfy/      Self-hosted push (SDD-008 D-2b).
  selfdef-integration-signal/    Signal IM via `signal-cli` subprocess (SDD-008 D-2c).
  selfdef-integration-slack/     Slack incoming-webhook (SDD-008 Q-C).
  selfdef-integration-discord/   Discord webhook (2000-char cap with truncation).
  selfdef-integration-smtp/      Email via STARTTLS / implicit-TLS / plain (SDD-008 D-7 Q-E).
  selfdef-integration-twilio/    Twilio SMS, send-only (SDD-008 Q-D).
  selfdef-integration-pagerduty/ PagerDuty Events API v2; OCSF 6 → PD 4 severity collapse (SDD-008 Q-G).
  selfdef-integration-loki/      Grafana Loki push-API; three auth modes (SDD-008 Q-G).
  selfdef-integration-opensearch/ OpenSearch / Elasticsearch document index; three auth modes (SDD-008 Q-G).
  selfdef-integration-thehive/   TheHive alert API; TLP=Amber default (SDD-008 Q-G).
  selfdef-integration-wall/      `wall(1)` broadcast TTY session-attention (SDD-008 D-8).
  selfdef-integration-write/     `write(1)` per-user TTY session-attention (D-024 — sibling of wall).
  selfdef-responder/             Action runners (lockdown, snapshot, etc.).
  selfdef-api/                   Read-only HTTP API + /metrics + control verbs + token hot-rotation.
  selfdef-nats/                  Multi-host bridge over NATS / JetStream.
  selfdef-collector-auditd/      auditd → bus.
  selfdef-collector-journald/    journald → bus.
  selfdef-collector-tetragon/    Tetragon JSON → bus.
  selfdef-collector-suricata/    Suricata EVE → bus.
  selfdef-collector-canary/      Honeytoken file watch → bus.
  selfdef-collector-eventstream/ External JSONL emitters (ssh-wrap, modules) → bus. Opt-in integrity check.
  selfdef-collector-ebpf/        Native in-kernel collection via aya.
  selfdef-cli/                   selfdefctl admin binary (init, doctor, modules, api, keys, rbac, …).
  selfdef-daemon/                selfdefd main binary.
  selfdef-ssh-wrap/              Drop-in ssh wrapper (client-side).

  # --- Cross-repo binding crates (sovereign-os E11 mirrors) ---
  selfdef-dashboard-manifest/    SD-R-DASHBOARD-MANIFEST-1 — per-module
                                 TOML declaring port/auth-tier/subpath;
                                 read by sovereign-os master-dashboard
                                 aggregator (R452/R460).
  selfdef-history-sink/          SD-R-EVENT-LOG-1 — JSONL emitter for
                                 module lifecycle events; consumed by
                                 sovereign-os global-history modules
                                 reader (R448/R465).
  selfdef-auth-tier/             SD-R-AUTH-TIER-1 — typed 6-tier auth
                                 enum (NoAuth → … → NetworkLevel)
                                 mirroring sovereign-os R450 ladder.
  selfdef-surface-manifest/      SD-R-MULTI-SURFACE-AUDIT-1 — per-module
                                 TOML declaring which of the 8 §1g
                                 surfaces (core/cli/tui/api/mcp/
                                 dashboard/webapp/service) the module
                                 ships; consumed by sovereign-os
                                 surface-map (R453/R462).
  selfdef-ux-checklist/          SD-R-UX-CHECKLIST-1 — per-module TOML
                                 declaring UX-quality standing across
                                 the 6 R457 dimensions
                                 (action-budget/discoverable/
                                 recoverable/next-step/operator-named/
                                 readable-30s); consumed by
                                 sovereign-os ux-design-audit (R464).
  selfdef-audit-manifest/        SD-R-AUDIT-1 — per-module TOML
                                 declaring anti-minimization findings
                                 against the 8 R456 patterns;
                                 consumed by sovereign-os
                                 anti-minimization-audit (R466).
  selfdef-bashrc-install/        SD-R-BASHRC-1 — Rust harness for the
                                 operator-facing bash installer at
                                 `packaging/bash/selfdefctl-bashrc-install.sh`;
                                 mirrors sovereign-os R447.
  selfdef-doc-manifest/          SD-R-DOC-MANIFEST-1 — per-module TOML
                                 declaring which of the 6 §1g doc
                                 surfaces (readme/sdd/helptext/metric-
                                 inventory/mandate-row/man-page) the
                                 module ships; DocState enum
                                 (Shipped/Waived/Planned) with
                                 Shipped-requires-path + Waived-
                                 requires-reason validation; consumed
                                 by sovereign-os doc-coverage
                                 (R454/R471).
  selfdef-cross-repo-saturation/ SD-R-SATURATION-1 — meta-test crate
                                 that depends on all 8 cross-repo
                                 mirror crates above + asserts (10
                                 integration tests) workspace
                                 saturation: count floor + crate-name
                                 uniqueness + binding-ID uniqueness +
                                 array-length match + cross-crate
                                 alias agreement + bashrc constants +
                                 kebab-case taxonomy-entry hygiene +
                                 no duplicate entries within a
                                 taxonomy. Sister to sovereign-os R473.

modules/                         Install modules — operator-activatable units.
rules/                           Detection-as-code (sigma, tetragon, yara).
packaging/                       OS packaging artifacts (debian, systemd, apparmor, lib).
  packaging/lib/module-lib.sh    Shared module-script library (SDD-006 v2).
selfdef-ebpf/                    eBPF programs (aya). Separate build target.
tests/                           Integration tests, replay corpora.
docs/                            mdbook documentation + audit + SDD trees + dev/operator runbooks.
  docs/dev/                      Contributor-facing runbooks (signing, doctor, init, rbac, integrations template, ...).
  docs/operator/                 Operator-facing references (`channels.md` is the canonical 12-channel reference).
  docs/sdd/                      Nine SDDs (000-charter + 001..008 implemented; 009 requirements-only stub).
  docs/review/                   Audit programme — Phase 2..8 ledgers (Phase 8 deferred per cycle constraints).
  docs/decisions.md              Operator-decisions audit log (D-001..D-024 — every `Q-X` row across SDDs answered or explicitly deferred).
  docs/handoff/                  Cold-start signposts for cross-session continuity.
ansible/                         Deployment playbooks.
```

## Quickstart

```bash
# Build
cargo build --release --locked

# Package — F-2027-043: the daemon and the CLI are separate
# Debian targets. Build both so `selfdefctl` lands on PATH
# alongside the daemon.
cargo install cargo-deb
cargo deb -p selfdef-daemon
cargo deb -p selfdef-cli

# Install
sudo dpkg -i target/debian/selfdef-daemon_*.deb
sudo dpkg -i target/debian/selfdef-cli_*.deb
sudo systemctl enable --now selfdefd
selfdefctl status

# Bootstrap config + run cross-cutting health check
sudo selfdefctl init config
sudo selfdefctl init modules
selfdefctl doctor
```

## Development

```bash
# Format, lint, test, audit (run these before every commit)
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo deny check
cargo audit
```

## Milestones

- [x] **M1** — Foundation: workspace, toolchain, CI, packaging skeleton, docs.
- [x] **M2** — Event envelope: `selfdef-core` OCSF-aligned types, snapshot + property tests.
- [x] **M3** — First spine: auditd → bus → SQLite end-to-end.
- [x] **M4** — Notifier + first rule (SSH brute-force → ntfy).
- [x] **M5** — Sigma engine with hot reload, replay corpus.
- [x] **M6** — journald, Tetragon, Suricata collectors.
- [x] **M7** — Detection-as-code CI: per-rule tests, lint, ATT&CK coverage.
- [x] **M8** — Honeytokens + responder actions.
- [x] **M9** — Client-side SSH wrapper.
- [x] **M10** — Custom eBPF programs (aya).
- [x] **M11** — Forensics + Velociraptor integration.
- [x] **M12** — Mobile dashboard / read-only HTTP API.
- [x] **M13** — Control-plane verbs + TLS/mTLS for the API.
- [x] **M14** — Per-token capabilities (read vs control) for the API.
- [x] **M15** — NATS bridge for multi-host correlation.
- [x] **M16** — `/metrics` Prometheus exposition on the daemon's API.
- [x] **AI-machine track** — `tetragon` substrate + `agent-guard` policy bundle (5 policies, audit/enforce profiles, container or pod-label scope) + `observability` (Prometheus scrape + Grafana dashboard).
- [x] **Phase-1 audit cycle** — architect/PM sweep across the codebase. Six SDDs (charter + 001..006) plus the cleanup PRs they implied. Every blocker, important, SDD-debt finding now closed or has a shipped follow-up. See [`docs/review/99-findings-ledger.md`](docs/review/99-findings-ledger.md).
- [x] **Audit-shipped opt-ins** — rule signing (`selfdef-signing` crate), TracingPolicy signing (`tetragon` module), API token hot-rotation (`selfdefctl api rotate-token` + daemon SIGUSR2), eventstream integrity gate, k8s RBAC posture check, shared module-script library v2.
- [x] **Operator lifecycle verbs** — `selfdefctl init {config,modules,checklist}` (bootstrap) and `selfdefctl doctor [--json]` (verification). Together: day-0 bootstrap → day-N health check, one verb each.

## Cross-repo binding (sovereign-os ↔ selfdef)

selfdef is one half of a two-repo system. The companion is
[`cyberpunk042/sovereign-os`](https://github.com/cyberpunk042/sovereign-os),
the operator-facing OS-image-pipeline & §1g/§1h compliance instrument
suite. The two repos co-progress via a set of **typed TOML manifests**:
selfdef modules emit them, sovereign-os instruments consume them.

Per the operator-§1g standing rule the canonical taxonomies (auth
tiers, §1g surfaces, UX dimensions, anti-minimization patterns) MUST
agree verbatim across both repos. Every cross-repo crate exports a
`const` array (e.g., `AUTH_TIERS`, `SURFACE_TAXONOMY`,
`UX_DIMENSIONS`, `PATTERN_IDS`) and includes a unit test asserting
its order matches the sovereign-os source-of-truth. **Drift on either
side fails tests on BOTH sides** — the binding is contract-level, not
just documentation.

| Cross-repo binding ID         | Manifest file path                        | sovereign-os consumer  | Mirrored taxonomy             |
|-------------------------------|-------------------------------------------|------------------------|-------------------------------|
| `SD-R-DASHBOARD-MANIFEST-1`   | `/etc/selfdef/dashboards/<m>.toml`        | `master-dashboard` (R452/R460) | 6-tier auth ladder + 8-surface taxonomy |
| `SD-R-EVENT-LOG-1`            | `/var/log/sovereign-os/modules.jsonl`     | `global-history` (R448/R465)   | event-status enum             |
| `SD-R-AUTH-TIER-1`            | (consumed via dashboard-manifest)         | `auth-tier` (R450)             | 6-tier ladder (typed enum)    |
| `SD-R-MULTI-SURFACE-AUDIT-1`  | `/etc/selfdef/surfaces/<m>.toml`          | `surface-map` (R453/R462)      | 8-surface §1g taxonomy        |
| `SD-R-UX-CHECKLIST-1`         | `/etc/selfdef/ux-checklists/<m>.toml`     | `ux-design-audit` (R457/R464)  | 6-dimension UX-quality enum   |
| `SD-R-AUDIT-1`                | `/etc/selfdef/audit-manifests/<m>.toml`   | `anti-minimization-audit` (R456/R466) | 8-pattern minimization catalog |
| `SD-R-BASHRC-1`               | (operator-runnable installer)             | sister to `bashrc-install.sh` (R447) | sentinel-bounded bashrc block |
| `SD-R-DOC-MANIFEST-1`         | `/etc/selfdef/doc-manifests/<m>.toml`     | `doc-coverage` (R454/R471)     | 6-kind doc-surface catalog    |

Operators with both repos cloned can run
`sovereign-osctl compliance status` to see runtime + doc + UX + audit +
selfdef-discovery state for both halves of the system in one screen.

## Threat model

See [SECURITY.md](SECURITY.md) — the daemon itself is a target. SDD-004 ([`docs/sdd/004-security-threat-model.md`](docs/sdd/004-security-threat-model.md)) rewrote the threat model to cover the post-M15 + post-AI-machine surfaces (`/metrics` endpoint, Tetragon policy directory, eventstream JSONL trust, k8s pod-label RBAC). The "Known gaps" list now enumerates each remaining gap with its tracking status; the previously-deferred follow-ups (rule signing, eventstream integrity, API token rotation, TracingPolicy signing, RBAC posture check) all ship as opt-in features turned on per `selfdefctl init checklist`.

The audit-recommended hardening posture for an AI-machine deployment is in the "Hardening checklist" sidebar at the end of SECURITY.md's Mitigations section.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
