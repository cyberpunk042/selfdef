# Security & Threat Model

Security tooling is a high-value target. An attacker who compromises the
detector wins twice: they evade detection *and* they gain a privileged process
on the host. This document is the threat model of the daemon itself plus the
surfaces the shipped modules introduce.

## Assets

| Asset | Where | Why it matters |
|-------|-------|----------------|
| Daemon binary | `/usr/bin/selfdefd` | Tampering = silent detection failure |
| Daemon config | `/etc/selfdef/` | Misconfig = blind spots; secrets in config |
| Detection rules | `/etc/selfdef/rules/` | Tampering = silent detection failure |
| Hot event store | `/var/lib/selfdef/state.sqlite` | Recent forensic record |
| Cold event archive | Off-host (logging VPS) | Tamper-resistant forensic record |
| Notification credentials | `/etc/selfdef/secrets/` | ntfy tokens, signal-cli auth |
| eBPF programs | embedded in binary | Tampering disables in-kernel detection |
| `/metrics` endpoint | UNIX socket `/run/selfdef.sock` or TCP `<api.bind>` | Activity-fingerprint information; chained-attack timing of credential edits to daemon restart (see API surface mitigations + F-2026-066 known gap) |
| Tetragon policy directory | `/etc/tetragon/tetragon.tp.d/` | Writable: malicious YAML loads as kernel-level eBPF policy (Sigkill / Override / NotifyKiller / mask). Owned by the `tetragon` module install |
| Eventstream JSONL paths | Varies — see `[collectors.eventstream].paths`, default `/var/lib/selfdef/eventstream/` | Event-injection vector. Crafted Findings can fire the notifier chain or pollute the multi-host NATS bridge via `host_tag` spoofing |

## Adversaries

1. **Opportunistic remote attacker** — SSH brute, RCE on an exposed service.
   No prior knowledge of the host. *Should be stopped at perimeter.*
2. **Authenticated local attacker** — has a shell, possibly as a regular user.
   Trying to escalate or pivot. *Should be detected.*
3. **Root-level attacker** — already has root. Trying to disable detection,
   tamper with logs, persist quietly. *Should be **expensive** to fully evade.*
4. **Malicious SSH server** — you connected to it. Tries to abuse forwarding
   features against your client. *Mitigated by the SSH wrapper.*
5. **Supply-chain attacker** — compromises a dependency. *Mitigated by deny
   policy, reproducible builds, dependency review.*
6. **Cluster-tenant attacker** — has Pod-label `PATCH` rights on the cluster
   (Kubernetes deployments only). Trying to defeat `agent-guard`'s
   `scope = "pod-label"` selector by either opting unrelated pods into
   agent-guard's policies (denial-of-service-of-attention) or opting the
   actual agent pod out (defeat). *Mitigated by cluster RBAC posture; see
   Policy surface mitigations.*

## Trust assumptions

- Kernel is trusted. (Defense against kernel-level rootkits is out of scope
  for v1; revisit when dm-verity/sysext layer lands.)
- Hardware root of trust (TPM 2.0) is trusted where present, used for sealing
  notification credentials and SSH agent keys.
- The off-host log bucket is in a different administrative domain than the
  host. (Practically: a $5 VPS with a different provider.)
- For Kubernetes deployments: the cluster control plane is trusted to enforce
  RBAC. `agent-guard`'s pod-label scope inherits the cluster's RBAC posture
  on Pod-label `PATCH` — see Policy surface mitigations.

## Mitigations by layer

### Build & supply chain
- Pinned Rust toolchain (`rust-toolchain.toml`).
- `Cargo.lock` committed and built with `--locked`.
- `cargo-deny` enforces license and source policy.
- `cargo-audit` blocks builds on known CVEs.
- `cargo-vet` (future) tracks human-reviewed crate versions.
- Reproducible builds in a clean container; hash published with releases.
- Releases signed with cosign; SBOM (CycloneDX) attached.

### Process
- `selfdef:selfdef` user, no shell, no home directory writable.
- Systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectKernelModules`, `MemoryDenyWriteExecute`, syscall filter, minimal
  capability set.
- AppArmor profile constrains file system reach.
- `panic = "abort"` in release: no unwinding into hostile state.
- `unsafe_code = "forbid"` everywhere except the eBPF crate.

### Configuration & rules
- Config and rules are read-only at runtime; daemon owns no write capability
  for these paths.
- SIGHUP triggers a full re-read into a fresh in-memory rule set; old set
  retained until new set validates.
- Rule files signed (cosign, future) — daemon refuses unsigned rules in
  production mode.

### Storage
- Hot store on a path only the daemon writes; mode 0600.
- Cold archive shipped immediately and never modified locally.
- DB integrity checked on startup; corruption alerts loudly.

### Notification
- Outbound credentials in `/etc/selfdef/secrets/`, mode 0600, loaded on
  start, never re-read from disk (so an attacker editing them doesn't
  exfiltrate without a daemon restart).
- TPM-sealed where TPM present.
- Notification *failures* themselves are events — silent silence is suspicious.

### Tamper detection
- Self-watchdog: daemon publishes a heartbeat; absence of heartbeat for
  > 60s is itself logged to journal and (via fallback path) attempts to
  notify.
- AIDE baseline includes the daemon binary, config, and rules.
- Tetragon TracingPolicy specifically watches `/usr/bin/selfdefd`,
  `/etc/selfdef/`, `/var/lib/selfdef/` for modification by anything that
  is not the daemon's own update path.

### API surface
- **UNIX socket transport** (default): filesystem permissions are the auth
  boundary. Default `0660 root:adm`; recommended for on-host scrapers
  (Prometheus running on the same host).
- **TCP transport**: bearer-token required on every request. The token is
  read from `api.token_file` (mode `0600`, `root:selfdef` on the daemon
  host or `prometheus:prometheus` on the scrape host) and is loaded once at
  startup — rotation is a deliberate operator action via daemon restart, not
  an automated watcher (see "Side channel" below).
- **TLS / mTLS**: opt-in; required when binding outside `127.0.0.1`.
- **`/metrics` is read-cap**: the same bearer token grants read access to
  `/status`, `/events`, `/findings`, `/events/stream`, and `/metrics`. It
  does NOT grant control-verb access (`/rules/reload`, `/panic`,
  `/actions/*/run`) — those need the separate `control_token_file`.
  Verified by the integration test
  `crates/selfdef-api/tests/m12_api.rs::metrics_allows_read_capability`.
- **Side channel**: `selfdef_uptime_seconds` lets a scraper observe daemon
  restarts. Rotate notifier credentials via a deliberate operator action,
  not through automated watchers that key on uptime resets. See known gap
  F-2026-066.
- **Per-token SSE subscriber quota** (SDD-007): `/events/stream` is capped
  at `MAX_SSE_SUBSCRIBERS_PER_TOKEN` (default 8) per bearer-token fingerprint
  and `MAX_SSE_SUBSCRIBERS` (default 64) process-wide. The token fingerprint
  is SHA-256 of the presented bearer; the per-token map prunes empty entries
  on `Drop` so rotation doesn't leak counter slots. Bounds the authenticated-
  only DoS a single malicious bearer-holder (or a leaked token) can mount
  against legitimate operators — capping each token's slice means revoking
  the abusive token restores legitimate access. Both caps are operator-
  tunable via `[api].max_sse_subscribers` and `max_sse_subscribers_per_token`
  in `selfdef.toml`; `None`/`Some(0)` fall back to the defaults. Distinguishable
  503 reasons (`"sse subscriber cap reached"` global vs `"per-token sse cap
  reached"`) so operators can tell which limit they hit. See
  `crates/selfdef-api/src/handlers.rs::SubscriberGuard` and SDD-007 for the
  full implementation + the deferred terminate-on-revoke hardening note.

### Policy surface
- **TracingPolicy directory** (`/etc/tetragon/tetragon.tp.d/`): the
  `tetragon` module creates this directory at install time. Recommended
  mode `0750 root:root`; only `agent-guard` and any other operator-approved
  policy module should write to it. An `integrity-sentinel` paths file
  should baseline this directory's contents so unexpected additions /
  removals fire a Detection Finding.
- **Pod-label scope** (`agent-guard` `scope = "pod-label"`, k8s only): the
  policy boundary is the configured `pod_label_key=pod_label_value` pair.
  Any cluster identity with `PATCH` rights on a Pod's labels can move the
  boundary — opt unrelated pods in (DoS of attention) or opt the agent pod
  out (defeat). Document the required RBAC posture in your cluster's
  `Role` / `RoleBinding` for the namespace agent-guard watches; restrict
  Pod-label `PATCH` to cluster-admin or a narrowly-scoped service account.
  See Adversary class 6.
- **Eventstream JSONL trust**: every line in every path listed in
  `[collectors.eventstream].paths` is treated by the daemon as if a trusted
  collector emitted it. The daemon-owned default
  `/var/lib/selfdef/eventstream/` should be `0750 selfdef:selfdef`.
  Operator-owned emitters (e.g. the user's own
  `~/.local/share/selfdef/ssh-wrap.jsonl`) inherit the user's trust posture
  — a compromise of that user's account is event-injection. See known gap
  F-2026-026 / F-2026-065.

### Hardening checklist (AI-machine deployment)

For a typical AI-machine deployment (`tetragon` + `agent-guard` +
`observability` + `integrity-sentinel`), the audit-recommended hardening
posture is:

- `/etc/tetragon/tetragon.tp.d/` — `0750 root:root`.
- `/var/lib/selfdef/eventstream/` — `0750 selfdef:selfdef`.
- `/etc/selfdef/api.token` — `0600 root:selfdef` on the daemon host
  (or `0600 prometheus:prometheus` on the scraper host).
- `agent-guard` pod-label scope (k8s only): cluster RBAC restricts
  Pod-label `PATCH` to cluster-admin or a narrowly-scoped service account.
- `integrity-sentinel` paths file includes `/etc/tetragon/`,
  `/etc/selfdef/`, and `/var/lib/selfdef/eventstream/` so tamper attempts
  surface as Detection Findings.
- `/metrics` exposed via UNIX socket on hosts where the credential dir
  is not exclusively root-writable; rotate the API token via a deliberate
  daemon restart.

This block is intentionally short — copy it into your deployment runbook.

## Known gaps (tracked, not yet closed)

- No dm-verity layer for the daemon yet — root *can* still tamper.
- No remote attestation; assumes operator trusts the host at build time.
- Rule signing — **opt-in shipped**. Set
  `[security].require_signed_rules = true` and
  `[security].signing_public_key_file = "<path>"` in
  `selfdef.toml`. The daemon refuses to load any rule lacking a
  valid sibling `<rule>.yml.minisig` under the configured
  minisign public key. Operators sign with the standalone
  `minisign` CLI (`minisign -S -m <rule>.yml -s <secret-key>`).
  See `docs/dev/signing.md` for the full runbook + threat-model
  caveats. Default is off so the existing unsigned-rule
  workflow keeps working.
- Defense against kernel rootkits is delegated to "don't run a compromised
  kernel" — i.e. UEFI Secure Boot + signed kernels, out of band.
- **Eventstream JSONL injection (F-2026-026 / F-2026-065).**
  `selfdefctl events emit --out <path>` is an event-injection
  primitive. Anyone with write access to a path the daemon
  tails via `[collectors.eventstream].paths` can inject
  Findings-shaped events that fire the notifier chain or
  pollute the multi-host NATS bridge via `host_tag` spoofing.
  The mitigation is filesystem-level: daemon-owned paths
  must be `0750 selfdef:selfdef`; operator-owned paths
  inherit that operator's trust posture. An **opt-in**
  parse-time integrity check shipped as the F-2026-026
  follow-up — set `[collectors.eventstream].integrity_check = true`
  and the daemon refuses to tail any path that is
  world-writable or owned by a UID outside
  `{daemon-effective-uid, root} ∪ allowed_owners`. Disabled
  by default to preserve operator-owned emitters
  (`~/.local/share/selfdef/ssh-wrap.jsonl`); turn on when the
  hardening checklist's `0750 selfdef:selfdef` posture is
  in place.
- **Metrics uptime side channel (F-2026-066).** The
  `selfdef_uptime_seconds` counter on `/metrics` lets a
  scraper observe daemon restarts. An attacker who can
  scrape `/metrics` and also has unprivileged write access
  to the notifier-credentials directory could time a
  credential-file edit to a daemon restart, exploiting the
  "credentials loaded once at startup" mitigation. Bind
  `/metrics` to UNIX socket only (or to localhost behind a
  bearer token) on hosts where the credential dir is not
  exclusively root-writable. Credential rotation should
  remain a deliberate operator action; an automated
  uptime-watcher rotator is the wrong shape.
- **TracingPolicy signing (F-2026-024 follow-up — shipped).**
  The `tetragon` module's `apply.sh` and `check.sh` re-use
  `selfdefctl keys verify` to validate every policy file's
  sibling `.minisig` against `[security].signing_public_key_file`.
  Turn on via `require_signed_policies = true` in
  `/etc/selfdef/modules/tetragon.toml`; apply refuses to
  (re)start tetragon if any policy is unsigned or invalid, and
  `selfdefctl modules check` reports the unsigned count as a
  `failed` status. See `docs/dev/signing.md` "TracingPolicy
  signing" for the runbook. Caveat: agent-guard renders policies
  at runtime and its output isn't pre-signed — that's documented
  in the runbook and intentionally out of scope.
- **Metrics-token rotation (F-2026-023 follow-up — shipped).**
  `selfdefctl api rotate-token` ships in selfdef ≥ this release.
  The verb generates a fresh 32-byte high-entropy token, writes
  it atomically to `[api].token_file` (tempfile + fsync + rename
  + chmod 0600), then optionally signals the running daemon
  (`--pid <pid>` or `--pid auto` to discover via `systemctl show
  -p MainPID selfdefd.service`). On SIGUSR2 the daemon re-reads
  the token file under the shared `Arc<RwLock<>>` that backs the
  bearer-token middleware — in-flight requests authenticate
  against the new token without dropping the existing
  connection. The previous token continues to work until the
  signal is delivered, so operators can stagger the rotation
  on scraper hosts. Reload errors (empty file, IO failure) log
  a structured warning and keep the previously-loaded tokens in
  place — the daemon stays up; existing valid tokens keep
  working.
- **k8s label-RBAC posture (F-2026-025 follow-up — shipped).**
  `selfdefctl rbac check` ships. Without `--probe` it prints the
  recommended posture + the exact `kubectl auth can-i` commands
  the operator should run. With `--probe` it shells out to those
  commands for a built-in set of subjects
  (`system:authenticated`, `system:unauthenticated`) plus any
  operator-supplied `--as` and exits non-zero if any subject can
  PATCH pod labels. See `docs/dev/rbac-posture.md` for the full
  runbook. The check is documentation + spot-checking on a
  fixed subject set, not a cluster-wide enumeration — use
  `rbac-tool` or `kubectl-who-can` for that.

## Reporting

If you find a vulnerability in this codebase, file a private security advisory
on the repository — do not open a public issue.
