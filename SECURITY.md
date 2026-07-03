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
| Notification credentials | `/etc/selfdef/secrets/` | ntfy tokens, signal-cli auth, SMTP `password_file` (`[notifier.smtp]` per SDD-008 D-7 Q-E), Twilio `auth_token_file` (`[notifier.twilio]` per SDD-008 Q-D), Slack `webhook_url_file` (`[notifier.slack]` per SDD-008 Q-C), Discord `webhook_url_file` (`[notifier.discord]` per SDD-008), PagerDuty `routing_key_file` (`[notifier.pagerduty]` per SDD-008 Q-G), Loki `auth_token_file` (`[notifier.loki]` per SDD-008 Q-G), OpenSearch `auth_token_file` (`[notifier.opensearch]` per SDD-008 Q-G — Basic password OR API key depending on `auth_kind`), TheHive `api_key_file` (`[notifier.thehive]` per SDD-008 Q-G) — webhook URLs, the PagerDuty routing key, the Loki bearer token, the OpenSearch credential, and the TheHive API key are themselves the auth secret. Each integration crate reads its credential from a disk path; daemon must run as the file owner and the file mode must keep group/world readers out (`0600` recommended). |
| TTY broadcast | `wall(1)` via `[notifier.wall]` (SDD-008 D-8), `write(1)` via `[notifier.write]` (D-024 — per-user sibling of wall) | Two session-attention transports — `wall` broadcasts to every logged-in TTY; `write` targets a configured allowlist (`[notifier.write].users`) one user at a time. Both render one-line attention banners when severity ≥ floor (default `high` on both). Daemon needs `tty`-group membership or root to wall/write. Defense-in-depth: severity_floor refuses to broadcast on routine events; operators who lower it past the default carry the noise themselves. The `write(1)` username allowlist is regex-validated at config-load (`[a-zA-Z0-9._-]+`) — shell metacharacters reject startup. |
| Notification escalations store | `[notifier.escalations_path]` (per SDD-008 D-5 — typically `/var/lib/selfdef/escalations.sqlite`) | Persists every outbound notification's rendered title + body until the operator acks or `max_rung` expires. **Cleartext at rest**: the table holds the alert content (which may contain hostnames, IPs, ATT&CK technique-ids, file paths, command lines). An attacker with read access to this file learns which events the daemon noticed. SQLite WAL mode means an extra `-wal` + `-shm` sibling file with the same sensitivity. Mode `0600`, daemon owner only. Closed-event rows are deleted (`selfdefctl notify forget`); SQLite does not zero the freelist by default — rotated content remains recoverable until a `VACUUM`. |
| HTTP ack URL leakage | `[notifier.ack_link_base]` + 6 outbound channels (smtp, slack, discord, twilio, wall, write) (per SDD-008 D-4 HTTP ack, Phase 7 F-2032-002, D-024 write-channel addendum) | When `ack_link_base` is configured, the daemon embeds a `<base>/<token>` URL in every outbound notification. **The token IS the auth** for the `GET /notify/ack/:token` route — there is no bearer-token check. UUIDv7 has ~74 bits of post-timestamp entropy → not brute-forceable online. **Realistic attack surface is third-party log leakage**: SMTP relay logs / Slack workspace search / Discord audit log / Twilio dashboard / `wall(1)`-readable TTYs / `write(1)`-targeted TTYs all see the full URL. The `write(1)` channel narrows broadcast vs `wall(1)` (only listed users' TTYs receive it), but each listed user — and anyone reading over their shoulder — still sees the URL in the rendered banner. Operators sharing a Slack channel with non-SOC members, or auto-archiving SMS, leak ack capability to those readers. Mitigation: prefer machine-only Q-G channels (pagerduty / loki / opensearch / thehive — these do NOT include the URL in their wire body) or restrict the human-facing channels to SOC-only delivery destinations. After the token-stability fix (Phase 7 F-2032-005), a leaked token stays valid for the full lifetime of the unacked row, including across rung re-fires. |
| eBPF programs | embedded in binary | Tampering disables in-kernel detection |
| `/metrics` endpoint | UNIX socket `/run/selfdef.sock` or TCP `<api.bind>` | Activity-fingerprint information; chained-attack timing of credential edits to daemon restart (see API surface mitigations + F-2026-066 known gap) |
| `/v1/*` read surface | Same UNIX socket + TCP path | MS010/MS011/MS027 + four-watchdog set state. Read-only; gated by the read bearer token on TCP. Information-disclosure: hardware specs (CPU/memory/GPU inventory, sain-01 verdict), network reachability (internet/DNS/cloudflared/tailscale/traefik), filesystem usage (per-mount + selfdef log dirs), RAID degradation, GPU power draw, CPU mode. See "API surface" mitigations for the leak-on-token-compromise + subprocess-DoS profile. |
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

### Response self-protection (anti-self-attack)
The responder and guardian wield destructive primitives (kill / quarantine /
isolate / revoke / block / SIGKILL) driven by events whose fields a local or
federated attacker can influence (a crafted/misattributed collector or Tetragon
event). Both responders therefore refuse to turn that power against the IPS
itself or the operator (findings F-2026-116 … F-2026-125):

- **Self-preservation.** No pid-targeting action signals the daemon's own pid
  (`pid_from_event` filters `std::process::id()`), and the guardian refuses to
  SIGKILL its own pid — a crafted event naming the daemon can't make the IPS
  kill itself. Init (pid 1) is refused everywhere.
- **No operator lock-out.** `block_ip` refuses loopback / unspecified /
  multicast / link-local / broadcast addresses (can't self-DoS the host's
  networking). Session / API-token / MFA revocation and the `revoke_session`
  action refuse a configured *exclusion list* of protected principals — **but
  that list defaults empty; populate it** (see the hardening checklist) or the
  protection is inert.
- **No argument injection.** Every action that shells out (`revoke_session`,
  the guardian's `podman kill`, `velociraptor_escalate`) refuses an
  attacker-influenced value starting with `-` and/or passes `--` so a value
  like `--all` can never be flag-parsed (e.g. `podman kill --all` mass-kill).
- **No console spoofing.** Guardian console alerts strip terminal control /
  escape sequences before writing to `/dev/console`.
- **Federation trust boundary.** With `[responder].act_on_federated = false`,
  destructive response to a cross-host finding is refused unless the event
  carried a valid trusted-peer signature (F-2026-111).
- **Circuit-breakers** (opt-in): per-target dedup + a global rate-cap bound a
  finding flood from driving mass destruction.

> Most destructive effectors run in **dry-run by default**
> (`[responder].dry_run = true`) — they preview, not execute — so these guards
> matter most once you enable real response (`dry_run = false`). The guardian
> (`selfdef-guardian`) has no dry-run mode and its guards apply unconditionally.

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
- Self-watchdog: the daemon emits the systemd watchdog heartbeat
  (`sd_notify WATCHDOG=1` every 30s, `run_heartbeat`) and `selfdefd.service`
  sets `WatchdogSec=60` (a 2-beat window), so a **hung** daemon (deadlocked /
  runtime-wedged — alive but not beating, which `Restart=on-failure` can't
  catch) is killed + restarted by systemd at the deadline, with the watchdog
  timeout logged to the journal. Optional add-on (operator drop-in, not shipped
  by default to avoid a notify-storm on a crash-loop): an `OnFailure=` notify
  unit for an out-of-band alert on watchdog restart. See F-2026-100.
- AIDE baseline includes the daemon binary, config, and rules.
- Tetragon credential-access policy (`rules/tetragon/observe-sensitive-files.yaml`)
  observes file *opens* under `/etc/selfdef/secrets/` (action `Post`/observe,
  T1552), and the optional agent-guard `etc-write-guard` observes `/etc/`
  writes broadly (T1565, `Post`). A dedicated Tetragon policy
  (`rules/tetragon/observe-selfdef-tamper.yaml`) watches the daemon binary
  `/usr/bin/selfdefd` + the config/rules tree `/etc/selfdef/` for access by any
  binary outside the daemon/CLI/package-update exclusion set (`matchBinaries:
  NotIn` selfdefd, selfdefctl, dpkg/apt, install, systemd — T1554, action
  `Post`/observe). The `/var/lib/selfdef/` state dir is **deliberately not**
  in this policy — the daemon rewrites it constantly, so a kernel watch there is
  a high false-positive surface; its integrity relies on the periodic AIDE
  baseline (above) instead. **Caveat (F-2026-099):** the policy ships as a
  validation-pending draft (`selfdef.io/validation: REQUIRED-ON-TETRAGON-HOST`)
  and keys on `security_file_open` (any open, not write-specific), so until it
  is loaded + confirmed firing on a live Tetragon host, real-time daemon-binary
  + config tamper detection still leans on the periodic AIDE baseline rather
  than this in-kernel policy.

### Four-watchdog set (IPS spine, MS046+MS047+MS044+MS048)

Four cooperating boundary-enforcement layers ship with the package as
the IPS spine. Each layer addresses a different class of adversary
move (see Adversaries above):

| Watchdog | Layer | Adversary it counters |
| --- | --- | --- |
| friction-audit (MS046) | hardware frame | PCIe / ZFS / memory tamper before kernel even boots. Boot-**ordered** `Before=podman/docker/containerd` (`sovereign-guard.service`, oneshot); on a failed gate it exits non-zero + emits an audit event. NOTE: `Before=` is systemd *ordering*, not a hard requirement — the shipped unit shows no `Requires=`/`Requisite=` on the runtime units, so by default a failed gate does **not** itself block podman/docker/containerd from starting (it runs first + audits). Hard blocking needs an operator-added requirement dependency (drop-in). See Known gap F-2026-098. |
| perimeter (MS047) | kernel syscall | Arbitrary-binary execution under any user; in-kernel `Sigkill` on `sys_execve` outside the verbatim sain-01 §6 allowlist `{python3, nvidia-smi, vllm, podman}`. Extensions require an MS003-signed manifest + TTL ≤ 30 days (one detached signature is cryptographically verified; the manifest's two distinct kids are attestation metadata, **not** a second verified co-signature — see Known gap F-2026-095). |
| guardian (MS044) | supervisor tier | Tetragon-policy violations the kernel-fence catches; fans out the verbatim 3-step response (`podman kill` / atomic ZFS audit append / `/dev/console` BEL alert). Circuit breaker prevents same-target flood (5 SIGKILLs / 60s). |
| scheduler (MS048) | routing layer | Resource-pressure-induced shortcuts: never let expensive cognition wait on cheap preparation; never let cheap speculation commit without expensive verification when risk demands it. 7-axis objective + 5 backpressure surfaces (Blackwell VRAM / RTX 3090 / CPU PSI / RAM PSI / IO PSI / human-gate queue). |

Audit-chain invariant (all 3 emitting watchdogs — perimeter, guardian,
scheduler): every event is SHA-256-chained to the prior event via a
`prev_event_sha256` field in its OCSF JSONL line. The `selfdefctl
doctor` `watchdog-set` category surfaces chain-break detection as a
critical signal pointing at the matching runbook.

Operator surfaces — operators can detect tampering across the spine
without per-watchdog drill-down:

- `selfdefctl doctor` — watchdog-set category reports deployability +
  per-watchdog audit-chain integrity
- `selfdefctl trio --watch N` — live 4-panel snapshot
- `selfdefctl trio-tail` — unified live OCSF tail
- Grafana — 9 panels (one per failing-state aggregate + chain length)
- 20 operator runbooks in the companion `devops-solutions-information-hub`
  wiki/runbooks/, 5 per watchdog covering startup-failures + chain
  corruption + false-positive rollback + key rotation + investigation

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
- **`/v1/*` four-watchdog + dashboard surface** (MS010/MS011/MS027 + the
  four-watchdog set): all `/v1/*` routes shipped to date are READ-ONLY
  and gated by the same bearer token + UNIX-socket-filesystem-permission
  boundary as the legacy read endpoints. The route set as of 2026-05-21:
  `/v1/{friction-audit,perimeter,guardian,scheduler}` + their `/history`
  siblings + `/v1/scheduler/{backpressure,weights,explain/:request_id}`
  + `/v1/modules{,/:name}` (`:name` regex-validated `[a-z0-9-]{1,64}`
  against directory traversal) + `/v1/alerts` (server-side classifier
  for the 9 four-watchdog alert series) + `/v1/hardware{,/capabilities,
  /sain01}` (cached probe, OnceLock) + `/v1/network` (live ping +
  systemd is-active probe) + `/v1/storage` (live `df` + log-dir walk)
  + `/v1/raid` (live `/proc/mdstat` read) + `/v1/gpu` (live `nvidia-smi`
  power-draw vs operator-authored `/etc/selfdef/gpu-policy.toml`) +
  `/v1/cpu` (live `/sys/devices/system/cpu/*/cpufreq/scaling_governor`
  + SMT state read). **Information-disclosure profile**: each `/v1/*`
  route exposes operational state (hardware specs, network reachability,
  filesystem usage, RAID degradation, GPU power draw, CPU mode). A
  legitimate read-token holder learns the host's complete sovereign
  configuration; a leaked read token leaks the same. Mitigation: rotate
  read tokens on operator action (same as `/metrics`); for hosts where
  even read access must be operator-only, prefer the UNIX-socket
  transport and keep TCP off. **Subprocess probe DoS**: `/v1/network`
  invokes `ping` + `systemctl` + `getent`; `/v1/storage` invokes `df`;
  `/v1/gpu` invokes `nvidia-smi`. Each is bounded by the OS-level
  subprocess timeout and probe complexity (ping has `-W 2`; df returns
  in O(ms); nvidia-smi is one CSV query). A read-token holder can
  trigger these on every request — bound the resulting load via the
  same rate-limit / per-token throttle posture as the other read
  endpoints. No control-verb effect on the host.
- **Cached vs live probes**: `/v1/hardware*` is cached per-process via
  `OnceLock` — hardware doesn't hot-swap, so probing once at first
  request is sufficient. `/v1/network` / `/v1/storage` / `/v1/raid` /
  `/v1/gpu` / `/v1/cpu` re-probe on every request because their
  underlying state DOES change (mounts fill, RAID degrades, GPU draw
  shifts under load, CPU mode is operator-mutable). The cached-vs-live
  distinction is part of the API contract — operators monitoring
  hardware drift should NOT use `/v1/hardware` (it won't update);
  operators monitoring filesystem fill SHOULD use `/v1/storage` (live).
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
  **Terminate-on-revoke posture (D-002, 2026-05-15)**: token rotation refuses
  *new* connections immediately via bearer-auth, but existing SSE connections
  continue to drain until they hit the F-2027-062 slow-client timeout
  (currently `30s`, hardcoded — see
  `crates/selfdef-api/src/handlers.rs:396`) or the client disconnects
  naturally. The 30-second timeout is the **documented upper bound** on the
  leak window between a token rotation and the final close of a connection
  bearing the revoked credential. Operators who require zero leak window
  should rotate, then wait ≥30s before treating the credential as fully
  revoked. `drained_at`-per-fingerprint terminate-on-revoke hardening is the
  documented upgrade path if operator demand surfaces (see SDD-007 D-3 and
  `docs/decisions.md` D-002 for the rationale to keep current behaviour).

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
- **If you enable real (non-dry-run) destructive response**, populate the
  self-lockout exclusion lists with your operator + break-glass accounts —
  they default empty: `[responder].revoke_session_excluded_users`, and the
  protected-principal sets on the session / API-token / MFA revocation
  effectors when wired. Without this, a crafted event naming the operator can
  revoke their access mid-incident.
- **For NATS federation with auto-response**, set
  `[responder].act_on_federated = false` and configure per-peer signing keys
  (`[bus.nats].signing_key_file` + `[bus.nats.peer_keys]`) so only
  cryptographically-authenticated cross-host findings can drive destructive
  response.
- **If you expose the grant-issuance API** (`POST /v1/grants/issue`), set
  `[grants].overlap_policy = "refuse"` (or `"warn"`) so a compromised control
  capability cannot mint an unbounded sprawl of overlapping / escalating
  grants. Default `off` keeps the historical unconditional-issue behavior; the
  gate is fail-safe (it only ever blocks *adding* an overlapping grant, never
  narrows existing access). Pair it with `[grants].issuance_cooldown_secs > 0`
  to rate-bound re-minting of an identical grant (refused with 429), which also
  catches re-mint churn of an already-expired/revoked grant.

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
- **Extension dual-control is single-sig (F-2026-095).** The
  perimeter watchdog row claims extension manifests "require
  multi-sig", but `ExtensionStore::load_signed` verifies exactly
  **one** detached signature (`<manifest>.json.minisig`) against
  any trust-root `.pub`; `validate()` requires `signer_kid` and
  `auditor_kid` to be present and distinct, but those are metadata
  covered by the single signature, not an independently-verified
  second co-signature. So a holder of **one** trust-root signing
  key can forge a manifest with any two kids — two-person control
  degrades to single-control (gated behind operator-key compromise,
  not a file-drop bypass: the single signature *is* enforced).
  Closing it is a PO decision (A: add a second distinct-signer
  signature via the `selfdef-threshold-sig-store` pattern + a
  `kid`→trust-root-key mapping; B: accept attested single-sig and
  correct the "multi-sig" wording). Tracked in the findings ledger.
- **kill_pid PID-reuse TOCTOU (F-2026-090).** `KillPidAction`
  sends `kill -TERM` to the raw actor pid with no re-verification
  that the pid still refers to the detected process; if the
  offending process exits and the kernel reassigns its pid between
  detection and response, SIGTERM can hit an innocent process.
  Doubly opt-in (responder defaults `dry_run = true` +
  `allowed_actions = ["notify"]`, so live kill needs both flipped).
  Re-verification design (start-time vs exe-identity; fail-open vs
  fail-closed when `/proc` is unreadable) is a PO decision — a naive
  exe-check would skip self-deleting malware (`/proc/<pid>/exe →
  …(deleted)`), so it's surfaced, not auto-fixed.
- **Collector death is not live-supervised (F-2026-089).** A
  collector task that panics mid-run isn't watched by the daemon's
  main `select!` — it's only detected (and warned) at shutdown, so
  a security source can go blind for a full run before the operator
  sees it. The shutdown path now reports the abnormal termination
  truthfully (no more false "stopped"); live supervision + the
  warn-vs-restart-vs-exit policy is a tracked PO decision.
- **friction-audit gate orders but doesn't hard-block runtimes
  (F-2026-098).** `sovereign-guard.service` is `Before=podman/
  docker/containerd` (oneshot) and `friction-audit.sh` exits
  non-zero + emits an audit event on a failed PCIe/ZFS/memory
  gate. But `Before=` is systemd *ordering*, not a requirement:
  no `Requires=`/`Requisite=` is shipped on the runtime units
  (SDD-027 documents ordering; the L3 test verifies `Before=` is
  *honored*, i.e. ordering, not blocking), so a tampered host
  that fails the gate still starts its container runtimes — the
  failure is audited, not enforced. The honest guarantee is
  "runs first + audits on failure". Hard pre-boot blocking needs
  an operator-added `Requires=sovereign-guard.service` (or
  `Requisite=`) drop-in on podman/docker/containerd, or an
  event-driven responder action that stops the runtime when the
  gate-fail audit event fires. Which mechanism to ship by default
  (and whether hard-fail-at-boot is even desirable vs. audit-only,
  given it could brick a host on a false-positive hardware
  reading) is a PO decision.
- **Tetragon daemon self-protection policy — DRAFTED, validation-pending
  (F-2026-099).** The Tamper-detection section once claimed a Tetragon
  TracingPolicy watching `/usr/bin/selfdefd` + `/etc/selfdef/` +
  `/var/lib/selfdef/` for modification that was not shipped. It now IS
  shipped as `rules/tetragon/observe-selfdef-tamper.yaml` — a
  `security_file_open` observe policy (action `Post`, never blocks) on the
  daemon binary `/usr/bin/selfdefd` + the config/rules tree `/etc/selfdef/`,
  with a `matchBinaries: NotIn` exclusion for the legitimate writers
  (selfdefd, selfdefctl, dpkg/dpkg-deb, apt/apt-get, install, systemd) — i.e.
  the daemon-update-path exclusion (the non-trivial design part) is concrete.
  Two honest caveats remain: (1) it carries
  `selfdef.io/validation: REQUIRED-ON-TETRAGON-HOST` and has NOT been verified
  to load + fire on a live Tetragon kernel (none in CI), so it is deliberately
  not marked "fixed" — claiming it works unvalidated would repeat this
  finding's own over-claim; observe-only ⇒ zero risk while unvalidated
  (worst case it just doesn't fire = the prior state). (2) `/var/lib/selfdef/`
  is deliberately **excluded** from the watch — the daemon rewrites it
  constantly (high false-positive surface); its integrity relies on the
  periodic AIDE baseline scan (`integrity-sentinel`, which also covers config
  + rules explicitly and the binary via AIDE's standard `/usr/bin` coverage).
  Optional future refinement: a write-specific (`security_path_*`) kprobe once
  the open-mode policy is validated on a Tetragon host.
- **Self-watchdog hang-detection — FIXED (F-2026-100).** The
  daemon emits `WATCHDOG=1` every 30s but `selfdefd.service` had no
  `WatchdogSec=`, so systemd ignored it and a *hung* daemon went
  undetected. Now `WatchdogSec=60` is set (2-beat window): a hung
  daemon is killed + restarted by systemd, watchdog timeout logged.
  Remaining optional add-on (not shipped by default to avoid a
  notify-storm on a crash-loop): an `OnFailure=` notify unit for an
  out-of-band alert — a small PO drop-in.

## Reporting

If you find a vulnerability in this codebase, file a private security advisory
on the repository — do not open a public issue.
