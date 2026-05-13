# Security & Threat Model

Security tooling is a high-value target. An attacker who compromises the
detector wins twice: they evade detection *and* they gain a privileged process
on the host. This document is the threat model of the daemon itself.

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

## Trust assumptions

- Kernel is trusted. (Defense against kernel-level rootkits is out of scope
  for v1; revisit when dm-verity/sysext layer lands.)
- Hardware root of trust (TPM 2.0) is trusted where present, used for sealing
  notification credentials and SSH agent keys.
- The off-host log bucket is in a different administrative domain than the
  host. (Practically: a $5 VPS with a different provider.)

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

## Known gaps (tracked, not yet closed)

- No dm-verity layer for the daemon yet — root *can* still tamper.
- No remote attestation; assumes operator trusts the host at build time.
- Rule signing not yet enforced.
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
  inherit that operator's trust posture. A daemon-side
  ownership / mode check at parse time is tracked under
  SDD-004 follow-up.
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

## Reporting

If you find a vulnerability in this codebase, file a private security advisory
on the repository — do not open a public issue.
