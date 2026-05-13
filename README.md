# selfdef

Self-defense service for Linux hosts (Debian 13+, Ubuntu 24.04+).
A multi-layered host detection, deception, and response platform aimed at
personal workstations, home servers, public VPSes, and AI-machine hosts
running containerised agents.

> **Status:** All milestones M1–M15 shipped. Nine modules ship in the
> catalog (see [`docs/src/modules-roadmap.md`](docs/src/modules-roadmap.md)).
> Phase 1 architecture audit at [`docs/review/`](docs/review/) lists
> the open issues; SDDs at [`docs/sdd/`](docs/sdd/) carry the design
> work for each blocker.

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

## Module catalog

| Slug | Category | Purpose |
| --- | --- | --- |
| `detect-host` | detection | Wraps the daemon — collectors, correlator, responder, notifier, store, API. |
| `bridge-l2` | network | Transparent L2 bridge + nftables FORWARD policy. Foundation for inline IDS / TLS-tap modules. |
| `suricata` | network | Inline IDS via NFQUEUE or AF_PACKET copy-mode. |
| `polarproxy` | network | TLS termination → PCAP-over-IP for content visibility. |
| `vpn-bridge` | network | Remote-network connectivity: WireGuard relay, Tailscale, Cloudflare Tunnel. |
| `integrity-sentinel` | hardening | SHA256 baseline + drift detection. Optional notifier emission. |
| `tetragon` | hardening | Tetragon (Cilium eBPF) substrate: config, event JSONL, policy dir, `/metrics`. |
| `agent-guard` | hardening | TracingPolicies for AI agents in containers (etc-write, shell-exec, egress, SecureMessage stub, GPU device). |
| `observability` | observability | Prometheus scrape config + Grafana dashboard for the selfdef stack. |

Activate modules in `/etc/selfdef/modules.toml`; manage with
`selfdefctl modules {list,info,apply,check,status,uninstall}`.
See [`docs/src/modules.md`](docs/src/modules.md) for the contract and
[`docs/src/modules-roadmap.md`](docs/src/modules-roadmap.md) for status.

## Layout

```
crates/                          One workspace, many focused crates.
  selfdef-core/                  Schema, event envelope, errors.
  selfdef-config/                Layered config (TOML + env + CLI).
  selfdef-bus/                   Event bus abstraction.
  selfdef-store/                 SQLite (hot) + DuckDB (warm) storage.
  selfdef-correlator/            Sigma rule engine.
  selfdef-notifier/              ntfy, signal-cli sinks.
  selfdef-responder/             Action runners (lockdown, snapshot, etc.).
  selfdef-api/                   Read-only HTTP API + /metrics + control verbs.
  selfdef-nats/                  Multi-host bridge over NATS / JetStream.
  selfdef-collector-auditd/      auditd → bus.
  selfdef-collector-journald/    journald → bus.
  selfdef-collector-tetragon/    Tetragon JSON → bus.
  selfdef-collector-suricata/    Suricata EVE → bus.
  selfdef-collector-canary/      Honeytoken file watch → bus.
  selfdef-collector-eventstream/ External JSONL emitters (ssh-wrap, modules) → bus.
  selfdef-collector-ebpf/        Native in-kernel collection via aya.
  selfdef-cli/                   selfdefctl admin binary.
  selfdef-daemon/                selfdefd main binary.
  selfdef-ssh-wrap/              Drop-in ssh wrapper (client-side).

modules/                         Install modules — operator-activatable units.
rules/                           Detection-as-code (sigma, tetragon, yara).
packaging/                       OS packaging artifacts (debian, systemd, apparmor).
selfdef-ebpf/                    eBPF programs (aya). Separate build target.
tests/                           Integration tests, replay corpora.
docs/                            mdbook documentation + audit + SDD trees.
ansible/                         Deployment playbooks.
```

## Quickstart

```bash
# Build
cargo build --release --locked

# Package
cargo install cargo-deb
cargo deb -p selfdef-daemon

# Install
sudo dpkg -i target/debian/selfdef-daemon_*.deb
sudo systemctl enable --now selfdefd
selfdefctl status
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

## Threat model

See [SECURITY.md](SECURITY.md) — the daemon itself is a target.

The post-M15 audit ([`docs/review/80-security-audit.md`](docs/review/80-security-audit.md))
flagged new attack surfaces (`/metrics` exposure, Tetragon policy
directory, pod-label trust) that the SECURITY.md threat model
does not yet cover; design work for the rewrite is tracked in
the SDD pipeline.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
