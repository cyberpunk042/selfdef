# selfdef

Self-defense service for Linux hosts (Debian 13+, Ubuntu 24.04+).
A multi-layered host detection, deception, and response platform aimed at
personal workstations, home servers, and public VPSes.

> **Status:** Milestone 1 — Foundation. Scaffolding only; not runnable yet.

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

Explicit non-goal: offensive action against attackers. Active deception
(honeytokens, honey services) is in scope; hacking back is not, ever.

## Layout

```
crates/                          One workspace, many focused crates.
  selfdef-core/                  Schema, event envelope, errors.
  selfdef-config/                Layered config (TOML + env + CLI).
  selfdef-bus/                   Event bus abstraction.
  selfdef-store/                 SQLite (hot) + DuckDB (warm) storage.
  selfdef-correlator/            Rule engine.
  selfdef-notifier/              ntfy, signal-cli sinks.
  selfdef-responder/             Action runners (lockdown, snapshot, etc.).
  selfdef-collector-auditd/      auditd → bus.
  selfdef-collector-journald/    journald → bus.
  selfdef-collector-tetragon/    Tetragon JSON → bus.
  selfdef-collector-suricata/    Suricata EVE → bus.
  selfdef-cli/                   selfdefctl admin binary.
  selfdef-daemon/                selfdefd main binary.

rules/                           Detection-as-code.
  sigma/                         Sigma rules.
  yara/                          YARA rules.
  tetragon/                      Tetragon TracingPolicies.

packaging/                       OS packaging artifacts.
  debian/                        cargo-deb metadata, postinst/postrm.
  systemd/                       Hardened unit files.
  apparmor/                      AppArmor profile for the daemon.

selfdef-ebpf/                    eBPF programs (aya). Separate build target.
tests/                           Integration tests, replay corpora, adversary maps.
docs/                            mdbook documentation.
ansible/                         Deployment playbooks.
```

## Quickstart (once Milestone 3 lands)

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

## Threat model

See [SECURITY.md](SECURITY.md) — the daemon itself is a target.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
