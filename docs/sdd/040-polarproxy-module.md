# SDD-040 — Polarproxy module — transparent TLS inspection — MS023

> Status: **draft** — Stage-2 architectural spec for the shipped
> `polarproxy` module under `modules/polarproxy/`. The module
> provisions transparent TLS termination → PCAP-over-IP for content
> visibility, with two profile modes (host-tls-mitm vs bridge-tap).
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS023 (catalog
> `backlog/milestones/MS023-polarproxy-module-tls-inspection.md`)
> Builds on: SDD-039 (MS024 bridge-l2 — `bridge-tap` profile
> dependency); soft-dependency, not hard
> Companions: packaging/test/L2-polarproxy.bats (9 tests)

## Problem

Content-visibility on encrypted traffic requires TLS termination
under a controlled CA — the operator becomes the man-in-the-middle
for their own outbound TLS. PolarProxy provides this:
- Terminates inbound TLS using a per-host operator-controlled CA
- Re-encrypts to the upstream after capturing the cleartext
- Emits PCAP-over-IP on a configured port for downstream inspection

Without a shipped module, every operator deploying polarproxy has
to author the systemd unit + nftables redirect + cert plumbing.

## Module inventory (shipped)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/polarproxy/module.toml` | category=network, default profile=host-tls-mitm |
| Apply | `modules/polarproxy/install/apply.sh` | Renders unit + nftables ruleset |
| Check | `modules/polarproxy/install/check.sh` | Read-only verifier |
| Uninstall | `modules/polarproxy/install/uninstall.sh` | Tear-down |
| L2 tests | `packaging/test/L2-polarproxy.bats` | 9 tests |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Two-profile contract

| Profile | What it does | Bridge-l2 dep |
|---|---|---|
| `host-tls-mitm` | TLS termination at the host's loopback; nftables redirects outbound 443 → polarproxy:listen_port | None (works standalone) |
| `bridge-tap` | TLS termination at the L2 bridge; transparent for endpoints | Soft — apply.sh checks for bridge-l2 active before proceeding |

The soft-dependency is implemented inside `apply.sh` rather than
the manifest `depends_on` so `host-tls-mitm` works without
bridge-l2 installed.

### Deliverable 2 — Configuration knobs

| Key | Default | Purpose |
|---|---|---|
| `profile` | `"host-tls-mitm"` | Mode selector |
| `listen_port` | `10443` | Where polarproxy receives redirected TLS |
| `pcap_over_ip_port` | `4430` | Where polarproxy emits captured PCAP |

### Deliverable 3 — Override env vars (testability)

| Env var | Default | Purpose |
|---|---|---|
| `SELFDEF_POLARPROXY_CONFIG` | `/etc/selfdef/modules/polarproxy.toml` | Config override |
| `SELFDEF_POLARPROXY_TEMPLATES` | `/usr/share/selfdef/modules/polarproxy/templates` | Template dir override |
| `SELFDEF_POLARPROXY_UNIT_PATH` | `/etc/systemd/system/polarproxy.service` | Systemd unit dest |
| `SELFDEF_POLARPROXY_NFT_PATH` | `/etc/nftables.d/selfdef-polarproxy.conf` | Nftables rule dest |

L2 bats smoke uses these to render to a tmpdir.

### Deliverable 4 — Outputs

| Artifact | Path |
|---|---|
| Systemd unit | `polarproxy.service` |
| Nftables ruleset | `/etc/nftables.d/selfdef-polarproxy.conf` |

## Production-readiness gates

| Gate | Verification |
|---|---|
| Manifest install.kind = script | L2 bats test 2 |
| 3 install scripts shipped | L2 bats test 3 |
| apply.sh DRY_RUN aware | L2 bats test 5 |
| 4 override env vars exposed | L2 bats test 6 |
| Reads profile + listen_port + pcap_over_ip_port | L2 bats test 7 |
| Default profile = host-tls-mitm | L2 bats test 8 |
| Writes unit + nftables ruleset | L2 bats test 9 |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest with default=host-tls-mitm
2. ✅ apply.sh with 4 override env vars + 3 config keys
3. ✅ check.sh + uninstall.sh
4. ✅ L2 bats coverage (9 tests)

## Authorization for Stage-3+ work

- Per-domain TLS policy (don't MITM banking sites, etc.) — extend
  config with `allowlist` / `denylist` of SNI patterns
- Cert rotation automation
- bridge-tap profile L3 nspawn boot-replay test once L3 infrastructure
  ships

— End of SDD-040 / MS023 Stage-2.
