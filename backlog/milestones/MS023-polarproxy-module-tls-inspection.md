# MS023 — Polarproxy module — TLS inspection

> Parent: `backlog/milestones/INDEX.md` row MS023 (source ref `modules/polarproxy`).
> Source: `modules/polarproxy/` (508 lines across README.md, module.toml, config/defaults.toml, profiles/host-tls-mitm.toml, profiles/bridge-tap.toml, install/apply.sh, install/check.sh, install/lib.sh, install/uninstall.sh, templates/polarproxy.service.tmpl, templates/nat-redirect.rule.tmpl).
> All entries below extract verbatim from these files. No invention.

## Epics (E0231–E0240)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0231 | Module identity — `polarproxy` v0.1.0, category=network, summary "Transparent TLS termination → PCAP-over-IP for content visibility"; deployment of [PolarProxy](https://www.netresec.com/?page=PolarProxy): TLS termination + re-encryption + cleartext flows emitted as PCAP-over-IP on tcp/4430 for downstream IDS / capture tools (most commonly Suricata or Wireshark / tshark) | `module.toml` 1–4 + `README.md` 1–6 |
| E0232 | Threat / use case — operator wants to inspect "what's actually inside" TLS flows crossing this host; JA3 fingerprints + SNI aren't enough; needs plaintext for content rules; PolarProxy acts as MITM with operator-installed CA on endpoints; module wires it into the network path and exposes the decrypted feed | `README.md` 8–14 |
| E0233 | Scope owned — 1) systemd unit `polarproxy.service` runs PolarProxy binary with configured listener/TLS/log paths; 2) nftables redirect (host-tls-mitm only) TCP/443 from local host → 10443 (or configured `listen_port`); 3) Pointer file `/etc/selfdef/modules/polarproxy.toml` exposing `pcap_over_ip_port` so downstream consumers (future `selfdef-collector-pcap` or Suricata AF_PACKET feed via `polarproxytls` dummy interface) can pick it up | `README.md` 16–27 |
| E0234 | Scope NOT owned — 1) installation of PolarProxy binary (`.NET` binary released by Netresec; obtain per licence terms and put on `$PATH` as `PolarProxy`; module's `requires` will fail closed if not present); 2) CA generation and endpoint trust distribution ("operator responsibility — wrong place to automate it"); 3) `polarproxytls` dummy interface for `bridge-tap` profile (created on-demand by service unit when needed) | `README.md` 29–39 |
| E0235 | Two profiles — `host-tls-mitm` (adds nftables NAT redirect from this host's TCP/443 to local PolarProxy listener; cleartext exposed on tcp/4430; no dependency) + `bridge-tap` (runs PolarProxy as inline tap on L2 bridge; cleartext fed into dummy `polarproxytls` netdev so Suricata can read it via AF_PACKET; depends on `bridge-l2` checked at apply time); default profile `host-tls-mitm`; `available = ["host-tls-mitm", "bridge-tap"]`; soft-dependency expressed by empty `depends_on = []` + runtime check inside apply.sh | `README.md` 41–46 + `module.toml` 7–11 + 30–32 + `apply.sh` 36–46 |
| E0236 | Config schema — `profile` (host-tls-mitm/bridge-tap) / `listen_port` (10443) / `pcap_over_ip_port` (4430) / `cert_http_port` (10080; set 0 to disable) / `log_dir` (`/var/log/polarproxy`) / `ca_pfx_path` (`/etc/polarproxy/ca.pfx` — PFX bundle PolarProxy signs with) / `ca_pfx_password` (empty → read from env) / `bridge_name` (`br0`, used by bridge-tap only); overlay precedence "defaults overlaid by profile, then host config, then env vars" | `README.md` 49–59 + `config/defaults.toml` 1–9 |
| E0237 | Provides / requires / consumes — `provides = ["tls-mitm", "pcap-over-ip"]` (tls-mitm = clear-side feed of decrypted TCP/443; pcap-over-ip = TCP/4430 listener consumable by suricata/zeek/etc.); `consumes = []`; `requires = [{kind="binary", value="PolarProxy"}, {kind="binary", value="nft"}, {kind="binary", value="systemctl"}]`; `conflicts = []` | `module.toml` 13–22 |
| E0238 | Apply pipeline — preflight (config readable / PolarProxy / nft / systemctl) → profile validation → bridge-tap runtime soft-dep check (`nft list table inet selfdef_bridge`) → systemd unit render via sed substitution + idempotent compare-and-install + manifest record (F-2027-024) → nftables redirect (host-tls-mitm only) render + install + `nft -f` load + manifest record / OR bridge-tap branch removes stale host-tls-mitm NAT table → systemctl daemon-reload if unit changed → enable + start (or reload-or-restart if already running) → final JSON status (`skipped` if 0 changes / `ok` if N changes) | `apply.sh` 1–149 |
| E0239 | Idempotency + dry-run + profile switch + check + uninstall — `SELFDEF_DRY_RUN=1` short-circuits every state change; re-running on already-target host emits `"status":"skipped"`; switching profiles (host-tls-mitm ↔ bridge-tap) cleanly removes previous profile's nftables rule before adding new one's; `check.sh` validates 3 probes (unit installed / service active / nft table loaded for host-tls-mitm) without side-effects (DRY_RUN=0 forced per F-2027-027); `uninstall.sh` removes nftables redirect (if any) + stops + disables polarproxy.service + walks manifest (F-2027-024) for rendered files + legacy enum fallback for pre-v2 installs + tolerates per-step failures + does NOT delete PolarProxy binary, captured PCAPs, or CA bundle | `README.md` 61–72 + `apply.sh` + `check.sh` + `uninstall.sh` |
| E0240 | Caveats — TLS interception is operator-visible and policy-bearing (do NOT enable without explicit user/device consent + documented data-handling policy); PolarProxy 1.x and 2.x have slightly different CLI flags (module targets 1.x defaults; override via `/etc/systemd/system/polarproxy.service.d/override.conf` for 2.x); per-host `host-tls-mitm` only redirects this host's outbound TCP/443 — doesn't intercept traffic transiting a bridge (use `bridge-tap` for that); systemd unit hardening (DynamicUser / NoNewPrivileges / ProtectSystem=strict / ProtectHome / PrivateTmp / ReadWritePaths=log_dir / StateDirectory / LogsDirectory; Restart=on-failure RestartSec=5); listen_port defaults to 10443 so unit runs unprivileged (no CAP_NET_BIND needed for <1024) | `README.md` 74–86 + `templates/polarproxy.service.tmpl` 25–38 |

## Modules (M00577–M00602)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00577 | `module.toml` — manifest (name + version + summary + category + depends_on + conflicts + provides + consumes + requires + install + profiles) | `module.toml` 1–32 | E0231 |
| M00578 | `README.md` — 86-line operator doc (threat + scope + profiles + config + idempotency + uninstall + caveats) | `README.md` 1–86 | E0231 |
| M00579 | `config/defaults.toml` — 9-line baseline overlaid by profile + host config + env | `config/defaults.toml` 1–9 | E0236 |
| M00580 | `profiles/host-tls-mitm.toml` — host-side TCP/443 NAT redirect profile (listen_port=10443 / pcap=4430 / cert_http=10080) | `profiles/host-tls-mitm.toml` 1–7 | E0235 |
| M00581 | `profiles/bridge-tap.toml` — inline-L2 tap profile (cert_http=0 disabled / bridge_name=br0) | `profiles/bridge-tap.toml` 1–7 | E0235 |
| M00582 | `install/apply.sh` — 148-line idempotent applier (preflight + render + install + load + enable + start) | `install/apply.sh` 1–148 | E0238 |
| M00583 | `install/check.sh` — 43-line side-effect-free probe (unit + service + nft) | `install/check.sh` 1–43 | E0239 |
| M00584 | `install/lib.sh` — shared helpers (sources `packaging/lib/module-lib.sh`); requires v2 (F-2027-024 opt-in) | `install/lib.sh` 1–31 | E0238 |
| M00585 | `install/uninstall.sh` — 85-line tear-down (stop + disable + nft delete + manifest walk + legacy fallback + daemon-reload + manifest clear) | `install/uninstall.sh` 1–85 | E0239 |
| M00586 | `templates/polarproxy.service.tmpl` — systemd unit template with 6 substitution tokens + DynamicUser hardening | `templates/polarproxy.service.tmpl` 1–41 | E0240 |
| M00587 | `templates/nat-redirect.rule.tmpl` — nftables redirect rule template (`@@LISTEN_PORT@@` substitution) | `templates/nat-redirect.rule.tmpl` 1–13 | E0238 |
| M00588 | Provided surface — `tls-mitm` (clear-side feed of decrypted TCP/443 flows) | `module.toml` 13 + 15 | E0237 |
| M00589 | Provided surface — `pcap-over-ip` (TCP/4430 listener; suricata/zeek/etc. can consume) | `module.toml` 14 + 15 | E0237 |
| M00590 | Required binary — `PolarProxy` (`.NET` binary from Netresec; module fails closed if absent) | `module.toml` 18–19 + `apply.sh` 24 + `README.md` 31–34 | E0237 |
| M00591 | Required binary — `nft(8)` | `module.toml` 20 + `apply.sh` 25 | E0237 |
| M00592 | Required binary — `systemctl` | `module.toml` 21 + `apply.sh` 26 | E0237 |
| M00593 | Soft dependency — bridge-tap profile requires `bridge-l2` (checked at apply time via `nft list table inet selfdef_bridge`) | `module.toml` 7–11 + `apply.sh` 41–46 | E0235 |
| M00594 | Manifest integration — F-2027-024 (`module_record_file` / `module_render_files` / `module_clear_manifest`) replaces hand-curated UNIT_PATH + NFT_RULESET_PATH duplication | `install/lib.sh` 10–14 + `apply.sh` 79–81 + `apply.sh` 106–109 + `uninstall.sh` 47–63 + `uninstall.sh` 83 | E0238 + E0239 |
| M00595 | Module-lib version pin — `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2` (3-tier lookup precedence: env var / workspace-relative / installed system path) | `install/lib.sh` 15–30 | E0238 |
| M00596 | nftables dedicated table — `inet selfdef_polarproxy` (never touches operator's existing nat table; replaced wholesale on each apply) | `templates/nat-redirect.rule.tmpl` 8–13 | E0238 |
| M00597 | Substitution tokens (6) — `@@LISTEN_PORT@@` / `@@PCAP_OVER_IP_PORT@@` / `@@CERT_HTTP_FLAG@@` / `@@LOG_DIR@@` / `@@CA_PFX_PATH@@` / `@@CA_PFX_PASSWORD_OPT@@` | `templates/polarproxy.service.tmpl` 10–15 + `apply.sh` 62–69 | E0238 |
| M00598 | systemd unit hardening — DynamicUser / NoNewPrivileges / ProtectSystem=strict / ProtectHome / PrivateTmp / ReadWritePaths=log_dir / StateDirectory / LogsDirectory / Restart=on-failure / RestartSec=5 | `templates/polarproxy.service.tmpl` 25–38 | E0240 |
| M00599 | Downstream consumer pointer — `/etc/selfdef/modules/polarproxy.toml` exposes `pcap_over_ip_port` for `selfdef-collector-pcap` (future) or Suricata AF_PACKET via `polarproxytls` dummy netdev | `README.md` 24–27 | E0233 |
| M00600 | Unprivileged-port default — listen_port=10443 means CAP_NET_BIND not required (PolarProxy unit runs unprivileged) | `templates/polarproxy.service.tmpl` 27–29 | E0240 |
| M00601 | Migration / version-mismatch path — `uninstall.sh` falls back to legacy hand-coded paths (UNIT_PATH + NFT_RULESET_PATH) if manifest count is 0 (pre-v2 installs) | `install/uninstall.sh` 65–76 | E0239 |
| M00602 | Override path for PolarProxy 2.x — operator drops `ExecStart` override at `/etc/systemd/system/polarproxy.service.d/override.conf` | `README.md` 79–82 | E0240 |

## Features (F02641–F02760)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F02641 | module.toml `name = "polarproxy"` | `module.toml` 1 | M00577 |
| F02642 | module.toml `version = "0.1.0"` | `module.toml` 2 | M00577 |
| F02643 | module.toml `summary = "Transparent TLS termination → PCAP-over-IP for content visibility"` | `module.toml` 3 | M00577 |
| F02644 | module.toml `category = "network"` | `module.toml` 4 | M00577 |
| F02645 | module.toml `depends_on = []` (soft dep on bridge-l2 expressed empty; runtime check in apply.sh) | `module.toml` 7–10 | M00577 + M00593 |
| F02646 | module.toml `conflicts = []` | `module.toml` 11 | M00577 |
| F02647 | module.toml `provides = ["tls-mitm", "pcap-over-ip"]` | `module.toml` 15 | M00588 + M00589 |
| F02648 | module.toml `consumes = []` | `module.toml` 16 | M00577 |
| F02649 | module.toml `requires` — binary PolarProxy | `module.toml` 18–19 | M00590 |
| F02650 | module.toml `requires` — binary nft | `module.toml` 20 | M00591 |
| F02651 | module.toml `requires` — binary systemctl | `module.toml` 21 | M00592 |
| F02652 | module.toml `[install] kind = "script"` | `module.toml` 24–25 | M00577 |
| F02653 | module.toml `apply = "install/apply.sh"` | `module.toml` 26 | M00577 + M00582 |
| F02654 | module.toml `check = "install/check.sh"` | `module.toml` 27 | M00577 + M00583 |
| F02655 | module.toml `uninstall = "install/uninstall.sh"` | `module.toml` 28 | M00577 + M00585 |
| F02656 | module.toml `[profiles] default = "host-tls-mitm"` | `module.toml` 30–31 | M00577 + M00580 |
| F02657 | module.toml `available = ["host-tls-mitm", "bridge-tap"]` | `module.toml` 32 | M00577 + M00580 + M00581 |
| F02658 | README threat — operator wants to inspect "what's actually inside" TLS flows | `README.md` 10 | E0232 |
| F02659 | README threat — JA3 + SNI alone insufficient; plaintext required for content rules | `README.md` 11 | E0232 |
| F02660 | README threat — PolarProxy MITM with operator-installed CA on endpoints | `README.md` 12 | E0232 |
| F02661 | README scope — owned: systemd unit `polarproxy.service` | `README.md` 20–21 | E0233 |
| F02662 | README scope — owned: nftables redirect (host-tls-mitm only) TCP/443 → 10443 | `README.md` 22–23 | E0233 |
| F02663 | README scope — owned: pointer file `/etc/selfdef/modules/polarproxy.toml` exposing pcap_over_ip_port | `README.md` 24–27 | M00599 |
| F02664 | README not-owned — PolarProxy binary installation | `README.md` 31–34 | E0234 |
| F02665 | README not-owned — CA generation + endpoint trust distribution | `README.md` 35–36 | E0234 |
| F02666 | README not-owned — `polarproxytls` dummy interface (created on-demand by service unit) | `README.md` 37–39 | E0234 |
| F02667 | README profile host-tls-mitm — adds nftables NAT redirect | `README.md` 45 | E0235 |
| F02668 | README profile host-tls-mitm — cleartext exposed on tcp/4430 | `README.md` 45 | E0235 |
| F02669 | README profile bridge-tap — inline tap on L2 bridge | `README.md` 46 | E0235 |
| F02670 | README profile bridge-tap — cleartext fed into dummy `polarproxytls` netdev | `README.md` 46 | E0235 |
| F02671 | README profile bridge-tap — Suricata reads via AF_PACKET | `README.md` 46 | E0235 |
| F02672 | README profile bridge-tap — depends on bridge-l2 (checked at apply time) | `README.md` 46 | M00593 |
| F02673 | README config `profile` key | `README.md` 52 | E0236 |
| F02674 | README config `listen_port = 10443` (local TLS listener) | `README.md` 53 | E0236 |
| F02675 | README config `pcap_over_ip_port = 4430` (cleartext PCAP-over-IP) | `README.md` 54 | E0236 |
| F02676 | README config `cert_http_port = 10080` (CA cert exposure; set 0 to disable) | `README.md` 55 | E0236 |
| F02677 | README config `log_dir = "/var/log/polarproxy"` | `README.md` 56 | E0236 |
| F02678 | README config `ca_pfx_path = "/etc/polarproxy/ca.pfx"` (PFX bundle PolarProxy signs with) | `README.md` 57 | E0236 |
| F02679 | README config `ca_pfx_password = ""` (empty → read from env) | `README.md` 58 | E0236 |
| F02680 | defaults.toml `bridge_name = "br0"` (used by bridge-tap only) | `config/defaults.toml` 9 | E0236 |
| F02681 | profiles/host-tls-mitm.toml — pcap_over_ip_port=4430 + cert_http_port=10080 | `profiles/host-tls-mitm.toml` 1–7 | M00580 |
| F02682 | profiles/bridge-tap.toml — `cert_http_port = 0` disabled by default for inline tap | `profiles/bridge-tap.toml` 6 | M00581 |
| F02683 | profiles/bridge-tap.toml — `bridge_name = "br0"` | `profiles/bridge-tap.toml` 7 | M00581 |
| F02684 | README idempotency — `SELFDEF_DRY_RUN=1` short-circuits every state change | `README.md` 63 | E0239 |
| F02685 | README idempotency — re-running on target-state host emits `"status":"skipped"` | `README.md` 64 | E0239 |
| F02686 | README idempotency — profile switching cleanly removes previous profile's nftables rule | `README.md` 65–66 | E0239 |
| F02687 | README uninstall — removes nftables redirect (if any) | `README.md` 70 | E0239 |
| F02688 | README uninstall — stops + disables polarproxy.service | `README.md` 70–71 | E0239 |
| F02689 | README uninstall — does NOT delete PolarProxy binary, PCAPs, or CA bundle | `README.md` 71–72 | E0239 |
| F02690 | README caveat — TLS interception operator-visible + policy-bearing | `README.md` 76 | E0240 |
| F02691 | README caveat — require explicit user/device consent + documented data-handling policy | `README.md` 77–78 | E0240 |
| F02692 | README caveat — PolarProxy 1.x/2.x CLI flag differences | `README.md` 79–80 | E0240 |
| F02693 | README caveat — module targets 1.x defaults | `README.md` 80 | E0240 |
| F02694 | README caveat — 2.x override via /etc/systemd/system/polarproxy.service.d/override.conf | `README.md` 81–82 | M00602 |
| F02695 | README caveat — host-tls-mitm only intercepts this host's TCP/443 | `README.md` 83–85 | E0240 |
| F02696 | README caveat — use bridge-tap for transit traffic | `README.md` 85–86 | E0240 |
| F02697 | apply.sh `set -euo pipefail` | `apply.sh` 9 | M00582 |
| F02698 | apply.sh `MODULE="polarproxy"` | `apply.sh` 11 | M00582 |
| F02699 | apply.sh `DRY_RUN="${SELFDEF_DRY_RUN:-0}"` | `apply.sh` 12 | M00582 |
| F02700 | apply.sh CONFIG_FILE default `/etc/selfdef/modules/polarproxy.toml` | `apply.sh` 13 | M00582 |
| F02701 | apply.sh TEMPLATE_DIR default `/usr/share/selfdef/modules/polarproxy/templates` | `apply.sh` 14 | M00582 |
| F02702 | apply.sh UNIT_PATH default `/etc/systemd/system/polarproxy.service` | `apply.sh` 15 | M00582 |
| F02703 | apply.sh NFT_RULESET_PATH default `/etc/nftables.d/selfdef-polarproxy.conf` | `apply.sh` 16 | M00582 |
| F02704 | apply.sh preflight — config file readable check (die if not) | `apply.sh` 23 | M00582 |
| F02705 | apply.sh preflight — PolarProxy binary check | `apply.sh` 24 | M00590 |
| F02706 | apply.sh preflight — nft binary check | `apply.sh` 25 | M00591 |
| F02707 | apply.sh preflight — systemctl binary check | `apply.sh` 26 | M00592 |
| F02708 | apply.sh profile validation — die if not host-tls-mitm|bridge-tap | `apply.sh` 36–39 | E0235 |
| F02709 | apply.sh bridge-tap runtime soft-dep — `nft list table inet selfdef_bridge` | `apply.sh` 42–46 | M00593 |
| F02710 | apply.sh systemd unit render — sed 6-token substitution into mktemp file | `apply.sh` 60–69 | M00597 |
| F02711 | apply.sh systemd unit idempotency — cmp -s RENDERED_UNIT UNIT_PATH skip | `apply.sh` 72–73 | M00582 |
| F02712 | apply.sh systemd unit install — `install -D -m 0644 RENDERED_UNIT UNIT_PATH` + reload_systemd=1 | `apply.sh` 75–77 | M00582 |
| F02713 | apply.sh manifest record — `module_record_file "$UNIT_PATH"` (F-2027-024) | `apply.sh` 80–81 | M00594 |
| F02714 | apply.sh nft table presence probe — `nft list table inet selfdef_polarproxy` → HAVE_NFT_TABLE | `apply.sh` 84–87 | M00596 |
| F02715 | apply.sh nftables render — sed `@@LISTEN_PORT@@` substitution into mktemp file | `apply.sh` 93–96 | M00587 |
| F02716 | apply.sh nftables idempotency — cmp + HAVE_NFT_TABLE check | `apply.sh` 98–99 | M00582 |
| F02717 | apply.sh nftables install + load — `install -D` + `nft -f` | `apply.sh` 101–104 | M00596 |
| F02718 | apply.sh nftables manifest record (host-tls-mitm only) | `apply.sh` 106–109 | M00594 |
| F02719 | apply.sh bridge-tap cleanup — delete stale `inet selfdef_polarproxy` nft table | `apply.sh` 113–115 | E0239 |
| F02720 | apply.sh bridge-tap cleanup — remove stale NFT_RULESET_PATH file | `apply.sh` 117–119 | E0239 |
| F02721 | apply.sh service — systemctl daemon-reload if reload_systemd=1 | `apply.sh` 124–126 | M00582 |
| F02722 | apply.sh service — `systemctl is-enabled` check + enable if not | `apply.sh` 128–133 | M00582 |
| F02723 | apply.sh service — `systemctl is-active` check + reload-or-restart if running, else start | `apply.sh` 135–141 | M00582 |
| F02724 | apply.sh finalise — `emit_status "skipped" "already at target state"` if changes=0 | `apply.sh` 144–145 | M00582 |
| F02725 | apply.sh finalise — `emit_status "ok" "applied N change(s)"` otherwise | `apply.sh` 146–147 | M00582 |
| F02726 | check.sh F-2027-027 — DRY_RUN forced 0 (side-effect-free) | `check.sh` 8 | M00583 |
| F02727 | check.sh probe 1 — config readable (else emit failed + exit 1) | `check.sh` 17 | M00583 |
| F02728 | check.sh probe 2 — UNIT_PATH readable | `check.sh` 21–23 | M00583 |
| F02729 | check.sh probe 3 — `systemctl is-active polarproxy.service` | `check.sh` 25–29 | M00583 |
| F02730 | check.sh probe 4 — host-tls-mitm only `nft list table inet selfdef_polarproxy` | `check.sh` 31–35 | M00583 |
| F02731 | check.sh success — `emit_status "ok" "polarproxy.service running ($PROFILE)"` + exit 0 | `check.sh` 37–39 | M00583 |
| F02732 | check.sh failure — joined problems with `;` separator + exit 1 | `check.sh` 40–43 | M00583 |
| F02733 | uninstall.sh override log prefix — `[polarproxy:uninstall]` | `uninstall.sh` 20 | M00585 |
| F02734 | uninstall.sh override run() — tolerates per-step failures via `|| log "(continuing past failure)"` | `uninstall.sh` 21–31 | M00585 |
| F02735 | uninstall.sh stop service if active | `uninstall.sh` 35–37 | M00585 |
| F02736 | uninstall.sh disable service if enabled | `uninstall.sh` 38–40 | M00585 |
| F02737 | uninstall.sh delete `inet selfdef_polarproxy` nft table if present | `uninstall.sh` 43–45 | M00585 |
| F02738 | uninstall.sh manifest walk — `module_render_files` enumerates recorded files | `uninstall.sh` 47–63 | M00594 |
| F02739 | uninstall.sh unit_was_recorded sentinel — daemon-reload only if unit was in manifest | `uninstall.sh` 56–58 + 78–81 | M00585 |
| F02740 | uninstall.sh legacy migration — if manifest count=0 fall back to UNIT_PATH + NFT_RULESET_PATH enum | `uninstall.sh` 65–76 | M00601 |
| F02741 | uninstall.sh manifest clear — `module_clear_manifest` | `uninstall.sh` 83 | M00594 |
| F02742 | uninstall.sh exit — `emit_status "ok" "uninstalled (N file(s) removed)"` | `uninstall.sh` 85 | M00585 |
| F02743 | lib.sh — `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2` opted into v2 for manifest helpers | `install/lib.sh` 10–14 | M00595 |
| F02744 | lib.sh — F-2027-024 rationale (replaces UNIT_PATH+NFT_RULESET_PATH duplication) | `install/lib.sh` 8–12 | M00594 |
| F02745 | lib.sh lookup precedence 1 — `$SELFDEF_MODULE_LIB` env var | `install/lib.sh` 16–22 | M00595 |
| F02746 | lib.sh lookup precedence 2 — workspace-relative `../../../packaging/lib/module-lib.sh` | `install/lib.sh` 23–26 | M00595 |
| F02747 | lib.sh lookup precedence 3 — installed system path `/usr/share/selfdef/lib/module-lib.sh` | `install/lib.sh` 27–29 | M00595 |
| F02748 | lib.sh shared helpers — log / emit_status / die / run / toml_get | `install/lib.sh` 1–4 | M00595 |
| F02749 | systemd unit Description — "PolarProxy TLS interception (managed by selfdef)" | `templates/polarproxy.service.tmpl` 2 | M00586 |
| F02750 | systemd unit Documentation — https://www.netresec.com/?page=PolarProxy | `templates/polarproxy.service.tmpl` 3 | M00586 |
| F02751 | systemd unit After/Wants network-online.target | `templates/polarproxy.service.tmpl` 4–5 | M00586 |
| F02752 | systemd unit Type=simple | `templates/polarproxy.service.tmpl` 8 | M00586 |
| F02753 | systemd unit ExecStart — env PolarProxy with -v / -p L,P / --pcapoveripconnect / --cacert load / pw / certhttp / -o | `templates/polarproxy.service.tmpl` 16–23 | M00586 |
| F02754 | systemd unit Restart=on-failure RestartSec=5 | `templates/polarproxy.service.tmpl` 25–26 | M00598 |
| F02755 | systemd unit DynamicUser=yes (no CAP_NET_BIND needed; listen_port=10443) | `templates/polarproxy.service.tmpl` 27–29 | M00598 + M00600 |
| F02756 | systemd unit StateDirectory=polarproxy + LogsDirectory=polarproxy | `templates/polarproxy.service.tmpl` 30–31 | M00598 |
| F02757 | systemd unit hardening — NoNewPrivileges=yes / ProtectSystem=strict / ProtectHome=yes / PrivateTmp=yes | `templates/polarproxy.service.tmpl` 33–37 | M00598 |
| F02758 | systemd unit ReadWritePaths=@@LOG_DIR@@ (substituted) | `templates/polarproxy.service.tmpl` 38 | M00598 |
| F02759 | systemd unit WantedBy=multi-user.target | `templates/polarproxy.service.tmpl` 41 | M00586 |
| F02760 | nat-redirect.rule.tmpl — table inet selfdef_polarproxy / chain output type nat hook output priority dstnat policy accept / meta l4proto tcp tcp dport 443 redirect to :@@LISTEN_PORT@@ | `templates/nat-redirect.rule.tmpl` 1–13 | M00587 + M00596 |

## Requirements (R05281–R05520)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R05281 | Module name MUST be `polarproxy` | `module.toml` 1 | F02641 | non-negotiable | false | 10 |
| R05282 | Module version MUST be 0.1.0 | `module.toml` 2 | F02642 | non-negotiable | false | 10 |
| R05283 | Module summary MUST be "Transparent TLS termination → PCAP-over-IP for content visibility" | `module.toml` 3 | F02643 | non-negotiable | false | 10 |
| R05284 | Module category MUST be `network` | `module.toml` 4 | F02644 | non-negotiable | false | 10 |
| R05285 | Module SHALL declare `depends_on = []` (soft-dep via apply.sh) | `module.toml` 10 | F02645 | non-negotiable | false | 10 |
| R05286 | Module SHALL declare `conflicts = []` | `module.toml` 11 | F02646 | non-negotiable | false | 10 |
| R05287 | Module SHALL provide `tls-mitm` surface | `module.toml` 15 | F02647 | non-negotiable | false | 10 |
| R05288 | Module SHALL provide `pcap-over-ip` surface | `module.toml` 15 | F02647 | non-negotiable | false | 10 |
| R05289 | tls-mitm = clear-side feed of decrypted TCP/443 flows | `module.toml` 13 | M00588 | non-negotiable | false | 10 |
| R05290 | pcap-over-ip = TCP/4430 listener consumable by suricata/zeek/etc. | `module.toml` 14 | M00589 | non-negotiable | false | 10 |
| R05291 | Module SHALL declare `consumes = []` | `module.toml` 16 | F02648 | non-negotiable | false | 10 |
| R05292 | Required binary — PolarProxy (kind=binary) | `module.toml` 19 | F02649 | non-negotiable | false | 10 |
| R05293 | Required binary — nft (kind=binary) | `module.toml` 20 | F02650 | non-negotiable | false | 10 |
| R05294 | Required binary — systemctl (kind=binary) | `module.toml` 21 | F02651 | non-negotiable | false | 10 |
| R05295 | Install kind MUST be `script` | `module.toml` 25 | F02652 | non-negotiable | false | 10 |
| R05296 | Apply script path `install/apply.sh` | `module.toml` 26 | F02653 | non-negotiable | false | 10 |
| R05297 | Check script path `install/check.sh` | `module.toml` 27 | F02654 | non-negotiable | false | 10 |
| R05298 | Uninstall script path `install/uninstall.sh` | `module.toml` 28 | F02655 | non-negotiable | false | 10 |
| R05299 | Default profile MUST be `host-tls-mitm` | `module.toml` 31 | F02656 | non-negotiable | false | 10 |
| R05300 | Available profiles MUST equal `["host-tls-mitm", "bridge-tap"]` | `module.toml` 32 | F02657 | non-negotiable | false | 10 |
| R05301 | Threat — operator wants to inspect what's actually inside TLS flows | `README.md` 10 | F02658 | non-negotiable | false | 10 |
| R05302 | JA3 fingerprints + SNI alone insufficient | `README.md` 11 | F02659 | non-negotiable | false | 10 |
| R05303 | Plaintext required for content rules | `README.md` 11 | F02659 | non-negotiable | false | 10 |
| R05304 | PolarProxy acts as MITM with operator-installed CA on endpoints | `README.md` 12 | F02660 | non-negotiable | false | 10 |
| R05305 | Module wires PolarProxy into network path | `README.md` 13–14 | E0232 | non-negotiable | false | 10 |
| R05306 | Module exposes the decrypted feed to downstream consumers | `README.md` 14 | E0232 | non-negotiable | false | 10 |
| R05307 | Scope OWNS — `polarproxy.service` systemd unit | `README.md` 20–21 | F02661 | non-negotiable | false | 10 |
| R05308 | systemd unit MUST run PolarProxy with configured listener/TLS/log paths | `README.md` 21–22 | F02661 | non-negotiable | false | 10 |
| R05309 | Scope OWNS — nftables redirect (host-tls-mitm only) | `README.md` 22–23 | F02662 | non-negotiable | false | 10 |
| R05310 | nftables redirect MUST redirect TCP/443 from local host → 10443 (configurable) | `README.md` 22–23 | F02662 | non-negotiable | false | 10 |
| R05311 | Scope OWNS — pointer file at /etc/selfdef/modules/polarproxy.toml | `README.md` 24–25 | F02663 | non-negotiable | false | 10 |
| R05312 | Pointer file MUST expose pcap_over_ip_port | `README.md` 25 | F02663 | non-negotiable | false | 10 |
| R05313 | Pointer file consumable by future `selfdef-collector-pcap` | `README.md` 25–26 | M00599 | non-negotiable | false | 10 |
| R05314 | Pointer file consumable by Suricata AF_PACKET via `polarproxytls` dummy interface | `README.md` 26–27 | M00599 | non-negotiable | false | 10 |
| R05315 | Scope does NOT OWN — installation of PolarProxy binary | `README.md` 31–33 | F02664 | non-negotiable | false | 10 |
| R05316 | PolarProxy binary obtained per Netresec licence terms | `README.md` 32–33 | F02664 | non-negotiable | false | 10 |
| R05317 | PolarProxy binary MUST be on `$PATH` as `PolarProxy` | `README.md` 33 | F02664 | non-negotiable | false | 10 |
| R05318 | Module's `requires` fail closed if PolarProxy binary not present | `README.md` 34 | M00590 | non-negotiable | false | 10 |
| R05319 | Scope does NOT OWN — CA generation | `README.md` 35 | F02665 | non-negotiable | false | 10 |
| R05320 | Scope does NOT OWN — endpoint trust distribution | `README.md` 35 | F02665 | non-negotiable | false | 10 |
| R05321 | CA generation + trust distribution is operator responsibility | `README.md` 35 | F02665 | non-negotiable | false | 10 |
| R05322 | "Wrong place to automate" CA generation | `README.md` 36 | F02665 | non-negotiable | false | 10 |
| R05323 | Scope does NOT OWN — `polarproxytls` dummy interface | `README.md` 37 | F02666 | non-negotiable | false | 10 |
| R05324 | `polarproxytls` interface created on-demand by service unit when needed | `README.md` 38–39 | F02666 | non-negotiable | false | 10 |
| R05325 | Profile `host-tls-mitm` adds nftables NAT redirect | `README.md` 45 | F02667 | non-negotiable | false | 10 |
| R05326 | Profile `host-tls-mitm` exposes cleartext on tcp/4430 | `README.md` 45 | F02668 | non-negotiable | false | 10 |
| R05327 | Profile `host-tls-mitm` has no dependency | `README.md` 45 | E0235 | non-negotiable | false | 10 |
| R05328 | Profile `bridge-tap` runs PolarProxy as inline tap on L2 bridge | `README.md` 46 | F02669 | non-negotiable | false | 10 |
| R05329 | Profile `bridge-tap` feeds cleartext into dummy `polarproxytls` netdev | `README.md` 46 | F02670 | non-negotiable | false | 10 |
| R05330 | Profile `bridge-tap` allows Suricata read via AF_PACKET | `README.md` 46 | F02671 | non-negotiable | false | 10 |
| R05331 | Profile `bridge-tap` depends on `bridge-l2` | `README.md` 46 | F02672 | non-negotiable | false | 10 |
| R05332 | bridge-l2 dependency checked at apply time | `README.md` 46 | M00593 | non-negotiable | false | 10 |
| R05333 | Config key `profile` (host-tls-mitm/bridge-tap) | `README.md` 52 | F02673 | non-negotiable | false | 10 |
| R05334 | Config key `listen_port` default 10443 | `README.md` 53 | F02674 | non-negotiable | false | 10 |
| R05335 | listen_port = local PolarProxy TLS listener | `README.md` 53 | F02674 | non-negotiable | false | 10 |
| R05336 | Config key `pcap_over_ip_port` default 4430 | `README.md` 54 | F02675 | non-negotiable | false | 10 |
| R05337 | pcap_over_ip_port = cleartext PCAP-over-IP listener | `README.md` 54 | F02675 | non-negotiable | false | 10 |
| R05338 | Config key `cert_http_port` default 10080 | `README.md` 55 | F02676 | non-negotiable | false | 10 |
| R05339 | cert_http_port = CA cert exposure port | `README.md` 55 | F02676 | non-negotiable | false | 10 |
| R05340 | cert_http_port = 0 SHALL disable CA cert exposure | `README.md` 55 | F02676 | non-negotiable | false | 10 |
| R05341 | Config key `log_dir` default /var/log/polarproxy | `README.md` 56 | F02677 | non-negotiable | false | 10 |
| R05342 | Config key `ca_pfx_path` default /etc/polarproxy/ca.pfx | `README.md` 57 | F02678 | non-negotiable | false | 10 |
| R05343 | ca_pfx_path = PFX bundle PolarProxy signs with | `README.md` 57 | F02678 | non-negotiable | false | 10 |
| R05344 | Config key `ca_pfx_password` default empty | `README.md` 58 | F02679 | non-negotiable | false | 10 |
| R05345 | Empty ca_pfx_password → read from env | `README.md` 58 | F02679 | non-negotiable | false | 10 |
| R05346 | Config key `bridge_name` default `br0` (bridge-tap only) | `config/defaults.toml` 9 | F02680 | non-negotiable | false | 10 |
| R05347 | Defaults overlaid by profile | `config/defaults.toml` 1 | E0236 | non-negotiable | false | 10 |
| R05348 | Profile overlaid by host config | `config/defaults.toml` 1 | E0236 | non-negotiable | false | 10 |
| R05349 | Host config overlaid by env vars | `config/defaults.toml` 1 | E0236 | non-negotiable | false | 10 |
| R05350 | profiles/host-tls-mitm.toml sets profile=host-tls-mitm | `profiles/host-tls-mitm.toml` 4 | M00580 | non-negotiable | false | 10 |
| R05351 | profiles/host-tls-mitm.toml sets listen_port=10443 | `profiles/host-tls-mitm.toml` 5 | M00580 | non-negotiable | false | 10 |
| R05352 | profiles/host-tls-mitm.toml sets pcap_over_ip_port=4430 | `profiles/host-tls-mitm.toml` 6 | M00580 | non-negotiable | false | 10 |
| R05353 | profiles/host-tls-mitm.toml sets cert_http_port=10080 | `profiles/host-tls-mitm.toml` 7 | M00580 | non-negotiable | false | 10 |
| R05354 | profiles/bridge-tap.toml sets profile=bridge-tap | `profiles/bridge-tap.toml` 4 | M00581 | non-negotiable | false | 10 |
| R05355 | profiles/bridge-tap.toml sets listen_port=10443 | `profiles/bridge-tap.toml` 5 | M00581 | non-negotiable | false | 10 |
| R05356 | profiles/bridge-tap.toml sets pcap_over_ip_port=4430 | `profiles/bridge-tap.toml` 6 | M00581 | non-negotiable | false | 10 |
| R05357 | profiles/bridge-tap.toml sets cert_http_port=0 (disabled for inline tap) | `profiles/bridge-tap.toml` 7 | F02682 | non-negotiable | false | 10 |
| R05358 | profiles/bridge-tap.toml sets bridge_name=br0 | `profiles/bridge-tap.toml` 8 | F02683 | non-negotiable | false | 10 |
| R05359 | SELFDEF_DRY_RUN=1 SHALL short-circuit every state change | `README.md` 63 | F02684 | non-negotiable | false | 10 |
| R05360 | Re-running on target state SHALL emit "status":"skipped" | `README.md` 64 | F02685 | non-negotiable | false | 10 |
| R05361 | Profile switching SHALL cleanly remove previous profile's nftables rule | `README.md` 65–66 | F02686 | non-negotiable | false | 10 |
| R05362 | Profile switching MUST happen before adding new profile's rule | `README.md` 66 | F02686 | non-negotiable | false | 10 |
| R05363 | uninstall.sh SHALL remove nftables redirect if any | `README.md` 70 | F02687 | non-negotiable | false | 10 |
| R05364 | uninstall.sh SHALL stop polarproxy.service | `README.md` 70 | F02688 | non-negotiable | false | 10 |
| R05365 | uninstall.sh SHALL disable polarproxy.service | `README.md` 71 | F02688 | non-negotiable | false | 10 |
| R05366 | uninstall.sh MUST NOT delete PolarProxy binary | `README.md` 71–72 | F02689 | non-negotiable | false | 10 |
| R05367 | uninstall.sh MUST NOT delete captured PCAPs | `README.md` 71–72 | F02689 | non-negotiable | false | 10 |
| R05368 | uninstall.sh MUST NOT delete CA bundle | `README.md` 71–72 | F02689 | non-negotiable | false | 10 |
| R05369 | Caveat — TLS interception is operator-visible | `README.md` 76 | F02690 | non-negotiable | false | 10 |
| R05370 | Caveat — TLS interception is policy-bearing | `README.md` 76 | F02690 | non-negotiable | false | 10 |
| R05371 | Caveat — explicit user/device consent required | `README.md` 77 | F02691 | non-negotiable | false | 10 |
| R05372 | Caveat — documented data-handling policy required | `README.md` 78 | F02691 | non-negotiable | false | 10 |
| R05373 | Caveat — PolarProxy 1.x and 2.x have different CLI flags | `README.md` 79–80 | F02692 | non-negotiable | false | 10 |
| R05374 | Module currently targets 1.x defaults | `README.md` 80 | F02693 | non-negotiable | false | 10 |
| R05375 | Override path — /etc/systemd/system/polarproxy.service.d/override.conf | `README.md` 81–82 | F02694 | non-negotiable | false | 10 |
| R05376 | Caveat — host-tls-mitm only redirects this host's outbound TCP/443 | `README.md` 83–85 | F02695 | non-negotiable | false | 10 |
| R05377 | Caveat — host-tls-mitm does NOT intercept bridge transit | `README.md` 84–85 | F02695 | non-negotiable | false | 10 |
| R05378 | Caveat — use bridge-tap for bridge transit | `README.md` 85–86 | F02696 | non-negotiable | false | 10 |
| R05379 | apply.sh MUST set -euo pipefail | `apply.sh` 9 | F02697 | non-negotiable | false | 10 |
| R05380 | apply.sh MODULE constant = "polarproxy" | `apply.sh` 11 | F02698 | non-negotiable | false | 10 |
| R05381 | apply.sh DRY_RUN read from SELFDEF_DRY_RUN env (default 0) | `apply.sh` 12 | F02699 | non-negotiable | false | 10 |
| R05382 | apply.sh CONFIG_FILE default /etc/selfdef/modules/polarproxy.toml | `apply.sh` 13 | F02700 | non-negotiable | false | 10 |
| R05383 | apply.sh CONFIG_FILE override via SELFDEF_POLARPROXY_CONFIG | `apply.sh` 13 | F02700 | non-negotiable | false | 10 |
| R05384 | apply.sh TEMPLATE_DIR default /usr/share/selfdef/modules/polarproxy/templates | `apply.sh` 14 | F02701 | non-negotiable | false | 10 |
| R05385 | apply.sh TEMPLATE_DIR override via SELFDEF_POLARPROXY_TEMPLATES | `apply.sh` 14 | F02701 | non-negotiable | false | 10 |
| R05386 | apply.sh UNIT_PATH default /etc/systemd/system/polarproxy.service | `apply.sh` 15 | F02702 | non-negotiable | false | 10 |
| R05387 | apply.sh UNIT_PATH override via SELFDEF_POLARPROXY_UNIT_PATH | `apply.sh` 15 | F02702 | non-negotiable | false | 10 |
| R05388 | apply.sh NFT_RULESET_PATH default /etc/nftables.d/selfdef-polarproxy.conf | `apply.sh` 16 | F02703 | non-negotiable | false | 10 |
| R05389 | apply.sh NFT_RULESET_PATH override via SELFDEF_POLARPROXY_NFT_PATH | `apply.sh` 16 | F02703 | non-negotiable | false | 10 |
| R05390 | apply.sh sources install/lib.sh | `apply.sh` 19–20 | M00595 | non-negotiable | false | 10 |
| R05391 | apply.sh preflight — config readable check | `apply.sh` 23 | F02704 | non-negotiable | false | 10 |
| R05392 | apply.sh preflight — PolarProxy binary check via `command -v` | `apply.sh` 24 | F02705 | non-negotiable | false | 10 |
| R05393 | apply.sh preflight — nft binary check via `command -v` | `apply.sh` 25 | F02706 | non-negotiable | false | 10 |
| R05394 | apply.sh preflight — systemctl binary check via `command -v` | `apply.sh` 26 | F02707 | non-negotiable | false | 10 |
| R05395 | apply.sh PROFILE read via toml_get (default host-tls-mitm) | `apply.sh` 28 | F02673 | non-negotiable | false | 10 |
| R05396 | apply.sh LISTEN_PORT read via toml_get (default 10443) | `apply.sh` 29 | F02674 | non-negotiable | false | 10 |
| R05397 | apply.sh PCAP_PORT read via toml_get (default 4430) | `apply.sh` 30 | F02675 | non-negotiable | false | 10 |
| R05398 | apply.sh CERT_HTTP_PORT read via toml_get (default 10080) | `apply.sh` 31 | F02676 | non-negotiable | false | 10 |
| R05399 | apply.sh LOG_DIR read via toml_get (default /var/log/polarproxy) | `apply.sh` 32 | F02677 | non-negotiable | false | 10 |
| R05400 | apply.sh CA_PFX read via toml_get (default /etc/polarproxy/ca.pfx) | `apply.sh` 33 | F02678 | non-negotiable | false | 10 |
| R05401 | apply.sh CA_PFX_PW read via toml_get (default empty) | `apply.sh` 34 | F02679 | non-negotiable | false | 10 |
| R05402 | apply.sh profile validation — die if not host-tls-mitm|bridge-tap | `apply.sh` 36–39 | F02708 | non-negotiable | false | 10 |
| R05403 | apply.sh profile validation error message format — "profile must be host-tls-mitm|bridge-tap, got 'X'" | `apply.sh` 38 | F02708 | non-negotiable | false | 10 |
| R05404 | apply.sh bridge-tap runtime soft-dep — `nft list table inet selfdef_bridge` | `apply.sh` 43 | F02709 | non-negotiable | false | 10 |
| R05405 | apply.sh bridge-tap soft-dep failure message — "bridge-tap profile requires bridge-l2 to be loaded first" | `apply.sh` 44 | F02709 | non-negotiable | false | 10 |
| R05406 | apply.sh changes counter starts at 0 | `apply.sh` 48 | M00582 | non-negotiable | true | 10 |
| R05407 | apply.sh UNIT_TMPL = $TEMPLATE_DIR/polarproxy.service.tmpl | `apply.sh` 51 | M00586 | non-negotiable | false | 10 |
| R05408 | apply.sh dies if UNIT_TMPL not readable | `apply.sh` 52 | M00586 | non-negotiable | false | 10 |
| R05409 | apply.sh cert_http_flag = "--certhttp N" or empty | `apply.sh` 54–55 | F02753 | non-negotiable | false | 10 |
| R05410 | apply.sh cert_http_flag empty when CERT_HTTP_PORT=0 | `apply.sh` 55 | F02753 | non-negotiable | false | 10 |
| R05411 | apply.sh pw_opt = `--password "$CA_PFX_PW"` or empty | `apply.sh` 57–58 | F02753 | non-negotiable | false | 10 |
| R05412 | apply.sh renders unit via mktemp + sed 6-token substitution | `apply.sh` 60–69 | F02710 | non-negotiable | false | 10 |
| R05413 | apply.sh trap removes RENDERED_UNIT on EXIT | `apply.sh` 61 | F02710 | non-negotiable | false | 10 |
| R05414 | apply.sh sed substitutes @@LISTEN_PORT@@ | `apply.sh` 63 | M00597 | non-negotiable | false | 10 |
| R05415 | apply.sh sed substitutes @@PCAP_OVER_IP_PORT@@ | `apply.sh` 64 | M00597 | non-negotiable | false | 10 |
| R05416 | apply.sh sed substitutes @@CERT_HTTP_FLAG@@ | `apply.sh` 65 | M00597 | non-negotiable | false | 10 |
| R05417 | apply.sh sed substitutes @@LOG_DIR@@ | `apply.sh` 66 | M00597 | non-negotiable | false | 10 |
| R05418 | apply.sh sed substitutes @@CA_PFX_PATH@@ | `apply.sh` 67 | M00597 | non-negotiable | false | 10 |
| R05419 | apply.sh sed substitutes @@CA_PFX_PASSWORD_OPT@@ | `apply.sh` 68 | M00597 | non-negotiable | false | 10 |
| R05420 | apply.sh systemd unit idempotency — cmp -s RENDERED_UNIT UNIT_PATH | `apply.sh` 72 | F02711 | non-negotiable | false | 10 |
| R05421 | apply.sh systemd unit skip path — log "systemd unit already at target state" | `apply.sh` 73 | F02711 | non-negotiable | false | 10 |
| R05422 | apply.sh systemd unit install — install -D -m 0644 | `apply.sh` 75 | F02712 | non-negotiable | false | 10 |
| R05423 | apply.sh systemd unit install sets reload_systemd=1 | `apply.sh` 76 | F02712 | non-negotiable | false | 10 |
| R05424 | apply.sh increments changes counter after install | `apply.sh` 77 | M00582 | non-negotiable | true | 10 |
| R05425 | apply.sh F-2027-024 — module_record_file "$UNIT_PATH" idempotent | `apply.sh` 79–81 | F02713 | non-negotiable | false | 10 |
| R05426 | apply.sh nft table probe — `nft list table inet selfdef_polarproxy` | `apply.sh` 85 | F02714 | non-negotiable | false | 10 |
| R05427 | apply.sh HAVE_NFT_TABLE sentinel set 0/1 | `apply.sh` 84–87 | F02714 | non-negotiable | false | 10 |
| R05428 | apply.sh NAT_TMPL = $TEMPLATE_DIR/nat-redirect.rule.tmpl | `apply.sh` 90 | F02760 | non-negotiable | false | 10 |
| R05429 | apply.sh dies if NAT_TMPL missing | `apply.sh` 91 | F02760 | non-negotiable | false | 10 |
| R05430 | apply.sh nftables render via mktemp + sed @@LISTEN_PORT@@ | `apply.sh` 93–96 | F02715 | non-negotiable | false | 10 |
| R05431 | apply.sh extends trap to cleanup RENDERED_NAT | `apply.sh` 95 | F02715 | non-negotiable | false | 10 |
| R05432 | apply.sh nftables idempotency — cmp + HAVE_NFT_TABLE | `apply.sh` 98 | F02716 | non-negotiable | false | 10 |
| R05433 | apply.sh nftables skip log — "nftables redirect already at target state" | `apply.sh` 99 | F02716 | non-negotiable | false | 10 |
| R05434 | apply.sh nftables install — install -D -m 0644 | `apply.sh` 101–102 | F02717 | non-negotiable | false | 10 |
| R05435 | apply.sh nftables load — `nft -f $NFT_RULESET_PATH` | `apply.sh` 103 | F02717 | non-negotiable | false | 10 |
| R05436 | apply.sh increments changes by 2 after nftables install+load | `apply.sh` 104 | M00582 | non-negotiable | true | 10 |
| R05437 | apply.sh F-2027-024 — module_record_file "$NFT_RULESET_PATH" (host-tls-mitm only) | `apply.sh` 106–109 | F02718 | non-negotiable | false | 10 |
| R05438 | apply.sh bridge-tap branch — remove stale `inet selfdef_polarproxy` nft table if present | `apply.sh` 113–115 | F02719 | non-negotiable | false | 10 |
| R05439 | apply.sh bridge-tap branch — remove stale NFT_RULESET_PATH file if present | `apply.sh` 117–119 | F02720 | non-negotiable | false | 10 |
| R05440 | apply.sh bridge-tap branch — increments changes for each removal | `apply.sh` 115 + 119 | M00582 | non-negotiable | true | 10 |
| R05441 | apply.sh systemctl daemon-reload only if reload_systemd=1 | `apply.sh` 124–126 | F02721 | non-negotiable | false | 10 |
| R05442 | apply.sh service — `systemctl is-enabled --quiet polarproxy.service` check | `apply.sh` 128 | F02722 | non-negotiable | false | 10 |
| R05443 | apply.sh service — enable if not enabled | `apply.sh` 131 | F02722 | non-negotiable | false | 10 |
| R05444 | apply.sh service — `systemctl is-active --quiet polarproxy.service` check | `apply.sh` 135 | F02723 | non-negotiable | false | 10 |
| R05445 | apply.sh service — reload-or-restart if already running | `apply.sh` 137 | F02723 | non-negotiable | false | 10 |
| R05446 | apply.sh service — start if not running | `apply.sh` 139 | F02723 | non-negotiable | false | 10 |
| R05447 | apply.sh finalise emits "skipped" if changes==0 | `apply.sh` 144–145 | F02724 | non-negotiable | false | 10 |
| R05448 | apply.sh finalise emits "ok" applied N change(s) otherwise | `apply.sh` 146–147 | F02725 | non-negotiable | false | 10 |
| R05449 | check.sh MUST set -euo pipefail | `check.sh` 3 | M00583 | non-negotiable | false | 10 |
| R05450 | check.sh F-2027-027 — DRY_RUN forced 0 (side-effect-free) | `check.sh` 7–8 | F02726 | non-negotiable | false | 10 |
| R05451 | check.sh CONFIG_FILE default override via SELFDEF_POLARPROXY_CONFIG | `check.sh` 9 | M00583 | non-negotiable | false | 10 |
| R05452 | check.sh UNIT_PATH default override via SELFDEF_POLARPROXY_UNIT_PATH | `check.sh` 10 | M00583 | non-negotiable | false | 10 |
| R05453 | check.sh sources install/lib.sh | `check.sh` 12–13 | M00595 | non-negotiable | false | 10 |
| R05454 | check.sh problems array starts empty | `check.sh` 15 | F02732 | non-negotiable | true | 10 |
| R05455 | check.sh probe — config readable; else emit_status failed + exit 1 | `check.sh` 17 | F02727 | non-negotiable | false | 10 |
| R05456 | check.sh probe — UNIT_PATH readable problem if missing | `check.sh` 21–23 | F02728 | non-negotiable | false | 10 |
| R05457 | check.sh probe — polarproxy.service active problem if not | `check.sh` 25–29 | F02729 | non-negotiable | false | 10 |
| R05458 | check.sh probe — host-tls-mitm + nft + table missing → problem | `check.sh` 31–35 | F02730 | non-negotiable | false | 10 |
| R05459 | check.sh success — emit_status "ok" "polarproxy.service running ($PROFILE)" | `check.sh` 38 | F02731 | non-negotiable | false | 10 |
| R05460 | check.sh failure — joined problems with ';' separator | `check.sh` 41 | F02732 | non-negotiable | false | 10 |
| R05461 | check.sh failure — exit 1 | `check.sh` 43 | F02732 | non-negotiable | false | 10 |
| R05462 | check.sh success — exit 0 | `check.sh` 39 | F02731 | non-negotiable | false | 10 |
| R05463 | uninstall.sh MUST set -euo pipefail | `uninstall.sh` 8 | M00585 | non-negotiable | false | 10 |
| R05464 | uninstall.sh MODULE constant = "polarproxy" | `uninstall.sh` 10 | M00585 | non-negotiable | false | 10 |
| R05465 | uninstall.sh log() prefix `[polarproxy:uninstall]` | `uninstall.sh` 20 | F02733 | non-negotiable | false | 10 |
| R05466 | uninstall.sh run() tolerates per-step failure via `|| log "(continuing past failure)"` | `uninstall.sh` 29 | F02734 | non-negotiable | false | 10 |
| R05467 | uninstall.sh stop service if `is-active --quiet` | `uninstall.sh` 35–37 | F02735 | non-negotiable | false | 10 |
| R05468 | uninstall.sh disable service if `is-enabled --quiet` | `uninstall.sh` 38–40 | F02736 | non-negotiable | false | 10 |
| R05469 | uninstall.sh delete nft table if `nft list table inet selfdef_polarproxy` succeeds | `uninstall.sh` 43–45 | F02737 | non-negotiable | false | 10 |
| R05470 | uninstall.sh walk manifest via `module_render_files` | `uninstall.sh` 63 | F02738 | non-negotiable | false | 10 |
| R05471 | uninstall.sh increments removed for each file removed | `uninstall.sh` 61 | M00585 | non-negotiable | true | 10 |
| R05472 | uninstall.sh increments manifest_count for each manifest entry | `uninstall.sh` 55 | M00585 | non-negotiable | true | 10 |
| R05473 | uninstall.sh sets unit_was_recorded=1 if UNIT_PATH in manifest | `uninstall.sh` 56–58 | F02739 | non-negotiable | true | 10 |
| R05474 | uninstall.sh legacy fallback triggers if manifest_count=0 | `uninstall.sh` 67 | F02740 | non-negotiable | false | 10 |
| R05475 | uninstall.sh legacy fallback removes UNIT_PATH if present | `uninstall.sh` 68–71 | F02740 | non-negotiable | false | 10 |
| R05476 | uninstall.sh legacy fallback removes NFT_RULESET_PATH if present | `uninstall.sh` 72–75 | F02740 | non-negotiable | false | 10 |
| R05477 | uninstall.sh daemon-reload only if unit_was_recorded=1 or legacy-path with unit absent | `uninstall.sh` 79–81 | F02739 | non-negotiable | false | 10 |
| R05478 | uninstall.sh calls module_clear_manifest | `uninstall.sh` 83 | F02741 | non-negotiable | false | 10 |
| R05479 | uninstall.sh emits "ok" "uninstalled (N file(s) removed)" | `uninstall.sh` 85 | F02742 | non-negotiable | false | 10 |
| R05480 | install/lib.sh MODULE comment header | `install/lib.sh` 1 | M00595 | non-negotiable | false | 10 |
| R05481 | install/lib.sh — shared helpers from /usr/share/selfdef/lib/module-lib.sh | `install/lib.sh` 1–4 | F02748 | non-negotiable | false | 10 |
| R05482 | install/lib.sh — caller MUST set MODULE | `install/lib.sh` 5 | M00595 | non-negotiable | false | 10 |
| R05483 | install/lib.sh — caller MUST set DRY_RUN | `install/lib.sh` 6 | M00595 | non-negotiable | false | 10 |
| R05484 | install/lib.sh — caller MUST set CONFIG_FILE | `install/lib.sh` 7 | M00595 | non-negotiable | false | 10 |
| R05485 | install/lib.sh — F-2027-024 v2 opt-in rationale documented | `install/lib.sh` 8–14 | F02744 | non-negotiable | false | 10 |
| R05486 | install/lib.sh — SELFDEF_MODULE_LIB_VERSION_REQUIRED=2 | `install/lib.sh` 14 | F02743 | non-negotiable | false | 10 |
| R05487 | install/lib.sh — lookup precedence 1: $SELFDEF_MODULE_LIB env | `install/lib.sh` 16–22 | F02745 | non-negotiable | false | 10 |
| R05488 | install/lib.sh — lookup precedence 2: workspace-relative packaging/lib/module-lib.sh | `install/lib.sh` 23–26 | F02746 | non-negotiable | false | 10 |
| R05489 | install/lib.sh — lookup precedence 3: /usr/share/selfdef/lib/module-lib.sh | `install/lib.sh` 27–29 | F02747 | non-negotiable | false | 10 |
| R05490 | systemd unit Description "PolarProxy TLS interception (managed by selfdef)" | `templates/polarproxy.service.tmpl` 2 | F02749 | non-negotiable | false | 10 |
| R05491 | systemd unit Documentation https://www.netresec.com/?page=PolarProxy | `templates/polarproxy.service.tmpl` 3 | F02750 | non-negotiable | false | 10 |
| R05492 | systemd unit After=network-online.target | `templates/polarproxy.service.tmpl` 4 | F02751 | non-negotiable | false | 10 |
| R05493 | systemd unit Wants=network-online.target | `templates/polarproxy.service.tmpl` 5 | F02751 | non-negotiable | false | 10 |
| R05494 | systemd unit Type=simple | `templates/polarproxy.service.tmpl` 8 | F02752 | non-negotiable | false | 10 |
| R05495 | systemd unit ExecStart uses /usr/bin/env PolarProxy | `templates/polarproxy.service.tmpl` 16 | F02753 | non-negotiable | false | 10 |
| R05496 | systemd unit ExecStart includes -v verbose flag | `templates/polarproxy.service.tmpl` 17 | F02753 | non-negotiable | false | 10 |
| R05497 | systemd unit ExecStart includes `-p L,P` listener spec | `templates/polarproxy.service.tmpl` 18 | F02753 | non-negotiable | false | 10 |
| R05498 | systemd unit ExecStart includes --pcapoveripconnect 127.0.0.1:P | `templates/polarproxy.service.tmpl` 19 | F02753 | non-negotiable | false | 10 |
| R05499 | systemd unit ExecStart includes --cacert load $CA_PFX | `templates/polarproxy.service.tmpl` 20 | F02753 | non-negotiable | false | 10 |
| R05500 | systemd unit ExecStart includes optional --password | `templates/polarproxy.service.tmpl` 21 | F02753 | non-negotiable | false | 10 |
| R05501 | systemd unit ExecStart includes optional --certhttp N | `templates/polarproxy.service.tmpl` 22 | F02753 | non-negotiable | false | 10 |
| R05502 | systemd unit ExecStart includes -o $LOG_DIR | `templates/polarproxy.service.tmpl` 23 | F02753 | non-negotiable | false | 10 |
| R05503 | systemd unit Restart=on-failure | `templates/polarproxy.service.tmpl` 25 | F02754 | non-negotiable | false | 10 |
| R05504 | systemd unit RestartSec=5 | `templates/polarproxy.service.tmpl` 26 | F02754 | non-negotiable | false | 10 |
| R05505 | systemd unit DynamicUser=yes (no CAP_NET_BIND for listen_port>=1024) | `templates/polarproxy.service.tmpl` 29 | F02755 | non-negotiable | false | 10 |
| R05506 | systemd unit listen_port default 10443 (>1024 unprivileged) | `templates/polarproxy.service.tmpl` 27–29 | M00600 | non-negotiable | false | 10 |
| R05507 | systemd unit StateDirectory=polarproxy | `templates/polarproxy.service.tmpl` 30 | F02756 | non-negotiable | false | 10 |
| R05508 | systemd unit LogsDirectory=polarproxy | `templates/polarproxy.service.tmpl` 31 | F02756 | non-negotiable | false | 10 |
| R05509 | systemd unit NoNewPrivileges=yes | `templates/polarproxy.service.tmpl` 34 | F02757 | non-negotiable | false | 10 |
| R05510 | systemd unit ProtectSystem=strict | `templates/polarproxy.service.tmpl` 35 | F02757 | non-negotiable | false | 10 |
| R05511 | systemd unit ProtectHome=yes | `templates/polarproxy.service.tmpl` 36 | F02757 | non-negotiable | false | 10 |
| R05512 | systemd unit PrivateTmp=yes | `templates/polarproxy.service.tmpl` 37 | F02757 | non-negotiable | false | 10 |
| R05513 | systemd unit ReadWritePaths=$LOG_DIR | `templates/polarproxy.service.tmpl` 38 | F02758 | non-negotiable | false | 10 |
| R05514 | systemd unit WantedBy=multi-user.target | `templates/polarproxy.service.tmpl` 41 | F02759 | non-negotiable | false | 10 |
| R05515 | nat-redirect.rule.tmpl declares table inet selfdef_polarproxy | `templates/nat-redirect.rule.tmpl` 8 | F02760 | non-negotiable | false | 10 |
| R05516 | nat-redirect.rule.tmpl chain output type nat hook output priority dstnat policy accept | `templates/nat-redirect.rule.tmpl` 9–10 | F02760 | non-negotiable | false | 10 |
| R05517 | nat-redirect.rule.tmpl rule — meta l4proto tcp tcp dport 443 redirect to :@@LISTEN_PORT@@ | `templates/nat-redirect.rule.tmpl` 11 | F02760 | non-negotiable | false | 10 |
| R05518 | nat-redirect.rule.tmpl comment "selfdef-polarproxy" on the redirect rule | `templates/nat-redirect.rule.tmpl` 11 | F02760 | non-negotiable | false | 10 |
| R05519 | nat-redirect.rule.tmpl preserves operator's existing nat table (lives in own table) | `templates/nat-redirect.rule.tmpl` 4–6 | M00596 | non-negotiable | false | 10 |
| R05520 | Composite — MS023 (10 epics / 26 modules / 120 features / 240 reqs) covers polarproxy module v0.1.0 (508 lines): module.toml (4-block manifest) + README.md (86-line operator doc) + config/defaults.toml (9 keys) + profiles/host-tls-mitm.toml + profiles/bridge-tap.toml + apply.sh (148-line idempotent applier) + check.sh (43-line probe) + lib.sh (v2 shared helper loader) + uninstall.sh (85-line manifest-walked tear-down) + polarproxy.service.tmpl (41-line hardened DynamicUser unit) + nat-redirect.rule.tmpl (13-line dedicated table); 2 profiles (host-tls-mitm + bridge-tap with bridge-l2 soft-dep); 3 required binaries (PolarProxy + nft + systemctl); 2 surfaces (tls-mitm + pcap-over-ip); F-2027-024 manifest integration + F-2027-027 DRY_RUN-forced-0; integrates with MS002 collector fabric (consumes pcap-over-ip) + MS006 module-system + MS021 shared module-script lib v2 + MS020 L1-L5 test harness | `modules/polarproxy/` 508 lines | E0231 + E0232 + E0233 + E0234 + E0235 + E0236 + E0237 + E0238 + E0239 + E0240 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module identity (R05281–R05300) + threat-model + scope owned/not-owned (R05301–R05324) + two profiles (R05325–R05332) + 8 config keys + overlay precedence (R05333–R05358) + idempotency/dry-run/uninstall (R05359–R05378) + apply.sh full transcription (R05379–R05448) + check.sh full transcription (R05449–R05462) + uninstall.sh full transcription (R05463–R05479) + install/lib.sh full transcription (R05480–R05489) + systemd unit + nftables rule full transcription (R05490–R05519) + composite (R05520)
- Source range 508 lines yields 240 R-rows representing ~47% line-coverage at the verbatim-citation level
- Project boundary — MS023 is selfdef IPS module scope; sovereign-os DOES NOT have a polarproxy equivalent (TLS inspection is host-defense surface, not workstation-runtime surface)
- F-2027-024 + F-2027-027 references — these are finding numbers from selfdef's SDD ledger (MS013 27-SDD charter); manifest helper opt-in + DRY_RUN-forced-zero respectively

## Cross-references

- Adjacent INDEX rows: MS022 per-token SSE subscriber quota / MS024 Bridge-L2 module (bridge-tap profile soft-dep)
- Module-system integration — MS023 module follows the standard `module.toml` + apply/check/uninstall shape codified by MS006 module fabric + MS021 shared module-script lib v2
- Surface integration — `tls-mitm` provides clear-side feed; `pcap-over-ip` provides TCP/4430 listener; future MS002 `selfdef-collector-pcap` SHALL consume `pcap-over-ip` via pointer file `/etc/selfdef/modules/polarproxy.toml`
- Cross-module dependency — `bridge-tap` profile soft-depends on MS024 bridge-l2 (`nft list table inet selfdef_bridge` runtime probe)
- Test integration — MS020 L1-L5 layered harness covers Module-script test category (Category 3 of 4) which MS023 apply/check/uninstall scripts SHALL exercise
- Audit integration — F-2027-024 manifest-helper opt-in derives from MS013 27-SDD charter findings ledger
- Cross-repo binding — sovereign-os has no polarproxy equivalent; if cross-repo audit needed, route through MS007 audit-manifest typed-mirror crate (SATURATED 8/8)
- Operator references: https://www.netresec.com/?page=PolarProxy + Netresec PolarProxy 1.x/2.x CLI docs + nftables(8) inet/nat hooks doc + systemd(5) DynamicUser/ProtectSystem/PrivateTmp directives + Suricata AF_PACKET dummy-netdev guide
