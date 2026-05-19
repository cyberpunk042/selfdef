# MS024 — Bridge-L2 module — layer-2 transparent bridge

> Parent: `backlog/milestones/INDEX.md` row MS024 (source ref `modules/bridge-l2`).
> Source: `modules/bridge-l2/` (477 lines across README.md, module.toml, config/defaults.toml, profiles/passthrough.toml, profiles/opnsense-edge.toml, install/apply.sh, install/check.sh, install/lib.sh, install/uninstall.sh, templates/nftables.conf.tmpl).
> All entries below extract verbatim from these files. No invention.

## Epics (E0241–E0250)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0241 | Module identity — `bridge-l2` v0.1.0, category=network, summary "Transparent L2 bridge + nftables policy (foundation for inline modules)"; transparent Layer-2 bridge with nftables policy chain that other inline modules (`suricata`, `polarproxy`) hook into; "this is the **foundation** module: it owns `br0` (or whatever you call your bridge) and the FORWARD policy on it" | `module.toml` 1–4 + `README.md` 1–6 |
| E0242 | What it does — 4 actions: 1) Creates Linux bridge interface (default `br0`); 2) Adds configured member interfaces to bridge and brings them up with no IP address (bridge is L3-invisible from data path); 3) Installs nftables ruleset that owns FORWARD chain on `br0` + drops INPUT on management interface if configured + exposes empty `selfdef_bridge_forward_hook` chain that inline-module consumers add jumps into ("the owning module does **not** know about its consumers"); 4) Persists everything via systemd-networkd or idempotent boot-time script (selectable in profile) | `README.md` 8–23 |
| E0243 | Two profiles — `passthrough` (members configurable in host config; FORWARD policy = `accept` — pure transparent bridge, no filtering yet; "Use this as a baseline before stacking IDS/IPS on top") + `opnsense-edge` (two NICs WAN-facing + LAN-facing; FORWARD policy = `accept`; "assumes a downstream OPNsense is the actual firewall; the bridge is purely an inspection vantage"; persist=systemd-networkd; members intentionally left empty — operator names the two physical NICs in /etc/selfdef/host.toml); profiles set defaults; operator overrides member NICs and bridge name in `/etc/selfdef/host.toml` | `README.md` 25–33 + `profiles/passthrough.toml` 1–6 + `profiles/opnsense-edge.toml` 1–12 |
| E0244 | Config schema — `profile` (passthrough/opnsense-edge) / `bridge_name` (default br0) / `members` (NIC list, empty by default) / `management_iface` (optional; INPUT-drop applied if set) / `forward_policy` (accept|drop) / `persist` (systemd-networkd|boot-script|none, default boot-script); overlay precedence "defaults overlaid by profile, then host config, then env vars" with reference to `docs/src/modules.md#config-layering` | `README.md` 35–48 + `config/defaults.toml` 1–8 |
| E0245 | Provides / requires / consumes — `provides = ["l2-bridge", "forward-policy"]` (l2-bridge = Linux bridge interface every inline module can hook for Suricata AF_PACKET / NFQUEUE attachment etc.; forward-policy = nftables FORWARD chain owned by this module; other modules add jumps into their own chains rather than rewriting policy); `consumes = []`; `requires` (5 items: binary ip + binary nft + binary systemctl + kernel-feature CONFIG_BRIDGE + kernel-feature CONFIG_NF_TABLES); `depends_on = []`, `conflicts = []` | `module.toml` 6–24 |
| E0246 | Apply pipeline — preflight (config readable / ip binary / nft binary) + read config (bridge_name + forward_policy + management_iface + members) + validate (bridge_name non-empty / forward_policy ∈ {accept,drop} / members non-empty) + 3 idempotency-aware bridge operations (bridge create if absent / enslave each member if not enslaved / bring up each member if not up + bring up bridge if not up) + nftables ruleset render (sed substitute @@BRIDGE_NAME@@ + @@FORWARD_POLICY@@ + @@MGMT_INPUT_RULE@@) + cmp-skip + install + load + manifest record F-2027-024 + final JSON status | `install/apply.sh` 1–111 |
| E0247 | nftables ruleset structure — `table inet selfdef_bridge` with 4 chains: `forward_hook` (empty; inline modules add jumps) / `forward` (type filter hook forward priority filter; policy @@FORWARD_POLICY@@; iifname @@BRIDGE_NAME@@ jump forward_hook + oifname @@BRIDGE_NAME@@ jump forward_hook) / `input` (type filter hook input priority filter; policy accept; @@MGMT_INPUT_RULE@@) / `output` (type filter hook output priority filter; policy accept); MGMT_RULE substituted to "iifname \"$MGMT_IFACE\" ct state new drop" if MGMT_IFACE set else "# (no management_iface configured)" comment | `templates/nftables.conf.tmpl` 1–34 + `apply.sh` 78–90 |
| E0248 | Idempotency + dry-run + check + uninstall — `install/apply.sh` safe to re-run; on host already at target state makes zero changes and exits 0 with `{"module":"bridge-l2","status":"skipped","message":"already at target state"}`; `SELFDEF_DRY_RUN=1` causes every state-changing step to print what it would do without touching system; `check.sh` 5 probes (config readable / bridge present + up / each member enslaved / nftables ruleset file present / nftables table loaded) with DRY_RUN forced 0 (F-2027-027); `uninstall.sh` deletes nftables table + walks manifest (F-2027-024) + legacy fallback for pre-v2 installs + tears down bridge (set down + delete) + member NICs released to standalone but NOT re-configured (operator re-applies previous IP/DHCP setup); operator must run uninstall from console or management interface | `README.md` 50–60 + `apply.sh` 107–111 + `check.sh` 1–70 + `uninstall.sh` 1–81 |
| E0249 | toml_get_list helper — module-specific helper to read TOML inline array of strings (shared lib's toml_get only reads scalars); returns newline-separated tokens with quotes + whitespace stripped; line parsing: grep `^key=` + strip brackets + split on `,` + strip whitespace + strip quotes | `install/lib.sh` 35–52 |
| E0250 | Caveats — running this on a host whose only network access is via to-be-bridged NICs will sever connection ("Either run it from the management interface or from console"); first apply does NOT schedule "revert if no operator check-in within N minutes" safety — that's planned for same module's v0.2.0 | `README.md` 62–69 |

## Modules (M00603–M00628)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00603 | `module.toml` — manifest (5-block manifest including 5-item `requires` with binaries + kernel-features) | `module.toml` 1–34 | E0241 |
| M00604 | `README.md` — 69-line foundation-module operator doc | `README.md` 1–69 | E0241 |
| M00605 | `config/defaults.toml` — 7-key baseline (bridge_name + members[] + management_iface + forward_policy + persist) | `config/defaults.toml` 1–7 | E0244 |
| M00606 | `profiles/passthrough.toml` — baseline transparent-bridge profile (3 keys; bridge_name=br0 + forward_policy=accept + persist=boot-script) | `profiles/passthrough.toml` 1–5 | E0243 |
| M00607 | `profiles/opnsense-edge.toml` — edge inspection profile (5 keys; persist=systemd-networkd; members[] intentionally empty) | `profiles/opnsense-edge.toml` 1–12 | E0243 |
| M00608 | `install/apply.sh` — 111-line idempotent applier (preflight + read + validate + bridge ops + nftables render+install+load + manifest record) | `install/apply.sh` 1–111 | E0246 |
| M00609 | `install/check.sh` — 70-line side-effect-free probe (5 problems-array probes) | `install/check.sh` 1–70 | E0248 |
| M00610 | `install/lib.sh` — 52-line shared+local helpers (v2 opt-in + toml_get_list local helper) | `install/lib.sh` 1–52 | E0249 |
| M00611 | `install/uninstall.sh` — 81-line tear-down (nft delete + manifest walk + legacy fallback + bridge down + delete) | `install/uninstall.sh` 1–81 | E0248 |
| M00612 | `templates/nftables.conf.tmpl` — 34-line nft ruleset template with 3 substitution tokens + 4 chains | `templates/nftables.conf.tmpl` 1–34 | E0247 |
| M00613 | Provided surface — `l2-bridge` (Linux bridge every inline module can hook via Suricata AF_PACKET / NFQUEUE) | `module.toml` 10–11 + 15 | E0245 |
| M00614 | Provided surface — `forward-policy` (nftables FORWARD chain owned by this module; consumers add jumps) | `module.toml` 12–14 + 15 | E0245 |
| M00615 | Required binary — `ip(8)` | `module.toml` 19 + `apply.sh` 28 | E0245 |
| M00616 | Required binary — `nft(8)` | `module.toml` 20 + `apply.sh` 29 | E0245 |
| M00617 | Required binary — `systemctl` | `module.toml` 21 | E0245 |
| M00618 | Required kernel-feature — `CONFIG_BRIDGE` | `module.toml` 22 | E0245 |
| M00619 | Required kernel-feature — `CONFIG_NF_TABLES` | `module.toml` 23 | E0245 |
| M00620 | bridge_exists helper — `ip link show dev "$1" type bridge` | `apply.sh` 44 | E0246 |
| M00621 | member_of helper — `ip -o link show "$1"` + awk master match | `apply.sh` 45 | E0246 |
| M00622 | link_up helper — `ip -o link show "$1"` + grep "state UP" | `apply.sh` 46 | E0246 |
| M00623 | nftables table — `inet selfdef_bridge` (4 chains: forward_hook empty / forward / input / output) | `templates/nftables.conf.tmpl` 10–33 | E0247 |
| M00624 | nftables forward_hook chain — empty by design; inline modules add jumps into it | `templates/nftables.conf.tmpl` 12–14 | E0247 |
| M00625 | nftables forward chain — type filter hook forward priority filter; policy @@FORWARD_POLICY@@; iifname/oifname @@BRIDGE_NAME@@ jump forward_hook | `templates/nftables.conf.tmpl` 16–20 | E0247 |
| M00626 | nftables input chain — policy accept; management-iface INPUT-drop rule substituted via @@MGMT_INPUT_RULE@@ | `templates/nftables.conf.tmpl` 22–28 | E0247 |
| M00627 | Manifest integration — F-2027-024 (`module_record_file` / `module_render_files` / `module_clear_manifest`) replaces hand-curated NFT_RULESET_PATH duplication | `install/lib.sh` 8–14 + `apply.sh` 99–104 + `uninstall.sh` 16–21 + 57–67 + 75 | E0246 + E0248 |
| M00628 | toml_get_list module-specific helper — reads TOML inline array of strings (shared lib's toml_get only reads scalars); newline-separated output | `install/lib.sh` 35–52 | E0249 |

## Features (F02761–F02880)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F02761 | module.toml `name = "bridge-l2"` | `module.toml` 1 | M00603 |
| F02762 | module.toml `version = "0.1.0"` | `module.toml` 2 | M00603 |
| F02763 | module.toml `summary = "Transparent L2 bridge + nftables policy (foundation for inline modules)"` | `module.toml` 3 | M00603 |
| F02764 | module.toml `category = "network"` | `module.toml` 4 | M00603 |
| F02765 | module.toml `depends_on = []` | `module.toml` 6 | M00603 |
| F02766 | module.toml `conflicts = []` | `module.toml` 7 | M00603 |
| F02767 | module.toml `provides = ["l2-bridge", "forward-policy"]` | `module.toml` 15 | M00613 + M00614 |
| F02768 | module.toml `consumes = []` | `module.toml` 16 | M00603 |
| F02769 | module.toml `requires` — binary ip | `module.toml` 19 | M00615 |
| F02770 | module.toml `requires` — binary nft | `module.toml` 20 | M00616 |
| F02771 | module.toml `requires` — binary systemctl | `module.toml` 21 | M00617 |
| F02772 | module.toml `requires` — kernel-feature CONFIG_BRIDGE | `module.toml` 22 | M00618 |
| F02773 | module.toml `requires` — kernel-feature CONFIG_NF_TABLES | `module.toml` 23 | M00619 |
| F02774 | module.toml `[install] kind = "script"` | `module.toml` 26–27 | M00603 |
| F02775 | module.toml `apply = "install/apply.sh"` | `module.toml` 28 | M00603 + M00608 |
| F02776 | module.toml `check = "install/check.sh"` | `module.toml` 29 | M00603 + M00609 |
| F02777 | module.toml `uninstall = "install/uninstall.sh"` | `module.toml` 30 | M00603 + M00611 |
| F02778 | module.toml `[profiles] default = "passthrough"` | `module.toml` 32–33 | M00603 + M00606 |
| F02779 | module.toml `available = ["passthrough", "opnsense-edge"]` | `module.toml` 34 | M00603 + M00606 + M00607 |
| F02780 | README — "foundation module" phrase | `README.md` 4–5 | E0241 |
| F02781 | README — module owns `br0` + FORWARD policy | `README.md` 5–6 | E0241 |
| F02782 | README action 1 — creates Linux bridge (default `br0`) | `README.md` 10 | E0242 |
| F02783 | README action 2 — adds configured member interfaces | `README.md` 11–12 | E0242 |
| F02784 | README action 2 — members brought up with no IP address | `README.md` 12 | E0242 |
| F02785 | README action 2 — bridge is L3-invisible from data path | `README.md` 13 | E0242 |
| F02786 | README action 3 — installs nftables ruleset | `README.md` 14 | E0242 |
| F02787 | README action 3 — owns FORWARD chain on `br0` | `README.md` 15 | E0242 |
| F02788 | README action 3 — passes or drops by policy depending on profile | `README.md` 16 | E0242 |
| F02789 | README action 3 — drops INPUT on management interface if configured | `README.md` 17 | E0242 |
| F02790 | README action 3 — management plane is outbound-only | `README.md` 18 | E0242 |
| F02791 | README action 3 — exposes empty `selfdef_bridge_forward_hook` chain | `README.md` 19 | M00624 |
| F02792 | README action 3 — `suricata`, `polarproxy`, future inline modules add jumps into hook | `README.md` 19–21 | M00624 |
| F02793 | README action 3 — "owning module does not know about its consumers" | `README.md` 21 | M00624 |
| F02794 | README action 4 — persists via systemd-networkd or idempotent boot-time script | `README.md` 22–23 | E0242 |
| F02795 | README action 4 — selectable in profile | `README.md` 23 | E0242 |
| F02796 | README profile passthrough — pure transparent bridge no filtering | `README.md` 29 | E0243 |
| F02797 | README profile passthrough — baseline before stacking IDS/IPS | `README.md` 29 | E0243 |
| F02798 | README profile opnsense-edge — two NICs WAN-facing + LAN-facing | `README.md` 30 | E0243 |
| F02799 | README profile opnsense-edge — assumes downstream OPNsense is actual firewall | `README.md` 30 | E0243 |
| F02800 | README profile opnsense-edge — bridge is purely an inspection vantage | `README.md` 30 | E0243 |
| F02801 | README — profiles set defaults; operator overrides in /etc/selfdef/host.toml | `README.md` 32–33 | E0243 |
| F02802 | README config `profile = "opnsense-edge"` | `README.md` 39 | E0244 |
| F02803 | README config `bridge_name = "br0"` | `README.md` 40 | E0244 |
| F02804 | README config `members = ["eno1", "eno2"]` | `README.md` 41 | E0244 |
| F02805 | README config `management_iface = "wlan0"` (optional; INPUT-drop applied if set) | `README.md` 42 | E0244 |
| F02806 | README config `forward_policy = "accept"` (accept | drop) | `README.md` 43 | E0244 |
| F02807 | README config `persist = "systemd-networkd"` (systemd-networkd | boot-script | none) | `README.md` 44 | E0244 |
| F02808 | README — `docs/src/modules.md#config-layering` precedence reference | `README.md` 47–48 | E0244 |
| F02809 | defaults.toml `bridge_name = "br0"` | `config/defaults.toml` 4 | E0244 |
| F02810 | defaults.toml `members = []` | `config/defaults.toml` 5 | E0244 |
| F02811 | defaults.toml `management_iface = ""` (empty = no management-INPUT drop) | `config/defaults.toml` 6 | E0244 |
| F02812 | defaults.toml `forward_policy = "accept"` (accept | drop) | `config/defaults.toml` 7 | E0244 |
| F02813 | defaults.toml `persist = "boot-script"` (systemd-networkd | boot-script | none) | `config/defaults.toml` 8 | E0244 |
| F02814 | profiles/passthrough.toml `bridge_name = "br0"` | `profiles/passthrough.toml` 3 | M00606 |
| F02815 | profiles/passthrough.toml `forward_policy = "accept"` | `profiles/passthrough.toml` 4 | M00606 |
| F02816 | profiles/passthrough.toml `persist = "boot-script"` | `profiles/passthrough.toml` 5 | M00606 |
| F02817 | profiles/opnsense-edge.toml `bridge_name = "br0"` | `profiles/opnsense-edge.toml` 5 | M00607 |
| F02818 | profiles/opnsense-edge.toml `forward_policy = "accept"` | `profiles/opnsense-edge.toml` 6 | M00607 |
| F02819 | profiles/opnsense-edge.toml `persist = "systemd-networkd"` | `profiles/opnsense-edge.toml` 7 | M00607 |
| F02820 | profiles/opnsense-edge.toml `members = []` intentionally — operator names two physical NICs | `profiles/opnsense-edge.toml` 9–12 | M00607 |
| F02821 | profiles/opnsense-edge.toml `management_iface = ""` | `profiles/opnsense-edge.toml` 12 | M00607 |
| F02822 | README idempotency — apply.sh safe to re-run | `README.md` 52–53 | E0248 |
| F02823 | README idempotency — zero changes on target-state host | `README.md` 53–54 | E0248 |
| F02824 | README idempotency — exits 0 with `{"module":"bridge-l2","status":"skipped","message":"already at target state"}` | `README.md` 54 | E0248 |
| F02825 | README dry-run — `SELFDEF_DRY_RUN=1` prints intended changes | `README.md` 58–60 | E0248 |
| F02826 | README caveat — running on host with only-bridge-member NICs severs connection | `README.md` 64–66 | E0250 |
| F02827 | README caveat — run from management interface or console | `README.md` 66 | E0250 |
| F02828 | README caveat — first apply does NOT schedule revert-if-no-checkin safety | `README.md` 67–68 | E0250 |
| F02829 | README caveat — revert-if-no-checkin planned for v0.2.0 | `README.md` 69 | E0250 |
| F02830 | apply.sh `set -euo pipefail` | `apply.sh` 12 | M00608 |
| F02831 | apply.sh CONFIG_FILE default `/etc/selfdef/modules/bridge-l2.toml` | `apply.sh` 16 | M00608 |
| F02832 | apply.sh CONFIG_FILE override via SELFDEF_BRIDGE_L2_CONFIG | `apply.sh` 16 | M00608 |
| F02833 | apply.sh stdin alternative — BRIDGE_L2_CONFIG_FROM_STDIN=1 | `apply.sh` 10 | M00608 |
| F02834 | apply.sh TEMPLATE_DIR default /usr/share/selfdef/modules/bridge-l2/templates | `apply.sh` 17 | M00608 |
| F02835 | apply.sh NFT_RULESET_PATH = /etc/nftables.d/selfdef-bridge.conf | `apply.sh` 18 | M00608 |
| F02836 | apply.sh sources install/lib.sh | `apply.sh` 23–24 | M00610 |
| F02837 | apply.sh preflight — config readable (die if not) | `apply.sh` 27 | M00608 |
| F02838 | apply.sh preflight — ip(8) binary check | `apply.sh` 28 | M00615 |
| F02839 | apply.sh preflight — nft(8) binary check | `apply.sh` 29 | M00616 |
| F02840 | apply.sh reads bridge_name via toml_get (default br0) | `apply.sh` 31 | M00608 |
| F02841 | apply.sh reads forward_policy via toml_get (default accept) | `apply.sh` 32 | M00608 |
| F02842 | apply.sh reads management_iface via toml_get (default empty) | `apply.sh` 33 | M00608 |
| F02843 | apply.sh reads members via toml_get_list helper | `apply.sh` 34 | M00628 |
| F02844 | apply.sh validation — bridge_name non-empty | `apply.sh` 36 | M00608 |
| F02845 | apply.sh validation — forward_policy ∈ {accept,drop} | `apply.sh` 37–38 | M00608 |
| F02846 | apply.sh validation — members list non-empty (at least one NIC required) | `apply.sh` 39 | M00608 |
| F02847 | apply.sh bridge_exists helper — `ip link show dev "$1" type bridge` | `apply.sh` 44 | M00620 |
| F02848 | apply.sh member_of helper — awk-parses `ip -o link show` for master | `apply.sh` 45 | M00621 |
| F02849 | apply.sh link_up helper — `ip -o link show | grep "state UP"` | `apply.sh` 46 | M00622 |
| F02850 | apply.sh creates bridge if !bridge_exists | `apply.sh` 48–53 | M00608 |
| F02851 | apply.sh skip log "bridge $BRIDGE_NAME already present" | `apply.sh` 49 | M00608 |
| F02852 | apply.sh `ip link add name "$BRIDGE_NAME" type bridge` | `apply.sh` 51 | M00608 |
| F02853 | apply.sh loops each member; enslaves if not member_of | `apply.sh` 55–62 | M00608 |
| F02854 | apply.sh `ip link set "$iface" master "$BRIDGE_NAME"` | `apply.sh` 60 | M00608 |
| F02855 | apply.sh brings up each member if !link_up | `apply.sh` 63–66 | M00608 |
| F02856 | apply.sh `ip link set "$iface" up` | `apply.sh` 64 | M00608 |
| F02857 | apply.sh brings up bridge if !link_up | `apply.sh` 69–72 | M00608 |
| F02858 | apply.sh nftables template path `$TEMPLATE_DIR/nftables.conf.tmpl` | `apply.sh` 75 | M00612 |
| F02859 | apply.sh MGMT_RULE substitution — `iifname "$MGMT_IFACE" ct state new drop` if MGMT_IFACE set | `apply.sh` 78–82 | M00626 |
| F02860 | apply.sh MGMT_RULE substitution — `# (no management_iface configured)` comment if empty | `apply.sh` 81 | M00626 |
| F02861 | apply.sh nftables render via mktemp + sed 3-token substitution | `apply.sh` 84–90 | M00612 |
| F02862 | apply.sh substitutes @@BRIDGE_NAME@@ | `apply.sh` 87 | M00612 |
| F02863 | apply.sh substitutes @@FORWARD_POLICY@@ | `apply.sh` 88 | M00612 |
| F02864 | apply.sh substitutes @@MGMT_INPUT_RULE@@ | `apply.sh` 89 | M00612 |
| F02865 | apply.sh idempotency — cmp -s RENDERED NFT_RULESET_PATH skip | `apply.sh` 92–93 | M00608 |
| F02866 | apply.sh install — `install -D -m 0644` + `nft -f` load | `apply.sh` 95–96 | M00608 |
| F02867 | apply.sh changes += 2 after nft install + load | `apply.sh` 97 | M00608 |
| F02868 | apply.sh F-2027-024 manifest record (always, even if file already at target state) | `apply.sh` 99–104 | M00627 |
| F02869 | apply.sh finalise — emit "skipped" if changes==0 | `apply.sh` 107–108 | M00608 |
| F02870 | apply.sh finalise — emit "ok" applied N changes otherwise | `apply.sh` 109–110 | M00608 |
| F02871 | nftables template — `flush ruleset` directive | `templates/nftables.conf.tmpl` 9 | M00612 |
| F02872 | nftables template — `table inet selfdef_bridge` declaration | `templates/nftables.conf.tmpl` 10 | M00623 |
| F02873 | nftables template — forward_hook chain empty (consumer jumps target) | `templates/nftables.conf.tmpl` 12–14 | M00624 |
| F02874 | nftables template — forward chain hook=forward priority=filter; policy=@@FORWARD_POLICY@@ | `templates/nftables.conf.tmpl` 16–17 | M00625 |
| F02875 | nftables template — forward chain iifname @@BRIDGE_NAME@@ jump forward_hook | `templates/nftables.conf.tmpl` 18 | M00625 |
| F02876 | nftables template — forward chain oifname @@BRIDGE_NAME@@ jump forward_hook | `templates/nftables.conf.tmpl` 19 | M00625 |
| F02877 | nftables template — input chain hook=input priority=filter; policy=accept | `templates/nftables.conf.tmpl` 22–23 | M00626 |
| F02878 | nftables template — input chain @@MGMT_INPUT_RULE@@ injection point | `templates/nftables.conf.tmpl` 27 | M00626 |
| F02879 | nftables template — output chain hook=output priority=filter; policy=accept | `templates/nftables.conf.tmpl` 30–32 | M00623 |
| F02880 | check.sh + uninstall.sh + lib.sh full transcription — 5-probe check + manifest-walked uninstall + legacy fallback + bridge teardown (set down + delete) + toml_get_list local helper + F-2027-024 v2 opt-in + 3-tier lookup precedence + uninstall.sh override log+run for partial-failure tolerance | `install/check.sh` + `install/uninstall.sh` + `install/lib.sh` | M00609 + M00611 + M00610 |

## Requirements (R05521–R05760)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R05521 | Module name MUST be `bridge-l2` | `module.toml` 1 | F02761 | non-negotiable | false | 10 |
| R05522 | Module version MUST be 0.1.0 | `module.toml` 2 | F02762 | non-negotiable | false | 10 |
| R05523 | Module summary MUST be "Transparent L2 bridge + nftables policy (foundation for inline modules)" | `module.toml` 3 | F02763 | non-negotiable | false | 10 |
| R05524 | Module category MUST be `network` | `module.toml` 4 | F02764 | non-negotiable | false | 10 |
| R05525 | Module SHALL declare `depends_on = []` | `module.toml` 6 | F02765 | non-negotiable | false | 10 |
| R05526 | Module SHALL declare `conflicts = []` | `module.toml` 7 | F02766 | non-negotiable | false | 10 |
| R05527 | Module SHALL provide `l2-bridge` surface | `module.toml` 15 | F02767 | non-negotiable | false | 10 |
| R05528 | Module SHALL provide `forward-policy` surface | `module.toml` 15 | F02767 | non-negotiable | false | 10 |
| R05529 | l2-bridge = Linux bridge interface every inline module can hook | `module.toml` 10–11 | M00613 | non-negotiable | false | 10 |
| R05530 | l2-bridge usage — Suricata AF_PACKET attachment | `module.toml` 11 | M00613 | non-negotiable | false | 10 |
| R05531 | l2-bridge usage — NFQUEUE attachment | `module.toml` 11 | M00613 | non-negotiable | false | 10 |
| R05532 | forward-policy = nftables FORWARD chain owned by this module | `module.toml` 12 | M00614 | non-negotiable | false | 10 |
| R05533 | forward-policy — other modules add jumps into their own chains rather than rewriting policy | `module.toml` 13–14 | M00614 | non-negotiable | false | 10 |
| R05534 | Module SHALL declare `consumes = []` | `module.toml` 16 | F02768 | non-negotiable | false | 10 |
| R05535 | Required binary — ip | `module.toml` 19 | F02769 | non-negotiable | false | 10 |
| R05536 | Required binary — nft | `module.toml` 20 | F02770 | non-negotiable | false | 10 |
| R05537 | Required binary — systemctl | `module.toml` 21 | F02771 | non-negotiable | false | 10 |
| R05538 | Required kernel-feature — CONFIG_BRIDGE | `module.toml` 22 | F02772 | non-negotiable | false | 10 |
| R05539 | Required kernel-feature — CONFIG_NF_TABLES | `module.toml` 23 | F02773 | non-negotiable | false | 10 |
| R05540 | Install kind = "script" | `module.toml` 27 | F02774 | non-negotiable | false | 10 |
| R05541 | Apply script path "install/apply.sh" | `module.toml` 28 | F02775 | non-negotiable | false | 10 |
| R05542 | Check script path "install/check.sh" | `module.toml` 29 | F02776 | non-negotiable | false | 10 |
| R05543 | Uninstall script path "install/uninstall.sh" | `module.toml` 30 | F02777 | non-negotiable | false | 10 |
| R05544 | Default profile MUST be `passthrough` | `module.toml` 33 | F02778 | non-negotiable | false | 10 |
| R05545 | Available profiles MUST equal `["passthrough", "opnsense-edge"]` | `module.toml` 34 | F02779 | non-negotiable | false | 10 |
| R05546 | Module SHALL be the "foundation module" | `README.md` 4–5 | F02780 | non-negotiable | false | 10 |
| R05547 | Module owns `br0` (or whatever bridge name) | `README.md` 5–6 | F02781 | non-negotiable | false | 10 |
| R05548 | Module owns FORWARD policy on br0 | `README.md` 6 | F02781 | non-negotiable | false | 10 |
| R05549 | Module SHALL create Linux bridge interface | `README.md` 10 | F02782 | non-negotiable | false | 10 |
| R05550 | Default bridge name MUST be `br0` | `README.md` 10 | F02782 | non-negotiable | false | 10 |
| R05551 | Module SHALL add configured member interfaces to bridge | `README.md` 11 | F02783 | non-negotiable | false | 10 |
| R05552 | Module SHALL bring members up with no IP address | `README.md` 12 | F02784 | non-negotiable | false | 10 |
| R05553 | Bridge MUST be L3-invisible from data path | `README.md` 13 | F02785 | non-negotiable | false | 10 |
| R05554 | Module SHALL install nftables ruleset | `README.md` 14 | F02786 | non-negotiable | false | 10 |
| R05555 | Module owns FORWARD chain on br0 | `README.md` 15 | F02787 | non-negotiable | false | 10 |
| R05556 | Module passes or drops by policy depending on profile | `README.md` 16 | F02788 | non-negotiable | false | 10 |
| R05557 | Module drops INPUT on management interface if configured | `README.md` 17 | F02789 | non-negotiable | false | 10 |
| R05558 | Management plane MUST be outbound-only | `README.md` 18 | F02790 | non-negotiable | false | 10 |
| R05559 | Module exposes empty `selfdef_bridge_forward_hook` chain | `README.md` 19 | F02791 | non-negotiable | false | 10 |
| R05560 | suricata, polarproxy, future inline modules add jumps into hook | `README.md` 19–21 | F02792 | non-negotiable | false | 10 |
| R05561 | "Owning module does not know about its consumers" | `README.md` 21 | F02793 | non-negotiable | false | 10 |
| R05562 | Module persists via systemd-networkd OR idempotent boot-time script | `README.md` 22–23 | F02794 | non-negotiable | false | 10 |
| R05563 | Persistence selectable in profile | `README.md` 23 | F02795 | non-negotiable | false | 10 |
| R05564 | Profile `passthrough` — pure transparent bridge | `README.md` 29 | F02796 | non-negotiable | false | 10 |
| R05565 | Profile `passthrough` — no filtering | `README.md` 29 | F02796 | non-negotiable | false | 10 |
| R05566 | Profile `passthrough` — baseline before stacking IDS/IPS | `README.md` 29 | F02797 | non-negotiable | false | 10 |
| R05567 | Profile `opnsense-edge` — two NICs WAN-facing + LAN-facing | `README.md` 30 | F02798 | non-negotiable | false | 10 |
| R05568 | Profile `opnsense-edge` — assumes downstream OPNsense is firewall | `README.md` 30 | F02799 | non-negotiable | false | 10 |
| R05569 | Profile `opnsense-edge` — bridge is inspection vantage | `README.md` 30 | F02800 | non-negotiable | false | 10 |
| R05570 | Profiles set defaults | `README.md` 32 | F02801 | non-negotiable | false | 10 |
| R05571 | Operator overrides member NICs in /etc/selfdef/host.toml | `README.md` 32–33 | F02801 | non-negotiable | false | 10 |
| R05572 | Operator overrides bridge name in /etc/selfdef/host.toml | `README.md` 33 | F02801 | non-negotiable | false | 10 |
| R05573 | Config key `profile` (passthrough/opnsense-edge) | `README.md` 39 | F02802 | non-negotiable | false | 10 |
| R05574 | Config key `bridge_name` default br0 | `README.md` 40 | F02803 | non-negotiable | false | 10 |
| R05575 | Config key `members` — list of NIC names | `README.md` 41 | F02804 | non-negotiable | false | 10 |
| R05576 | Config key `management_iface` optional | `README.md` 42 | F02805 | non-negotiable | false | 10 |
| R05577 | management_iface — INPUT-drop applied if set | `README.md` 42 | F02805 | non-negotiable | false | 10 |
| R05578 | Config key `forward_policy` (accept | drop) | `README.md` 43 | F02806 | non-negotiable | false | 10 |
| R05579 | Config key `persist` (systemd-networkd | boot-script | none) | `README.md` 44 | F02807 | non-negotiable | false | 10 |
| R05580 | Config layering reference — docs/src/modules.md#config-layering | `README.md` 47–48 | F02808 | non-negotiable | false | 10 |
| R05581 | defaults.toml bridge_name = "br0" | `config/defaults.toml` 4 | F02809 | non-negotiable | false | 10 |
| R05582 | defaults.toml members = [] | `config/defaults.toml` 5 | F02810 | non-negotiable | false | 10 |
| R05583 | defaults.toml management_iface = "" | `config/defaults.toml` 6 | F02811 | non-negotiable | false | 10 |
| R05584 | management_iface empty = no INPUT-drop applied | `config/defaults.toml` 6 | F02811 | non-negotiable | false | 10 |
| R05585 | defaults.toml forward_policy = "accept" | `config/defaults.toml` 7 | F02812 | non-negotiable | false | 10 |
| R05586 | forward_policy accept|drop only | `config/defaults.toml` 7 | F02812 | non-negotiable | false | 10 |
| R05587 | defaults.toml persist = "boot-script" | `config/defaults.toml` 8 | F02813 | non-negotiable | false | 10 |
| R05588 | persist systemd-networkd|boot-script|none only | `config/defaults.toml` 8 | F02813 | non-negotiable | false | 10 |
| R05589 | passthrough profile bridge_name = "br0" | `profiles/passthrough.toml` 3 | F02814 | non-negotiable | false | 10 |
| R05590 | passthrough profile forward_policy = "accept" | `profiles/passthrough.toml` 4 | F02815 | non-negotiable | false | 10 |
| R05591 | passthrough profile persist = "boot-script" | `profiles/passthrough.toml` 5 | F02816 | non-negotiable | false | 10 |
| R05592 | opnsense-edge profile bridge_name = "br0" | `profiles/opnsense-edge.toml` 5 | F02817 | non-negotiable | false | 10 |
| R05593 | opnsense-edge profile forward_policy = "accept" | `profiles/opnsense-edge.toml` 6 | F02818 | non-negotiable | false | 10 |
| R05594 | opnsense-edge profile persist = "systemd-networkd" | `profiles/opnsense-edge.toml` 7 | F02819 | non-negotiable | false | 10 |
| R05595 | opnsense-edge profile members = [] intentionally | `profiles/opnsense-edge.toml` 11 | F02820 | non-negotiable | false | 10 |
| R05596 | opnsense-edge — operator names the two physical NICs | `profiles/opnsense-edge.toml` 9–10 | F02820 | non-negotiable | false | 10 |
| R05597 | opnsense-edge profile management_iface = "" | `profiles/opnsense-edge.toml` 12 | F02821 | non-negotiable | false | 10 |
| R05598 | install/apply.sh safe to re-run | `README.md` 52 | F02822 | non-negotiable | false | 10 |
| R05599 | On target-state host apply makes zero changes | `README.md` 53 | F02823 | non-negotiable | false | 10 |
| R05600 | On target-state host apply exits 0 | `README.md` 53 | F02823 | non-negotiable | false | 10 |
| R05601 | Skipped JSON — `{"module":"bridge-l2","status":"skipped","message":"already at target state"}` | `README.md` 54 | F02824 | non-negotiable | false | 10 |
| R05602 | SELFDEF_DRY_RUN=1 causes every state-changing step to print what it would do | `README.md` 58–59 | F02825 | non-negotiable | false | 10 |
| R05603 | SELFDEF_DRY_RUN=1 exits without touching system | `README.md` 59–60 | F02825 | non-negotiable | false | 10 |
| R05604 | Caveat — running on host with only-bridge-member NICs severs connection | `README.md` 64–66 | F02826 | non-negotiable | false | 10 |
| R05605 | Caveat — run from management interface or console | `README.md` 66 | F02827 | non-negotiable | false | 10 |
| R05606 | Caveat — first apply does NOT schedule revert-if-no-checkin | `README.md` 67–68 | F02828 | non-negotiable | false | 10 |
| R05607 | Caveat — revert-if-no-checkin planned for v0.2.0 | `README.md` 69 | F02829 | non-negotiable | false | 10 |
| R05608 | apply.sh MUST set -euo pipefail | `apply.sh` 12 | F02830 | non-negotiable | false | 10 |
| R05609 | apply.sh MODULE = "bridge-l2" | `apply.sh` 14 | M00608 | non-negotiable | false | 10 |
| R05610 | apply.sh DRY_RUN read from SELFDEF_DRY_RUN env | `apply.sh` 15 | M00608 | non-negotiable | false | 10 |
| R05611 | apply.sh CONFIG_FILE default `/etc/selfdef/modules/bridge-l2.toml` | `apply.sh` 16 | F02831 | non-negotiable | false | 10 |
| R05612 | apply.sh CONFIG_FILE override via SELFDEF_BRIDGE_L2_CONFIG | `apply.sh` 16 | F02832 | non-negotiable | false | 10 |
| R05613 | apply.sh stdin alternative via BRIDGE_L2_CONFIG_FROM_STDIN=1 | `apply.sh` 10 | F02833 | non-negotiable | false | 10 |
| R05614 | apply.sh TEMPLATE_DIR default `/usr/share/selfdef/modules/bridge-l2/templates` | `apply.sh` 17 | F02834 | non-negotiable | false | 10 |
| R05615 | apply.sh TEMPLATE_DIR override via SELFDEF_BRIDGE_L2_TEMPLATES | `apply.sh` 17 | F02834 | non-negotiable | false | 10 |
| R05616 | apply.sh NFT_RULESET_PATH = `/etc/nftables.d/selfdef-bridge.conf` | `apply.sh` 18 | F02835 | non-negotiable | false | 10 |
| R05617 | apply.sh sources install/lib.sh | `apply.sh` 23–24 | F02836 | non-negotiable | false | 10 |
| R05618 | apply.sh preflight — config readable check (die if not) | `apply.sh` 27 | F02837 | non-negotiable | false | 10 |
| R05619 | apply.sh preflight — `command -v ip` check | `apply.sh` 28 | F02838 | non-negotiable | false | 10 |
| R05620 | apply.sh preflight — `command -v nft` check | `apply.sh` 29 | F02839 | non-negotiable | false | 10 |
| R05621 | apply.sh reads BRIDGE_NAME via toml_get | `apply.sh` 31 | F02840 | non-negotiable | false | 10 |
| R05622 | apply.sh reads FORWARD_POLICY via toml_get | `apply.sh` 32 | F02841 | non-negotiable | false | 10 |
| R05623 | apply.sh reads MGMT_IFACE via toml_get | `apply.sh` 33 | F02842 | non-negotiable | false | 10 |
| R05624 | apply.sh reads MEMBERS via toml_get_list | `apply.sh` 34 | F02843 | non-negotiable | false | 10 |
| R05625 | apply.sh validation — bridge_name MUST be non-empty | `apply.sh` 36 | F02844 | non-negotiable | false | 10 |
| R05626 | apply.sh validation — bridge_name die message "bridge_name is empty in $CONFIG_FILE" | `apply.sh` 36 | F02844 | non-negotiable | false | 10 |
| R05627 | apply.sh validation — forward_policy ∈ {accept,drop} | `apply.sh` 37 | F02845 | non-negotiable | false | 10 |
| R05628 | apply.sh validation — forward_policy die message format | `apply.sh` 38 | F02845 | non-negotiable | false | 10 |
| R05629 | apply.sh validation — members MUST be non-empty | `apply.sh` 39 | F02846 | non-negotiable | false | 10 |
| R05630 | apply.sh validation — members die message "members list is empty — at least one NIC is required" | `apply.sh` 39 | F02846 | non-negotiable | false | 10 |
| R05631 | apply.sh bridge_exists helper definition | `apply.sh` 44 | F02847 | non-negotiable | false | 10 |
| R05632 | apply.sh member_of helper definition | `apply.sh` 45 | F02848 | non-negotiable | false | 10 |
| R05633 | apply.sh link_up helper definition | `apply.sh` 46 | F02849 | non-negotiable | false | 10 |
| R05634 | apply.sh creates bridge if !bridge_exists | `apply.sh` 48 | F02850 | non-negotiable | false | 10 |
| R05635 | apply.sh bridge-already-present log "bridge $BRIDGE_NAME already present" | `apply.sh` 49 | F02851 | non-negotiable | false | 10 |
| R05636 | apply.sh `ip link add name "$BRIDGE_NAME" type bridge` | `apply.sh` 51 | F02852 | non-negotiable | false | 10 |
| R05637 | apply.sh increments changes after bridge create | `apply.sh` 52 | M00608 | non-negotiable | true | 10 |
| R05638 | apply.sh loops members; skips empty lines | `apply.sh` 55–56 | F02853 | non-negotiable | false | 10 |
| R05639 | apply.sh enslaves member if !member_of | `apply.sh` 57–62 | F02853 | non-negotiable | false | 10 |
| R05640 | apply.sh enslave log "iface already enslaved to BRIDGE_NAME" | `apply.sh` 58 | F02853 | non-negotiable | false | 10 |
| R05641 | apply.sh `ip link set "$iface" master "$BRIDGE_NAME"` | `apply.sh` 60 | F02854 | non-negotiable | false | 10 |
| R05642 | apply.sh brings up member if !link_up | `apply.sh` 63–66 | F02855 | non-negotiable | false | 10 |
| R05643 | apply.sh `ip link set "$iface" up` | `apply.sh` 64 | F02856 | non-negotiable | false | 10 |
| R05644 | apply.sh brings up bridge if !link_up | `apply.sh` 69–72 | F02857 | non-negotiable | false | 10 |
| R05645 | apply.sh TEMPLATE path = $TEMPLATE_DIR/nftables.conf.tmpl | `apply.sh` 75 | F02858 | non-negotiable | false | 10 |
| R05646 | apply.sh dies if TEMPLATE missing | `apply.sh` 76 | M00608 | non-negotiable | false | 10 |
| R05647 | apply.sh MGMT_RULE substitution — non-empty mgmt_iface → `iifname "$MGMT_IFACE" ct state new drop` | `apply.sh` 78–79 | F02859 | non-negotiable | false | 10 |
| R05648 | apply.sh MGMT_RULE substitution — empty mgmt_iface → `# (no management_iface configured)` | `apply.sh` 80–82 | F02860 | non-negotiable | false | 10 |
| R05649 | apply.sh renders nftables via mktemp + sed 3-token substitution | `apply.sh` 84–90 | F02861 | non-negotiable | false | 10 |
| R05650 | apply.sh trap cleans mktemp file on EXIT | `apply.sh` 85 | M00608 | non-negotiable | false | 10 |
| R05651 | apply.sh substitutes @@BRIDGE_NAME@@ | `apply.sh` 87 | F02862 | non-negotiable | false | 10 |
| R05652 | apply.sh substitutes @@FORWARD_POLICY@@ | `apply.sh` 88 | F02863 | non-negotiable | false | 10 |
| R05653 | apply.sh substitutes @@MGMT_INPUT_RULE@@ | `apply.sh` 89 | F02864 | non-negotiable | false | 10 |
| R05654 | apply.sh nftables idempotency — cmp -s RENDERED NFT_RULESET_PATH | `apply.sh` 92 | F02865 | non-negotiable | false | 10 |
| R05655 | apply.sh nftables skip log "nftables ruleset already at target state" | `apply.sh` 93 | F02865 | non-negotiable | false | 10 |
| R05656 | apply.sh install — `install -D -m 0644` | `apply.sh` 95 | F02866 | non-negotiable | false | 10 |
| R05657 | apply.sh load — `nft -f $NFT_RULESET_PATH` | `apply.sh` 96 | F02866 | non-negotiable | false | 10 |
| R05658 | apply.sh changes += 2 after nft install + load | `apply.sh` 97 | F02867 | non-negotiable | false | 10 |
| R05659 | apply.sh F-2027-024 manifest record always (even if file at target state) | `apply.sh` 99–104 | F02868 | non-negotiable | false | 10 |
| R05660 | apply.sh F-2027-024 manifest-record-always rationale documented | `apply.sh` 99–103 | F02868 | non-negotiable | false | 10 |
| R05661 | apply.sh finalise — emit_status "skipped" if changes==0 | `apply.sh` 107–108 | F02869 | non-negotiable | false | 10 |
| R05662 | apply.sh finalise — emit_status "ok" applied N change(s) otherwise | `apply.sh` 109–110 | F02870 | non-negotiable | false | 10 |
| R05663 | nft template — `flush ruleset` MUST be first directive | `templates/nftables.conf.tmpl` 9 | F02871 | non-negotiable | false | 10 |
| R05664 | nft template — table inet selfdef_bridge | `templates/nftables.conf.tmpl` 10 | F02872 | non-negotiable | false | 10 |
| R05665 | nft template — forward_hook chain MUST be empty | `templates/nftables.conf.tmpl` 12–14 | F02873 | non-negotiable | false | 10 |
| R05666 | nft template — forward_hook chain is consumer jumps target | `templates/nftables.conf.tmpl` 12–13 | F02873 | non-negotiable | false | 10 |
| R05667 | nft template — "owning module does not know about its consumers" comment | `templates/nftables.conf.tmpl` 13–14 | F02873 | non-negotiable | false | 10 |
| R05668 | nft template — forward chain type filter hook forward priority filter | `templates/nftables.conf.tmpl` 17 | F02874 | non-negotiable | false | 10 |
| R05669 | nft template — forward chain policy @@FORWARD_POLICY@@ | `templates/nftables.conf.tmpl` 17 | F02874 | non-negotiable | false | 10 |
| R05670 | nft template — forward chain iifname @@BRIDGE_NAME@@ jump forward_hook | `templates/nftables.conf.tmpl` 18 | F02875 | non-negotiable | false | 10 |
| R05671 | nft template — forward chain oifname @@BRIDGE_NAME@@ jump forward_hook | `templates/nftables.conf.tmpl` 19 | F02876 | non-negotiable | false | 10 |
| R05672 | nft template — input chain type filter hook input priority filter | `templates/nftables.conf.tmpl` 23 | F02877 | non-negotiable | false | 10 |
| R05673 | nft template — input chain policy accept | `templates/nftables.conf.tmpl` 23 | F02877 | non-negotiable | false | 10 |
| R05674 | nft template — input chain @@MGMT_INPUT_RULE@@ injection point | `templates/nftables.conf.tmpl` 27 | F02878 | non-negotiable | false | 10 |
| R05675 | nft template — output chain type filter hook output priority filter | `templates/nftables.conf.tmpl` 31 | F02879 | non-negotiable | false | 10 |
| R05676 | nft template — output chain policy accept | `templates/nftables.conf.tmpl` 31 | F02879 | non-negotiable | false | 10 |
| R05677 | nft template header — "selfdef bridge-l2 ruleset — managed by selfdefctl modules apply" | `templates/nftables.conf.tmpl` 2 | M00612 | non-negotiable | false | 10 |
| R05678 | nft template header — "Do not hand-edit; changes are clobbered on the next apply" | `templates/nftables.conf.tmpl` 3 | M00612 | non-negotiable | false | 10 |
| R05679 | nft template shebang `#!/usr/sbin/nft -f` | `templates/nftables.conf.tmpl` 1 | M00612 | non-negotiable | false | 10 |
| R05680 | check.sh MUST set -euo pipefail | `install/check.sh` 7 | M00609 | non-negotiable | false | 10 |
| R05681 | check.sh F-2027-027 — DRY_RUN forced 0 (read-only by contract) | `install/check.sh` 10–14 | M00609 | non-negotiable | false | 10 |
| R05682 | check.sh CONFIG_FILE default + SELFDEF_BRIDGE_L2_CONFIG override | `install/check.sh` 15 | M00609 | non-negotiable | false | 10 |
| R05683 | check.sh NFT_RULESET_PATH = /etc/nftables.d/selfdef-bridge.conf | `install/check.sh` 16 | M00609 | non-negotiable | false | 10 |
| R05684 | check.sh sources install/lib.sh | `install/check.sh` 19–20 | M00610 | non-negotiable | false | 10 |
| R05685 | check.sh problems array initial empty | `install/check.sh` 22 | M00609 | non-negotiable | true | 10 |
| R05686 | check.sh probe — config readable; else emit failed + exit 1 | `install/check.sh` 24–27 | M00609 | non-negotiable | false | 10 |
| R05687 | check.sh probe — bridge_name read via toml_get | `install/check.sh` 29 | M00609 | non-negotiable | false | 10 |
| R05688 | check.sh probe — members read via toml_get_list | `install/check.sh` 30 | M00628 | non-negotiable | false | 10 |
| R05689 | check.sh probe — bridge exists via `ip link show dev BRIDGE_NAME type bridge` | `install/check.sh` 33 | M00609 | non-negotiable | false | 10 |
| R05690 | check.sh probe — bridge up via `ip -o link show BRIDGE_NAME | grep state UP` | `install/check.sh` 35 | M00609 | non-negotiable | false | 10 |
| R05691 | check.sh probe — each member enslaved to BRIDGE_NAME | `install/check.sh` 40–45 | M00609 | non-negotiable | false | 10 |
| R05692 | check.sh probe — NFT_RULESET_PATH file readable | `install/check.sh` 49–51 | M00609 | non-negotiable | false | 10 |
| R05693 | check.sh probe — `nft list table inet selfdef_bridge` loaded | `install/check.sh` 54–58 | M00609 | non-negotiable | false | 10 |
| R05694 | check.sh success — emit "ok" "bridge BRIDGE_NAME up; nftables ruleset loaded" + exit 0 | `install/check.sh` 61–63 | M00609 | non-negotiable | false | 10 |
| R05695 | check.sh failure — joined problems with ';' + exit 1 | `install/check.sh` 64–68 | M00609 | non-negotiable | false | 10 |
| R05696 | install/lib.sh — SELFDEF_MODULE_LIB_VERSION_REQUIRED=2 | `install/lib.sh` 14 | M00610 | non-negotiable | false | 10 |
| R05697 | install/lib.sh — F-2027-024 v2 opt-in rationale documented | `install/lib.sh` 8–13 | M00627 | non-negotiable | false | 10 |
| R05698 | install/lib.sh — lookup precedence 1: $SELFDEF_MODULE_LIB env | `install/lib.sh` 22 | M00610 | non-negotiable | false | 10 |
| R05699 | install/lib.sh — lookup precedence 2: workspace-relative packaging/lib/module-lib.sh | `install/lib.sh` 24 | M00610 | non-negotiable | false | 10 |
| R05700 | install/lib.sh — lookup precedence 3: /usr/share/selfdef/lib/module-lib.sh | `install/lib.sh` 26 | M00610 | non-negotiable | false | 10 |
| R05701 | install/lib.sh — toml_get_list module-specific helper | `install/lib.sh` 35–52 | M00628 | non-negotiable | false | 10 |
| R05702 | toml_get_list — reads TOML inline array of strings | `install/lib.sh` 35–36 | M00628 | non-negotiable | false | 10 |
| R05703 | toml_get_list — shared lib's toml_get only reads scalars | `install/lib.sh` 36 | M00628 | non-negotiable | false | 10 |
| R05704 | toml_get_list — returns newline-separated tokens | `install/lib.sh` 37 | M00628 | non-negotiable | false | 10 |
| R05705 | toml_get_list — strips quotes + whitespace | `install/lib.sh` 37 | M00628 | non-negotiable | false | 10 |
| R05706 | toml_get_list — grep `^key=` | `install/lib.sh` 41 | M00628 | non-negotiable | false | 10 |
| R05707 | toml_get_list — strip brackets `[...]` | `install/lib.sh` 45 | M00628 | non-negotiable | false | 10 |
| R05708 | toml_get_list — split on `,` (IFS=,) | `install/lib.sh` 46 | M00628 | non-negotiable | false | 10 |
| R05709 | toml_get_list — strip leading/trailing whitespace | `install/lib.sh` 48 | M00628 | non-negotiable | false | 10 |
| R05710 | toml_get_list — strip leading/trailing quotes | `install/lib.sh` 49 | M00628 | non-negotiable | false | 10 |
| R05711 | uninstall.sh MUST set -euo pipefail | `install/uninstall.sh` 10 | M00611 | non-negotiable | false | 10 |
| R05712 | uninstall.sh MODULE = "bridge-l2" | `install/uninstall.sh` 12 | M00611 | non-negotiable | false | 10 |
| R05713 | uninstall.sh DRY_RUN read from SELFDEF_DRY_RUN env | `install/uninstall.sh` 13 | M00611 | non-negotiable | false | 10 |
| R05714 | uninstall.sh CONFIG_FILE default + override | `install/uninstall.sh` 14 | M00611 | non-negotiable | false | 10 |
| R05715 | uninstall.sh NFT_RULESET_PATH fallback path documented | `install/uninstall.sh` 16–19 | M00611 | non-negotiable | false | 10 |
| R05716 | uninstall.sh log() prefix `[bridge-l2:uninstall]` | `install/uninstall.sh` 30 | M00611 | non-negotiable | false | 10 |
| R05717 | uninstall.sh log() prefix predates SDD-006; preserved | `install/uninstall.sh` 25–27 | M00611 | non-negotiable | false | 10 |
| R05718 | uninstall.sh run() — keeps going past per-step failures | `install/uninstall.sh` 28 + 39 | M00611 | non-negotiable | false | 10 |
| R05719 | uninstall.sh — partial uninstalls tolerable | `install/uninstall.sh` 29 | M00611 | non-negotiable | false | 10 |
| R05720 | uninstall.sh — BRIDGE_NAME default br0 + read from CONFIG_FILE if present | `install/uninstall.sh` 44–47 | M00611 | non-negotiable | false | 10 |
| R05721 | uninstall.sh — delete `inet selfdef_bridge` nft table | `install/uninstall.sh` 50–52 | M00611 | non-negotiable | false | 10 |
| R05722 | uninstall.sh — "don't touch anything outside it" | `install/uninstall.sh` 50 | M00611 | non-negotiable | false | 10 |
| R05723 | uninstall.sh — walk manifest via `module_render_files` | `install/uninstall.sh` 56–62 | M00611 | non-negotiable | false | 10 |
| R05724 | uninstall.sh — manifest_count tracks rows | `install/uninstall.sh` 57 | M00611 | non-negotiable | true | 10 |
| R05725 | uninstall.sh — legacy fallback if manifest_count==0 | `install/uninstall.sh` 66–73 | M00611 | non-negotiable | false | 10 |
| R05726 | uninstall.sh — legacy fallback removes NFT_RULESET_PATH | `install/uninstall.sh` 70 | M00611 | non-negotiable | false | 10 |
| R05727 | uninstall.sh — clears manifest via `module_clear_manifest` | `install/uninstall.sh` 74 | M00611 | non-negotiable | false | 10 |
| R05728 | uninstall.sh — tears down bridge if exists | `install/uninstall.sh` 77 | M00611 | non-negotiable | false | 10 |
| R05729 | uninstall.sh — `ip link set BRIDGE_NAME down` | `install/uninstall.sh` 78 | M00611 | non-negotiable | false | 10 |
| R05730 | uninstall.sh — `ip link delete BRIDGE_NAME type bridge` | `install/uninstall.sh` 79 | M00611 | non-negotiable | false | 10 |
| R05731 | uninstall.sh emits "ok" "uninstalled" | `install/uninstall.sh` 81 | M00611 | non-negotiable | false | 10 |
| R05732 | uninstall.sh — member NICs released to standalone but NOT re-configured | `install/uninstall.sh` 4–5 | M00611 | non-negotiable | false | 10 |
| R05733 | uninstall.sh — operator re-applies previous IP/DHCP setup | `install/uninstall.sh` 5–6 | M00611 | non-negotiable | false | 10 |
| R05734 | uninstall.sh — operator must run from console or management interface | `install/uninstall.sh` 6–7 | M00611 | non-negotiable | false | 10 |
| R05735 | apply.sh — config-read fallback to env if CONFIG_FILE not present | `apply.sh` 8–10 | M00608 | non-negotiable | false | 10 |
| R05736 | apply.sh — rendered by selfdefctl modules apply from defaults + profile + host overrides | `apply.sh` 8–9 | M00608 | non-negotiable | false | 10 |
| R05737 | nftables ruleset stays inside `inet selfdef_bridge` table | `templates/nftables.conf.tmpl` 10 + `install/uninstall.sh` 50 | M00623 | non-negotiable | false | 10 |
| R05738 | nftables hook priority = filter | `templates/nftables.conf.tmpl` 17 + 23 + 31 | M00623 | non-negotiable | false | 10 |
| R05739 | nftables forward_hook chain MUST remain empty in this module | `templates/nftables.conf.tmpl` 12–14 | M00624 | non-negotiable | false | 10 |
| R05740 | nftables hook chain MUST be the public extension point for inline modules | `templates/nftables.conf.tmpl` 12–14 + `README.md` 19–21 | M00624 | non-negotiable | false | 10 |
| R05741 | nftables management-INPUT-drop SHALL apply only when management_iface is set | `apply.sh` 78–82 + `templates/nftables.conf.tmpl` 22–28 | M00626 | non-negotiable | false | 10 |
| R05742 | nftables ruleset SHALL be at `/etc/nftables.d/selfdef-bridge.conf` | `apply.sh` 18 + `install/check.sh` 16 + `install/uninstall.sh` 19 | M00608 | non-negotiable | false | 10 |
| R05743 | apply.sh changes counter increments per state mutation | `apply.sh` 42 + 52 + 61 + 65 + 71 + 97 | M00608 | non-negotiable | true | 10 |
| R05744 | apply.sh emit_status status="ok" message format MUST equal "applied $changes change(s)" | `apply.sh` 110 | F02870 | non-negotiable | false | 10 |
| R05745 | apply.sh emit_status status="skipped" message format MUST equal "already at target state" | `apply.sh` 108 | F02869 | non-negotiable | false | 10 |
| R05746 | nft template substitution token @@BRIDGE_NAME@@ documented | `templates/nftables.conf.tmpl` 5 | M00612 | non-negotiable | false | 10 |
| R05747 | nft template substitution token @@MGMT_IFACE@@ documented (note: actual substitution is @@MGMT_INPUT_RULE@@) | `templates/nftables.conf.tmpl` 6 + `apply.sh` 89 | M00612 | non-negotiable | false | 10 |
| R05748 | nft template substitution token @@FORWARD_POLICY@@ documented | `templates/nftables.conf.tmpl` 7 | M00612 | non-negotiable | false | 10 |
| R05749 | nft template management comment — outbound-only sessions survive established/related | `templates/nftables.conf.tmpl` 24–26 | M00626 | non-negotiable | false | 10 |
| R05750 | install/lib.sh required caller variable — MODULE | `install/lib.sh` 5 | M00610 | non-negotiable | false | 10 |
| R05751 | install/lib.sh required caller variable — DRY_RUN | `install/lib.sh` 6 | M00610 | non-negotiable | false | 10 |
| R05752 | install/lib.sh required caller variable — CONFIG_FILE | `install/lib.sh` 7 | M00610 | non-negotiable | false | 10 |
| R05753 | install/lib.sh shared helpers — log / emit_status / die / run / toml_get | `install/lib.sh` 1–3 | M00610 | non-negotiable | false | 10 |
| R05754 | apply.sh — bridge_exists helper SHALL detect via type=bridge filter | `apply.sh` 44 | M00620 | non-negotiable | false | 10 |
| R05755 | apply.sh — member_of helper SHALL parse master via awk | `apply.sh` 45 | M00621 | non-negotiable | false | 10 |
| R05756 | apply.sh — link_up helper SHALL detect "state UP" | `apply.sh` 46 | M00622 | non-negotiable | false | 10 |
| R05757 | apply.sh — increments changes counter for each enslave operation | `apply.sh` 61 | M00608 | non-negotiable | true | 10 |
| R05758 | apply.sh — increments changes counter for each member up operation | `apply.sh` 65 | M00608 | non-negotiable | true | 10 |
| R05759 | apply.sh — increments changes counter for bridge-up operation | `apply.sh` 71 | M00608 | non-negotiable | true | 10 |
| R05760 | Composite — MS024 (10 epics / 26 modules / 120 features / 240 reqs) covers bridge-l2 module v0.1.0 (477 lines): module.toml (5-block manifest with 5-item requires including 2 kernel-features) + README.md (69-line foundation-module doc) + config/defaults.toml (7 keys) + 2 profiles (passthrough/opnsense-edge) + apply.sh (111-line idempotent applier with 3 bridge helpers) + check.sh (70-line side-effect-free 5-probe verifier) + lib.sh (52-line v2 opt-in + toml_get_list module-specific helper) + uninstall.sh (81-line manifest-walked tear-down) + nftables.conf.tmpl (34-line table inet selfdef_bridge with 4 chains forward_hook+forward+input+output); 2 surfaces (l2-bridge + forward-policy); foundation for MS023 polarproxy bridge-tap + future suricata + NFQUEUE inline modules; "owning module does not know about its consumers"; F-2027-024 manifest integration + F-2027-027 DRY_RUN-forced-0 | `modules/bridge-l2/` 477 lines | E0241 + E0242 + E0243 + E0244 + E0245 + E0246 + E0247 + E0248 + E0249 + E0250 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module identity (R05521–R05545) + foundation + 4 actions (R05546–R05563) + 2 profiles (R05564–R05572) + config schema (R05573–R05580) + defaults.toml (R05581–R05588) + 2 profile files (R05589–R05597) + idempotency + dry-run + caveats (R05598–R05607) + apply.sh full transcription (R05608–R05662) + nftables template full transcription (R05663–R05679) + check.sh full transcription (R05680–R05695) + lib.sh + toml_get_list (R05696–R05710) + uninstall.sh full transcription (R05711–R05734) + cross-file invariants (R05735–R05759) + composite (R05760)
- Source range 477 lines yields 240 R-rows representing ~50% line-coverage at the verbatim-citation level
- Project boundary — MS024 is selfdef IPS module scope; provides the L2 bridge surface for MS023 polarproxy bridge-tap profile + future MS027 suricata module
- F-2027-024 + F-2027-027 references — finding numbers from selfdef SDD ledger (MS013 27-SDD charter) for manifest-helper opt-in + DRY_RUN-forced-zero respectively

## Cross-references

- Adjacent INDEX rows: MS023 polarproxy (bridge-tap profile consumes bridge-l2 + verifies `nft list table inet selfdef_bridge`) / MS025 Detect-host module
- Foundation role — MS024 is the "foundation module" — MS023 polarproxy bridge-tap profile, future MS027 suricata, future NFQUEUE-attached modules all consume the `l2-bridge` + `forward-policy` surfaces
- Surface integration — `l2-bridge` provides Linux bridge for Suricata AF_PACKET/NFQUEUE; `forward-policy` provides forward_hook chain as extension point ("owning module does not know about its consumers")
- Module-system integration — MS024 follows standard `module.toml` + apply/check/uninstall shape codified by MS006 module fabric + MS021 shared module-script lib v2
- Test integration — MS020 L1-L5 layered harness covers Module-script test category (Category 3 of 4) which MS024 apply/check/uninstall scripts SHALL exercise
- Audit integration — F-2027-024 manifest-helper opt-in derives from MS013 27-SDD charter findings ledger
- Cross-repo binding — sovereign-os has no bridge-l2 equivalent (host-defense L2 surface is IPS-only); cross-repo audit (if needed) routes through MS007 audit-manifest typed-mirror crate
- Operator references: nftables(8) inet/forward/input/output hooks + filter priority + ip-link(8) `type bridge` + `master` + AF_PACKET dummy-netdev guide + Linux kernel CONFIG_BRIDGE + CONFIG_NF_TABLES docs
