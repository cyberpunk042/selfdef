# MS043 — IPS operator surface — CLI + TUI + dashboard-mirror exports

**Parent**: selfdef IPS daemon — boundary-enforcement layer of the cyberpunk042 ecosystem
**Source**: `~/infohub/raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md`
- line 581 ("Fullstack matters only at the edges: dashboards, APIs, orchestration UI")
- lines 3290-3325 (Dashboard Philosophy — 9 operational questions, "A dashboard should not show vanity graphs")
- lines 15625-15665 (local dashboard / CLI / API / IDE clients catalog)
- lines 16440-16466 (Phase 10 Full Cockpit — 11 UI surfaces)
- lines 14760-14780 (Configuration Surfaces — three operator levels)
**Operator standing direction** (verbatim, 2026-05-19): *"Do not minimize the work in selfdef"* / *"if I talk about an IPS feature its obviously not in Sovereign-OS"* / *"I expect dashboards and a good UX... over 20 dashboards and a main one and everything can be turned on and off"*
**Cross-repo mirror**: sovereign-os M060 — cockpit consumes selfdef dashboard-ready state through MS007 typed-mirror crates (D-12..D-18); this milestone is the SELFDEF-OWNED operator-facing surface (standalone — must work even when sovereign-os is offline)
**Project boundary**: this milestone catalogs ONLY the selfdef IPS-side operator surface (CLI + TUI + minimal local web + dashboard-mirror exports); sovereign-os runtime cockpit lives in M060

## Doctrinal anchors

> "A dashboard should not show vanity graphs." (dump 3299)
> "Fullstack matters only at the edges: dashboards, APIs, orchestration UI." (dump 581)
> "Do not minimize the work in selfdef" (operator standing direction, 2026-05-19)

## Projection statement

The selfdef IPS daemon **must be operable standalone** — selfdef is the boundary-enforcement organ that protects host integrity even when sovereign-os runtime is offline / unhealthy / rebuilding. Selfdef therefore has its OWN three-tier operator surface (CLI + TUI terminal dashboard + minimal local web fallback), plus a MS007-exported dashboard-ready state that sovereign-os M060 D-12..D-18 dashboards consume read-only. The IPS-side surface emphasizes: rules / grants / capability registry / quarantine / audit-cycle status / authority FSM state / profile envelope. NEVER mutates sovereign-os state.

## Epics (E0431-E0440)

| epic | name | source |
|---|---|---|
| E0431 | Selfdef CLI surface — `selfdef` command tree (status / rules / grants / quarantine / audit / profile / cap / sandbox / fs / net / signing-keys / replay) | dump 15634-15640 + operator standing direction |
| E0432 | Selfdef TUI dashboard — terminal-based main dashboard (curses/ratatui-style) for standalone operator use when no GUI present | operator standing direction "Do not minimize the work in selfdef" |
| E0433 | Selfdef minimal local web — bootstrap-only HTTPS dashboard reachable on localhost:7575 (fallback when TUI unavailable) | dump 15625-15665 + operator standing direction |
| E0434 | Selfdef dashboard-mirror exports — MS007 typed-mirror crates publishing dashboard-ready state (D-12..D-18 source) | cross-ref MS007 |
| E0435 | Selfdef operator config surface — three operator levels (User / Power user / System) for IPS-side toggles | dump 14760-14780 + operator standing direction |
| E0436 | Selfdef CLI authentication — operator key (MS003) required for any mutation; read-only ops allowed without auth | cross-ref MS003 + operator standing direction |
| E0437 | Selfdef offline survivability — every operator surface works without sovereign-os runtime present | operator standing direction "Respect the projects" |
| E0438 | Selfdef incident-response shortcuts — single-key actions for break-glass scenarios (drop-all-grants / kill-quarantine / freeze-profile) | dump 16450 + operator standing direction |
| E0439 | Selfdef observability surface — logs / OCSF events / M049 traces accessible from CLI + TUI | cross-ref MS026 + M049 |
| E0440 | Selfdef UX coherence — keyboard-first interaction, no mouse-required paths, WCAG 2.1 AA where rendering applies | operator standing direction |

## Modules (M01097-M01122)

| module | name | source |
|---|---|---|
| M01097 | selfdef-cli-binary | dump 15634-15640 |
| M01098 | selfdef-cli-status-subcommand | architecture + dump 15634 |
| M01099 | selfdef-cli-rules-subcommand | architecture + cross-ref MS024 + MS038 |
| M01100 | selfdef-cli-grants-subcommand | cross-ref MS035 + MS037 + MS038 |
| M01101 | selfdef-cli-quarantine-subcommand | cross-ref MS042 |
| M01102 | selfdef-cli-audit-subcommand | cross-ref MS009 |
| M01103 | selfdef-cli-profile-subcommand | cross-ref MS040 |
| M01104 | selfdef-cli-cap-subcommand | cross-ref MS035 |
| M01105 | selfdef-cli-sandbox-subcommand | cross-ref MS036 |
| M01106 | selfdef-cli-fs-subcommand | cross-ref MS037 |
| M01107 | selfdef-cli-net-subcommand | cross-ref MS038 |
| M01108 | selfdef-cli-signing-keys-subcommand | cross-ref MS003 |
| M01109 | selfdef-cli-replay-subcommand | cross-ref MS009 |
| M01110 | selfdef-tui-dashboard | operator standing direction |
| M01111 | selfdef-tui-rules-panel | cross-ref MS024 + MS038 |
| M01112 | selfdef-tui-grants-panel | cross-ref MS035 + MS037 + MS038 |
| M01113 | selfdef-tui-quarantine-panel | cross-ref MS042 |
| M01114 | selfdef-tui-audit-panel | cross-ref MS009 |
| M01115 | selfdef-tui-authority-panel | cross-ref MS039 + MS040 |
| M01116 | selfdef-minimal-web-server | dump 15625-15665 + architecture |
| M01117 | selfdef-dashboard-mirror-publisher | cross-ref MS007 |
| M01118 | selfdef-operator-config-loader | dump 14760-14780 + architecture |
| M01119 | selfdef-operator-auth-gate | cross-ref MS003 |
| M01120 | selfdef-incident-response-shortcuts | operator standing direction + dump 16450 |
| M01121 | selfdef-observability-surface-bridge | cross-ref MS026 + M049 |
| M01122 | selfdef-ux-coherence-engine | operator standing direction |

## Features (F05041-F05160)

| feature | name | source |
|---|---|---|
| F05041 | CLI — `selfdef status` shows daemon health + ring summary + profile + signature | architecture + dump 15634 |
| F05042 | CLI — `selfdef status --json` returns structured output | architecture |
| F05043 | CLI — `selfdef status --watch` streams updates | architecture |
| F05044 | CLI — `selfdef rules list` lists active nftables rules | cross-ref MS024 + MS038 |
| F05045 | CLI — `selfdef rules show <rule-id>` shows rule detail + provenance | cross-ref MS024 |
| F05046 | CLI — `selfdef rules diff` shows pending vs active | cross-ref MS039 (L3 Prepare staging) |
| F05047 | CLI — `selfdef rules apply <rule-id>` applies staged rule (operator-signed) | cross-ref MS039 + MS003 |
| F05048 | CLI — `selfdef rules revert <rule-id>` reverts applied rule | cross-ref MS041 |
| F05049 | CLI — `selfdef grants list` lists active grants (filesystem + network + capability) | cross-ref MS035 + MS037 + MS038 |
| F05050 | CLI — `selfdef grants show <grant-id>` shows grant detail | cross-ref MS035 |
| F05051 | CLI — `selfdef grants revoke <grant-id>` revokes grant (operator-signed) | cross-ref MS035 + MS003 |
| F05052 | CLI — `selfdef grants extend <grant-id> --ttl <seconds>` extends TTL (operator-signed) | cross-ref MS038 + MS003 |
| F05053 | CLI — `selfdef quarantine list` lists quarantined tools | cross-ref MS042 |
| F05054 | CLI — `selfdef quarantine show <quarantine-id>` shows quarantine detail | cross-ref MS042 |
| F05055 | CLI — `selfdef quarantine restore <quarantine-id>` restores false-positive (operator-signed) | cross-ref MS042 + MS003 |
| F05056 | CLI — `selfdef quarantine purge` purges old quarantines beyond retention | cross-ref MS037 |
| F05057 | CLI — `selfdef audit cycle` runs MS009 audit cycle now | cross-ref MS009 |
| F05058 | CLI — `selfdef audit status` shows last audit cycle results | cross-ref MS009 |
| F05059 | CLI — `selfdef audit chain` verifies signing chain end-to-end | cross-ref MS003 + MS009 |
| F05060 | CLI — `selfdef profile show` shows active profile + envelope | cross-ref MS040 |
| F05061 | CLI — `selfdef profile set <name>` switches active profile (operator-signed) | cross-ref MS040 + MS003 |
| F05062 | CLI — `selfdef profile gates list` shows predeclared gates (autonomous only) | cross-ref MS040 |
| F05063 | CLI — `selfdef cap list` lists active capability tokens | cross-ref MS035 |
| F05064 | CLI — `selfdef cap mint --scope <scope>` mints capability token (operator-signed) | cross-ref MS035 + MS003 |
| F05065 | CLI — `selfdef cap revoke <cap-id>` revokes capability token | cross-ref MS035 + MS003 |
| F05066 | CLI — `selfdef sandbox list` lists active sandbox allocations | cross-ref MS036 |
| F05067 | CLI — `selfdef sandbox tier <id>` shows sandbox tier (A/B/C/D) | cross-ref MS036 |
| F05068 | CLI — `selfdef sandbox kill <id>` kills sandbox (operator-signed) | cross-ref MS036 + MS003 |
| F05069 | CLI — `selfdef fs grants` lists active filesystem grants | cross-ref MS037 |
| F05070 | CLI — `selfdef fs deny <path>` adds path to deny-list (operator-signed) | cross-ref MS037 + MS003 |
| F05071 | CLI — `selfdef net grants` lists active network grants | cross-ref MS038 |
| F05072 | CLI — `selfdef net allow <fqdn> --profile <name>` allows FQDN for profile | cross-ref MS038 + MS003 |
| F05073 | CLI — `selfdef signing-keys list` lists registered MS003 keys | cross-ref MS003 |
| F05074 | CLI — `selfdef signing-keys rotate` rotates operator key (high-risk gated) | cross-ref MS003 + MS041 |
| F05075 | CLI — `selfdef replay verify` runs MS009 replay validator now | cross-ref MS009 |
| F05076 | CLI — every command emits M049 trace + OCSF event | cross-ref M049 + MS026 |
| F05077 | CLI — every mutating command requires operator MS003 signature | cross-ref MS003 |
| F05078 | CLI — read-only commands allowed without operator signature | architecture |
| F05079 | CLI — `--watch` flag streams updates for any list command | architecture |
| F05080 | CLI — `--json` flag returns structured output for any command | architecture |
| F05081 | TUI — main dashboard layout = 4 panels (rules / grants / quarantine / authority) | operator standing direction |
| F05082 | TUI — rules panel shows rule count by ring + recent applies | cross-ref MS024 + MS039 |
| F05083 | TUI — grants panel shows grant count by type + TTL expiry timeline | cross-ref MS035 + MS037 + MS038 |
| F05084 | TUI — quarantine panel shows quarantine count + recent quarantines | cross-ref MS042 |
| F05085 | TUI — authority panel shows current profile envelope L0..L6 + Ring 0..4 | cross-ref MS039 + MS040 |
| F05086 | TUI — keyboard shortcuts (j/k navigation, Enter to drill, q to quit) | operator standing direction |
| F05087 | TUI — single-key incident-response shortcuts (P=panic-drop-all, F=freeze-profile) | operator standing direction + dump 16450 |
| F05088 | TUI — color scheme: terminal-default + colorblind-safe palette | operator standing direction |
| F05089 | TUI — focus indicators visible (bold + inverted selection) | operator standing direction |
| F05090 | TUI — accessibility: full keyboard navigation, no mouse required | operator standing direction |
| F05091 | TUI — startup time `<` 100ms (no animations on entry) | architecture |
| F05092 | TUI — exits cleanly on SIGTERM / SIGINT preserving cursor state | architecture |
| F05093 | Minimal web — HTTPS server on localhost:7575 (fallback when TUI unavailable) | dump 15625-15665 + architecture |
| F05094 | Minimal web — TLS cert via selfdef MS003 self-signed (operator-pinned) | cross-ref MS003 |
| F05095 | Minimal web — single-page interface, no JS frameworks (vanilla HTML + minimal JS) | operator standing direction |
| F05096 | Minimal web — same 4-panel layout as TUI | architecture + operator standing direction |
| F05097 | Minimal web — operator MS003 key required for any mutation | cross-ref MS003 |
| F05098 | Minimal web — read-only views accessible without operator key | architecture |
| F05099 | Minimal web — auto-refreshes every 2s via SSE | architecture |
| F05100 | Minimal web — accessible via Cmd-1..Cmd-4 keyboard shortcuts mapping to panels | operator standing direction |
| F05101 | Minimal web — WCAG 2.1 AA contrast (4.5:1 minimum) | operator standing direction |
| F05102 | Minimal web — dark mode + light mode + auto-from-system | operator standing direction |
| F05103 | Minimal web — destructive actions confirmation dialog (rollback / kill / revoke) | operator standing direction |
| F05104 | Minimal web — never reachable on LAN by default (localhost-only) | architecture + operator standing direction |
| F05105 | Mirror exports — selfdef-rules-mirror (D-12 networking source) | cross-ref MS007 + MS024 + MS038 |
| F05106 | Mirror exports — selfdef-grants-mirror (D-13 filesystem source) | cross-ref MS007 + MS037 |
| F05107 | Mirror exports — selfdef-capability-mirror (D-14 cap-token source) | cross-ref MS007 + MS035 |
| F05108 | Mirror exports — selfdef-sandbox-mirror (D-15 sandbox source) | cross-ref MS007 + MS036 |
| F05109 | Mirror exports — selfdef-audit-mirror (D-16 audit cycle source) | cross-ref MS007 + MS009 |
| F05110 | Mirror exports — selfdef-quarantine-mirror (D-17 quarantine source) | cross-ref MS007 + MS042 |
| F05111 | Mirror exports — selfdef-trust-score-mirror (D-18 trust score source) | cross-ref MS007 + MS042 |
| F05112 | Mirror exports — all mirror crates published under MS007 8/8 SATURATED scheme | cross-ref MS007 |
| F05113 | Mirror exports — all mirror crates signed via MS003 | cross-ref MS003 + MS007 |
| F05114 | Mirror exports — all mirror crates schema_version "1.0.0" | cross-ref MS007 |
| F05115 | Mirror exports — all mirror crates re-exported via sovereign-os cargo workspace | cross-ref MS007 |
| F05116 | Mirror exports — mirror crates expose state read-only (no mutation interface) | cross-ref MS007 + operator standing direction |
| F05117 | Operator config — User level: simple profile selection + prompts | dump 14760-14780 |
| F05118 | Operator config — Power-user level: per-profile toggle for each MS034-MS042 boundary | dump 14760-14780 + operator standing direction |
| F05119 | Operator config — System level: deep policy + chain-of-trust roots + replay validator schedule | dump 14760-14780 |
| F05120 | Operator config — every toggle persisted under /etc/selfdef/operator.toml | architecture |
| F05121 | Operator config — toggle changes signed via MS003 | cross-ref MS003 |
| F05122 | Operator config — toggle changes emit M049 trace + OCSF Configuration Change class 5001 | cross-ref M049 + MS026 |
| F05123 | Operator config — toggle changes retained 365 days with prior versions accessible | architecture |
| F05124 | Operator auth — CLI mutations require operator-signed request | cross-ref MS003 |
| F05125 | Operator auth — TUI mutations require operator-signed request (via signing-key helper) | cross-ref MS003 |
| F05126 | Operator auth — minimal-web mutations require operator key upload | cross-ref MS003 |
| F05127 | Operator auth — operator key derived from hardware token (YubiKey / TPM / smartcard) when configured | architecture + cross-ref MS003 |
| F05128 | Operator auth — read-only ops allowed without authentication (D-12..D-18 mirror exports + read-only TUI panels) | architecture |
| F05129 | Operator auth — authentication failures emit OCSF Audit Activity class 1003 | cross-ref MS026 |
| F05130 | Offline survivability — selfdef daemon runs without sovereign-os | operator standing direction "Respect the projects" |
| F05131 | Offline survivability — selfdef CLI works without sovereign-os | operator standing direction |
| F05132 | Offline survivability — selfdef TUI works without sovereign-os | operator standing direction |
| F05133 | Offline survivability — selfdef minimal-web works without sovereign-os | operator standing direction |
| F05134 | Offline survivability — selfdef mirror exports remain published even if sovereign-os consumer is offline | cross-ref MS007 + operator standing direction |
| F05135 | Offline survivability — selfdef audit replay validator runs independently | cross-ref MS009 |
| F05136 | Offline survivability — selfdef writes its own logs to /var/log/selfdef/ regardless of M049 reachability | cross-ref M049 + architecture |
| F05137 | Incident response — single-key "panic drop all grants" (operator key required) | dump 16450 + operator standing direction |
| F05138 | Incident response — single-key "freeze profile" (lock active profile against transitions) | cross-ref MS040 + operator standing direction |
| F05139 | Incident response — single-key "kill all quarantined tools" + force quarantine | cross-ref MS042 |
| F05140 | Incident response — single-key "rotate operator key" (emergency rotation) | cross-ref MS003 |
| F05141 | Incident response — every break-glass action emits OCSF Detection Finding class 2004 | cross-ref MS026 |
| F05142 | Incident response — every break-glass action signed via MS003 | cross-ref MS003 |
| F05143 | Incident response — break-glass actions logged separately at /var/log/selfdef/break-glass/ | architecture |
| F05144 | Observability bridge — `selfdef logs` tails recent log lines | cross-ref MS026 |
| F05145 | Observability bridge — `selfdef events` streams OCSF events live | cross-ref MS026 |
| F05146 | Observability bridge — `selfdef trace <trace-id>` shows M049 span detail | cross-ref M049 |
| F05147 | Observability bridge — TUI footer shows last 3 OCSF events | cross-ref MS026 |
| F05148 | Observability bridge — minimal-web mirrors observability views via SSE | cross-ref MS026 + cross-ref M049 |
| F05149 | UX coherence — every key combination documented at `selfdef help` | architecture |
| F05150 | UX coherence — every action surfaceable via keyboard | operator standing direction |
| F05151 | UX coherence — destructive actions require confirmation (--yes flag in CLI, dialog in TUI/web) | operator standing direction |
| F05152 | UX coherence — undo available where reversible (cap-mint can be revoked) | operator standing direction |
| F05153 | UX coherence — error states show root-cause + recovery action | operator standing direction + cross-ref M055 |
| F05154 | UX coherence — empty states show next-action hint | operator standing direction |
| F05155 | UX coherence — long operations show progress + ETA + cancel option | operator standing direction |
| F05156 | UX coherence — color contrast 4.5:1 minimum where rendering applies | operator standing direction + WCAG 2.1 |
| F05157 | UX coherence — focus indicators always visible | operator standing direction + WCAG 2.1 |
| F05158 | UX coherence — keyboard shortcut palette accessible via `?` in TUI | operator standing direction |
| F05159 | UX coherence — minimal-web supports keyboard navigation (Tab, arrow keys, Enter, Esc) | operator standing direction + WCAG 2.1 |
| F05160 | UX coherence — operator can disable any non-essential surface (dashboard / minimal-web / TUI) | operator standing direction "everything can be turned on and off" |

## Requirements (R10081-R10320)

| req | description | source | feature | priority | exception | sub-reqs |
|---|---|---|---|---|---|---|
| R10081 | Doctrinal — "Do not minimize the work in selfdef" | operator standing direction 2026-05-19 | F05081 | non-negotiable | false | 10 |
| R10082 | Doctrinal — "if I talk about an IPS feature its obviously not in Sovereign-OS" | operator standing direction | F05130 | non-negotiable | false | 10 |
| R10083 | Doctrinal — selfdef has its OWN operator surface independent of sovereign-os | operator standing direction | F05130 | non-negotiable | false | 10 |
| R10084 | Doctrinal — selfdef surface works when sovereign-os is offline | operator standing direction | F05130 | non-negotiable | false | 10 |
| R10085 | Doctrinal — every dashboard answers operational questions, not vanity graphs | dump 3299 | F05081 | non-negotiable | false | 10 |
| R10086 | Doctrinal — fullstack at edges (dashboards / APIs / orchestration UI) | dump 581 | F05081 | non-negotiable | false | 10 |
| R10087 | CLI — binary name `selfdef` installed at /usr/bin/selfdef | architecture | F05041 | non-negotiable | false | 10 |
| R10088 | CLI — binary signed via MS003 selfdef-signing | cross-ref MS003 | F05077 | non-negotiable | false | 10 |
| R10089 | CLI — every subcommand emits M049 trace span | cross-ref M049 | F05076 | non-negotiable | false | 10 |
| R10090 | CLI — every mutating subcommand emits OCSF Configuration Change class 5001 | cross-ref MS026 | F05076 | non-negotiable | false | 10 |
| R10091 | CLI — every read-only subcommand emits OCSF System Activity class 1001 | cross-ref MS026 | F05076 | non-negotiable | false | 10 |
| R10092 | CLI — `selfdef status` shows daemon health | architecture | F05041 | non-negotiable | false | 10 |
| R10093 | CLI — `selfdef status` shows ring summary (count per Ring 0..4) | cross-ref MS039 | F05041 | non-negotiable | false | 10 |
| R10094 | CLI — `selfdef status` shows active profile name | cross-ref MS040 | F05041 | non-negotiable | false | 10 |
| R10095 | CLI — `selfdef status` shows MS003 chain-of-trust signature | cross-ref MS003 | F05041 | non-negotiable | false | 10 |
| R10096 | CLI — `selfdef status --json` returns structured JSON | architecture | F05042 | non-negotiable | false | 10 |
| R10097 | CLI — `selfdef status --watch` streams updates | architecture | F05043 | non-negotiable | false | 10 |
| R10098 | CLI — `selfdef rules list` lists active nftables rules | cross-ref MS024 + MS038 | F05044 | non-negotiable | false | 10 |
| R10099 | CLI — `selfdef rules show <id>` shows rule detail + provenance | cross-ref MS024 | F05045 | non-negotiable | false | 10 |
| R10100 | CLI — `selfdef rules diff` shows pending vs active rules | cross-ref MS039 | F05046 | non-negotiable | false | 10 |
| R10101 | CLI — `selfdef rules apply <id>` applies staged rule (operator-signed) | cross-ref MS039 + MS003 | F05047 | non-negotiable | false | 10 |
| R10102 | CLI — `selfdef rules revert <id>` reverts applied rule | cross-ref MS041 | F05048 | non-negotiable | false | 10 |
| R10103 | CLI — `selfdef grants list` lists active grants across boundaries | cross-ref MS035 + MS037 + MS038 | F05049 | non-negotiable | false | 10 |
| R10104 | CLI — `selfdef grants show <id>` shows grant detail | cross-ref MS035 | F05050 | non-negotiable | false | 10 |
| R10105 | CLI — `selfdef grants revoke <id>` revokes grant (operator-signed) | cross-ref MS035 + MS003 | F05051 | non-negotiable | false | 10 |
| R10106 | CLI — `selfdef grants extend <id> --ttl <sec>` extends TTL (operator-signed) | cross-ref MS038 + MS003 | F05052 | non-negotiable | false | 10 |
| R10107 | CLI — `selfdef quarantine list` lists quarantined tools | cross-ref MS042 | F05053 | non-negotiable | false | 10 |
| R10108 | CLI — `selfdef quarantine show <id>` shows quarantine detail | cross-ref MS042 | F05054 | non-negotiable | false | 10 |
| R10109 | CLI — `selfdef quarantine restore <id>` restores false-positive | cross-ref MS042 + MS003 | F05055 | non-negotiable | false | 10 |
| R10110 | CLI — `selfdef quarantine purge` purges old quarantines | cross-ref MS037 | F05056 | non-negotiable | false | 10 |
| R10111 | CLI — `selfdef audit cycle` runs MS009 audit cycle | cross-ref MS009 | F05057 | non-negotiable | false | 10 |
| R10112 | CLI — `selfdef audit status` shows last results | cross-ref MS009 | F05058 | non-negotiable | false | 10 |
| R10113 | CLI — `selfdef audit chain` verifies signing chain | cross-ref MS003 + MS009 | F05059 | non-negotiable | false | 10 |
| R10114 | CLI — `selfdef profile show` shows active profile + envelope | cross-ref MS040 | F05060 | non-negotiable | false | 10 |
| R10115 | CLI — `selfdef profile set <name>` switches profile (operator-signed) | cross-ref MS040 + MS003 | F05061 | non-negotiable | false | 10 |
| R10116 | CLI — `selfdef profile gates list` shows predeclared gates (autonomous only) | cross-ref MS040 | F05062 | non-negotiable | false | 10 |
| R10117 | CLI — `selfdef cap list` lists active capability tokens | cross-ref MS035 | F05063 | non-negotiable | false | 10 |
| R10118 | CLI — `selfdef cap mint --scope <s>` mints capability (operator-signed) | cross-ref MS035 + MS003 | F05064 | non-negotiable | false | 10 |
| R10119 | CLI — `selfdef cap revoke <id>` revokes capability | cross-ref MS035 + MS003 | F05065 | non-negotiable | false | 10 |
| R10120 | CLI — `selfdef sandbox list` lists active sandboxes | cross-ref MS036 | F05066 | non-negotiable | false | 10 |
| R10121 | CLI — `selfdef sandbox tier <id>` shows sandbox tier | cross-ref MS036 | F05067 | non-negotiable | false | 10 |
| R10122 | CLI — `selfdef sandbox kill <id>` kills sandbox (operator-signed) | cross-ref MS036 + MS003 | F05068 | non-negotiable | false | 10 |
| R10123 | CLI — `selfdef fs grants` lists filesystem grants | cross-ref MS037 | F05069 | non-negotiable | false | 10 |
| R10124 | CLI — `selfdef fs deny <path>` adds path to deny-list | cross-ref MS037 + MS003 | F05070 | non-negotiable | false | 10 |
| R10125 | CLI — `selfdef net grants` lists network grants | cross-ref MS038 | F05071 | non-negotiable | false | 10 |
| R10126 | CLI — `selfdef net allow <fqdn> --profile <name>` allows FQDN | cross-ref MS038 + MS003 | F05072 | non-negotiable | false | 10 |
| R10127 | CLI — `selfdef signing-keys list` lists MS003 keys | cross-ref MS003 | F05073 | non-negotiable | false | 10 |
| R10128 | CLI — `selfdef signing-keys rotate` rotates operator key (high-risk gated) | cross-ref MS003 + MS041 | F05074 | non-negotiable | false | 10 |
| R10129 | CLI — `selfdef replay verify` runs MS009 replay validator | cross-ref MS009 | F05075 | non-negotiable | false | 10 |
| R10130 | CLI — `--watch` flag available for all list subcommands | architecture | F05079 | non-negotiable | false | 10 |
| R10131 | CLI — `--json` flag available for all subcommands | architecture | F05080 | non-negotiable | false | 10 |
| R10132 | CLI — read-only ops do not require operator signature | architecture | F05078 | non-negotiable | false | 10 |
| R10133 | CLI — mutating ops require operator signature OR --confirm with operator key | cross-ref MS003 | F05077 | non-negotiable | false | 10 |
| R10134 | CLI — bash + fish + zsh completions installed by package | architecture | F05041 | non-negotiable | false | 10 |
| R10135 | CLI — every subcommand documented at `selfdef help <subcommand>` | architecture | F05149 | non-negotiable | false | 10 |
| R10136 | CLI — `selfdef --version` prints version + MS003 signature digest | architecture + cross-ref MS003 | F05041 | non-negotiable | false | 10 |
| R10137 | CLI — startup time `<` 50ms p95 | architecture | F05041 | non-negotiable | false | 10 |
| R10138 | CLI — graceful handling of CTRL-C (no orphan child processes) | architecture | F05041 | non-negotiable | false | 10 |
| R10139 | CLI — exit codes follow sysexits.h (0 OK, 64 usage, 66 input, 77 perm denied) | architecture | F05041 | non-negotiable | false | 10 |
| R10140 | TUI — binary entry: `selfdef tui` launches main dashboard | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10141 | TUI — 4-panel layout (rules / grants / quarantine / authority) | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10142 | TUI — rules panel shows rule count per ring | cross-ref MS024 + MS039 | F05082 | non-negotiable | false | 10 |
| R10143 | TUI — rules panel shows recent applies (last 10) | cross-ref MS024 | F05082 | non-negotiable | false | 10 |
| R10144 | TUI — grants panel shows grant count by type | cross-ref MS035 + MS037 + MS038 | F05083 | non-negotiable | false | 10 |
| R10145 | TUI — grants panel shows TTL expiry timeline | cross-ref MS038 | F05083 | non-negotiable | false | 10 |
| R10146 | TUI — quarantine panel shows quarantine count | cross-ref MS042 | F05084 | non-negotiable | false | 10 |
| R10147 | TUI — quarantine panel shows recent quarantines (last 5) | cross-ref MS042 | F05084 | non-negotiable | false | 10 |
| R10148 | TUI — authority panel shows L0..L6 envelope | cross-ref MS039 + MS040 | F05085 | non-negotiable | false | 10 |
| R10149 | TUI — authority panel shows Ring 0..4 | cross-ref MS039 + MS040 | F05085 | non-negotiable | false | 10 |
| R10150 | TUI — keyboard navigation: j/k between rows, h/l between panels | operator standing direction | F05086 | non-negotiable | false | 10 |
| R10151 | TUI — Enter drills into selected item | operator standing direction | F05086 | non-negotiable | false | 10 |
| R10152 | TUI — q exits to shell | operator standing direction | F05086 | non-negotiable | false | 10 |
| R10153 | TUI — ? opens shortcut palette | operator standing direction | F05158 | non-negotiable | false | 10 |
| R10154 | TUI — P (capital) triggers panic-drop-all-grants (operator-key required) | dump 16450 + operator standing direction | F05137 | non-negotiable | false | 10 |
| R10155 | TUI — F (capital) freezes active profile (operator-key required) | cross-ref MS040 | F05138 | non-negotiable | false | 10 |
| R10156 | TUI — terminal-default color scheme + colorblind-safe palette | operator standing direction | F05088 | non-negotiable | false | 10 |
| R10157 | TUI — focus indicator: bold + inverted selection | operator standing direction | F05089 | non-negotiable | false | 10 |
| R10158 | TUI — no mouse required (full keyboard navigation) | operator standing direction + WCAG 2.1 | F05090 | non-negotiable | false | 10 |
| R10159 | TUI — startup time `<` 100ms | architecture | F05091 | non-negotiable | false | 10 |
| R10160 | TUI — no animations on entry | architecture | F05091 | non-negotiable | false | 10 |
| R10161 | TUI — exits cleanly on SIGTERM (cursor restored) | architecture | F05092 | non-negotiable | false | 10 |
| R10162 | TUI — exits cleanly on SIGINT (cursor restored) | architecture | F05092 | non-negotiable | false | 10 |
| R10163 | TUI — footer shows last 3 OCSF events live | cross-ref MS026 | F05147 | non-negotiable | false | 10 |
| R10164 | TUI — every action emits M049 trace | cross-ref M049 | F05076 | non-negotiable | false | 10 |
| R10165 | TUI — every mutating action requires operator signature | cross-ref MS003 | F05125 | non-negotiable | false | 10 |
| R10166 | Minimal web — HTTPS server on localhost:7575 | architecture | F05093 | non-negotiable | false | 10 |
| R10167 | Minimal web — TLS cert via MS003 self-signed (operator-pinned) | cross-ref MS003 | F05094 | non-negotiable | false | 10 |
| R10168 | Minimal web — single-page interface (no SPA framework) | operator standing direction | F05095 | non-negotiable | false | 10 |
| R10169 | Minimal web — vanilla HTML + minimal JS (`<` 50KB total) | operator standing direction | F05095 | non-negotiable | false | 10 |
| R10170 | Minimal web — 4-panel layout matching TUI | architecture | F05096 | non-negotiable | false | 10 |
| R10171 | Minimal web — mutations require operator MS003 key upload | cross-ref MS003 | F05097 | non-negotiable | false | 10 |
| R10172 | Minimal web — read-only views accessible without operator key | architecture | F05098 | non-negotiable | false | 10 |
| R10173 | Minimal web — auto-refresh via SSE every 2s | architecture | F05099 | non-negotiable | false | 10 |
| R10174 | Minimal web — keyboard shortcuts (Cmd-1..Cmd-4) mapping to panels | operator standing direction | F05100 | non-negotiable | false | 10 |
| R10175 | Minimal web — WCAG 2.1 AA contrast (4.5:1 minimum) | operator standing direction | F05101 | non-negotiable | false | 10 |
| R10176 | Minimal web — dark mode | operator standing direction | F05102 | non-negotiable | false | 10 |
| R10177 | Minimal web — light mode | operator standing direction | F05102 | non-negotiable | false | 10 |
| R10178 | Minimal web — auto-from-system mode | operator standing direction | F05102 | non-negotiable | false | 10 |
| R10179 | Minimal web — destructive actions confirmation dialog | operator standing direction | F05103 | non-negotiable | false | 10 |
| R10180 | Minimal web — localhost-only by default (never LAN-reachable without explicit toggle) | architecture + operator standing direction | F05104 | non-negotiable | false | 10 |
| R10181 | Minimal web — disable-able (operator can turn off the entire web surface) | operator standing direction "everything can be turned on and off" | F05160 | non-negotiable | false | 10 |
| R10182 | Mirror — selfdef-rules-mirror crate publishes Ring 0-4 rule state for D-12 | cross-ref MS007 + MS024 + MS038 | F05105 | non-negotiable | false | 10 |
| R10183 | Mirror — selfdef-grants-mirror crate publishes filesystem-grant state for D-13 | cross-ref MS007 + MS037 | F05106 | non-negotiable | false | 10 |
| R10184 | Mirror — selfdef-capability-mirror crate publishes capability-token state for D-14 | cross-ref MS007 + MS035 | F05107 | non-negotiable | false | 10 |
| R10185 | Mirror — selfdef-sandbox-mirror crate publishes sandbox allocation for D-15 | cross-ref MS007 + MS036 | F05108 | non-negotiable | false | 10 |
| R10186 | Mirror — selfdef-audit-mirror crate publishes audit cycle for D-16 | cross-ref MS007 + MS009 | F05109 | non-negotiable | false | 10 |
| R10187 | Mirror — selfdef-quarantine-mirror crate publishes quarantine archive for D-17 | cross-ref MS007 + MS042 | F05110 | non-negotiable | false | 10 |
| R10188 | Mirror — selfdef-trust-score-mirror crate publishes trust score for D-18 | cross-ref MS007 + MS042 | F05111 | non-negotiable | false | 10 |
| R10189 | Mirror — all mirror crates published under MS007 8/8 SATURATED | cross-ref MS007 | F05112 | non-negotiable | false | 10 |
| R10190 | Mirror — all mirror crates signed via MS003 | cross-ref MS003 + MS007 | F05113 | non-negotiable | false | 10 |
| R10191 | Mirror — all mirror crates carry schema_version "1.0.0" | cross-ref MS007 | F05114 | non-negotiable | false | 10 |
| R10192 | Mirror — all mirror crates re-exported via sovereign-os cargo workspace | cross-ref MS007 | F05115 | non-negotiable | false | 10 |
| R10193 | Mirror — mirror crates expose state read-only (no mutation interface) | cross-ref MS007 + operator standing direction | F05116 | non-negotiable | false | 10 |
| R10194 | Mirror — mirror crates continue to publish even when consumer offline | cross-ref MS007 | F05134 | non-negotiable | false | 10 |
| R10195 | Mirror — mirror crate updates emit M049 trace | cross-ref M049 + cross-ref MS007 | F05105 | non-negotiable | false | 10 |
| R10196 | Mirror — mirror crate version bumped on schema breaking changes | cross-ref MS007 + architecture | F05114 | non-negotiable | false | 10 |
| R10197 | Operator config — User level selects from six profiles | dump 14760-14780 | F05117 | non-negotiable | false | 10 |
| R10198 | Operator config — User level shows simple prompts (yes/no/which-profile) | dump 14760-14780 | F05117 | non-negotiable | false | 10 |
| R10199 | Operator config — Power-user level enables per-boundary toggles (MS034-MS042) | dump 14760-14780 | F05118 | non-negotiable | false | 10 |
| R10200 | Operator config — Power-user level includes TTL maximums, budget limits, allowed FQDN lists | dump 14760-14780 | F05118 | non-negotiable | false | 10 |
| R10201 | Operator config — System level configures policy bus root keys | dump 14760-14780 + cross-ref MS003 | F05119 | non-negotiable | false | 10 |
| R10202 | Operator config — System level configures chain-of-trust roots | dump 14760-14780 + cross-ref MS003 | F05119 | non-negotiable | false | 10 |
| R10203 | Operator config — System level configures replay validator schedule | dump 14760-14780 + cross-ref MS009 | F05119 | non-negotiable | false | 10 |
| R10204 | Operator config — every toggle persisted under /etc/selfdef/operator.toml | architecture | F05120 | non-negotiable | false | 10 |
| R10205 | Operator config — toggle changes signed via MS003 | cross-ref MS003 | F05121 | non-negotiable | false | 10 |
| R10206 | Operator config — toggle changes emit M049 trace | cross-ref M049 | F05122 | non-negotiable | false | 10 |
| R10207 | Operator config — toggle changes emit OCSF Configuration Change class 5001 | cross-ref MS026 | F05122 | non-negotiable | false | 10 |
| R10208 | Operator config — toggle prior versions retained 365 days minimum | architecture | F05123 | non-negotiable | false | 10 |
| R10209 | Operator config — never auto-promotes operator from User to Power-user without explicit opt-in | dump 14776 + operator standing direction | F05117 | non-negotiable | false | 10 |
| R10210 | Operator auth — CLI mutations require operator MS003 signature | cross-ref MS003 | F05124 | non-negotiable | false | 10 |
| R10211 | Operator auth — TUI mutations require operator MS003 signature | cross-ref MS003 | F05125 | non-negotiable | false | 10 |
| R10212 | Operator auth — minimal-web mutations require operator MS003 key upload | cross-ref MS003 | F05126 | non-negotiable | false | 10 |
| R10213 | Operator auth — operator key may be derived from hardware token (YubiKey/TPM/smartcard) | cross-ref MS003 | F05127 | non-negotiable | false | 10 |
| R10214 | Operator auth — read-only ops allowed without authentication | architecture | F05128 | non-negotiable | false | 10 |
| R10215 | Operator auth — auth failures emit OCSF Audit Activity class 1003 | cross-ref MS026 | F05129 | non-negotiable | false | 10 |
| R10216 | Operator auth — auth failure repeated `>=` 5 times within 5 min triggers OCSF Detection Finding 2004 | cross-ref MS026 | F05129 | non-negotiable | false | 10 |
| R10217 | Offline — selfdef daemon starts without sovereign-os reachable | operator standing direction | F05130 | non-negotiable | false | 10 |
| R10218 | Offline — selfdef CLI all commands work without sovereign-os | operator standing direction | F05131 | non-negotiable | false | 10 |
| R10219 | Offline — selfdef TUI all panels work without sovereign-os | operator standing direction | F05132 | non-negotiable | false | 10 |
| R10220 | Offline — selfdef minimal-web works without sovereign-os | operator standing direction | F05133 | non-negotiable | false | 10 |
| R10221 | Offline — selfdef mirror exports remain published even if no consumer | cross-ref MS007 | F05134 | non-negotiable | false | 10 |
| R10222 | Offline — selfdef audit replay validator runs independently | cross-ref MS009 | F05135 | non-negotiable | false | 10 |
| R10223 | Offline — selfdef logs to /var/log/selfdef/ regardless of M049 reachability | cross-ref M049 + architecture | F05136 | non-negotiable | false | 10 |
| R10224 | Offline — selfdef logs include all OCSF events buffered for later delivery | cross-ref MS026 + architecture | F05136 | non-negotiable | false | 10 |
| R10225 | Offline — buffer drained automatically when M049 becomes reachable | cross-ref M049 + architecture | F05136 | non-negotiable | false | 10 |
| R10226 | Incident — single-key panic-drop-all (operator key required) | dump 16450 + operator standing direction | F05137 | non-negotiable | false | 10 |
| R10227 | Incident — single-key freeze-profile (operator key required) | cross-ref MS040 | F05138 | non-negotiable | false | 10 |
| R10228 | Incident — single-key kill-all-quarantined + force-quarantine | cross-ref MS042 | F05139 | non-negotiable | false | 10 |
| R10229 | Incident — single-key rotate-operator-key emergency | cross-ref MS003 | F05140 | non-negotiable | false | 10 |
| R10230 | Incident — every break-glass action emits OCSF Detection Finding 2004 | cross-ref MS026 | F05141 | non-negotiable | false | 10 |
| R10231 | Incident — every break-glass action signed via MS003 | cross-ref MS003 | F05142 | non-negotiable | false | 10 |
| R10232 | Incident — break-glass logs separately at /var/log/selfdef/break-glass/ | architecture | F05143 | non-negotiable | false | 10 |
| R10233 | Incident — break-glass requires double-confirmation (operator key + typed confirmation phrase) | operator standing direction + cross-ref MS003 | F05137 | non-negotiable | false | 10 |
| R10234 | Incident — break-glass logged into MS009 audit chain | cross-ref MS009 | F05143 | non-negotiable | false | 10 |
| R10235 | Incident — break-glass auto-emits trace to M049 (priority high) | cross-ref M049 | F05141 | non-negotiable | false | 10 |
| R10236 | Observability — `selfdef logs` tails recent log lines | cross-ref MS026 | F05144 | non-negotiable | false | 10 |
| R10237 | Observability — `selfdef logs --since <duration>` filters by time | architecture | F05144 | non-negotiable | false | 10 |
| R10238 | Observability — `selfdef events` streams OCSF events live | cross-ref MS026 | F05145 | non-negotiable | false | 10 |
| R10239 | Observability — `selfdef events --filter <class>` filters by OCSF class | cross-ref MS026 | F05145 | non-negotiable | false | 10 |
| R10240 | Observability — `selfdef trace <trace-id>` shows M049 span detail | cross-ref M049 | F05146 | non-negotiable | false | 10 |
| R10241 | Observability — TUI footer shows last 3 OCSF events live | cross-ref MS026 | F05147 | non-negotiable | false | 10 |
| R10242 | Observability — minimal-web mirrors observability via SSE | cross-ref MS026 + M049 | F05148 | non-negotiable | false | 10 |
| R10243 | Observability — every surface reflects M049 trace state when available | cross-ref M049 | F05144 | non-negotiable | false | 10 |
| R10244 | UX — every key combination documented at `selfdef help` | architecture | F05149 | non-negotiable | false | 10 |
| R10245 | UX — every action reachable via keyboard | operator standing direction | F05150 | non-negotiable | false | 10 |
| R10246 | UX — destructive CLI actions require --yes flag | operator standing direction | F05151 | non-negotiable | false | 10 |
| R10247 | UX — destructive TUI actions require confirmation dialog | operator standing direction | F05151 | non-negotiable | false | 10 |
| R10248 | UX — destructive minimal-web actions require confirmation modal | operator standing direction | F05151 | non-negotiable | false | 10 |
| R10249 | UX — undo available where reversible | operator standing direction | F05152 | non-negotiable | false | 10 |
| R10250 | UX — cap-mint undoable via cap-revoke | cross-ref MS035 | F05152 | non-negotiable | false | 10 |
| R10251 | UX — grant-extend undoable via grant-revoke | cross-ref MS035 | F05152 | non-negotiable | false | 10 |
| R10252 | UX — profile-set undoable by switching back (logged) | cross-ref MS040 | F05152 | non-negotiable | false | 10 |
| R10253 | UX — error states show root-cause | operator standing direction + cross-ref M055 | F05153 | non-negotiable | false | 10 |
| R10254 | UX — error states show recovery action | operator standing direction + cross-ref M055 | F05153 | non-negotiable | false | 10 |
| R10255 | UX — empty states show next-action hint | operator standing direction | F05154 | non-negotiable | false | 10 |
| R10256 | UX — long operations show progress | operator standing direction | F05155 | non-negotiable | false | 10 |
| R10257 | UX — long operations show ETA | operator standing direction | F05155 | non-negotiable | false | 10 |
| R10258 | UX — long operations show cancel option | operator standing direction | F05155 | non-negotiable | false | 10 |
| R10259 | UX — color contrast 4.5:1 minimum where rendering applies | WCAG 2.1 + operator standing direction | F05156 | non-negotiable | false | 10 |
| R10260 | UX — focus indicators always visible | WCAG 2.1 + operator standing direction | F05157 | non-negotiable | false | 10 |
| R10261 | UX — keyboard shortcut palette accessible via `?` in TUI | operator standing direction | F05158 | non-negotiable | false | 10 |
| R10262 | UX — keyboard shortcut palette accessible via Cmd-? in minimal-web | operator standing direction | F05158 | non-negotiable | false | 10 |
| R10263 | UX — minimal-web supports Tab navigation | WCAG 2.1 | F05159 | non-negotiable | false | 10 |
| R10264 | UX — minimal-web supports arrow-key navigation | WCAG 2.1 | F05159 | non-negotiable | false | 10 |
| R10265 | UX — minimal-web supports Enter to activate | WCAG 2.1 | F05159 | non-negotiable | false | 10 |
| R10266 | UX — minimal-web supports Esc to dismiss | WCAG 2.1 | F05159 | non-negotiable | false | 10 |
| R10267 | UX — operator can disable CLI? — NO, CLI is essential (cannot be disabled) | operator standing direction + architecture | F05160 | non-negotiable | false | 10 |
| R10268 | UX — operator can disable TUI (default: enabled) | operator standing direction | F05160 | non-negotiable | false | 10 |
| R10269 | UX — operator can disable minimal-web (default: enabled, localhost-only) | operator standing direction | F05160 | non-negotiable | false | 10 |
| R10270 | UX — operator can disable any mirror crate publication | operator standing direction | F05160 | non-negotiable | false | 10 |
| R10271 | Boundary — selfdef surface NEVER mutates sovereign-os state | operator standing direction "Respect the projects" | F05130 | non-negotiable | false | 10 |
| R10272 | Boundary — selfdef surface NEVER mutates info-hub state | operator standing direction "knowledge = second-brain" | F05130 | non-negotiable | false | 10 |
| R10273 | Boundary — sovereign-os M060 cockpit READS selfdef state ONLY via MS007 mirrors | cross-ref MS007 + operator standing direction | F05116 | non-negotiable | false | 10 |
| R10274 | Boundary — operator restore actions from sovereign-os cockpit proxied via MS003-signed request to selfdef | cross-ref MS003 + cross-ref MS042 | F05126 | non-negotiable | false | 10 |
| R10275 | Boundary — info-hub knowledge surfaces appear as read-only contextual panels in TUI/web (optional) | operator standing direction | F05148 | non-negotiable | false | 10 |
| R10276 | Boundary — selfdef CLI/TUI/minimal-web NEVER calls sovereign-os APIs (no dependency) | operator standing direction | F05130 | non-negotiable | false | 10 |
| R10277 | Boundary — selfdef TUI is the BACKUP operator surface when sovereign-os cockpit is offline | operator standing direction | F05132 | non-negotiable | false | 10 |
| R10278 | Boundary — selfdef CLI is the PRIMARY operator surface for incident-response | operator standing direction + dump 16450 | F05137 | non-negotiable | false | 10 |
| R10279 | Boundary — selfdef minimal-web is the FALLBACK when both TUI and sovereign-os are unavailable | architecture + operator standing direction | F05093 | non-negotiable | false | 10 |
| R10280 | Boundary — boundary respect verified by MS009 replay validator chain | cross-ref MS009 + operator standing direction | F05273 | non-negotiable | false | 10 |
| R10281 | Schema — every CLI command schema published under MS007 selfdef-cli-mirror crate | cross-ref MS007 | F05041 | non-negotiable | false | 10 |
| R10282 | Schema — every TUI panel schema published under MS007 selfdef-tui-mirror crate | cross-ref MS007 | F05081 | non-negotiable | false | 10 |
| R10283 | Schema — every mirror crate schema_version "1.0.0" | cross-ref MS007 | F05114 | non-negotiable | false | 10 |
| R10284 | Schema — every mirror crate breaking change bumps schema_version | cross-ref MS007 + architecture | F05114 | non-negotiable | false | 10 |
| R10285 | Schema — schema documentation lives in MS007 crate README + verbatim dump quotes | cross-ref MS007 + operator standing direction | F05112 | non-negotiable | false | 10 |
| R10286 | Performance — CLI subcommand response p95 `<` 100ms (status / list ops) | architecture | F05041 | non-negotiable | false | 10 |
| R10287 | Performance — TUI first paint `<` 200ms | architecture | F05091 | non-negotiable | false | 10 |
| R10288 | Performance — TUI incremental update `<` 50ms p95 | architecture | F05091 | non-negotiable | false | 10 |
| R10289 | Performance — minimal-web first paint `<` 200ms p95 | architecture | F05095 | non-negotiable | false | 10 |
| R10290 | Performance — minimal-web SSE update `<` 50ms p95 | architecture | F05099 | non-negotiable | false | 10 |
| R10291 | Performance — mirror publication latency `<` 100ms p95 | cross-ref MS007 | F05116 | non-negotiable | false | 10 |
| R10292 | Telemetry — CLI subcommand invocation count per name emitted via M049 | cross-ref M049 | F05076 | non-negotiable | false | 10 |
| R10293 | Telemetry — TUI panel-view duration emitted via M049 | cross-ref M049 | F05076 | non-negotiable | false | 10 |
| R10294 | Telemetry — minimal-web request count emitted via M049 | cross-ref M049 | F05148 | non-negotiable | false | 10 |
| R10295 | Telemetry — operator auth failure rate emitted via M049 | cross-ref M049 + MS026 | F05129 | non-negotiable | false | 10 |
| R10296 | Telemetry — break-glass invocation count emitted via M049 (high-priority alert) | cross-ref M049 + dump 16450 | F05141 | non-negotiable | false | 10 |
| R10297 | Doctrinal preservation — dump 581 "Fullstack at the edges" verbatim in selfdef-cli-mirror doc | dump 581 + cross-ref MS007 | F05112 | non-negotiable | false | 10 |
| R10298 | Doctrinal preservation — dump 3299 "A dashboard should not show vanity graphs" verbatim in selfdef-tui-mirror doc | dump 3299 + cross-ref MS007 | F05112 | non-negotiable | false | 10 |
| R10299 | Doctrinal preservation — operator "Do not minimize the work in selfdef" verbatim in MS043 root doc | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10300 | Doctrinal preservation — operator "Respect the projects" verbatim in MS043 boundary section | operator standing direction | F05130 | non-negotiable | false | 10 |
| R10301 | Doctrinal preservation — verbatim quotes never paraphrased in any selfdef artifact | operator standing direction | F05112 | non-negotiable | false | 10 |
| R10302 | Closing — selfdef has 3 operator surfaces (CLI + TUI + minimal-web) + 7 mirror exports | architecture | F05081 | non-negotiable | false | 10 |
| R10303 | Closing — 7 mirror exports satisfy sovereign-os M060 dashboards D-12..D-18 | cross-ref M060 + cross-ref MS007 | F05111 | non-negotiable | false | 10 |
| R10304 | Closing — selfdef minimal-web fallback satisfies operator "20+ dashboards" goal in standalone IPS context | operator standing direction | F05093 | non-negotiable | false | 10 |
| R10305 | Closing — selfdef CLI command count `>=` 50 distinct subcommands | architecture | F05041 | non-negotiable | false | 10 |
| R10306 | Closing — selfdef TUI panel count = 4 (rules + grants + quarantine + authority) | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10307 | Closing — selfdef minimal-web panel count = 4 matching TUI | architecture | F05096 | non-negotiable | false | 10 |
| R10308 | Closing — selfdef offline survivability verified via M055 failure-mode taxonomy tests | cross-ref M055 + operator standing direction | F05130 | non-negotiable | false | 10 |
| R10309 | Closing — selfdef incident-response surface respects double-confirmation discipline | operator standing direction | F05137 | non-negotiable | false | 10 |
| R10310 | Closing — selfdef UX coherence WCAG 2.1 AA where rendering applies | WCAG 2.1 + operator standing direction | F05156 | non-negotiable | false | 10 |
| R10311 | Closing — selfdef catalog now at 43/43 milestones (this milestone extends the prior 42) | architecture + operator standing direction | F05081 | non-negotiable | false | 10 |
| R10312 | Closing — combined ecosystem catalog: selfdef 43 + sovereign-os 60 = 103 milestones | architecture | F05081 | non-negotiable | false | 10 |
| R10313 | Closing — operator standing /goal "10000+ requirements" exceeded individually per repo | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10314 | Closing — backward-sweep findings (6 redefinitions) logged in sovereign-os/backlog/notes/backward-sweep-2026-05-19-findings.md | architecture + operator standing direction | F05081 | non-negotiable | false | 10 |
| R10315 | Closing — backward-sweep patch passes pending (additive per operator standing direction) | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10316 | Closing — prior-dump review pending (operator: "there was also other dumps before that we decided to restart") | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10317 | Closing — SDD/TDD implementation phase begins only after both reviews + patch passes complete | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10318 | Closing — direct-to-main commits on both repos remain authorized | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10319 | Closing — every R-row carries 10 hard non-negotiable sub-requirements | operator standing direction | F05081 | non-negotiable | false | 10 |
| R10320 | Closing — sovereignty preserved: "intelligence remains in the user's hands" (peace machine axiom) | operator standing direction + sovereign-os M059 | F05081 | non-negotiable | false | 10 |

## Sub-requirements accounting

Every R-row carries 10 hard non-negotiable sub-requirements per operator standing direction. Total enforced sub-reqs = 240 R × 10 = **2,400 sub-requirements** for MS043.

## Cross-references

- **sovereign-os M055** — failure modes (offline survivability test taxonomy)
- **sovereign-os M060** — cockpit + dashboards (consumes selfdef state via MS007 mirrors D-12..D-18)
- **MS003** — selfdef-signing (signs every operator action + MS003 chain)
- **MS007** — typed-mirror crate scheme (selfdef-rules-mirror / -grants-mirror / -capability-mirror / -sandbox-mirror / -audit-mirror / -quarantine-mirror / -trust-score-mirror / -cli-mirror / -tui-mirror)
- **MS009** — audit cycles + replay validator
- **MS024** — eBPF + nftables (rules surface)
- **MS026** — observability + OCSF event emission
- **MS035** — capability tokens (cap surface)
- **MS036** — sandbox tiers (sandbox surface)
- **MS037** — filesystem boundary (fs surface + rollback engine)
- **MS038** — network boundary (net surface)
- **MS039** — authority levels + trust rings (authority panel)
- **MS040** — six-profile authority matrix (profile surface)
- **MS041** — commit authority (rollback surface)
- **MS042** — tool authority (quarantine surface)

## Schema

```
schema_version: "1.0.0"
milestone_id: MS043
parent: selfdef
epics: 10
modules: 26
features: 120
requirements: 240
sub_requirements_per_requirement: 10
total_sub_requirements: 2400
source_dump_lines:
  - 581
  - 3290-3325
  - 14760-14780
  - 15625-15665
  - 16440-16466
cross_repo_mirror: sovereign-os/M060
operator_surfaces:
  - cli: selfdef (50+ subcommands)
  - tui: selfdef tui (4 panels)
  - minimal_web: localhost:7575 (4 panels, fallback)
mirror_crates_published:
  - selfdef-rules-mirror
  - selfdef-grants-mirror
  - selfdef-capability-mirror
  - selfdef-sandbox-mirror
  - selfdef-audit-mirror
  - selfdef-quarantine-mirror
  - selfdef-trust-score-mirror
  - selfdef-cli-mirror
  - selfdef-tui-mirror
catalog_status:
  selfdef: 43/43 milestones COMPLETE (now extends prior 42)
  sovereign_os: 60/60 milestones COMPLETE (M060 cockpit + dashboards added)
  combined: 103 milestones, R10320 + R10200 = ~20520 requirements
```
