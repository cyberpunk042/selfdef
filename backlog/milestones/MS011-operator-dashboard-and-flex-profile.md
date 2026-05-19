# MS011 — Operator dashboard + flex profile

> Parent: `backlog/milestones/INDEX.md` row MS011.
> Source: `docs/sdd/026-operator-dashboard-and-flex-profile.md` (378 lines, captures verbatim operator goal expansion 2026-05-17, 3 operator surfaces / ONE state model, 13 Z-N vectors Z-1..Z-13, priority ranking, 4 non-goals, ratify mechanism, sister to sovereign-os SDD-025; builds on SDD-022 / SDD-023 / SDD-024 / SDD-025) + `dashboard/` directory (PWA assets: app.js / dashboard.css / index.html / manifest.json / service-worker.js). All entries below extract verbatim from these source files. No invention.

## Epics (E0111–E0120)

| Epic ID | Phrase | Source |
|---|---|---|
| E0111 | Operator directive verbatim (sacrosanct, 2026-05-17) — "multiple mode of functioning… flexible profile that allows AI / tools / me to download, fine-tune, parameters, build, run, use, train, adapt, eval… selfdef modules + advanced features + profiles… hotswap CPU/GPU modes with auto options… watt-set consumption tracking + deviance warning… autohealth + doctor + scans + event + notification… network state (internet / DNS / Cloudflared / tailscale / Traefik)… container-level vs system-level distinction… software RAID + log rotate + filesystem usage… MCP tool calls… Debian 13 non-GUI-by-default; ssh / dashboard / API / terminal tools OR AI… Python REPL + Programming / Proto-Programming / Proto-Proto-Programming with operator-defined custom CoT" | SDD-026 § Operator directive verbatim |
| E0112 | Mission — 3 operator surfaces, ONE state model (Terminal `selfdefctl` + `sovereign-osctl` / Dashboard HTTP UI / AI-mediated MCP) all consume the SAME underlying state | SDD-026 § Mission |
| E0113 | Architecture state-first surfaces-second — `selfdef-state` crate is the canonical store; no surface bypasses it; on-disk YAML/JSON files are the substrate | SDD-026 § Architecture |
| E0114 | Z-1 — `selfdef-dashboard` HTTP UI scaffold (8 tabs: Models / Modules / Profiles / Hardware / Network / Logs / MCP / REPL); askama+minijinja+HTMX; ZERO npm-tooling chain | SDD-026 Z-1 |
| E0115 | Z-2 — LM Studio / LM Link / Unsloth equivalent surface (Models tab); shells out to operator-installed tooling (llama.cpp / vllm / bitnet.cpp / unsloth); one-click "install missing tool" via module surface | SDD-026 Z-2 |
| E0116 | Z-3 flex-profile state (live delta over baseline YAMLs at `/var/lib/selfdef/flex-profile.json` with full revert history) + Z-4 CPU hotswap modes (ultra-low-power / balanced / sustained-burst / peak-inference + auto workload-aware) | SDD-026 Z-3 + Z-4 |
| E0117 | Z-5 GPU watt deviance warnings (`/etc/selfdef/gpu-policy.toml` operator-set expected_power_limit_watts; daemon warns on diff; Layer-B Prometheus gauge) + Z-6 autohealth/doctor/analysis/event/notification (composite scanner with cycle-3 audit + thermal-watch + module-gate + signing-audit + resources-audit; 4 notification backends as plugin modules) | SDD-026 Z-5 + Z-6 |
| E0118 | Z-7 Network state surface (per-component green/yellow/red on internet/DNS/Cloudflared/tailscale/Traefik with alternative + risk citation) + Z-8 Docker vs system-level (per-module [install_paths] manifest) + Z-9 software RAID (mdadm wrappers; selfdef NEVER touches array directly) + Z-10 log files + rotate + filesystem usage trends (logrotate.d drop-in; `sovereign_os_filesystem_*` Layer-B metric set) | SDD-026 Z-7 + Z-8 + Z-9 + Z-10 |
| E0119 | Z-11 MCP interop (`selfdef-mcp-server` stdio+TCP + MCP client transport from selfdef-cli; SD-R84 cycle-8 PR seeds 7 READ-ONLY tools: hardware.posture / hardware.export / modules.list / modules.diff / modules.info / models.list / models.lora.list; JSON Schema input_schema strict mode) + Z-12 Multi-tier REPL (Tier 0 Programming Rust / Tier 1 Proto-Programming Python `selfdef.repl` with 8 Tier-1 callables / Tier 2 operator-defined macros + custom CoT) + Z-13 Module options-to-install (`selfdefctl modules diff` SD-R83 INSTALLED/AVAILABLE/ORPHANED + `modules install-options` SD-R86 ready/blocked-by-hardware/blocked-by-missing-deps/needs-review) | SDD-026 Z-11 + Z-12 + Z-13 |
| E0120 | Priority ranking (HIGH Z-1/Z-5/Z-13; MEDIUM Z-3/Z-4/Z-6/Z-11/Z-7/Z-2/Z-12; LOW Z-8/Z-9/Z-10) + 4 non-goals (no heavyweight JS framework / no multi-tenant auth / no auto-applying fixes / not a model-zoo curator) + ratification mechanism (operator edits SDD-026, replaces "Recommendation:" with "Decision:" per Z-N) + `dashboard/` PWA assets (app.js / dashboard.css / index.html / manifest.json / service-worker.js) | SDD-026 § Priority ranking + Non-goals + Ratify + `dashboard/` |

## Modules (M00265–M00290)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00265 | Terminal surface — `selfdefctl` + `sovereign-osctl` keep evolving as deterministic scriptable surface (cycle-1..7 shipping focus) | SDD-026 § Mission 1 | E0112 |
| M00266 | Dashboard surface — HTTP UI served LOCALLY by daemon, browsable over SSH-port-forward OR operator's tailscale | SDD-026 § Mission 2 | E0112 |
| M00267 | AI-mediated surface — MCP tool calls + JSON-typed API so operator's claude-code (or any LM Studio / LM Link / Unsloth integration installed) can drive same state model | SDD-026 § Mission 3 | E0112 |
| M00268 | `selfdef-state` crate — canonical Rust crate every surface reads/writes through | SDD-026 § Architecture | E0113 |
| M00269 | Dashboard `--bind 127.0.0.1:8443` default + operator opt-in exposure via `/etc/selfdef/dashboard.toml` allowlist | SDD-026 § Architecture | E0114 |
| M00270 | `selfdef-mcp-server` — MCP stdio + TCP transports; exposes same verbs as CLI as tool calls | SDD-026 § Architecture + Z-11 | E0119 |
| M00271 | REPL surface — Python `selfdef.repl` module; multi-tier (Tier 0 Rust / Tier 1 Python / Tier 2 operator macros + CoT) | SDD-026 § Architecture + Z-12 | E0119 |
| M00272 | Dashboard tab Models — catalog (R212) + resident + variants + quants + advanced options (Unsloth-style parameter forms) | SDD-026 Z-1 | E0114 |
| M00273 | Dashboard tab Modules — installed + available-to-install (SD-R75 category/phase taxonomy; greys-out anything missing dependencies) | SDD-026 Z-1 | E0114 |
| M00274 | Dashboard tab Profiles — cycle through profiles + flexibility editor | SDD-026 Z-1 | E0114 |
| M00275 | Dashboard tab Hardware — GPU watts + CPU mode + RAID + filesystem usage | SDD-026 Z-1 | E0114 |
| M00276 | Dashboard tab Network — internet / DNS / Cloudflared / tailscale / Traefik | SDD-026 Z-1 | E0114 |
| M00277 | Dashboard tab Logs — rotated + raw + insights | SDD-026 Z-1 | E0114 |
| M00278 | Dashboard tab MCP — tool list + invocation log | SDD-026 Z-1 | E0114 |
| M00279 | Dashboard tab REPL — pop-out Python REPL (Proto-Programming tier) | SDD-026 Z-1 | E0114 |
| M00280 | Z-2 SHELL-OUT pattern — selfdef shells out to llama.cpp / vllm / bitnet.cpp / unsloth; dashboard knows WHICH binary is present + offers one-click "install missing tool" via module surface | SDD-026 Z-2 | E0115 |
| M00281 | Z-3 flex-profile JSON delta — `/var/lib/selfdef/flex-profile.json` LIVE delta over baseline profile YAMLs; full revert history; `selfdefctl profile flex {show,reset,promote}` | SDD-026 Z-3 | E0116 |
| M00282 | Z-4 named CPU modes — ultra-low-power / balanced / sustained-burst / peak-inference (performance + scaling-governor + SMT + C-state knobs as named modes) | SDD-026 Z-4 | E0116 |
| M00283 | Z-4 auto-CPU-mode — workload-aware switching based on SDD-025 `sovereign_os_inference_router_class_total` metric (rlm traffic → sustained-burst; ternary-lm traffic → balanced) | SDD-026 Z-4 | E0116 |
| M00284 | Z-5 GPU policy — `/etc/selfdef/gpu-policy.toml` per-GPU `expected_power_limit_watts`; daemon warns on deviance; `selfdefctl gpu watch` + dashboard renders diffs; Layer-B Prometheus gauge `gpu_power_limit_watts_deviance_count` per GPU | SDD-026 Z-5 | E0117 |
| M00285 | Z-6 notification fan-out — 4 backends as plugin modules (desktop dunst when GUI present / tailscale ping / matrix message / webhook operator-supplied URL); composite scanner runs cycle-3 audit + thermal-watch + module-gate + signing-audit + resources-audit | SDD-026 Z-6 | E0117 |
| M00286 | Z-8 module manifest `[install_paths]` table — `system = "..."` + `container = "..."` alternatives per module | SDD-026 Z-8 | E0118 |
| M00287 | Z-11 `selfdefctl mcp tools` (SD-R84 cycle-8 partial FOUNDATION) — curated 7 READ-ONLY tools manifest (hardware.posture / hardware.export / modules.list / modules.diff / modules.info / models.list / models.lora.list); JSON default + `--human` terminal view; every tool carries `input_schema` `type=object` `additionalProperties=false` | SDD-026 Z-11 SD-R84 | E0119 |
| M00288 | Z-12 `selfdefctl repl bootstrap` (SD-R85 cycle-8 foundation) + 8 Tier-1 callables (hardware / posture / modules / modules_info / modules_diff / models / lora_list / mcp_tools) + `selfdefctl repl tiers` 3-tier manifest | SDD-026 Z-12 SD-R85 | E0119 |
| M00289 | Z-13 `selfdefctl modules diff` (SD-R83 cycle-8 partial CLI) — INSTALLED / AVAILABLE / ORPHANED bucket partition; JSON output feeds dashboard "Browse available" tab; `selfdefctl modules install-options` (SD-R86 cycle-8) decorates AVAILABLE rows with ready / blocked-by-hardware / blocked-by-missing-deps / needs-review states; closes "Don't mix uninstalled and installed Module" requirement | SDD-026 Z-13 SD-R83 + SD-R86 | E0119 |
| M00290 | `dashboard/` PWA assets — app.js (HTMX client logic) + dashboard.css (askama-rendered + ZERO npm) + index.html (entry template) + manifest.json (PWA manifest) + service-worker.js (offline cache) | `dashboard/` | E0114 |

## Features (F01201–F01320)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F01201 | Operator directive sacrosanct verbatim quote present at SDD-026 § "Operator directive — verbatim (sacrosanct)" | SDD-026 § verbatim | E0111 | composite | false |
| F01202 | Operator directive — multiple mode of functioning like LM Studio / LM Link / Unsloth | SDD-026 § verbatim | E0111 | composite | false |
| F01203 | Operator directive — flexible profile that allows AI + tools + operator to download / fine-tune / parameters / build / run / use / train / adapt / eval | SDD-026 § verbatim | E0111 | composite | false |
| F01204 | Operator directive — tool to manage selfdef modules + module features + advanced features + profiles | SDD-026 § verbatim | E0111 | composite | false |
| F01205 | Operator directive — Hotswap CPU mode + GPU + auto option(s) | SDD-026 § verbatim | E0111 | composite | false |
| F01206 | Operator directive — watt set consumption tracking for GPU with deviance warning (e.g. RTX 3090 should be slightly reduced which isn't) | SDD-026 § verbatim | E0111 | composite | false |
| F01207 | Operator directive — autohealth + doctor + analysis + event + notification + messaging | SDD-026 § verbatim | E0111 | composite | false |
| F01208 | Operator directive — network state (internet / DNS / Cloudflared / tailscale / Traefik) | SDD-026 § verbatim | E0111 | composite | false |
| F01209 | Operator directive — non docker vs docker install distinction; greyout option that requires it + offer alternative + warn risk + offer re-enable | SDD-026 § verbatim | E0111 | composite | false |
| F01210 | Operator directive — container level vs system level | SDD-026 § verbatim | E0111 | composite | false |
| F01211 | Operator directive — module not installed wouldn't appear in dashboard but only in options offering to install | SDD-026 § verbatim | E0111 | composite | false |
| F01212 | Operator directive — software RAID management (observe + operate + configure) | SDD-026 § verbatim | E0111 | composite | false |
| F01213 | Operator directive — log files + need for logrotate + track filesystem usage per partition + global + insights | SDD-026 § verbatim | E0111 | composite | false |
| F01214 | Operator directive — interoperate with MCP via tools calls and/or MCP | SDD-026 § verbatim | E0111 | composite | false |
| F01215 | Operator directive — Debian 13 Sovereign OS is non-GUI by default; ssh + dashboard + API + terminal tools OR AI as chosen / needed | SDD-026 § verbatim | E0111 | composite | false |
| F01216 | Operator directive — Python REPL + Programming / Proto-Programming / Proto-Proto-Programming with operator-defined custom CoT | SDD-026 § verbatim | E0111 | composite | false |
| F01217 | Operator directive — save tokens + eliminate wasted paths / useless tracks | SDD-026 § verbatim | E0111 | composite | false |
| F01218 | Mission — 3 operator surfaces, ONE state model | SDD-026 § Mission | E0112 | composite | false |
| F01219 | Mission surface 1 — Terminal (selfdefctl + sovereign-osctl) keep evolving as deterministic scriptable surface | SDD-026 § Mission 1 | M00265 | composite | false |
| F01220 | Mission surface 2 — Dashboard HTTP UI served LOCALLY by daemon | SDD-026 § Mission 2 | M00266 | composite | false |
| F01221 | Mission surface 2 — browsable over SSH-port-forward or operator's tailscale | SDD-026 § Mission 2 | M00266 | composite | false |
| F01222 | Mission surface 3 — AI-mediated MCP tool calls + JSON-typed API surface | SDD-026 § Mission 3 | M00267 | composite | false |
| F01223 | All 3 surfaces consume SAME underlying state — never 3 forks of same logic | SDD-026 § Mission | E0112 | composite | false |
| F01224 | Architecture — state-first, surfaces second | SDD-026 § Architecture | E0113 | composite | false |
| F01225 | selfdef-state crate is the canonical state model | SDD-026 § Architecture | M00268 | composite | false |
| F01226 | On-disk YAML/JSON files are the substrate | SDD-026 § Architecture | M00268 | composite | false |
| F01227 | No surface bypasses the canonical store | SDD-026 § Architecture | E0113 | composite | false |
| F01228 | Dashboard server — `--bind 127.0.0.1:8443` by default | SDD-026 § Architecture | M00269 | composite | false |
| F01229 | Dashboard exposure opt-in via `/etc/selfdef/dashboard.toml` allowlist | SDD-026 § Architecture | M00269 | composite | true |
| F01230 | selfdef-mcp-server — MCP stdio transport | SDD-026 § Architecture | M00270 | composite | true |
| F01231 | selfdef-mcp-server — MCP TCP transport | SDD-026 § Architecture | M00270 | composite | true |
| F01232 | selfdef-mcp-server exposes same verbs as the CLI as tool calls | SDD-026 § Architecture | M00270 | composite | false |
| F01233 | REPL surface — Python `selfdef.repl` module | SDD-026 § Architecture | M00271 | composite | true |
| F01234 | REPL Tier 0 — Programming (write Rust crates linking to selfdef-store / selfdef-hardware) | SDD-026 § Architecture | M00271 | composite | false |
| F01235 | REPL Tier 1 — Proto-Programming (Python REPL atop selfdef crates with bindings) | SDD-026 § Architecture | M00271 | composite | true |
| F01236 | REPL Tier 2 — Proto-Proto-Programming (operator-defined macros + custom CoT + DSL extensions compiling to Tier 1 calls) | SDD-026 § Architecture | M00271 | composite | true |
| F01237 | Z-1 dashboard scaffold — daemon-served HTTP UI | SDD-026 Z-1 | E0114 | composite | true |
| F01238 | Z-1 backend — stateless HTML + small JS; existing selfdef-daemon | SDD-026 Z-1 | E0114 | composite | false |
| F01239 | Z-1 Models tab — catalog + resident + variants + quants + advanced options | SDD-026 Z-1 | M00272 | composite | true |
| F01240 | Z-1 Modules tab — installed + available-to-install + SD-R75 category/phase + greyout dep-missing | SDD-026 Z-1 | M00273 | composite | true |
| F01241 | Z-1 Profiles tab — cycle profiles + flexibility editor | SDD-026 Z-1 | M00274 | composite | true |
| F01242 | Z-1 Hardware tab — GPU watts + CPU mode + RAID + filesystem usage | SDD-026 Z-1 | M00275 | composite | true |
| F01243 | Z-1 Network tab — internet / DNS / Cloudflared / tailscale / Traefik | SDD-026 Z-1 | M00276 | composite | true |
| F01244 | Z-1 Logs tab — rotated + raw + insights | SDD-026 Z-1 | M00277 | composite | true |
| F01245 | Z-1 MCP tab — tool list + invocation log | SDD-026 Z-1 | M00278 | composite | true |
| F01246 | Z-1 REPL tab — pop-out Python REPL (Proto-Programming tier) | SDD-026 Z-1 | M00279 | composite | true |
| F01247 | Z-1 recommendation — Rust backend in selfdef-daemon | SDD-026 Z-1 | E0114 | composite | false |
| F01248 | Z-1 recommendation — askama / minijinja for templates | SDD-026 Z-1 | E0114 | composite | false |
| F01249 | Z-1 recommendation — HTMX for interactivity | SDD-026 Z-1 | E0114 | composite | false |
| F01250 | Z-1 recommendation — ZERO npm-tooling chain (master spec ethos — no JS framework bloat) | SDD-026 Z-1 | E0114 | composite | false |
| F01251 | Z-2 — Models tab gives operators what LM Studio gives (browse/pick/quant/download/load/evaluate) | SDD-026 Z-2 | M00272 | composite | true |
| F01252 | Z-2 — plus what Unsloth gives (fine-tune / LoRA / train / eval) | SDD-026 Z-2 | M00272 | composite | true |
| F01253 | Z-2 backed by R212 catalog + SD-R71 selfdef registry + SD-R81 LoRA state file | SDD-026 Z-2 | E0115 | composite | false |
| F01254 | Z-2 SHELL OUT to llama.cpp | SDD-026 Z-2 | M00280 | composite | true |
| F01255 | Z-2 SHELL OUT to vllm | SDD-026 Z-2 | M00280 | composite | true |
| F01256 | Z-2 SHELL OUT to bitnet.cpp | SDD-026 Z-2 | M00280 | composite | true |
| F01257 | Z-2 SHELL OUT to unsloth | SDD-026 Z-2 | M00280 | composite | true |
| F01258 | Z-2 dashboard knows WHICH binary is present + which workflows viable | SDD-026 Z-2 | M00280 | composite | false |
| F01259 | Z-2 dashboard offers one-click "install missing tool" via module surface | SDD-026 Z-2 | M00280 | composite | true |
| F01260 | Z-3 — replace static "profile" YAML with "flex-profile" (YAML PLUS operator-runtime mutations) | SDD-026 Z-3 | M00281 | composite | true |
| F01261 | Z-3 example flex — "this profile + Qwen3-Coder-32B attached + LoRA X on top" | SDD-026 Z-3 | M00281 | composite | false |
| F01262 | Z-3 persist — `/var/lib/selfdef/flex-profile.json` | SDD-026 Z-3 | M00281 | composite | true |
| F01263 | Z-3 persistence carries full revert history | SDD-026 Z-3 | M00281 | composite | false |
| F01264 | Z-3 baseline YAMLs stay AUTHORED; flex-profile JSON is LIVE delta | SDD-026 Z-3 | M00281 | composite | false |
| F01265 | Z-3 CLI — `selfdefctl profile flex show` | SDD-026 Z-3 | M00281 | cli_verb | true |
| F01266 | Z-3 CLI — `selfdefctl profile flex reset` | SDD-026 Z-3 | M00281 | cli_verb | true |
| F01267 | Z-3 CLI — `selfdefctl profile flex promote` | SDD-026 Z-3 | M00281 | cli_verb | true |
| F01268 | Z-4 named CPU mode — ultra-low-power | SDD-026 Z-4 | M00282 | composite | true |
| F01269 | Z-4 named CPU mode — balanced | SDD-026 Z-4 | M00282 | composite | true |
| F01270 | Z-4 named CPU mode — sustained-burst | SDD-026 Z-4 | M00282 | composite | true |
| F01271 | Z-4 named CPU mode — peak-inference | SDD-026 Z-4 | M00282 | composite | true |
| F01272 | Z-4 underlying knobs — performance / scaling-governor / SMT / C-state | SDD-026 Z-4 | M00282 | composite | false |
| F01273 | Z-4 dashboard radio-button switches between modes | SDD-026 Z-4 | M00282 | composite | true |
| F01274 | Z-4 CLI — `selfdefctl cpu-mode {set,auto}` | SDD-026 Z-4 | M00282 | cli_verb | true |
| F01275 | Z-4 daemon enforces selected mode | SDD-026 Z-4 | M00282 | composite | false |
| F01276 | Z-4 auto = workload-aware switching based on `sovereign_os_inference_router_class_total` metric | SDD-026 Z-4 | M00283 | composite | true |
| F01277 | Z-4 auto rule — rlm traffic → sustained-burst | SDD-026 Z-4 | M00283 | composite | false |
| F01278 | Z-4 auto rule — ternary-lm traffic → balanced | SDD-026 Z-4 | M00283 | composite | false |
| F01279 | Z-5 — operator-set per-GPU `expected_power_limit_watts` | SDD-026 Z-5 | M00284 | composite | true |
| F01280 | Z-5 example — RTX 3090 → 280W instead of 350W nominal | SDD-026 Z-5 | M00284 | composite | false |
| F01281 | Z-5 daemon warns when current power_limit_watts deviates | SDD-026 Z-5 | M00284 | composite | false |
| F01282 | Z-5 rules at `/etc/selfdef/gpu-policy.toml` | SDD-026 Z-5 | M00284 | composite | true |
| F01283 | Z-5 CLI — `selfdefctl gpu watch` | SDD-026 Z-5 | M00284 | cli_verb | true |
| F01284 | Z-5 dashboard surface renders diffs | SDD-026 Z-5 | M00284 | composite | true |
| F01285 | Z-5 Layer-B Prometheus gauge emits deviance count per GPU | SDD-026 Z-5 | M00284 | composite | true |
| F01286 | Z-6 composite scanner runs cycle-3 audit | SDD-026 Z-6 | M00285 | composite | true |
| F01287 | Z-6 composite scanner runs thermal-watch | SDD-026 Z-6 | M00285 | composite | true |
| F01288 | Z-6 composite scanner runs module-gate | SDD-026 Z-6 | M00285 | composite | true |
| F01289 | Z-6 composite scanner runs signing-audit | SDD-026 Z-6 | M00285 | composite | true |
| F01290 | Z-6 composite scanner runs resources-audit | SDD-026 Z-6 | M00285 | composite | true |
| F01291 | Z-6 notification backend — desktop (dunst when GUI present) | SDD-026 Z-6 | M00285 | composite | true |
| F01292 | Z-6 notification backend — tailscale ping | SDD-026 Z-6 | M00285 | composite | true |
| F01293 | Z-6 notification backend — matrix message | SDD-026 Z-6 | M00285 | composite | true |
| F01294 | Z-6 notification backend — webhook (operator-supplied URL) | SDD-026 Z-6 | M00285 | composite | true |
| F01295 | Z-6 backends are PLUGIN modules — operator opts in by enabling module | SDD-026 Z-6 | M00285 | composite | false |
| F01296 | Z-7 per-component health card — green / yellow / red | SDD-026 Z-7 | M00276 | composite | true |
| F01297 | Z-7 clicking offers alternative + cites risk | SDD-026 Z-7 | M00276 | composite | false |
| F01298 | Z-7 example — Cloudflared down → fallback direct tailscale tunnel (less private) | SDD-026 Z-7 | M00276 | composite | false |
| F01299 | Z-7 example — tailscale down → SSH on operator-known IPs still works | SDD-026 Z-7 | M00276 | composite | false |
| F01300 | Z-7 example — DNS upstream gone → switch local cloudflared resolver or 1.1.1.1 emergency | SDD-026 Z-7 | M00276 | composite | false |
| F01301 | Z-7 per-component status modules in selfdef; `network-status` script reads `/etc/selfdef/network-policy.toml` | SDD-026 Z-7 | M00276 | composite | true |
| F01302 | Z-8 — operator picks "system-level" (default sovereignty) or "container-level" (faster iterate / isolated deps) | SDD-026 Z-8 | M00286 | composite | true |
| F01303 | Z-8 dashboard greys-out paths that aren't installable today | SDD-026 Z-8 | M00286 | composite | false |
| F01304 | Z-8 options sub-tab shows the install command | SDD-026 Z-8 | M00286 | composite | true |
| F01305 | Z-8 each module manifest gains `[install_paths]` table with `system = "..."` + `container = "..."` | SDD-026 Z-8 | M00286 | composite | true |
| F01306 | Z-9 mdadm wrappers — `selfdefctl raid {status,detail,add-spare,fail,replace}` | SDD-026 Z-9 | E0118 | cli_verb | true |
| F01307 | Z-9 dashboard tab — array status / rebuild progress / disk-failure markers / spare assignment / periodic-scrub schedule | SDD-026 Z-9 | E0118 | composite | true |
| F01308 | Z-9 — selfdef shells out to mdadm; never touches array directly (operator-supplied disks → operator control) | SDD-026 Z-9 | E0118 | composite | false |
| F01309 | Z-10 log catalog — rotate-recommended badge when file exceeds operator-set threshold (default 100 MiB) | SDD-026 Z-10 | E0118 | composite | true |
| F01310 | Z-10 per-partition df + global overview | SDD-026 Z-10 | E0118 | composite | true |
| F01311 | Z-10 dashboard insight — `/var growth +12 GiB/week — at this rate you fill in 28 days` | SDD-026 Z-10 | E0118 | composite | false |
| F01312 | Z-10 CLI — `selfdefctl fs {usage,trends,log-audit}` | SDD-026 Z-10 | E0118 | cli_verb | true |
| F01313 | Z-10 logrotate.d drop-in aligned with operator threshold | SDD-026 Z-10 | E0118 | composite | true |
| F01314 | Z-10 trends computed over `sovereign_os_filesystem_*` Layer-B metrics (new metric set) | SDD-026 Z-10 | E0118 | composite | true |
| F01315 | Z-11 angle 1 — selfdef-mcp-server exposes selfdefctl verbs as MCP tools so operator's claude / claude-code / other MCP clients can drive selfdef | SDD-026 Z-11 | M00270 | composite | true |
| F01316 | Z-11 angle 2 — MCP client transport; selfdef-cli can CALL OUT to any operator-installed MCP server (Anthropic, local, etc.) for reasoning workflows | SDD-026 Z-11 | E0119 | composite | true |
| F01317 | Z-11 SD-R84 cycle-8 PR seeds — `selfdefctl mcp tools` curated manifest (JSON default + `--human` terminal view); cycle-8 doctrine READ-ONLY verbs only; 7 tools shipped | SDD-026 Z-11 SD-R84 | M00287 | composite | true |
| F01318 | Z-11 SD-R84 — every tool carries `input_schema` `type=object` + `additionalProperties=false` for strict MCP-client validation | SDD-026 Z-11 SD-R84 | M00287 | composite | false |
| F01319 | Z-12 SD-R85 — `selfdefctl repl bootstrap` emits Python script (subprocess wrappers; not pyo3 yet — future round) | SDD-026 Z-12 SD-R85 | M00288 | composite | true |
| F01320 | Composite — `dashboard/` PWA assets (app.js + dashboard.css + index.html + manifest.json + service-worker.js) are the Z-1 scaffold delivery; SD-R83 + SD-R84 + SD-R85 + SD-R86 are cycle-8 FOUNDATION decisions seeded; Z-1/Z-5/Z-13 are HIGH priority; ratify mechanism = operator edits SDD-026 replacing "Recommendation:" with "Decision:" per Z-N | `dashboard/` + SDD-026 priority + ratify | E0120 | composite | false |

## Requirements (R02401–R02640)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R02401 | SDD-026 captures verbatim operator goal expansion of 2026-05-17 as sacrosanct | SDD-026 § header | E0111 | non-negotiable | false | 10 |
| R02402 | SDD-026 verbatim operator directive must remain unmodified across milestone authoring | SDD-026 § verbatim | E0111 | non-negotiable | false | 10 |
| R02403 | Operator goal — multiple modes of functioning (LM Studio / LM Link / Unsloth-style) | SDD-026 § verbatim | F01202 | non-negotiable | false | 10 |
| R02404 | Operator goal — flexible profile (not just static profile) | SDD-026 § verbatim | F01203 | non-negotiable | false | 10 |
| R02405 | Flexible profile allows AI to download / fine-tune / parameters / build / run / use / train / adapt / eval | SDD-026 § verbatim | F01203 | non-negotiable | true | 10 |
| R02406 | Flexible profile allows tools to do same | SDD-026 § verbatim | F01203 | non-negotiable | true | 10 |
| R02407 | Flexible profile allows the operator to do same | SDD-026 § verbatim | F01203 | non-negotiable | true | 10 |
| R02408 | Operator goal — tool to manage selfdef modules | SDD-026 § verbatim | F01204 | non-negotiable | false | 10 |
| R02409 | Operator goal — tool to manage module features + advanced features | SDD-026 § verbatim | F01204 | non-negotiable | false | 10 |
| R02410 | Operator goal — tool to manage profiles | SDD-026 § verbatim | F01204 | non-negotiable | false | 10 |
| R02411 | Operator goal — Hotswap from one CPU mode to another with auto option(s) | SDD-026 § verbatim | F01205 | non-negotiable | false | 10 |
| R02412 | Operator goal — Hotswap GPU (same pattern as CPU hotswap) | SDD-026 § verbatim | F01205 | non-negotiable | false | 10 |
| R02413 | Operator goal — tracking watt-set consumption for GPU with deviance warning | SDD-026 § verbatim | F01206 | non-negotiable | false | 10 |
| R02414 | Operator goal — warning when RTX 3090 which should be slightly reduced isn't | SDD-026 § verbatim | F01206 | non-negotiable | false | 10 |
| R02415 | Operator goal — warn deviance from 'perfection' and other things | SDD-026 § verbatim | F01206 | non-negotiable | false | 10 |
| R02416 | Operator goal — scans | SDD-026 § verbatim | F01207 | non-negotiable | false | 10 |
| R02417 | Operator goal — autohealth + doctor + analysis | SDD-026 § verbatim | F01207 | non-negotiable | false | 10 |
| R02418 | Operator goal — event + notification + messaging | SDD-026 § verbatim | F01207 | non-negotiable | false | 10 |
| R02419 | Operator goal — state of access to internet / DNS / Cloudflared / tailscale / Traefik | SDD-026 § verbatim | F01208 | non-negotiable | false | 10 |
| R02420 | Operator goal — non-docker vs docker install distinction | SDD-026 § verbatim | F01209 | non-negotiable | false | 10 |
| R02421 | Operator goal — greyout option that requires it + offer alternative + warn risk + offer re-enable | SDD-026 § verbatim | F01209 | non-negotiable | false | 10 |
| R02422 | Operator goal — container level vs system level | SDD-026 § verbatim | F01210 | non-negotiable | false | 10 |
| R02423 | Operator goal — module not installed does NOT appear in dashboard (only in options offering install) | SDD-026 § verbatim | F01211 | non-negotiable | false | 10 |
| R02424 | Operator goal — software RAID management (observe + operate + configure) | SDD-026 § verbatim | F01212 | non-negotiable | false | 10 |
| R02425 | Operator goal — see all log files + need for logrotate | SDD-026 § verbatim | F01213 | non-negotiable | false | 10 |
| R02426 | Operator goal — track filesystem usage per partition + global + insights | SDD-026 § verbatim | F01213 | non-negotiable | false | 10 |
| R02427 | Operator goal — interoperate with MCP via tools calls and/or MCP | SDD-026 § verbatim | F01214 | non-negotiable | false | 10 |
| R02428 | Operator goal — Debian 13 Sovereign OS is non-GUI by default | SDD-026 § verbatim | F01215 | non-negotiable | false | 10 |
| R02429 | Operator goal — connect remotely to ssh and/or dashboard or API | SDD-026 § verbatim | F01215 | non-negotiable | false | 10 |
| R02430 | Operator goal — everything via dashboard / UI / terminal tools OR AI as operator's choice or even needs | SDD-026 § verbatim | F01215 | non-negotiable | false | 10 |
| R02431 | Operator goal — Python REPL + Programming / Proto-Programming / Proto-Proto-Programming | SDD-026 § verbatim | F01216 | non-negotiable | false | 10 |
| R02432 | Operator goal — custom CoT inside REPL | SDD-026 § verbatim | F01216 | non-negotiable | false | 10 |
| R02433 | Operator goal — advanced tailored features + enhancements + own integrated intelligence | SDD-026 § verbatim | F01216 | non-negotiable | false | 10 |
| R02434 | Operator goal — save tokens, eliminate wasted paths / useless tracks | SDD-026 § verbatim | F01217 | non-negotiable | false | 10 |
| R02435 | Mission — 3 operator surfaces, ONE state model | SDD-026 § Mission | E0112 | non-negotiable | false | 10 |
| R02436 | Surface 1 — Terminal `selfdefctl` deterministic + scriptable | SDD-026 § Mission 1 | M00265 | non-negotiable | false | 10 |
| R02437 | Surface 1 — Terminal `sovereign-osctl` (sister; cross-repo binding via documented contract) | SDD-026 § Mission 1 + SDD-038 | M00265 | non-negotiable | false | 10 |
| R02438 | Surface 2 — Dashboard HTTP UI served LOCALLY by daemon | SDD-026 § Mission 2 | M00266 | non-negotiable | false | 10 |
| R02439 | Surface 2 — browsable over SSH-port-forward | SDD-026 § Mission 2 | M00266 | non-negotiable | false | 10 |
| R02440 | Surface 2 — browsable over operator's tailscale | SDD-026 § Mission 2 | M00266 | non-negotiable | false | 10 |
| R02441 | Surface 2 — exposes every surface the CLI exposes + the discovery/install/configure UX operator named | SDD-026 § Mission 2 | M00266 | non-negotiable | false | 10 |
| R02442 | Surface 3 — AI-mediated MCP tool calls | SDD-026 § Mission 3 | M00267 | non-negotiable | false | 10 |
| R02443 | Surface 3 — JSON-typed API surface | SDD-026 § Mission 3 | M00267 | non-negotiable | false | 10 |
| R02444 | Surface 3 — operator's claude-code (or LM Studio / LM Link / Unsloth integration) drives same state model | SDD-026 § Mission 3 | M00267 | non-negotiable | false | 10 |
| R02445 | All 3 surfaces consume the SAME underlying state — never 3 forks of the same logic | SDD-026 § Mission | E0112 | non-negotiable | false | 10 |
| R02446 | Architecture — state-first, surfaces second | SDD-026 § Architecture | E0113 | non-negotiable | false | 10 |
| R02447 | State model is Rust crates + on-disk YAML/JSON files | SDD-026 § Architecture | M00268 | non-negotiable | false | 10 |
| R02448 | Architecture has 4 surface branches under the state model | SDD-026 § Architecture | E0113 | non-negotiable | false | 10 |
| R02449 | Architecture branch 1 — selfdefctl CLI | SDD-026 § Architecture | M00265 | non-negotiable | false | 10 |
| R02450 | Architecture branch 2 — selfdef-daemon dashboard server (HTTP) | SDD-026 § Architecture | M00266 | non-negotiable | false | 10 |
| R02451 | Architecture branch 3 — selfdef-mcp-server (MCP stdio + TCP transports) | SDD-026 § Architecture | M00270 | non-negotiable | false | 10 |
| R02452 | Architecture branch 4 — REPL surface (Python `selfdef.repl`) | SDD-026 § Architecture | M00271 | non-negotiable | false | 10 |
| R02453 | Every surface reads/writes through SAME `selfdef-state` crate | SDD-026 § Architecture | M00268 | non-negotiable | false | 10 |
| R02454 | Operator changes via dashboard land in same on-disk files the CLI manages | SDD-026 § Architecture | M00268 | non-negotiable | false | 10 |
| R02455 | No surface bypasses the canonical store | SDD-026 § Architecture | E0113 | non-negotiable | false | 10 |
| R02456 | Dashboard bind default — `127.0.0.1:8443` | SDD-026 § Architecture | M00269 | non-negotiable | false | 10 |
| R02457 | Dashboard exposure opt-in via `/etc/selfdef/dashboard.toml` allowlist | SDD-026 § Architecture | M00269 | non-negotiable | true | 10 |
| R02458 | selfdef-mcp-server supports MCP stdio transport | SDD-026 § Architecture | M00270 | non-negotiable | true | 10 |
| R02459 | selfdef-mcp-server supports MCP TCP transport | SDD-026 § Architecture | M00270 | non-negotiable | true | 10 |
| R02460 | selfdef-mcp-server exposes same verbs as CLI as tool calls | SDD-026 § Architecture | M00270 | non-negotiable | false | 10 |
| R02461 | REPL Tier 0 — Programming (Rust crates linking selfdef-store / selfdef-hardware; most expensive layer; full type-safety + zero overhead) | SDD-026 § Architecture | M00271 | non-negotiable | false | 10 |
| R02462 | REPL Tier 1 — Proto-Programming (Python REPL atop selfdef crates with bindings; operator iterates fast) | SDD-026 § Architecture | M00271 | non-negotiable | false | 10 |
| R02463 | REPL Tier 2 — Proto-Proto-Programming (operator-defined macros + custom CoT loops + DSL extensions compiling to Tier 1 calls; saves tokens; eliminates wasted paths; the "deeper" layer operator named) | SDD-026 § Architecture | M00271 | non-negotiable | false | 10 |
| R02464 | Z-1 — `selfdef-dashboard` HTTP UI scaffold exists | SDD-026 Z-1 | E0114 | non-negotiable | true | 10 |
| R02465 | Z-1 — stateless HTML + small JS; backend is existing selfdef-daemon | SDD-026 Z-1 | E0114 | non-negotiable | false | 10 |
| R02466 | Z-1 tab — Models (catalog R212 + resident + variants + quants + advanced options) | SDD-026 Z-1 | M00272 | non-negotiable | true | 10 |
| R02467 | Z-1 tab — Modules (installed + available-to-install; SD-R75 category/phase taxonomy; greys-out anything missing dependencies) | SDD-026 Z-1 | M00273 | non-negotiable | true | 10 |
| R02468 | Z-1 tab — Profiles (cycle through profiles + flexibility editor) | SDD-026 Z-1 | M00274 | non-negotiable | true | 10 |
| R02469 | Z-1 tab — Hardware (GPU watts + CPU mode + RAID + filesystem usage) | SDD-026 Z-1 | M00275 | non-negotiable | true | 10 |
| R02470 | Z-1 tab — Network (internet / DNS / Cloudflared / tailscale / Traefik) | SDD-026 Z-1 | M00276 | non-negotiable | true | 10 |
| R02471 | Z-1 tab — Logs (rotated + raw + insights) | SDD-026 Z-1 | M00277 | non-negotiable | true | 10 |
| R02472 | Z-1 tab — MCP (tool list + invocation log) | SDD-026 Z-1 | M00278 | non-negotiable | true | 10 |
| R02473 | Z-1 tab — REPL (pop-out Python REPL Proto-Programming tier) | SDD-026 Z-1 | M00279 | non-negotiable | true | 10 |
| R02474 | Z-1 recommendation — Rust backend in selfdef-daemon | SDD-026 Z-1 | E0114 | non-negotiable | false | 10 |
| R02475 | Z-1 recommendation — askama OR minijinja for templates | SDD-026 Z-1 | E0114 | non-negotiable | false | 10 |
| R02476 | Z-1 recommendation — HTMX for interactivity | SDD-026 Z-1 | E0114 | non-negotiable | false | 10 |
| R02477 | Z-1 recommendation — ZERO npm-tooling chain | SDD-026 Z-1 | E0114 | non-negotiable | false | 10 |
| R02478 | Z-1 master spec ethos — no JS framework bloat | SDD-026 Z-1 | E0114 | non-negotiable | false | 10 |
| R02479 | Z-1 PWA asset present — `dashboard/app.js` | `dashboard/app.js` | M00290 | non-negotiable | false | 10 |
| R02480 | Z-1 PWA asset present — `dashboard/dashboard.css` | `dashboard/dashboard.css` | M00290 | non-negotiable | false | 10 |
| R02481 | Z-1 PWA asset present — `dashboard/index.html` | `dashboard/index.html` | M00290 | non-negotiable | false | 10 |
| R02482 | Z-1 PWA asset present — `dashboard/manifest.json` | `dashboard/manifest.json` | M00290 | non-negotiable | false | 10 |
| R02483 | Z-1 PWA asset present — `dashboard/service-worker.js` (offline cache) | `dashboard/service-worker.js` | M00290 | non-negotiable | false | 10 |
| R02484 | Z-2 — Models tab gives operators what LM Studio gives (browse-pick-quant-download-load-evaluate) | SDD-026 Z-2 | M00272 | non-negotiable | true | 10 |
| R02485 | Z-2 — plus what Unsloth gives (fine-tune-LoRA-train-eval) | SDD-026 Z-2 | M00272 | non-negotiable | true | 10 |
| R02486 | Z-2 backed by R212 catalog | SDD-026 Z-2 | E0115 | non-negotiable | false | 10 |
| R02487 | Z-2 backed by SD-R71 selfdef registry | SDD-026 Z-2 | E0115 | non-negotiable | false | 10 |
| R02488 | Z-2 backed by SD-R81 LoRA state file | SDD-026 Z-2 | E0115 | non-negotiable | false | 10 |
| R02489 | Z-2 SHELLS OUT to operator-installed tooling rather than re-implement | SDD-026 Z-2 | M00280 | non-negotiable | false | 10 |
| R02490 | Z-2 shell-out target — llama.cpp | SDD-026 Z-2 | F01254 | non-negotiable | true | 10 |
| R02491 | Z-2 shell-out target — vllm | SDD-026 Z-2 | F01255 | non-negotiable | true | 10 |
| R02492 | Z-2 shell-out target — bitnet.cpp | SDD-026 Z-2 | F01256 | non-negotiable | true | 10 |
| R02493 | Z-2 shell-out target — unsloth | SDD-026 Z-2 | F01257 | non-negotiable | true | 10 |
| R02494 | Z-2 dashboard knows WHICH binary is present + which workflows viable | SDD-026 Z-2 | M00280 | non-negotiable | false | 10 |
| R02495 | Z-2 dashboard offers one-click "install missing tool" via module surface | SDD-026 Z-2 | M00280 | non-negotiable | true | 10 |
| R02496 | Z-3 — replace static "profile" YAML with "flex-profile" (YAML PLUS operator-runtime mutations) | SDD-026 Z-3 | M00281 | non-negotiable | false | 10 |
| R02497 | Z-3 flex-profile example — "this profile + Qwen3-Coder-32B attached + LoRA X on top" | SDD-026 Z-3 | F01261 | non-negotiable | false | 10 |
| R02498 | Z-3 persist at `/var/lib/selfdef/flex-profile.json` | SDD-026 Z-3 | M00281 | non-negotiable | true | 10 |
| R02499 | Z-3 persistence carries full revert history | SDD-026 Z-3 | M00281 | non-negotiable | false | 10 |
| R02500 | Z-3 — profile YAMLs stay the AUTHORED baseline | SDD-026 Z-3 | M00281 | non-negotiable | false | 10 |
| R02501 | Z-3 — flex-profile JSON is the LIVE delta | SDD-026 Z-3 | M00281 | non-negotiable | false | 10 |
| R02502 | Z-3 CLI verb — `selfdefctl profile flex show` | SDD-026 Z-3 | F01265 | non-negotiable | true | 10 |
| R02503 | Z-3 CLI verb — `selfdefctl profile flex reset` | SDD-026 Z-3 | F01266 | non-negotiable | true | 10 |
| R02504 | Z-3 CLI verb — `selfdefctl profile flex promote` | SDD-026 Z-3 | F01267 | non-negotiable | true | 10 |
| R02505 | Z-4 — CPU performance / scaling-governor / SMT / C-state knobs as named "CPU modes" | SDD-026 Z-4 | M00282 | non-negotiable | false | 10 |
| R02506 | Z-4 named CPU mode — ultra-low-power | SDD-026 Z-4 | F01268 | non-negotiable | true | 10 |
| R02507 | Z-4 named CPU mode — balanced | SDD-026 Z-4 | F01269 | non-negotiable | true | 10 |
| R02508 | Z-4 named CPU mode — sustained-burst | SDD-026 Z-4 | F01270 | non-negotiable | true | 10 |
| R02509 | Z-4 named CPU mode — peak-inference | SDD-026 Z-4 | F01271 | non-negotiable | true | 10 |
| R02510 | Z-4 dashboard radio-button switches between modes | SDD-026 Z-4 | M00282 | non-negotiable | true | 10 |
| R02511 | Z-4 CLI verb — `selfdefctl cpu-mode set` | SDD-026 Z-4 | F01274 | non-negotiable | true | 10 |
| R02512 | Z-4 CLI verb — `selfdefctl cpu-mode auto` | SDD-026 Z-4 | F01274 | non-negotiable | true | 10 |
| R02513 | Z-4 daemon enforces selected mode | SDD-026 Z-4 | M00282 | non-negotiable | false | 10 |
| R02514 | Z-4 auto-mode workload-aware switching based on `sovereign_os_inference_router_class_total` metric (SDD-025) | SDD-026 Z-4 + SDD-025 | M00283 | non-negotiable | true | 10 |
| R02515 | Z-4 auto rule — rlm traffic → sustained-burst | SDD-026 Z-4 | F01277 | non-negotiable | false | 10 |
| R02516 | Z-4 auto rule — ternary-lm traffic → balanced | SDD-026 Z-4 | F01278 | non-negotiable | false | 10 |
| R02517 | Z-5 — operator-set per-GPU `expected_power_limit_watts` | SDD-026 Z-5 | M00284 | non-negotiable | true | 10 |
| R02518 | Z-5 example — RTX 3090 expected_power_limit_watts = 280W instead of 350W nominal | SDD-026 Z-5 | F01280 | non-negotiable | false | 10 |
| R02519 | Z-5 — daemon warns when current power_limit_watts deviates | SDD-026 Z-5 | M00284 | non-negotiable | false | 10 |
| R02520 | Z-5 — rules live in `/etc/selfdef/gpu-policy.toml` | SDD-026 Z-5 | M00284 | non-negotiable | true | 10 |
| R02521 | Z-5 CLI verb — `selfdefctl gpu watch` | SDD-026 Z-5 | F01283 | non-negotiable | true | 10 |
| R02522 | Z-5 — dashboard surface renders deviance diffs | SDD-026 Z-5 | M00284 | non-negotiable | true | 10 |
| R02523 | Z-5 — Layer-B Prometheus gauge emits deviance count per GPU | SDD-026 Z-5 | M00284 | non-negotiable | true | 10 |
| R02524 | Z-5 builds on SD-R24 GPU power telemetry | SDD-026 Z-5 + SDD-018 SD-R24 | M00284 | non-negotiable | false | 10 |
| R02525 | Z-6 composite scanner runs scheduled audits | SDD-026 Z-6 | M00285 | non-negotiable | false | 10 |
| R02526 | Z-6 composite scanner — cycle-3 audit | SDD-026 Z-6 | F01286 | non-negotiable | true | 10 |
| R02527 | Z-6 composite scanner — thermal-watch | SDD-026 Z-6 | F01287 | non-negotiable | true | 10 |
| R02528 | Z-6 composite scanner — module-gate | SDD-026 Z-6 | F01288 | non-negotiable | true | 10 |
| R02529 | Z-6 composite scanner — signing-audit | SDD-026 Z-6 | F01289 | non-negotiable | true | 10 |
| R02530 | Z-6 composite scanner — resources-audit | SDD-026 Z-6 | F01290 | non-negotiable | true | 10 |
| R02531 | Z-6 notification backend — desktop (dunst when GUI present) | SDD-026 Z-6 | F01291 | non-negotiable | true | 10 |
| R02532 | Z-6 notification backend — tailscale ping | SDD-026 Z-6 | F01292 | non-negotiable | true | 10 |
| R02533 | Z-6 notification backend — matrix message | SDD-026 Z-6 | F01293 | non-negotiable | true | 10 |
| R02534 | Z-6 notification backend — webhook (operator-supplied URL) | SDD-026 Z-6 | F01294 | non-negotiable | true | 10 |
| R02535 | Z-6 — notification backends are PLUGIN modules | SDD-026 Z-6 | M00285 | non-negotiable | false | 10 |
| R02536 | Z-6 — operator opts in to each backend by enabling its module | SDD-026 Z-6 | M00285 | non-negotiable | false | 10 |
| R02537 | Z-7 — per-component health card (green / yellow / red) | SDD-026 Z-7 | M00276 | non-negotiable | true | 10 |
| R02538 | Z-7 — clicking offers the alternative + cites the risk | SDD-026 Z-7 | M00276 | non-negotiable | false | 10 |
| R02539 | Z-7 example — Cloudflared down → fallback to direct tailscale tunnel (less private) | SDD-026 Z-7 | F01298 | non-negotiable | false | 10 |
| R02540 | Z-7 example — tailscale down → SSH on operator-known IPs still works | SDD-026 Z-7 | F01299 | non-negotiable | false | 10 |
| R02541 | Z-7 example — DNS upstream gone → switch to local cloudflared resolver or 1.1.1.1 emergency | SDD-026 Z-7 | F01300 | non-negotiable | false | 10 |
| R02542 | Z-7 — per-component status modules in selfdef | SDD-026 Z-7 | M00276 | non-negotiable | true | 10 |
| R02543 | Z-7 — `network-status` script reads `/etc/selfdef/network-policy.toml` | SDD-026 Z-7 | M00276 | non-negotiable | true | 10 |
| R02544 | Z-7 — renders per-card cells | SDD-026 Z-7 | M00276 | non-negotiable | false | 10 |
| R02545 | Z-8 — per-feature install path matrix | SDD-026 Z-8 | M00286 | non-negotiable | false | 10 |
| R02546 | Z-8 — operator picks "system-level" (default sovereignty) | SDD-026 Z-8 | M00286 | non-negotiable | true | 10 |
| R02547 | Z-8 — operator picks "container-level" (faster iterate / isolated deps) | SDD-026 Z-8 | M00286 | non-negotiable | true | 10 |
| R02548 | Z-8 dashboard greys-out paths that aren't installable today | SDD-026 Z-8 | M00286 | non-negotiable | false | 10 |
| R02549 | Z-8 options sub-tab shows the install command | SDD-026 Z-8 | M00286 | non-negotiable | true | 10 |
| R02550 | Z-8 — each module manifest gains `[install_paths]` table | SDD-026 Z-8 | M00286 | non-negotiable | true | 10 |
| R02551 | Z-8 — `[install_paths]` carries `system = "..."` alternative | SDD-026 Z-8 | M00286 | non-negotiable | true | 10 |
| R02552 | Z-8 — `[install_paths]` carries `container = "..."` alternative | SDD-026 Z-8 | M00286 | non-negotiable | true | 10 |
| R02553 | Z-9 — mdadm wrappers | SDD-026 Z-9 | E0118 | non-negotiable | true | 10 |
| R02554 | Z-9 dashboard tab — array status | SDD-026 Z-9 | E0118 | non-negotiable | true | 10 |
| R02555 | Z-9 dashboard tab — rebuild progress | SDD-026 Z-9 | E0118 | non-negotiable | true | 10 |
| R02556 | Z-9 dashboard tab — disk-failure markers | SDD-026 Z-9 | E0118 | non-negotiable | true | 10 |
| R02557 | Z-9 dashboard tab — spare assignment | SDD-026 Z-9 | E0118 | non-negotiable | true | 10 |
| R02558 | Z-9 dashboard tab — periodic-scrub schedule | SDD-026 Z-9 | E0118 | non-negotiable | true | 10 |
| R02559 | Z-9 CLI — `selfdefctl raid status` | SDD-026 Z-9 | F01306 | non-negotiable | true | 10 |
| R02560 | Z-9 CLI — `selfdefctl raid detail` | SDD-026 Z-9 | F01306 | non-negotiable | true | 10 |
| R02561 | Z-9 CLI — `selfdefctl raid add-spare` | SDD-026 Z-9 | F01306 | non-negotiable | true | 10 |
| R02562 | Z-9 CLI — `selfdefctl raid fail` | SDD-026 Z-9 | F01306 | non-negotiable | true | 10 |
| R02563 | Z-9 CLI — `selfdefctl raid replace` | SDD-026 Z-9 | F01306 | non-negotiable | true | 10 |
| R02564 | Z-9 — selfdef shells out to mdadm | SDD-026 Z-9 | F01308 | non-negotiable | false | 10 |
| R02565 | Z-9 — selfdef NEVER touches the array directly (operator-supplied disks → operator control) | SDD-026 Z-9 | F01308 | non-negotiable | false | 10 |
| R02566 | Z-10 log catalog with rotate-recommended badge | SDD-026 Z-10 | E0118 | non-negotiable | true | 10 |
| R02567 | Z-10 badge fires when file exceeds operator-set threshold | SDD-026 Z-10 | E0118 | non-negotiable | false | 10 |
| R02568 | Z-10 default threshold — 100 MiB | SDD-026 Z-10 | E0118 | non-negotiable | false | 10 |
| R02569 | Z-10 — per-partition df overview | SDD-026 Z-10 | E0118 | non-negotiable | true | 10 |
| R02570 | Z-10 — global filesystem overview | SDD-026 Z-10 | E0118 | non-negotiable | true | 10 |
| R02571 | Z-10 dashboard insight example — `/var growth +12 GiB/week — at this rate you fill in 28 days` | SDD-026 Z-10 | F01311 | non-negotiable | false | 10 |
| R02572 | Z-10 CLI — `selfdefctl fs usage` | SDD-026 Z-10 | F01312 | non-negotiable | true | 10 |
| R02573 | Z-10 CLI — `selfdefctl fs trends` | SDD-026 Z-10 | F01312 | non-negotiable | true | 10 |
| R02574 | Z-10 CLI — `selfdefctl fs log-audit` | SDD-026 Z-10 | F01312 | non-negotiable | true | 10 |
| R02575 | Z-10 — ship a logrotate.d drop-in aligned with operator threshold | SDD-026 Z-10 | F01313 | non-negotiable | true | 10 |
| R02576 | Z-10 — trends computed over `sovereign_os_filesystem_*` Layer-B metrics (new metric set) | SDD-026 Z-10 | F01314 | non-negotiable | true | 10 |
| R02577 | Z-11 angle 1 — selfdef-mcp-server exposes selfdefctl verbs as MCP tools | SDD-026 Z-11 | M00270 | non-negotiable | true | 10 |
| R02578 | Z-11 angle 1 — operator's claude / claude-code / other MCP clients drive selfdef | SDD-026 Z-11 | M00270 | non-negotiable | false | 10 |
| R02579 | Z-11 angle 2 — MCP client transport: selfdef-cli CALLS OUT to any operator-installed MCP server | SDD-026 Z-11 | E0119 | non-negotiable | true | 10 |
| R02580 | Z-11 angle 2 — Anthropic / local / etc. MCP servers reachable | SDD-026 Z-11 | E0119 | non-negotiable | false | 10 |
| R02581 | Z-11 SD-R84 cycle-8 PR seeds manifest brick | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | false | 10 |
| R02582 | Z-11 SD-R84 — `selfdefctl mcp tools` renders curated tool manifest | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02583 | Z-11 SD-R84 — JSON default output | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02584 | Z-11 SD-R84 — `--human` terminal view | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02585 | Z-11 SD-R84 cycle-8 doctrine — READ-ONLY verbs only | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | false | 10 |
| R02586 | Z-11 SD-R84 cycle-8 — 7 tools shipped | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | false | 10 |
| R02587 | Z-11 SD-R84 cycle-8 tool — hardware.posture | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02588 | Z-11 SD-R84 cycle-8 tool — hardware.export | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02589 | Z-11 SD-R84 cycle-8 tool — modules.list | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02590 | Z-11 SD-R84 cycle-8 tool — modules.diff | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02591 | Z-11 SD-R84 cycle-8 tool — modules.info | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02592 | Z-11 SD-R84 cycle-8 tool — models.list | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02593 | Z-11 SD-R84 cycle-8 tool — models.lora.list | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | true | 10 |
| R02594 | Z-11 SD-R84 — write verbs (apply / set-mode / fetch / lora-attach) land in subsequent rounds with explicit per-tool opt-in gates | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | false | 10 |
| R02595 | Z-11 SD-R84 — every tool carries `input_schema` `type=object` | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | false | 10 |
| R02596 | Z-11 SD-R84 — every tool carries `input_schema` `additionalProperties=false` | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | false | 10 |
| R02597 | Z-11 SD-R84 — strict MCP-client validation | SDD-026 Z-11 SD-R84 | M00287 | non-negotiable | false | 10 |
| R02598 | Z-11 — future `selfdef-mcp-server` consumes SAME manifest the operator reads via `mcp tools` | SDD-026 Z-11 SD-R84 | M00270 | non-negotiable | false | 10 |
| R02599 | Z-12 SD-R85 cycle-8 PR seeds Tier 1 via subprocess wrappers (not pyo3 yet — future round) | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | false | 10 |
| R02600 | Z-12 SD-R85 — `selfdefctl repl bootstrap` emits Python script operator pastes into `python3 -i -c "$(...)"` | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02601 | Z-12 SD-R85 Tier-1 callable — hardware() | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02602 | Z-12 SD-R85 Tier-1 callable — posture() | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02603 | Z-12 SD-R85 Tier-1 callable — modules(category=..., phase=...) | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02604 | Z-12 SD-R85 Tier-1 callable — modules_info(slug, resolved=...) | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02605 | Z-12 SD-R85 Tier-1 callable — modules_diff(...) | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02606 | Z-12 SD-R85 Tier-1 callable — models() | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02607 | Z-12 SD-R85 Tier-1 callable — lora_list(state=...) | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02608 | Z-12 SD-R85 Tier-1 callable — mcp_tools() | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02609 | Z-12 SD-R85 — `selfdefctl repl tiers` prints manifest (3 tiers) | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02610 | Z-12 SD-R85 — `selfdefctl repl tiers` JSON default | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02611 | Z-12 SD-R85 — `selfdefctl repl tiers --human` terminal banner | SDD-026 Z-12 SD-R85 | M00288 | non-negotiable | true | 10 |
| R02612 | Z-12 SD-R85 — Tier 2 is operator-extension surface (operator owns custom CoT + token-saving aliases on top) | SDD-026 Z-12 SD-R85 | M00271 | non-negotiable | false | 10 |
| R02613 | Z-13 — dashboard Modules tab default shows INSTALLED modules | SDD-026 Z-13 | M00273 | non-negotiable | false | 10 |
| R02614 | Z-13 — "Browse available" sub-tab lists EVERY module in catalog | SDD-026 Z-13 | M00273 | non-negotiable | true | 10 |
| R02615 | Z-13 — R75 category/phase filter | SDD-026 Z-13 | M00273 | non-negotiable | true | 10 |
| R02616 | Z-13 — one-click "Install" runs `selfdefctl modules apply <slug>` | SDD-026 Z-13 | M00273 | non-negotiable | true | 10 |
| R02617 | Z-13 — uninstalled modules are NOT hidden; they're separately discoverable | SDD-026 Z-13 | M00273 | non-negotiable | false | 10 |
| R02618 | Z-13 SD-R83 cycle-8 — `selfdefctl modules diff` exists | SDD-026 Z-13 SD-R83 | M00289 | non-negotiable | true | 10 |
| R02619 | Z-13 SD-R83 bucket — INSTALLED (slug in both: catalog ∩ host-config) | SDD-026 Z-13 SD-R83 | M00289 | non-negotiable | true | 10 |
| R02620 | Z-13 SD-R83 bucket — AVAILABLE (slug in catalog only; operator can `apply --only X`) | SDD-026 Z-13 SD-R83 | M00289 | non-negotiable | true | 10 |
| R02621 | Z-13 SD-R83 bucket — ORPHANED (slug in host-config only; stale entry; restore manifest OR prune host-config) | SDD-026 Z-13 SD-R83 | M00289 | non-negotiable | true | 10 |
| R02622 | Z-13 SD-R83 JSON output feeds dashboard "Browse available" tab directly | SDD-026 Z-13 SD-R83 | M00289 | non-negotiable | false | 10 |
| R02623 | Z-13 SD-R83 operator-actionable hint surfaces when orphans present | SDD-026 Z-13 SD-R83 | M00289 | non-negotiable | false | 10 |
| R02624 | Z-13 SD-R86 cycle-8 — `selfdefctl modules install-options` walks SD-R83 AVAILABLE partition | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02625 | Z-13 SD-R86 — decorates rows with operator-actionable recommendations | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | false | 10 |
| R02626 | Z-13 SD-R86 state — `ready` (hardware gate passes + deps present) | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02627 | Z-13 SD-R86 state — `blocked-by-hardware` (gate fails; unmet predicates listed) | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02628 | Z-13 SD-R86 state — `blocked-by-missing-deps` (depends_on chain incomplete) | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02629 | Z-13 SD-R86 state — `needs-review` (hardware probe unavailable) | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02630 | Z-13 SD-R86 — `--category` filter | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02631 | Z-13 SD-R86 — `--only-ready` filter | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02632 | Z-13 SD-R86 — JSON output composes; dashboard "Install options" tab renders ready set by default | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | false | 10 |
| R02633 | Z-13 SD-R86 — closes "Don't mix uninstalled and installed Module" operator requirement | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | false | 10 |
| R02634 | Z-13 SD-R86 — exposed as Tier 1 REPL callable `modules_install_options(host_config=..., dir=..., category=..., only_ready=False)` | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02635 | Z-13 SD-R86 — exposed as MCP tool `selfdef.modules.install_options` | SDD-026 Z-13 SD-R86 | M00289 | non-negotiable | true | 10 |
| R02636 | Priority HIGH — Z-1 dashboard scaffold (large effort; foundation for everything) + Z-5 GPU watt deviance (small; operator-named, concrete) + Z-13 modules options-to-install (medium; closes discoverability gap) | SDD-026 § Priority | E0120 | non-negotiable | false | 10 |
| R02637 | Non-goal — heavyweight JS framework / SPA forbidden; askama+HTMX or equivalent minimal-stack only (master spec ethos) | SDD-026 § Non-goals | E0120 | non-negotiable | false | 10 |
| R02638 | Non-goal — multi-tenant dashboard auth forbidden (operator-only; allowlist by IP via `/etc/selfdef/dashboard.toml`; future round adds per-operator auth when fleet-multi-operator lands) | SDD-026 § Non-goals | E0120 | non-negotiable | false | 10 |
| R02639 | Non-goal — auto-applying recommended fixes forbidden; every dashboard action that changes state requires explicit operator click ("apply"); no background mutations | SDD-026 § Non-goals | E0120 | non-negotiable | false | 10 |
| R02640 | Composite — selfdef MS011 Operator Dashboard + Flex Profile (240 R-rows) ratified via operator editing SDD-026 + replacing "Recommendation:" with "Decision:" per Z-N; same arc as SDD-019→020→021→024→025; integrates with SDD-022 (hardware exploit) / SDD-023 (cross-repo model taxonomy) / SDD-024 (cycle-5 X-4 LoRA lifecycle) / SDD-025 (cycle-6 Y-5 capabilities cache) / sovereign-os SDD-025 (parallel-verb contract); cycle-8 PR seeds SD-R83 + SD-R84 + SD-R85 + SD-R86 FOUNDATION decisions | SDD-026 entire document | E0120 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS010: 6720 + 2400 = 9120 sub-requirements when MS011 lands

## Cross-references

- Sister sovereign-os SDD-025 — observability CLI architecture (parallel-verb contract)
- SDD-018 / SDD-022 — hardware-exploit doctrine (Z-5 GPU watt deviance builds on SD-R24 + R64+R66 surfaces)
- SDD-023 — cross-repo model-taxonomy mirror (Z-2 LM-Studio-equiv consumes R212 catalog)
- SDD-024 — cycle-5 vectors (X-4 LoRA lifecycle progresses with Z-1/Z-13 dashboard)
- SDD-025 — cycle-6 vectors (Y-5 capabilities cache composes with Z-1 dashboard load-time)
- MS006 — 14 functional modules (Z-1 Modules tab + Z-13 install-options surface drive)
- MS010 — Hardware-aware modules + tune surface (Z-5 GPU watt deviance + Z-13 SD-R86 hardware gate use MS010 contracts)
- Cross-repo binding doctrine: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md`
