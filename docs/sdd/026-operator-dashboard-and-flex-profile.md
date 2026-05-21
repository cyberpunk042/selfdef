# SDD-026 — Operator dashboard architecture + flexible-profile surface

> Status: **review** — vector-by-vector shipment in progress; 7 of
> 13 Z-vectors reached end-to-end production (backend + dashboard
> + L1 gate) as of 2026-05-21:
>   - Z-4 CPU mode classification — `/v1/cpu` + dashboard "CPU mode"
>     panel (commit 5690b8c)
>   - Z-5 GPU watt deviance — `/v1/gpu` + dashboard "GPU watts" panel
>     (commit a26a75c)
>   - Z-6 autohealth composite — `/v1/health` + dashboard top-of-page
>     panel + `selfdefctl health` CLI (commits fedf693 + 4e90962)
>   - Z-7 network state — `/v1/network` + dashboard "Network state"
>     panel (commit aede715)
>   - Z-9 software RAID — `/v1/raid` + dashboard "Software RAID"
>     panel (commit b8d2b1a)
>   - Z-10 storage state — `/v1/storage` + dashboard "Storage state"
>     panel (commit 7bd0313)
>   - Z-13 (SD-R83 portion) — `/v1/modules/diff` (commit 09b8385)
> Remaining Z-vectors at design-stage: Z-1 (8 dashboard tabs UX
> restructure), Z-2 (LM Studio surface), Z-3 (flex-profile state),
> Z-8 (Docker vs system-level install paths), Z-11 (MCP interop),
> Z-12 (Multi-tier REPL), Z-13 SD-R86/SD-R87 (install-options +
> topological install plan). SDD will move to `implemented` when
> the remaining 6 Z-vectors land.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21 (status: draft → review; 7-of-13 Z-vector
> production landing).
> Builds on: SDD-022 (hardware-exploit doctrine); SDD-023 (cross-repo
> model-taxonomy mirror); SDD-024 (cycle-5 vectors); SDD-025 (cycle-6
> vectors). Sister to sovereign-os SDD-025 (observability CLI
> architecture).
> Closes findings: none (architecture spec).

## Operator directive — verbatim (sacrosanct)

> "there are going to be multiple mode of functioning too, like LM
> Studio and LM Link maybe ? Unsloth ? What is the tools with a
> dashboard you can browse too with all the models and all their
> variant and quantization options and advanced features options and
> parametrization and all ? not just a mode by profile but a profile
> that is flexible and allow not only the AI and the tools but also
> me to download, fine-tune, parameters, build, run, use and train
> and adapt and use and eval and etc. Lets think of all the angles.
> Also tool to manage the selfdef modules, modules features and
> advanced features and profiles. Hotswap from one CPU mode to
> another to another with some auto option(s). Same for the GPU I
> guess and this like the tracking of the state like the watt set
> consumption for the GPU... with a warning if the RTX 3090 which
> should be sliglly reduce which isn't and things like this that
> warn deviance from 'perfertion' and other things. With scans too.
> with autohealth and doctor and analysis and event and
> notification and messaging. State of the access to internet, the
> DNS, the Cloudflared ? the tailscale, Traefik, non docker vs
> docker install ? possible ? greyout the option that require it
> and/or offer the alternative and warn of the potential risk or
> failure or such and/or offer to re-enable it if the user want the
> feature. container level vs system level. obviously the module
> if not installed would not appear in the dashboard but only in
> the options of the dashboard which offer to install any previously
> non-installed modules or features and whatnot anyway and configure
> them. It allow to see the management of the software raid and
> observe and operate and configure. to see all the logs files and
> need for log rotate, track files system usage and for each
> partitions and global and such. Offer insights. Allow to
> interoperate with an MCP via tools calls and/or MCP. (e.g. I
> might install node, claude and whatever deps and use it on it.)
> Always in the optic that this Debian 13 Sovereign OS is a non-GUI
> by default. I will obviously be able to plug a screen or mainly
> connect remotely to ssh and/or dashboard or API on whatsoever pot
> for whatsoever dashbaords and modules and tools. Everything via
> dashboard/UInterface or terminal tools OR AI, as my chose or even
> needs. I think there is also the notion of python and multiple
> level and something called REPL. but that's just one layer, one
> place we can do someting with this, its deeper I think, how we
> can go deep with the language when we know what we want to do,
> want we want to add, to to enhence, to alterate, to wrap, to
> save/need less tokens, save wasted paths / useless tracks and
> stuff like all this. Programming, Proto-Programing,
> Proto-Proto-Programming and inside REPL you do you own things
> and you even have custom CoT or such and advanced tailored
> features and enhencement and our own integrated intelligence and
> etc."

## Mission

Three operator surfaces, ONE state model:

1. **Terminal** — `selfdefctl` + `sovereign-osctl` keep evolving as
   the deterministic, scriptable surface (already the cycle-1..7
   shipping focus).
2. **Dashboard** — an HTTP UI served LOCALLY by the daemon, browsable
   over SSH-port-forward or the operator's tailscale, exposing every
   surface the CLI exposes + the discovery/install/configure UX the
   operator named.
3. **AI-mediated** — MCP tool calls + JSON-typed API surface so the
   operator's claude-code (or any LM Studio / LM Link / Unsloth
   integration they install) can drive the same state model the
   dashboard and CLI use.

All three consume the SAME underlying state — never three forks of
the same logic.

## Architecture: state-first, surfaces second

  state model (Rust crates + on-disk YAML/JSON files)
        │
        ├── selfdefctl CLI (existing — cycle 1-7 surface)
        │
        ├── selfdef-daemon dashboard server (HTTP) ──▶ browser
        │       └── --bind 127.0.0.1:8443 by default;
        │           operator opts in to exposure via
        │           /etc/selfdef/dashboard.toml allowlist
        │
        ├── selfdef-mcp-server (MCP stdio + TCP transports)
        │       └── exposes the same verbs as the CLI as tool calls
        │
        └── REPL surface (Python `selfdef.repl`) — multi-tier:
                  Programming        (write Rust / call libs)
                  Proto-Programming  (Python REPL atop selfdef crates)
                  Proto-Proto-Prog   (operator-defined macros + custom
                                      CoT over the proto layer)

Every surface reads/writes through the SAME `selfdef-state` crate so
operator changes via dashboard land in the same on-disk files the
CLI manages. No surface bypasses the canonical store.

## Cycle-7+ vector grid (Z-N, NEW)

Each Z-N corresponds to ONE operator-named feature from the
verbatim directive above. Operator pulls priorities by editing the
ranking table; cycle 7..N implementation rounds reference these.

### Z-1 — `selfdef-dashboard` HTTP UI scaffold

Stand up the daemon-served HTTP UI. Stateless HTML + small JS;
backend is the existing selfdef-daemon. Tabs:
  - Models: catalog (R212) + resident + variants + quants + advanced
    options (Unsloth-style parameter forms)
  - Modules: installed + available-to-install (the dashboard sees
    the SD-R75 category/phase taxonomy + grays-out anything missing
    its dependencies)
  - Profiles: cycle through profiles + flexibility editor
  - Hardware: GPU watts + CPU mode + RAID + filesystem usage
  - Network: internet / DNS / Cloudflared / tailscale / Traefik
  - Logs: rotated + raw + insights
  - MCP: tool list + invocation log
  - REPL: pop-out Python REPL (Proto-Programming tier)

  - Recommendation: Rust backend in selfdef-daemon; askama / minijinja
    for templates; HTMX for interactivity; ZERO npm-tooling chain
    (master spec ethos — no JS framework bloat).

### Z-2 — LM Studio / LM Link / Unsloth equivalent surface

The dashboard's Models tab gives operators what LM Studio gives:
browse-pick-quant-download-load-evaluate, plus what Unsloth gives:
fine-tune-LoRA-train-eval. Backed by the R212 catalog + the SD-R71
selfdef registry + the SD-R81 LoRA state file.

  - Recommendation: SHELL OUT to the operator-installed tooling
    (llama.cpp / vllm / bitnet.cpp / unsloth) rather than re-implement.
    The dashboard knows WHICH binary is present and which workflows
    are viable + offers a one-click "install missing tool" via the
    module surface.

### Z-3 — Module flex-profile (download/fine-tune/build/run/eval)

Replace "profile" (the static YAML) with "flex-profile" — the same
YAML PLUS operator-runtime mutations the dashboard applies (e.g.
"this profile + Qwen3-Coder-32B attached + LoRA X on top"). Persist
to /var/lib/selfdef/flex-profile.json with full revert history.

  - Recommendation: profile YAMLs stay the AUTHORED baseline; the
    flex-profile JSON is the LIVE delta. `selfdefctl profile
    flex {show,reset,promote}` operator surface.

### Z-4 — CPU hotswap modes with auto-option

CPU performance / scaling-governor / SMT / C-state knobs as named
"CPU modes" (e.g. ultra-low-power, balanced, sustained-burst,
peak-inference). Dashboard radio-button switches between them;
selfdefctl `cpu-mode {set,auto}`; daemon enforces.

  - Recommendation: auto = workload-aware switching based on the
    SDD-025 `sovereign_os_inference_router_class_total` metric (rlm
    traffic → sustained-burst; ternary-lm traffic → balanced).

### Z-5 — GPU watt deviance warnings

Operator-named: "warning if the RTX 3090 which should be slightly
reduce which isn't." Selfdef-side rule engine over the SD-R24 GPU
power telemetry — operator sets per-GPU "expected_power_limit_watts"
(e.g. RTX 3090 → 280W instead of 350W nominal); daemon warns when
current power_limit_watts deviates.

  - Recommendation: rules live in /etc/selfdef/gpu-policy.toml;
    selfdefctl `gpu watch` + dashboard surface render the diffs;
    Layer-B Prometheus gauge emits the deviance count per GPU.

### Z-6 — Autohealth / doctor / analysis / event / notification

Composite scanner that runs scheduled audits (cycle-3 audit cycle3
+ thermal-watch + module-gate + signing-audit + resources-audit)
+ emits to a notification fan-out:
  - desktop (dunst when GUI present)
  - tailscale ping
  - matrix message
  - webhook (operator-supplied URL)

  - Recommendation: notification backends are PLUGIN modules
    (extend the existing modules/ catalog). Operator opts in to
    each backend by enabling its module.

### Z-7 — Network state surface (internet/DNS/Cloudflared/tailscale/Traefik)

Per-component health card. Dashboard shows green/yellow/red on each;
clicking offers the alternative + cites the risk:
  - Cloudflared down → "you've lost the cloudflare-protected ingress;
    fallback to direct tailscale tunnel (less private)"
  - tailscale down → "you've lost the operator's primary remote
    access; SSH on the operator-known IPs still works"
  - DNS upstream gone → "alternative: switch to your local
    cloudflared resolver or 1.1.1.1 emergency"

  - Recommendation: per-component status modules in selfdef; the
    `network-status` script reads /etc/selfdef/network-policy.toml
    + renders the per-card cells.

### Z-8 — Docker vs system-level distinction

Per-feature install path matrix. Operator picks "system-level"
(default sovereignty) or "container-level" (faster iterate / isolated
deps); dashboard greys-out paths that aren't installable today + the
"options" sub-tab shows the install command.

  - Recommendation: each module's manifest gains an
    `[install_paths]` table with `system = "..."` and
    `container = "..."` alternatives.

### Z-9 — Software RAID management surface

mdadm wrappers. Dashboard tab: array status, rebuild progress,
disk-failure markers, spare assignment, periodic-scrub schedule.
selfdefctl `raid {status,detail,add-spare,fail,replace}`.

  - Recommendation: shell out to mdadm; selfdef NEVER touches the
    array directly (operator-supplied disks → operator control).

### Z-10 — Log files + rotate need + filesystem usage

Log catalog with rotate-recommended badge when a file exceeds
operator-set threshold (default 100 MiB). Per-partition df + global
overview; dashboard insights like "/var growth +12 GiB/week — at
this rate you fill in 28 days." selfdefctl `fs {usage,trends,
log-audit}`.

  - Recommendation: ship a logrotate.d drop-in that aligns with
    the operator threshold; trends are computed over the
    `sovereign_os_filesystem_*` Layer B metrics (new metric set).

### Z-11 — MCP interop (tool calls + MCP server)

Two angles:
  1. **selfdef-mcp-server** — exposes selfdefctl verbs as MCP tools
     so the operator's claude / claude-code / other MCP clients can
     drive selfdef.
  2. **MCP client transport** — selfdef-cli can CALL OUT to any
     operator-installed MCP server (Anthropic, local, etc.) for
     reasoning workflows.

  - **Decision (SD-R84, 2026-05-17, partial FOUNDATION)** — cycle-8
    PR seeds the manifest brick: `selfdefctl mcp tools` renders the
    curated tool manifest (JSON default + --human terminal view).
    Cycle-8 doctrine: READ-ONLY verbs only (hardware.posture,
    hardware.export, modules.list, modules.diff, modules.info,
    models.list, models.lora.list — 7 tools shipped). Write verbs
    (apply / set-mode / fetch / lora-attach) land in subsequent
    rounds with explicit per-tool opt-in gates. Every tool carries
    a JSON Schema `input_schema` with `type=object` +
    `additionalProperties=false` for strict MCP-client validation.
    The future `selfdef-mcp-server` (stdio + TCP transports) will
    consume the SAME manifest the operator already reads via
    `mcp tools` so client and server agree on the exposable surface
    before the server lands.

### Z-12 — Multi-tier REPL (Programming / Proto / Proto-Proto)

Python REPL ON TOP OF selfdef state:
  - Tier 0 (Programming): write Rust crates that link to
    selfdef-store, selfdef-hardware. The most expensive layer; full
    type-safety + zero overhead.
  - Tier 1 (Proto-Programming): Python REPL (selfdef.repl module)
    with bindings to the Rust crates. Operator iterates fast.
  - Tier 2 (Proto-Proto-Programming): operator-defined macros +
    custom CoT loops + DSL extensions that compile to Tier 1 calls.
    Saves tokens; eliminates wasted paths; the "deeper" layer the
    operator named.

  - **Decision (SD-R85, 2026-05-17, foundation)** — cycle-8 PR seeds
    Tier 1 via subprocess wrappers (not pyo3 yet — that's a future
    round). `selfdefctl repl bootstrap` emits the Python script the
    operator pastes into `python3 -i -c "$(...)"`. Eight callables:
      hardware() / posture() / modules(category=..., phase=...) /
      modules_info(slug, resolved=...) / modules_diff(...) /
      models() / lora_list(state=...) / mcp_tools()
    `selfdefctl repl tiers` prints the manifest (3 tiers) — JSON
    default, --human for terminal banner. Tier 2 is the operator-
    extension surface (we ship Tier 1 + the named callables; the
    operator owns the custom CoT / token-saving aliases on top).

### Z-13 — Module options-to-install surface

Dashboard's Modules tab default shows INSTALLED modules. A
"Browse available" sub-tab lists EVERY module in the catalog (R75
category/phase filter) with one-click "Install" that runs
`selfdefctl modules apply <slug>`. Uninstalled modules are NOT
hidden — they're separately discoverable.

  - **Decision (SD-R83, 2026-05-17, partial CLI surface)** — cycle-8
    PR seeds the CLI counterpart: `selfdefctl modules diff` partitions
    catalog × host-config into three buckets:
      INSTALLED  — slug in both (would apply)
      AVAILABLE  — slug in catalog only (operator can `apply --only X`)
      ORPHANED   — slug in host-config only (stale entry; restore
                   manifest OR prune host-config)
    JSON output feeds the future Z-1 dashboard "Browse available"
    tab directly. Operator-actionable hint surfaces when orphans
    are present. The dashboard side lands when Z-1 ships.

  - **Decision (SD-R86, 2026-05-17, install-options surface)** —
    cycle-8 PR grows the operator-decision side: `selfdefctl modules
    install-options` walks the SD-R83 AVAILABLE partition and
    decorates each row with operator-actionable recommendations:
      ready                       — hardware gate passes + deps present
      blocked-by-hardware         — gate fails (unmet predicates listed)
      blocked-by-missing-deps     — depends_on chain incomplete
      needs-review                — hardware probe unavailable
    `--category`, `--only-ready` filters compose with the JSON output
    so the dashboard's "Install options" tab renders the ready set
    by default + lets the operator drill into blocked rows. Closes
    the "Dont mix uninstalled and installed Module" operator
    requirement (verbatim). Also exposed as Tier 1 REPL callable
    `modules_install_options(host_config=..., dir=..., category=...,
    only_ready=False)` + MCP tool `selfdef.modules.install_options`.

## Cycle-7+ priority ranking

| Priority | Vector | Effort | Rationale |
|----------|--------|--------|-----------|
| HIGH     | Z-1 dashboard scaffold      | large  | Foundation for everything |
| HIGH     | Z-5 GPU watt deviance       | small  | Operator-named, concrete |
| HIGH     | Z-13 modules options-to-install | medium | Closes the discoverability gap |
| MEDIUM   | Z-3 flex-profile state      | medium | LIVE delta over baseline YAMLs |
| MEDIUM   | Z-4 CPU hotswap modes       | medium | Operator-named with auto-option |
| MEDIUM   | Z-6 autohealth + notification | large | Composite scanner |
| MEDIUM   | Z-11 MCP interop            | large  | Bridges to operator's claude |
| MEDIUM   | Z-7 network-state surface   | medium | Network-state card matrix |
| MEDIUM   | Z-2 LM Studio / Unsloth equiv | large | Shells out to ecosystem |
| MEDIUM   | Z-12 REPL multi-tier        | large  | Tier 1+2 are new surfaces |
| LOW      | Z-8 docker vs system install paths | medium | Per-module install_paths table |
| LOW      | Z-9 software RAID surface   | medium | mdadm wrappers |
| LOW      | Z-10 log + fs usage insights | medium | New Layer B metric set |

## Non-goals

- A heavyweight JS framework / SPA — askama+HTMX or equivalent
  minimal-stack only (master spec ethos).
- Multi-tenant dashboard auth — operator-only, allowlist by IP via
  /etc/selfdef/dashboard.toml; future round adds per-operator auth
  when fleet-multi-operator lands.
- Auto-applying recommended fixes — every dashboard action that
  changes state requires explicit operator click ("apply"). No
  background mutations.
- Selfdef as a model-zoo curator — Z-2 SHELLS OUT to the operator's
  preferred tool (Unsloth, LM Studio, etc.); selfdef catalogues the
  models + the workflows + the state file, never the model weights.

## How operators ratify

Edit this file → replace "Recommendation:" with "Decision:" on each
Z-N. Commit. Cycle 7..N rounds reference the decisions.

Same pattern as SDD-019 → SDD-020 → SDD-021 → SDD-024 → SDD-025.
The arc never closes; the SDDs do.

## Cross-references

- sovereign-os SDD-025 — observability CLI architecture (sister
  pattern — parallel-verb contract)
- SDD-018/022 — hardware-exploit doctrine (Z-5 GPU watt deviance
  builds on SD-R24 + R64+R66 surfaces)
- SDD-023 — cross-repo model-taxonomy mirror (Z-2 LM-Studio-equiv
  consumes R212 catalog)
- SDD-024 — cycle-5 vectors (X-4 LoRA lifecycle progresses with
  Z-1/Z-13 dashboard)
- SDD-025 — cycle-6 vectors (Y-5 capabilities cache composes with
  Z-1 dashboard load-time)
