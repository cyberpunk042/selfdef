# MS048 — Goldilocks Scheduler — hardware-aware resource routing

**Parent**: selfdef IPS daemon — boundary-enforcement layer of the cyberpunk042 ecosystem
**Source**: `~/infohub/raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md`
- lines 18000-18100 (Scheduling Policies — per-profile scheduling rule sets, evolves MS040 six-profile)
- lines 18100-18200 (Blackwell + KV/Context + Memory + Tool + Backpressure scheduling surfaces — five concrete surfaces)
- lines 18200-18250 (Scheduling Objective — 7-axis Goldilocks function + Concrete Decision Example + Key Scheduling Law)
**Operator standing direction** (verbatim, 2026-05-19): *"DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR, NOR THE NEED TO EXPLOIT THE STACK AND TECHNO TO THE MAX, avx-plus-plus base reason being"* / *"Do not minimize the work in selfdef"*
**Cross-references**: MS040 (six-profile authority matrix — scheduling rules elaborate the profiles), MS024 (communication boundary — scheduling surfaces operate within it), MS039 (Ring 0 authority — scheduler decisions are observable not authority-mutating), MS027 (observability — scheduler emits trace points), MS028-MS030 (inference modules — scheduler routes between them), MS044 (Guardian — VRAM/CPU/RAM backpressure affects when replay can run), MS046 (friction-audit — hardware frame produces the resource-availability signal scheduler consumes)
**Backward-sweep anchor**: this milestone is created from the avx-plus-plus dump tail backward-sweep review documented at `~/devops-solutions-information-hub/wiki/log/2026-05-20-avx-plus-plus-dump-tail-backward-sweep-review.md`
**Project boundary**: this milestone catalogs the SELFDEF IPS-side scheduler. Sovereign-os consumes scheduler state via MS007 typed-mirror crates (cockpit M-series); the cockpit displays scheduling decisions but does NOT author them. Per operator standing direction "if I talk about an IPS feature its obviously not in Sovereign-OS. Respect the projects." — the IPS daemon runs the cortex (Ryzen 9900X AVX-512), so the scheduler is selfdef-owned.

## Doctrinal anchors

> "**Never let expensive cognition wait on cheap preparation.**
> **Never let cheap speculation commit without expensive verification when risk demands it.**" (dump 18256-18257 — Key Scheduling Law)

> "maximize useful intelligence per unit of: latency / cost / risk / energy / human attention / hardware pressure" (dump 18204-18211 — Scheduling Objective)

> "Models propose. Runtime routes. CPU enforces. Tools prove. ZFS remembers. User chooses." (dump 18283-18288 — Core Law; MS048 owns the "Runtime routes" clause)

> "The objective is not maximum throughput." (dump 18203)

## Projection statement

The Goldilocks Scheduler is the **runtime routing layer** between the request stream and the hardware/cognition resources of the ultimate sovereign AI workstation (Ryzen 9900X AVX-512 deterministic cortex + RTX PRO 6000 Blackwell oracle + RTX 3090 scout + RAM/ZFS/NVMe continuity). It enforces the **7-axis objective function** (latency / cost / risk / energy / human attention / hardware pressure + a 7th compound term derived from the others) per request, honors the **5 backpressure surfaces** when resources are pressured, and emits decisions as MS027 observability traces.

The scheduler operates within the MS040 six-profile envelope: every routing decision is parameterized by the profile in effect (fast / careful / private / autonomous / experimental / production). The same request gets routed differently under different profiles — that is by design, not a bug.

The scheduler does NOT mutate authority. Authority is MS039's surface. The scheduler proposes; authority disposes. When the scheduler routes a request to a destructive tool, Ring 0 + MS003 still gate the actual write per the existing authority topology.

## Epics (E0461-E0470)

| epic | name | source |
|---|---|---|
| E0461 | Per-profile scheduling rule sets — the six profiles ✕ their rule tuples | dump 18000-18100 + MS040 F04796 |
| E0462 | Blackwell GPU scheduling — KV/Context residency + prefill/decode balance + branch-share | dump 18100-18130 + MS028 |
| E0463 | KV/Context routing — reuse hot context, avoid unnecessary prefill, batch similar shapes, keep stable prefixes resident | dump 18130-18150 + MS028 |
| E0464 | Memory scheduling — 5-stage retrieval pipeline (metadata bitset → sketch/popcount → embedding/rerank → graph → oracle synth) | dump 18150-18170 + MS027 |
| E0465 | Tool scheduling — read-only parallel / write snapshot+policy / network profile-gated / long async-hibernate / destructive human-gate | dump 18170-18190 + MS042 |
| E0466 | Backpressure surfaces — per-resource policy for VRAM/CPU/RAM/IO/human-gate pressure with measured triggers | dump 18190-18205 + MS027 |
| E0467 | PSI / DCGM / trace ingestion bridge — Linux PSI for CPU+RAM+IO, DCGM for GPU, MS027 traces for human-gate latency | dump 18197 (Linux PSI, DCGM, trace metrics feed the scheduler) |
| E0468 | 7-axis objective function — latency + cost + risk + energy + human-attention + hardware-pressure scoring with profile weights | dump 18200-18211 |
| E0469 | Concrete decision examples — code-bug scenario (Map+Draft+Filter+Verify+Test+Commit + Blackwell-busy fallback) as test fixture | dump 18213-18242 |
| E0470 | Cross-cutting observability + cockpit binding — scheduler decisions visible in MS027 stream + cockpit panel via MS007 typed mirror | cross-ref MS007 + MS027 + sovereign-os M-series |

## Modules (M01149-M01174)

| module | name | source |
|---|---|---|
| M01149 | selfdef-scheduler-core | architecture (entry crate) |
| M01150 | selfdef-scheduler-profile-rules (six profile rule sets) | dump 18000-18100 + MS040 |
| M01151 | selfdef-scheduler-blackwell-gpu | dump 18100-18130 |
| M01152 | selfdef-scheduler-kv-context | dump 18130-18150 |
| M01153 | selfdef-scheduler-memory-pipeline (5-stage) | dump 18150-18170 |
| M01154 | selfdef-scheduler-tool-routing | dump 18170-18190 |
| M01155 | selfdef-scheduler-backpressure | dump 18190-18205 |
| M01156 | selfdef-scheduler-psi-source (Linux /proc/pressure/*) | dump 18197 |
| M01157 | selfdef-scheduler-dcgm-source (NVIDIA DCGM) | dump 18197 |
| M01158 | selfdef-scheduler-human-gate-tracker | dump 18197 + MS003 |
| M01159 | selfdef-scheduler-objective-function (7-axis) | dump 18200-18211 |
| M01160 | selfdef-scheduler-decision-emitter (MS027 trace) | cross-ref MS027 |
| M01161 | selfdef-scheduler-replay-engine (MS009) | cross-ref MS009 |
| M01162 | selfdef-scheduler-mirror (MS007 typed mirror) | cross-ref MS007 |
| M01163 | selfdef-scheduler-tui-panel | cross-ref MS043 |
| M01164 | selfdef-scheduler-cli-subcommand-set | cross-ref MS043 |
| M01165 | selfdef-scheduler-http-api-endpoints | cross-ref MS043 |
| M01166 | selfdef-scheduler-cockpit-mirror-publisher | cross-ref MS007 + sovereign-os |
| M01167 | selfdef-scheduler-test-fixtures (code-bug example + canned scenarios) | dump 18213-18242 |
| M01168 | selfdef-scheduler-prometheus-exporter | cross-ref MS027 |
| M01169 | selfdef-scheduler-ocsf-emitter | cross-ref MS026 |
| M01170 | selfdef-scheduler-decision-audit (append-only ZFS log) | cross-ref MS044 |
| M01171 | selfdef-scheduler-config (selfdef.toml) | cross-ref MS043 |
| M01172 | selfdef-scheduler-policy-signer (MS003) | cross-ref MS003 |
| M01173 | selfdef-scheduler-failure-modes (operator runbook taxonomy) | cross-ref MS043 |
| M01174 | selfdef-scheduler-systemd-unit | cross-ref MS044 systemd pattern |

## Features (F05281-F05400)

Catalog growing-edge. Initial seed batch covers verbatim dump anchors;
additional features fill in over future rounds per the operator's
"continue endlessly" directive.

| feature | name | source |
|---|---|---|
| F05281 | Per-profile rule — fast: favor latency / scout-first / shallow verification | dump 18011-18014 |
| F05282 | Per-profile rule — careful: favor correctness / oracle verification / tests required | dump 18016-18019 |
| F05283 | Per-profile rule — private: local-only / cloud routes disabled / strict memory exposure | dump 18021-18024 |
| F05284 | Per-profile rule — autonomous: preserve continuity / batch approvals / sandbox-first / checkpoint often | dump 18026-18030 |
| F05285 | Per-profile rule — experimental: wide branch search / sandbox only / no host commit | dump 18032-18035 |
| F05286 | Per-profile rule — production: strict commit gates / low variance / strong observability | dump 18037-18040 |
| F05287 | The same request schedules differently under different profiles (verbatim) | dump 18044 |
| F05288 | Blackwell KV question — is prefix cached? | dump 18116 |
| F05289 | Blackwell KV question — is context already resident? | dump 18117 |
| F05290 | Blackwell KV question — can this branch share parent context? | dump 18118 |
| F05291 | Blackwell KV question — is the request decode-heavy or prefill-heavy? | dump 18119 |
| F05292 | Blackwell KV question — will this evict valuable KV? | dump 18120 |
| F05293 | KV routing preference — reuse hot context | dump 18125 |
| F05294 | KV routing preference — avoid unnecessary prefill | dump 18126 |
| F05295 | KV routing preference — batch similar context shapes | dump 18127 |
| F05296 | KV routing preference — keep stable prefixes resident | dump 18128 |
| F05297 | Memory retrieval stage 1 — metadata bitset filter | dump 18138 |
| F05298 | Memory retrieval stage 2 — sketch/popcount relevance | dump 18139 |
| F05299 | Memory retrieval stage 3 — embedding/rerank | dump 18140 |
| F05300 | Memory retrieval stage 4 — graph expansion | dump 18141 |
| F05301 | Memory retrieval stage 5 — oracle synthesis only if needed | dump 18142 |
| F05302 | Memory rule — do not throw every memory query at a model | dump 18145 |
| F05303 | Tool scheduling — read-only tools can run early and parallel | dump 18155-18156 |
| F05304 | Tool scheduling — write tools require snapshot/policy | dump 18158-18159 |
| F05305 | Tool scheduling — network tools require profile permission | dump 18161-18162 |
| F05306 | Tool scheduling — long tests can run async, branch hibernates | dump 18164-18165 |
| F05307 | Tool scheduling — destructive tools require human gate | dump 18167-18168 |
| F05308 | Backpressure — Blackwell VRAM high: reduce context, evict low-value KV, switch smaller oracle | dump 18175-18177 |
| F05309 | Backpressure — 3090 busy: reduce branch width, use CPU classifiers | dump 18179-18180 |
| F05310 | Backpressure — CPU pressure high: defer background indexing/evals | dump 18182-18183 |
| F05311 | Backpressure — RAM pressure high: hibernate branches, compact memory | dump 18185-18186 |
| F05312 | Backpressure — IO pressure high: delay cold scans, avoid large snapshots | dump 18188-18189 |
| F05313 | Backpressure — human gate queue high: batch approvals, lower autonomy | dump 18191-18192 |
| F05314 | Linux PSI feeds CPU + RAM + IO pressure | dump 18197 |
| F05315 | DCGM feeds GPU pressure | dump 18197 |
| F05316 | MS027 trace metrics feed scheduler (human-gate latency) | dump 18197 |
| F05317 | Objective: maximize useful intelligence per unit of latency | dump 18206 |
| F05318 | Objective: maximize useful intelligence per unit of cost | dump 18207 |
| F05319 | Objective: maximize useful intelligence per unit of risk | dump 18208 |
| F05320 | Objective: maximize useful intelligence per unit of energy | dump 18209 |
| F05321 | Objective: maximize useful intelligence per unit of human attention | dump 18210 |
| F05322 | Objective: maximize useful intelligence per unit of hardware pressure | dump 18211 |
| F05323 | Key Scheduling Law A — never let expensive cognition wait on cheap preparation | dump 18256 |
| F05324 | Key Scheduling Law B — never let cheap speculation commit without expensive verification when risk demands | dump 18257 |
| F05325 | Code-bug example — Map step: CPU + tools inspect repo | dump 18213-18214 |
| F05326 | Code-bug example — Draft step: 3090 produces 4 patch candidates | dump 18216-18217 |
| F05327 | Code-bug example — Filter step: AVX checks touched paths, risk, duplicate edits | dump 18219-18220 |
| F05328 | Code-bug example — Verify step: Blackwell reviews top 2 | dump 18222-18223 |
| F05329 | Code-bug example — Test step: sandbox runs targeted tests | dump 18225-18226 |
| F05330 | Code-bug example — Commit step: if pass, ZFS snapshot + apply | dump 18228-18229 |
| F05331 | Code-bug example — Blackwell-busy fallback path: 3090 generates more diagnostics + CPU static checks + memory similar failures | dump 18233-18237 |
| F05332 | Slow-tests fallback — branch hibernates, other work proceeds, resume on test result | dump 18244-18247 |
| F05333 | Doctrinal — not maximum throughput; useful intelligence per resource cost | dump 18203 |
| F05334 | Doctrinal — Models propose, Runtime routes, CPU enforces, Tools prove, ZFS remembers, User chooses | dump 18283-18288 |
| F05335 | Doctrinal — situated intelligence: your repos, tests, memory, hardware, policies, cost, continuity, rollback, consent | dump 18276-18278 |
| F05336 | Doctrinal — eight-axis choice surface: fast/careful, local/cloud, scout/oracle, sandbox/host, manual/autonomous, private/shared, cheap/best, exploratory/spec-driven | dump 18296-18305 |
| F05337 | Doctrinal — super-model is the whole governed machine, not one checkpoint | dump 18327-18328 |
| F05338 | Doctrinal — peace machine: powerful to act, disciplined to explain, reversible to trust, flexible to evolve, sovereign to user | dump 18341 |
| F05339 | Test fixture — code-bug full scenario as L1+L2 test asset | architecture |
| F05340 | Test fixture — Blackwell-busy scenario as L3 chaos test | architecture |
| F05341 | Decision emission — every scheduler decision emits an MS027 trace span | architecture + MS027 |
| F05342 | Decision audit — every scheduler decision appended to ZFS log (sync=always) | architecture + MS044 pattern |
| F05343 | Replay invariant — past decisions replayable against current policy snapshot | architecture + MS009 |
| F05344 | Operator override — operator can hard-pin a route (e.g. force Blackwell) per request via Ring 0 | architecture + MS039 |
| F05345 | TUI panel — scheduler row shows current backpressure state + 7-axis last-decision breakdown | architecture + MS043 |
| F05346 | CLI subcommand — selfdefctl scheduler show / history / explain <request-id> / replay <request-id> | architecture + MS043 |
| F05347 | HTTP API — GET /v1/scheduler + /v1/scheduler/history + /v1/scheduler/explain/:request-id | architecture + MS043 |
| F05348 | Cockpit panel — sovereign-os M-series (M068 reserved slot — TBC by sovereign-os arc) consumes selfdef-scheduler-mirror | cross-ref MS007 + sovereign-os |

(Features F05349-F05400 reserved for the second-round expansion covering
the per-resource backpressure trigger thresholds, the per-profile
weight matrix for the 7-axis objective, the operator-runbook taxonomy,
the systemd-unit + Debian-packaging surface, and the test contract.)

## Requirements (R11241-R11480 — 240 hard non-negotiables)

| requirement | text | source | feature | severity | depends_on_other_ms | sub_reqs |
|---|---|---|---|---|---|---|
| R11241 | Doctrinal — scheduler is the runtime routing layer; not authority, not enforcement | dump 18283-18288 | F05334 | non-negotiable | false | 10 |
| R11242 | Doctrinal — scheduler honors the 7-axis objective function | dump 18204-18211 | F05317-F05322 | non-negotiable | false | 10 |
| R11243 | Doctrinal — never let expensive cognition wait on cheap preparation | dump 18256 | F05323 | non-negotiable | false | 10 |
| R11244 | Doctrinal — never let cheap speculation commit without expensive verification | dump 18257 | F05324 | non-negotiable | false | 10 |
| R11245 | Doctrinal — scheduler not maximum-throughput; useful intelligence per resource cost | dump 18203 | F05333 | non-negotiable | false | 10 |
| R11246 | Doctrinal — eight-axis choice surface always operator-flippable | dump 18296-18305 | F05336 | non-negotiable | false | 10 |
| R11247 | Doctrinal — situated intelligence beats cloud scale | dump 18276-18278 | F05335 | non-negotiable | false | 10 |
| R11248 | Per-profile rule fast: favor latency / scout-first / shallow verification VERBATIM | dump 18011-18014 | F05281 | non-negotiable | false | 10 |
| R11249 | Per-profile rule careful: favor correctness / oracle verification / tests required VERBATIM | dump 18016-18019 | F05282 | non-negotiable | false | 10 |
| R11250 | Per-profile rule private: local-only / cloud routes disabled / strict memory exposure VERBATIM | dump 18021-18024 | F05283 | non-negotiable | false | 10 |
| R11251 | Per-profile rule autonomous: preserve continuity / batch approvals / sandbox-first / checkpoint often VERBATIM | dump 18026-18030 | F05284 | non-negotiable | false | 10 |
| R11252 | Per-profile rule experimental: wide branch search / sandbox only / no host commit VERBATIM | dump 18032-18035 | F05285 | non-negotiable | false | 10 |
| R11253 | Per-profile rule production: strict commit gates / low variance / strong observability VERBATIM | dump 18037-18040 | F05286 | non-negotiable | false | 10 |
| R11254 | Same request schedules differently under different profiles | dump 18044 | F05287 | non-negotiable | false | 10 |
| R11255 | Blackwell KV question — is prefix cached? — implemented as check | dump 18116 | F05288 | non-negotiable | false | 10 |
| R11256 | Blackwell KV question — is context already resident? — implemented as check | dump 18117 | F05289 | non-negotiable | false | 10 |
| R11257 | Blackwell KV question — can this branch share parent context? — implemented as check | dump 18118 | F05290 | non-negotiable | false | 10 |
| R11258 | Blackwell KV question — is request decode-heavy or prefill-heavy? — implemented as check | dump 18119 | F05291 | non-negotiable | false | 10 |
| R11259 | Blackwell KV question — will this evict valuable KV? — implemented as check | dump 18120 | F05292 | non-negotiable | false | 10 |
| R11260 | KV routing preference — reuse hot context | dump 18125 | F05293 | non-negotiable | false | 10 |
| R11261 | KV routing preference — avoid unnecessary prefill | dump 18126 | F05294 | non-negotiable | false | 10 |
| R11262 | KV routing preference — batch similar context shapes | dump 18127 | F05295 | non-negotiable | false | 10 |
| R11263 | KV routing preference — keep stable prefixes resident | dump 18128 | F05296 | non-negotiable | false | 10 |
| R11264 | Memory retrieval stage 1 — metadata bitset filter | dump 18138 | F05297 | non-negotiable | false | 10 |
| R11265 | Memory retrieval stage 2 — sketch/popcount relevance | dump 18139 | F05298 | non-negotiable | false | 10 |
| R11266 | Memory retrieval stage 3 — embedding/rerank | dump 18140 | F05299 | non-negotiable | false | 10 |
| R11267 | Memory retrieval stage 4 — graph expansion | dump 18141 | F05300 | non-negotiable | false | 10 |
| R11268 | Memory retrieval stage 5 — oracle synthesis only if needed | dump 18142 | F05301 | non-negotiable | false | 10 |
| R11269 | Memory rule — do not throw every memory query at a model | dump 18145 | F05302 | non-negotiable | false | 10 |
| R11270 | Tool scheduling — read-only tools can run early and parallel | dump 18155-18156 | F05303 | non-negotiable | false | 10 |
| R11271 | Tool scheduling — write tools require snapshot/policy | dump 18158-18159 | F05304 | non-negotiable | false | 10 |
| R11272 | Tool scheduling — network tools require profile permission | dump 18161-18162 | F05305 | non-negotiable | false | 10 |
| R11273 | Tool scheduling — long tests can run async, branch hibernates | dump 18164-18165 | F05306 | non-negotiable | false | 10 |
| R11274 | Tool scheduling — destructive tools require human gate | dump 18167-18168 | F05307 | non-negotiable | false | 10 |
| R11275 | Backpressure — Blackwell VRAM high: reduce context, evict low-value KV, switch smaller oracle | dump 18175-18177 | F05308 | non-negotiable | false | 10 |
| R11276 | Backpressure — 3090 busy: reduce branch width, use CPU classifiers | dump 18179-18180 | F05309 | non-negotiable | false | 10 |
| R11277 | Backpressure — CPU pressure high: defer background indexing/evals | dump 18182-18183 | F05310 | non-negotiable | false | 10 |
| R11278 | Backpressure — RAM pressure high: hibernate branches, compact memory | dump 18185-18186 | F05311 | non-negotiable | false | 10 |
| R11279 | Backpressure — IO pressure high: delay cold scans, avoid large snapshots | dump 18188-18189 | F05312 | non-negotiable | false | 10 |
| R11280 | Backpressure — human gate queue high: batch approvals, lower autonomy | dump 18191-18192 | F05313 | non-negotiable | false | 10 |
| R11281 | PSI ingestion — /proc/pressure/cpu, /proc/pressure/memory, /proc/pressure/io | dump 18197 | F05314 | non-negotiable | false | 10 |
| R11282 | DCGM ingestion — NVIDIA Data Center GPU Manager queryable | dump 18197 | F05315 | non-negotiable | false | 10 |
| R11283 | MS027 trace ingestion — scheduler reads its own trace for human-gate latency | dump 18197 | F05316 | non-negotiable | false | 10 |
| R11284 | Objective: maximize useful intelligence per unit of latency | dump 18206 | F05317 | non-negotiable | false | 10 |
| R11285 | Objective: maximize useful intelligence per unit of cost | dump 18207 | F05318 | non-negotiable | false | 10 |
| R11286 | Objective: maximize useful intelligence per unit of risk | dump 18208 | F05319 | non-negotiable | false | 10 |
| R11287 | Objective: maximize useful intelligence per unit of energy | dump 18209 | F05320 | non-negotiable | false | 10 |
| R11288 | Objective: maximize useful intelligence per unit of human attention | dump 18210 | F05321 | non-negotiable | false | 10 |
| R11289 | Objective: maximize useful intelligence per unit of hardware pressure | dump 18211 | F05322 | non-negotiable | false | 10 |
| R11290 | Per-profile weight matrix — 7-axis weights vary by profile | architecture (derived from 18004-18040) | F05281-F05286 + F05317-F05322 | non-negotiable | false | 10 |

### Per-profile 7-axis weight matrix (R11291-R11332)

| requirement | text | source | feature | severity | depends_on_other_ms | sub_reqs |
|---|---|---|---|---|---|---|
| R11291 | fast profile latency weight = high (1.0) | dump 18011-18014 + architecture | F05281 | non-negotiable | false | 10 |
| R11292 | fast profile cost weight = low (0.3) | architecture | F05281 | non-negotiable | false | 10 |
| R11293 | fast profile risk weight = low (0.3) | architecture | F05281 | non-negotiable | false | 10 |
| R11294 | fast profile energy weight = low (0.2) | architecture | F05281 | non-negotiable | false | 10 |
| R11295 | fast profile human-attention weight = low (0.2) | architecture | F05281 | non-negotiable | false | 10 |
| R11296 | fast profile hardware-pressure weight = medium (0.5) | architecture | F05281 | non-negotiable | false | 10 |
| R11297 | careful profile latency weight = medium (0.5) | dump 18016-18019 | F05282 | non-negotiable | false | 10 |
| R11298 | careful profile cost weight = medium (0.5) | architecture | F05282 | non-negotiable | false | 10 |
| R11299 | careful profile risk weight = high (1.0) | architecture | F05282 | non-negotiable | false | 10 |
| R11300 | careful profile energy weight = medium (0.5) | architecture | F05282 | non-negotiable | false | 10 |
| R11301 | careful profile human-attention weight = high (0.9) | architecture | F05282 | non-negotiable | false | 10 |
| R11302 | careful profile hardware-pressure weight = high (0.9) | architecture | F05282 | non-negotiable | false | 10 |
| R11303 | private profile latency weight = medium (0.5) | dump 18021-18024 | F05283 | non-negotiable | false | 10 |
| R11304 | private profile cost weight = irrelevant (cloud disabled) | architecture | F05283 | non-negotiable | false | 10 |
| R11305 | private profile risk weight = high (1.0) | architecture | F05283 | non-negotiable | false | 10 |
| R11306 | private profile energy weight = low (0.3) | architecture | F05283 | non-negotiable | false | 10 |
| R11307 | private profile memory-exposure weight = strict (must-not-cross) | dump 18023 | F05283 | non-negotiable | false | 10 |
| R11308 | private profile hardware-pressure weight = medium (0.5) | architecture | F05283 | non-negotiable | false | 10 |
| R11309 | autonomous profile latency weight = medium (0.5) | dump 18026-18030 | F05284 | non-negotiable | false | 10 |
| R11310 | autonomous profile continuity weight = high (1.0) | dump 18027 | F05284 | non-negotiable | false | 10 |
| R11311 | autonomous profile sandbox-first invariant | dump 18029 | F05284 | non-negotiable | false | 10 |
| R11312 | autonomous profile checkpoint-often invariant | dump 18030 | F05284 | non-negotiable | false | 10 |
| R11313 | autonomous profile human-attention weight = low (batch approvals) | dump 18028 | F05284 | non-negotiable | false | 10 |
| R11314 | autonomous profile hardware-pressure weight = medium (0.5) | architecture | F05284 | non-negotiable | false | 10 |
| R11315 | experimental profile branch-width = wide | dump 18033 | F05285 | non-negotiable | false | 10 |
| R11316 | experimental profile sandbox-only invariant | dump 18034 | F05285 | non-negotiable | false | 10 |
| R11317 | experimental profile no-host-commit invariant | dump 18035 | F05285 | non-negotiable | false | 10 |
| R11318 | experimental profile risk weight = low (sandboxed) | architecture | F05285 | non-negotiable | false | 10 |
| R11319 | experimental profile cost weight = low (encourage exploration) | architecture | F05285 | non-negotiable | false | 10 |
| R11320 | experimental profile hardware-pressure weight = low (0.3) | architecture | F05285 | non-negotiable | false | 10 |
| R11321 | production profile latency weight = high (0.9) | dump 18037-18040 | F05286 | non-negotiable | false | 10 |
| R11322 | production profile cost weight = medium (0.7) | architecture | F05286 | non-negotiable | false | 10 |
| R11323 | production profile risk weight = strict (must-not-cross) | dump 18038 | F05286 | non-negotiable | false | 10 |
| R11324 | production profile commit-gate invariant — every commit observable | dump 18038 | F05286 | non-negotiable | false | 10 |
| R11325 | production profile variance weight = low (deterministic) | dump 18039 | F05286 | non-negotiable | false | 10 |
| R11326 | production profile observability weight = high (1.0) | dump 18040 | F05286 | non-negotiable | false | 10 |
| R11327 | Per-profile weight matrix encoded as data, not code (operator-tunable) | architecture | F05286 | non-negotiable | false | 10 |
| R11328 | Per-profile weight matrix change requires MS003 multi-sig (production-tier values) | cross-ref MS003 | F05286 | non-negotiable | false | 10 |
| R11329 | Weight values normalized to [0,1] per axis | architecture | F05290 | non-negotiable | false | 10 |
| R11330 | Compound 7th axis = function(other 6) (operator-defined coupling) | architecture | F05290 | non-negotiable | false | 10 |
| R11331 | Weight matrix surfaced via `selfdefctl scheduler weights show --profile <p>` | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11332 | Weight matrix mutation logged to ZFS audit (sync=always) | architecture + MS044 | F05342 | non-negotiable | false | 10 |

### Backpressure trigger thresholds (R11333-R11362)

| requirement | text | source | feature | severity | depends_on_other_ms | sub_reqs |
|---|---|---|---|---|---|---|
| R11333 | Blackwell VRAM high threshold = 90% utilization | architecture | F05308 | non-negotiable | false | 10 |
| R11334 | Blackwell VRAM high response: reduce context = halve max_tokens budget | dump 18175-18177 | F05308 | non-negotiable | false | 10 |
| R11335 | Blackwell VRAM high response: evict low-value KV = LRU policy | architecture | F05308 | non-negotiable | false | 10 |
| R11336 | Blackwell VRAM high response: switch to smaller oracle (fallback table) | architecture | F05308 | non-negotiable | false | 10 |
| R11337 | 3090 GPU busy threshold = 80% utilization sustained 5s | architecture | F05309 | non-negotiable | false | 10 |
| R11338 | 3090 busy response: reduce branch width = N//2 | dump 18180 | F05309 | non-negotiable | false | 10 |
| R11339 | 3090 busy response: CPU classifiers as substitute | dump 18180 | F05309 | non-negotiable | false | 10 |
| R11340 | CPU pressure high threshold = PSI cpu some/avg10 > 50% | dump 18182 | F05310 | non-negotiable | false | 10 |
| R11341 | CPU pressure response: defer background indexing | dump 18183 | F05310 | non-negotiable | false | 10 |
| R11342 | CPU pressure response: defer evals queue | dump 18183 | F05310 | non-negotiable | false | 10 |
| R11343 | RAM pressure high threshold = PSI memory some/avg10 > 30% | dump 18185 | F05311 | non-negotiable | false | 10 |
| R11344 | RAM pressure response: hibernate branches (suspend, persist KV to ZFS) | dump 18186 | F05311 | non-negotiable | false | 10 |
| R11345 | RAM pressure response: compact memory graph | dump 18186 | F05311 | non-negotiable | false | 10 |
| R11346 | IO pressure high threshold = PSI io some/avg10 > 40% | dump 18188 | F05312 | non-negotiable | false | 10 |
| R11347 | IO pressure response: delay cold scans (deferred scan queue) | dump 18189 | F05312 | non-negotiable | false | 10 |
| R11348 | IO pressure response: avoid large ZFS snapshots (snapshot queue throttle) | dump 18189 | F05312 | non-negotiable | false | 10 |
| R11349 | Human gate queue high threshold = > 5 pending approvals | architecture | F05313 | non-negotiable | false | 10 |
| R11350 | Human gate response: batch approvals (multi-select operator UI) | dump 18192 | F05313 | non-negotiable | false | 10 |
| R11351 | Human gate response: lower autonomy (profile shift to careful temporarily) | dump 18192 | F05313 | non-negotiable | false | 10 |
| R11352 | All thresholds operator-tunable via /etc/selfdef/scheduler.toml | architecture | F05308-F05313 | non-negotiable | false | 10 |
| R11353 | Threshold change requires MS003 multi-sig (production-tier values) | cross-ref MS003 | F05352 | non-negotiable | false | 10 |
| R11354 | Threshold change logged to ZFS audit | architecture + MS044 | F05342 | non-negotiable | false | 10 |
| R11355 | Threshold breach emits MS027 trace span with breach_kind label | architecture + MS027 | F05341 | non-negotiable | false | 10 |
| R11356 | Threshold breach emits OCSF Detection 2004 event | cross-ref MS026 | F05349 | non-negotiable | false | 10 |
| R11357 | Hysteresis: threshold-breach exits when measurement < threshold - 10% for 10s | architecture | F05308-F05313 | non-negotiable | false | 10 |
| R11358 | Concurrent breaches: AND-of-responses applied (e.g. VRAM+CPU both high) | architecture | F05308-F05313 | non-negotiable | false | 10 |
| R11359 | Breach response idempotent (re-entering pressure state no-ops if already applied) | architecture | F05308-F05313 | non-negotiable | false | 10 |
| R11360 | Backpressure surface state machine state visible via /v1/scheduler/backpressure | architecture + MS043 | F05347 | non-negotiable | false | 10 |
| R11361 | Backpressure responses NEVER mutate authority (Ring 0 + MS003 unaffected) | architecture + MS039 | F05344 | non-negotiable | false | 10 |
| R11362 | Backpressure responses preserve in-flight requests (no kill, only re-route or defer) | architecture | F05344 | non-negotiable | false | 10 |

### Decision emitter + audit chain (R11363-R11392)

| requirement | text | source | feature | severity | depends_on_other_ms | sub_reqs |
|---|---|---|---|---|---|---|
| R11363 | Every scheduling decision emits MS027 trace span | architecture + MS027 | F05341 | non-negotiable | false | 10 |
| R11364 | Trace span includes request_id, profile, chosen_route, 7-axis breakdown | architecture | F05341 | non-negotiable | false | 10 |
| R11365 | Trace span includes backpressure state at decision time | architecture | F05341 | non-negotiable | false | 10 |
| R11366 | Every decision appended to /mnt/vault/context/scheduler_audit.log (ZFS sync=always) | architecture + MS044 pattern | F05342 | non-negotiable | false | 10 |
| R11367 | Audit log uses chained SHA-256 prev_event_sha256 (like Guardian/perimeter) | architecture + MS044 | F05342 | non-negotiable | false | 10 |
| R11368 | Audit log chain integrity check via `selfdefctl scheduler audit-cycle replay` | architecture + MS009 | F05343 | non-negotiable | false | 10 |
| R11369 | OCSF Detection 2004 emission on backpressure-triggered routing | cross-ref MS026 | F05349 | non-negotiable | false | 10 |
| R11370 | OCSF Audit 1003 emission on routine routing | cross-ref MS026 | F05349 | non-negotiable | false | 10 |
| R11371 | Audit log entries include scheduler version (semver) | architecture | F05342 | non-negotiable | false | 10 |
| R11372 | Audit log entries include policy SHA-256 (the rule-matrix in effect) | architecture | F05342 | non-negotiable | false | 10 |
| R11373 | Audit log replayable against a different policy SHA-256 (counterfactual) | architecture + MS009 | F05343 | non-negotiable | false | 10 |
| R11374 | Decision audit log readable from /v1/scheduler/history endpoint | architecture + MS043 | F05347 | non-negotiable | false | 10 |
| R11375 | Decision audit log queryable from selfdefctl scheduler explain <request-id> | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11376 | Decision audit log shipped to MS027 observability sinks (Loki, OpenSearch) | cross-ref MS027 | F05368 | non-negotiable | false | 10 |
| R11377 | Decision audit log entries TTL = persistent (never auto-evicted) | architecture | F05342 | non-negotiable | false | 10 |
| R11378 | Audit log evolves only via MS003-signed log-rotation operator action | cross-ref MS003 | F05342 | non-negotiable | false | 10 |
| R11379 | Audit log corruption detection inside coherence harness (L1 audit-chain-check) | cross-ref MS045 | F05343 | non-negotiable | false | 10 |
| R11380 | Audit log entry size budget — 1KB target, 4KB hard cap | architecture | F05342 | non-negotiable | false | 10 |
| R11381 | Audit log writes use append-only O_APPEND + fsync per entry | architecture + MS044 pattern | F05342 | non-negotiable | false | 10 |
| R11382 | Audit log directory mode 0750 owned by selfdef:selfdef | architecture | F05342 | non-negotiable | false | 10 |
| R11383 | Audit log entries include 8-axis choice surface at decision time | dump 18296-18305 | F05336 | non-negotiable | false | 10 |
| R11384 | Audit log entries include resulting decision rationale (free-form ≤512 chars) | architecture | F05342 | non-negotiable | false | 10 |
| R11385 | Audit log entries include downstream-effect prediction (route taken, expected ms, expected cost) | architecture | F05342 | non-negotiable | false | 10 |
| R11386 | Audit log entries include actual vs predicted (when post-execution closes loop) | architecture | F05342 | non-negotiable | false | 10 |
| R11387 | Audit log entries support replay diff (predicted vs actual delta) | architecture + MS009 | F05343 | non-negotiable | false | 10 |
| R11388 | Audit log entries include human-gate latency when operator decision was on path | architecture | F05316 | non-negotiable | false | 10 |
| R11389 | Audit log entries support operator-tagged "this was bad" / "this was good" feedback | architecture | F05342 | non-negotiable | false | 10 |
| R11390 | Audit log feedback feeds into the scheduler's weight-matrix evolution (manual at first) | architecture | F05290 | non-negotiable | false | 10 |
| R11391 | Audit log MS007 typed-mirror crate exports it for sovereign-os cockpit | cross-ref MS007 | F05348 | non-negotiable | false | 10 |
| R11392 | Audit log read-only invariant: even Ring 0 cannot edit past entries | architecture + MS039 | F05342 | non-negotiable | false | 10 |

### Replay engine + operator override + concrete-example fixtures (R11393-R11422)

| requirement | text | source | feature | severity | depends_on_other_ms | sub_reqs |
|---|---|---|---|---|---|---|
| R11393 | Replay engine replays past decision against current policy | architecture + MS009 | F05343 | non-negotiable | false | 10 |
| R11394 | Replay engine NEVER re-executes the request (read-only on the world) | architecture + MS009 | F05343 | non-negotiable | false | 10 |
| R11395 | Replay engine produces "would have routed to X under current policy" diff | architecture + MS009 | F05343 | non-negotiable | false | 10 |
| R11396 | Replay engine supports counterfactual: replay against alternate profile | architecture | F05343 | non-negotiable | false | 10 |
| R11397 | Replay engine surface: selfdefctl scheduler replay <request-id> [--profile <p>] | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11398 | Replay engine surface: GET /v1/scheduler/replay/<request-id> | architecture + MS043 | F05347 | non-negotiable | false | 10 |
| R11399 | Operator override: selfdefctl scheduler force <request-id> --route <route> | architecture + MS039 | F05344 | non-negotiable | false | 10 |
| R11400 | Operator override requires Ring 0 + MS003 signature | architecture + MS003 + MS039 | F05344 | non-negotiable | false | 10 |
| R11401 | Operator override recorded in audit log with override_kid field | architecture + MS044 | F05344 | non-negotiable | false | 10 |
| R11402 | Operator override TTL = single-request (does NOT alter weight matrix) | architecture | F05344 | non-negotiable | false | 10 |
| R11403 | Concrete decision example — code-bug Map step encoded as test fixture | dump 18213-18214 | F05339 | non-negotiable | false | 10 |
| R11404 | Concrete decision example — code-bug Draft step (3090, 4 candidates) test fixture | dump 18216-18217 | F05339 | non-negotiable | false | 10 |
| R11405 | Concrete decision example — code-bug Filter step (AVX checks) test fixture | dump 18219-18220 | F05339 | non-negotiable | false | 10 |
| R11406 | Concrete decision example — code-bug Verify step (Blackwell top 2) test fixture | dump 18222-18223 | F05339 | non-negotiable | false | 10 |
| R11407 | Concrete decision example — code-bug Test step (sandbox) test fixture | dump 18225-18226 | F05339 | non-negotiable | false | 10 |
| R11408 | Concrete decision example — code-bug Commit step (ZFS snapshot + apply) test fixture | dump 18228-18229 | F05339 | non-negotiable | false | 10 |
| R11409 | Blackwell-busy fallback example: 3090 generates more diagnostics | dump 18234 | F05340 | non-negotiable | false | 10 |
| R11410 | Blackwell-busy fallback example: CPU runs static checks | dump 18235 | F05340 | non-negotiable | false | 10 |
| R11411 | Blackwell-busy fallback example: memory retrieves similar failures | dump 18236 | F05340 | non-negotiable | false | 10 |
| R11412 | Slow-tests fallback: branch hibernates | dump 18245 | F05332 | non-negotiable | false | 10 |
| R11413 | Slow-tests fallback: other work proceeds | dump 18246 | F05332 | non-negotiable | false | 10 |
| R11414 | Slow-tests fallback: resume on test result | dump 18247 | F05332 | non-negotiable | false | 10 |
| R11415 | Eight-axis choice — fast/careful exposed as `--profile` CLI arg | dump 18296 | F05336 | non-negotiable | false | 10 |
| R11416 | Eight-axis choice — local/cloud exposed as profile guard | dump 18297 | F05336 | non-negotiable | false | 10 |
| R11417 | Eight-axis choice — scout/oracle exposed as route hint | dump 18298 | F05336 | non-negotiable | false | 10 |
| R11418 | Eight-axis choice — sandbox/host exposed as execution-tier flag | dump 18299 | F05336 | non-negotiable | false | 10 |
| R11419 | Eight-axis choice — manual/autonomous exposed as profile | dump 18300 | F05336 | non-negotiable | false | 10 |
| R11420 | Eight-axis choice — private/shared exposed as memory-exposure flag | dump 18301 | F05336 | non-negotiable | false | 10 |
| R11421 | Eight-axis choice — cheap/best exposed as cost-budget hint | dump 18302 | F05336 | non-negotiable | false | 10 |
| R11422 | Eight-axis choice — exploratory/spec-driven exposed as workflow flag | dump 18303 | F05336 | non-negotiable | false | 10 |

### TUI/CLI/HTTP-API surfaces (R11423-R11447)

| requirement | text | source | feature | severity | depends_on_other_ms | sub_reqs |
|---|---|---|---|---|---|---|
| R11423 | CLI subverb — selfdefctl scheduler show [--json] | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11424 | CLI subverb — selfdefctl scheduler history [--limit N] [--json] | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11425 | CLI subverb — selfdefctl scheduler explain <request-id> [--json] | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11426 | CLI subverb — selfdefctl scheduler replay <request-id> [--profile P] [--json] | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11427 | CLI subverb — selfdefctl scheduler weights show --profile <p> [--json] | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11428 | CLI subverb — selfdefctl scheduler force <request-id> --route R (Ring 0) | architecture + MS039 | F05346 | non-negotiable | false | 10 |
| R11429 | CLI subverb — selfdefctl scheduler audit-cycle replay [--json] | architecture + MS009 | F05346 | non-negotiable | false | 10 |
| R11430 | CLI surface gates L1-cli-surface.sh: scheduler == 7 subverbs | cross-ref MS045 | F05346 | non-negotiable | false | 10 |
| R11431 | HTTP API — GET /v1/scheduler — current state + last 16 decisions | architecture + MS043 | F05347 | non-negotiable | false | 10 |
| R11432 | HTTP API — GET /v1/scheduler/history?limit=N — decision history | architecture + MS043 | F05347 | non-negotiable | false | 10 |
| R11433 | HTTP API — GET /v1/scheduler/backpressure — backpressure state | architecture + MS043 | F05347 | non-negotiable | false | 10 |
| R11434 | HTTP API — GET /v1/scheduler/weights?profile=P — weight matrix readout | architecture + MS043 | F05347 | non-negotiable | false | 10 |
| R11435 | HTTP API — GET /v1/scheduler/explain/:request-id — single-decision detail | architecture + MS043 | F05347 | non-negotiable | false | 10 |
| R11436 | HTTP API endpoint gate L1-api-endpoints.sh: 5 scheduler routes | cross-ref MS045 | F05347 | non-negotiable | false | 10 |
| R11437 | TUI panel — scheduler row in main dashboard | dump 18044 + MS043 | F05345 | non-negotiable | false | 10 |
| R11438 | TUI panel — shows current backpressure state per resource | architecture + MS043 | F05345 | non-negotiable | false | 10 |
| R11439 | TUI panel — shows last decision 7-axis breakdown | architecture + MS043 | F05345 | non-negotiable | false | 10 |
| R11440 | TUI panel — j/k navigation between recent decisions | cross-ref MS043 F05086 | F05345 | non-negotiable | false | 10 |
| R11441 | TUI panel — Enter drills into decision detail | cross-ref MS043 F05086 | F05345 | non-negotiable | false | 10 |
| R11442 | Operator dashboard — scheduler section in dashboard/index.html | architecture + MS043 | F05345 | non-negotiable | false | 10 |
| R11443 | Operator dashboard — scheduler section auto-refresh every 10s | architecture + MS043 | F05345 | non-negotiable | false | 10 |
| R11444 | Operator dashboard — scheduler section WCAG AA 4.5:1 contrast | cross-ref MS043 R10175 | F05345 | non-negotiable | false | 10 |
| R11445 | Coherence harness — L1-dashboard-sections.sh covers scheduler section | cross-ref MS045 | F05345 | non-negotiable | false | 10 |
| R11446 | selfdefctl trio --watch shows scheduler aggregate alongside trio | architecture + MS043 | F05346 | non-negotiable | false | 10 |
| R11447 | Cockpit panel (sovereign-os) — sovereign-cockpit-scheduler-panel crate (project-boundary preserved) | cross-ref MS007 + sovereign-os | F05348 | non-negotiable | false | 10 |

### Operator runbooks + systemd + Debian + cross-repo mirror + L1-L5 tests (R11448-R11480)

| requirement | text | source | feature | severity | depends_on_other_ms | sub_reqs |
|---|---|---|---|---|---|---|
| R11448 | Operator runbook — scheduler-not-running (info-hub) | cross-ref MS043 | F05346 | non-negotiable | false | 10 |
| R11449 | Operator runbook — scheduler-backpressure-stuck-open | architecture + MS027 | F05308-F05313 | non-negotiable | false | 10 |
| R11450 | Operator runbook — scheduler-weight-matrix-rotation (MS003 multi-sig) | architecture + MS003 | F05290 | non-negotiable | false | 10 |
| R11451 | Operator runbook — scheduler-audit-log-corruption | architecture + MS044 pattern | F05343 | non-negotiable | false | 10 |
| R11452 | Operator runbook — scheduler-force-override-investigation | architecture + MS039 | F05344 | non-negotiable | false | 10 |
| R11453 | 5 runbooks total in ~/devops-solutions-information-hub/wiki/runbooks/ | cross-ref MS043 | F05373 | non-negotiable | false | 10 |
| R11454 | systemd unit selfdef-scheduler.service Type=simple Restart=always | cross-ref MS044 systemd pattern | F05348 | non-negotiable | false | 10 |
| R11455 | systemd unit After=tetragon.service zfs-mount.service selfdef-guardian.service | architecture | F05348 | non-negotiable | false | 10 |
| R11456 | systemd unit Ring 0 (User=root Group=root) per MS039 | cross-ref MS039 | F05348 | non-negotiable | false | 10 |
| R11457 | systemd unit hardening — ProtectSystem=strict + ReadWritePaths=/mnt/vault/context | cross-ref MS044 | F05348 | non-negotiable | false | 10 |
| R11458 | systemd unit StartLimitIntervalSec=60s + StartLimitBurst=10 (restart-storm cap) | cross-ref MS044 | F05348 | non-negotiable | false | 10 |
| R11459 | Debian postinst installs scheduler unit + creates /var/cache/selfdef/scheduler/ring | cross-ref MS044 | F05348 | non-negotiable | false | 10 |
| R11460 | Debian postrm purge: disable+stop+remove scheduler unit | cross-ref MS044 | F05348 | non-negotiable | false | 10 |
| R11461 | Cargo-deb assets ship selfdef-scheduler.service to /usr/share/selfdef/ | cross-ref MS044 | F05348 | non-negotiable | false | 10 |
| R11462 | Cross-repo mirror crate selfdef-scheduler-mirror (MS007 typed-mirror) | cross-ref MS007 | F05348 | non-negotiable | false | 10 |
| R11463 | Mirror crate exports Decision { request_id, profile, route, 7-axis, ts_ms, hostname, signer_kid } | cross-ref MS007 | F05348 | non-negotiable | false | 10 |
| R11464 | Mirror crate forbid(unsafe_code) + warn(missing_docs) | architecture | F05348 | non-negotiable | false | 10 |
| R11465 | Mirror crate SCHEMA_VERSION = "1.0.0" + validate() invariants | cross-ref MS007 | F05348 | non-negotiable | false | 10 |
| R11466 | L1 test — yamllint scheduler.toml.example | cross-ref MS045 | F05373 | non-negotiable | false | 10 |
| R11467 | L1 test — CLI surface 7 subverbs locked | cross-ref MS045 | F05346 | non-negotiable | false | 10 |
| R11468 | L1 test — API endpoint declarations locked (5 routes) | cross-ref MS045 | F05347 | non-negotiable | false | 10 |
| R11469 | L1 test — dashboard section present | cross-ref MS045 | F05345 | non-negotiable | false | 10 |
| R11470 | L2 bats — systemd unit hardening surface verified | cross-ref MS044 | F05348 | non-negotiable | false | 10 |
| R11471 | L2 bats — postinst/postrm install/uninstall flow | cross-ref MS044 | F05348 | non-negotiable | false | 10 |
| R11472 | L3 nspawn — scheduler boot-time decision replay (hardware-gated) | architecture | F05348 | non-negotiable | false | 10 |
| R11473 | L4 znver5 — full-stack hardware sched decision against real PSI+DCGM | dump 18197 | F05314-F05315 | non-negotiable | false | 10 |
| R11474 | L5 chaos — kill scheduler mid-decision, verify Restart=always + audit chain integrity | cross-ref MS044 | F05348 | non-negotiable | false | 10 |
| R11475 | Cargo unit tests — selfdef-scheduler + selfdef-scheduler-mirror in coherence harness | cross-ref MS045 | F05373 | non-negotiable | false | 10 |
| R11476 | sovereign-os cockpit panel crate sovereign-cockpit-scheduler-panel (no selfdef dep) | cross-ref MS007 | F05348 | non-negotiable | false | 10 |
| R11477 | Cockpit panel renders selfdef-emitted scheduler JSON at filesystem boundary | cross-ref MS007 | F05348 | non-negotiable | false | 10 |
| R11478 | Cockpit panel runbook links point at info-hub scheduler-* runbooks | architecture | F05348 | non-negotiable | false | 10 |
| R11479 | Closing — MS048 covers avx-plus-plus dump tail lines 18000-18250 verbatim | dump 18000-18250 | F05334 | non-negotiable | false | 10 |
| R11480 | Closing — selfdef catalog at 48/48 milestones with MS048 landed; backward-sweep loop closed | architecture + operator standing direction | F05334 | non-negotiable | false | 10 |

## Cross-cutting wiring

| MS048 R-row | Bound to | Across milestone |
|---|---|---|
| R11241-R11247 | Doctrinal anchors | MS040 + MS024 + MS027 + MS039 |
| R11248-R11254 | Per-profile rules | MS040 (six-profile envelope) |
| R11255-R11263 | Blackwell + KV/Context | MS028 (BitNet GPU inference) + MS030 (tensor parallel) |
| R11264-R11269 | Memory pipeline | MS027 (observability) + future memory-graph crate |
| R11270-R11274 | Tool routing | MS042 (tool authority) + MS036 (tool sandboxes) |
| R11275-R11283 | Backpressure + PSI/DCGM | MS027 + MS044 (Guardian — can't replay during VRAM-high) |
| R11284-R11290 | 7-axis objective | crosscut |

## Production-readiness gates (first-round)

| Gate | Verification |
|---|---|
| SDD-031 spec authored | `test -f docs/sdd/031-goldilocks-scheduler.md` |
| selfdef-scheduler-mirror crate compiles + tests | `cargo test -p selfdef-scheduler-mirror` exit 0 |
| selfdef-scheduler runtime crate compiles + tests | `cargo test -p selfdef-scheduler` exit 0 |
| Per-profile rule tuples validated against verbatim dump | each F05281-F05286 anchored to dump line numbers |
| 6 per-profile rule sets encoded + 5 backpressure surfaces wired | unit tests cover both |

## Implementation order (first-round only — later rounds expand)

1. SDD-031 spec (this milestone's Stage-1)
2. selfdef-scheduler-mirror crate (MS007 typed-mirror pattern)
3. selfdef-scheduler runtime crate (objective fn + profile-rule lookup + backpressure decision table)
4. CLI `selfdefctl scheduler show` (read-only first)
5. HTTP API `/v1/scheduler` (read-only first)
6. Cockpit panel binding (sovereign-os crate)
7. Operator runbooks
8. PSI / DCGM real-source bridges (require host hardware — gated)

This milestone authorizes Stage-2 implementation. Mark DONE only when
all first-round deliverables are in production AND the second-round
R11291-R11480 expansion is catalogued.

## Cross-references

- avx-plus-plus dump tail backward-sweep review: `~/devops-solutions-information-hub/wiki/log/2026-05-20-avx-plus-plus-dump-tail-backward-sweep-review.md`
- MS040 (six-profile authority matrix — scheduling rules elaborate the profiles)
- MS024 (communication boundary — scheduling surfaces operate within it)
- MS027 (observability — scheduler emits trace points)
- MS028-MS030 (inference modules — scheduler routes between them)
- MS044 (Guardian — VRAM/CPU/RAM backpressure affects replay)
- Three-watchdog trio production discipline (MS046+MS047+MS044) — template for MS048's own production discipline
