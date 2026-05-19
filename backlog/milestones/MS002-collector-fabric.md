# MS002 — Collector fabric — auditd / journald / eBPF / Tetragon / Suricata / eventstream / canary

> Parent: `backlog/milestones/INDEX.md` row MS002.
> Source: existing repo crates `selfdef-collector-{auditd,canary,ebpf,eventstream,journald,suricata,tetragon}` + `selfdef-ebpf-common` + `bpf/selfdef-bpf/` + `rules/{sigma,tetragon,yara}/` + selfdef-defense scope (IPS-side; NOT sovereign-os runtime scope).

## Epics (E0011–E0020)

| Epic ID | Phrase | Source |
|---|---|---|
| E0011 | Collector fabric — 7 named collectors feeding the event bus | `crates/selfdef-collector-*` (7 crates) |
| E0012 | auditd collector — Linux audit subsystem ingest | `crates/selfdef-collector-auditd` |
| E0013 | journald collector — systemd journal ingest | `crates/selfdef-collector-journald` |
| E0014 | eBPF collector — kernel-side observation via eBPF programs | `crates/selfdef-collector-ebpf` + `bpf/selfdef-bpf/` + `crates/selfdef-ebpf-common` |
| E0015 | Tetragon collector — TracingPolicy ingest | `crates/selfdef-collector-tetragon` + `rules/tetragon/` |
| E0016 | Suricata collector — IDS/IPS alerts + EVE JSON ingest | `crates/selfdef-collector-suricata` + `modules/suricata` |
| E0017 | eventstream collector — internal selfdef event ingest (SSE) | `crates/selfdef-collector-eventstream` |
| E0018 | canary collector — honeytoken trigger detection | `crates/selfdef-collector-canary` |
| E0019 | Sigma rules pack — 9-category detection-rule library | `rules/sigma/` (9 subdirs) |
| E0020 | Collector contract — every collector emits `Event` envelope with `Identity` + `Subject` + payload + timestamp | `crates/selfdef-core` + `crates/selfdef-bus` |

## Modules (M00027–M00052)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00027 | auditd parser — auditd rule output line parser | `crates/selfdef-collector-auditd` Parser | E0012 |
| M00028 | auditd rule loader — operator-defined audit rules → kernel | `crates/selfdef-collector-auditd` RuleLoader | E0012 |
| M00029 | journald reader — systemd journal cursor reader | `crates/selfdef-collector-journald` Reader | E0013 |
| M00030 | journald structured-field extractor — JSON priority / unit / pid / SYSLOG_IDENTIFIER | `crates/selfdef-collector-journald` Extractor | E0013 |
| M00031 | eBPF program — file-touch observer (open / openat / unlink / unlinkat) | `bpf/selfdef-bpf/` + `crates/selfdef-collector-ebpf` | E0014 |
| M00032 | eBPF program — network-attempt observer (connect / accept / sendto) | `bpf/selfdef-bpf/` + `crates/selfdef-collector-ebpf` | E0014 |
| M00033 | eBPF program — process-spawn observer (execve / clone) | `bpf/selfdef-bpf/` + `crates/selfdef-collector-ebpf` | E0014 |
| M00034 | eBPF program — syscall-latency observer | `bpf/selfdef-bpf/` + `crates/selfdef-collector-ebpf` | E0014 |
| M00035 | eBPF common — shared eBPF maps + ring-buffer + perf-event userspace bridge | `crates/selfdef-ebpf-common` | E0014 |
| M00036 | Tetragon TracingPolicy loader — kube-style policy CRD ingest | `crates/selfdef-collector-tetragon` | E0015 |
| M00037 | Tetragon observe-sensitive-files policy | `rules/tetragon/observe-sensitive-files.yaml` | E0015 |
| M00038 | TracingPolicy signing — operator-signed policies only (audit-shipped opt-in) | `crates/selfdef-signing` + Tetragon | E0015 |
| M00039 | Suricata EVE-JSON parser — alert / fileinfo / dns / http / tls / flow extractor | `crates/selfdef-collector-suricata` EveParser | E0016 |
| M00040 | Suricata rule package — community + emerging-threats + custom | `modules/suricata/` rule paths | E0016 |
| M00041 | Suricata canary smoke rule — SID 2100498 testmynids.org trigger | `modules/suricata/` + selfdef README §"Operator quick-start" | E0016 |
| M00042 | eventstream SSE source — selfdef daemon's own /v1/events stream re-ingested | `crates/selfdef-collector-eventstream` | E0017 |
| M00043 | eventstream integrity — signed-event-stream invariant (audit-shipped opt-in) | `crates/selfdef-collector-eventstream` + `crates/selfdef-signing` | E0017 |
| M00044 | canary file trigger — honeyfile access detection | `crates/selfdef-collector-canary` | E0018 |
| M00045 | canary network trigger — honeyservice connect detection | `crates/selfdef-collector-canary` | E0018 |
| M00046 | canary token trigger — fake API-key use detection | `crates/selfdef-collector-canary` | E0018 |
| M00047 | Sigma rule pack — command_and_control category | `rules/sigma/command_and_control/` | E0019 |
| M00048 | Sigma rule pack — credential_access category | `rules/sigma/credential_access/` | E0019 |
| M00049 | Sigma rule pack — defense_evasion + discovery + execution categories | `rules/sigma/{defense_evasion,discovery,execution}/` | E0019 |
| M00050 | Sigma rule pack — hardening + impact categories | `rules/sigma/{hardening,impact}/` | E0019 |
| M00051 | Sigma rule pack — persistence + privilege_escalation categories | `rules/sigma/{persistence,privilege_escalation}/` | E0019 |
| M00052 | Per-collector backpressure policy — operator-tunable per-collector ring-buffer depth | `crates/selfdef-bus` + per-collector cfg | E0011 |

## Features (F00121–F00240)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00121 | Toggle collector — auditd (enabled/disabled) | modules.toml | E0012 | mode | true |
| F00122 | Toggle collector — journald | modules.toml | E0013 | mode | true |
| F00123 | Toggle collector — eBPF | modules.toml | E0014 | mode | true |
| F00124 | Toggle collector — Tetragon | modules.toml | E0015 | mode | true |
| F00125 | Toggle collector — Suricata | modules.toml | E0016 | mode | true |
| F00126 | Toggle collector — eventstream | modules.toml | E0017 | mode | true |
| F00127 | Toggle collector — canary | modules.toml | E0018 | mode | true |
| F00128 | Profile knob — `collectors.enabled = csv` | `crates/selfdef-config` | E0011 | profile | true |
| F00129 | Env var `SELFDEF_COLLECTORS_ENABLED` | `crates/selfdef-config` | E0011 | env_var | true |
| F00130 | CLI `--collectors <csv>` | `crates/selfdef-cli` | E0011 | cli_verb | true |
| F00131 | Dashboard — per-collector status (running / stopped / errored) | `dashboard/` | E0011 | dashboard | true |
| F00132 | Dashboard — per-collector events/sec | `dashboard/` | E0011 | dashboard | true |
| F00133 | API `GET /v1/collectors` (lists all 7 with state) | `crates/selfdef-api` | E0011 | api_endpoint | true |
| F00134 | API `GET /v1/collectors/{name}/stats` | `crates/selfdef-api` | E0011 | api_endpoint | true |
| F00135 | API `POST /v1/collectors/{name}/restart` | `crates/selfdef-api` | E0011 | api_endpoint | true |
| F00136 | Metric `selfdef_collector_events_total{collector}` | every collector | E0011 | observability_metric | true |
| F00137 | Metric `selfdef_collector_errors_total{collector,kind}` | every collector | E0011 | observability_metric | true |
| F00138 | Metric `selfdef_collector_dropped_total{collector}` | every collector | E0011 | observability_metric | true |
| F00139 | auditd rule preset — operator-tunable audit ruleset | `crates/selfdef-collector-auditd` | M00028 | profile | true |
| F00140 | auditd rule preset — `default` (minimal SELinux + sudo + syscall) | preset | M00028 | composite | true |
| F00141 | auditd rule preset — `paranoid` (filesystem + network + process tree) | preset | M00028 | composite | true |
| F00142 | auditd rule preset — `forensic` (everything + execve full argv) | preset | M00028 | composite | true |
| F00143 | auditd event field — `serial` | `crates/selfdef-collector-auditd` | M00027 | data_model | false |
| F00144 | auditd event field — `timestamp` | `crates/selfdef-collector-auditd` | M00027 | data_model | false |
| F00145 | auditd event field — `audit_type` (SYSCALL / EXECVE / PATH / CWD / PROCTITLE / ...) | `crates/selfdef-collector-auditd` | M00027 | data_model | false |
| F00146 | auditd event field — `pid` / `uid` / `gid` / `auid` | `crates/selfdef-collector-auditd` | M00027 | data_model | false |
| F00147 | auditd event field — `subj` (SELinux context) | `crates/selfdef-collector-auditd` | M00027 | data_model | false |
| F00148 | journald field — `_SYSTEMD_UNIT` | `crates/selfdef-collector-journald` | M00030 | data_model | false |
| F00149 | journald field — `MESSAGE` | `crates/selfdef-collector-journald` | M00030 | data_model | false |
| F00150 | journald field — `PRIORITY` | `crates/selfdef-collector-journald` | M00030 | data_model | false |
| F00151 | journald field — `_PID` / `_UID` / `_GID` / `_COMM` / `_EXE` | `crates/selfdef-collector-journald` | M00030 | data_model | false |
| F00152 | journald cursor checkpoint — resumable read across restart | `crates/selfdef-collector-journald` | M00029 | composite | false |
| F00153 | journald unit-filter — operator-tunable include/exclude list | `crates/selfdef-config` | M00029 | profile | true |
| F00154 | eBPF program — `selfdef_open_observer.bpf.c` | `bpf/selfdef-bpf/` | M00031 | composite | true |
| F00155 | eBPF program — `selfdef_unlink_observer.bpf.c` | `bpf/selfdef-bpf/` | M00031 | composite | true |
| F00156 | eBPF program — `selfdef_connect_observer.bpf.c` | `bpf/selfdef-bpf/` | M00032 | composite | true |
| F00157 | eBPF program — `selfdef_accept_observer.bpf.c` | `bpf/selfdef-bpf/` | M00032 | composite | true |
| F00158 | eBPF program — `selfdef_execve_observer.bpf.c` | `bpf/selfdef-bpf/` | M00033 | composite | true |
| F00159 | eBPF program — `selfdef_clone_observer.bpf.c` | `bpf/selfdef-bpf/` | M00033 | composite | true |
| F00160 | eBPF program — `selfdef_syscall_lat.bpf.c` (latency histogram) | `bpf/selfdef-bpf/` | M00034 | composite | true |
| F00161 | eBPF map — `events` ring-buffer (BPF_MAP_TYPE_RINGBUF) | `crates/selfdef-ebpf-common` | M00035 | data_model | false |
| F00162 | eBPF map — `pid_filter` (BPF_MAP_TYPE_HASH for allow/deny) | `crates/selfdef-ebpf-common` | M00035 | data_model | false |
| F00163 | eBPF map — `path_prefix_filter` (BPF_MAP_TYPE_TRIE for /etc + /root + /home prefixes) | `crates/selfdef-ebpf-common` | M00035 | data_model | false |
| F00164 | eBPF userspace bridge — `libbpf-rs` consumer of ring-buffer | `crates/selfdef-ebpf-common` | M00035 | composite | false |
| F00165 | Profile knob — `ebpf.programs = csv` (operator-selects which observers load) | `crates/selfdef-config` | E0014 | profile | true |
| F00166 | Env var `SELFDEF_EBPF_PROGRAMS` | `crates/selfdef-config` | E0014 | env_var | true |
| F00167 | CLI `--ebpf-programs <csv>` | `crates/selfdef-cli` | E0014 | cli_verb | true |
| F00168 | Dashboard — eBPF program load state (per program: loaded / failed / verifier-rejected) | `dashboard/` | E0014 | dashboard | true |
| F00169 | Dashboard — eBPF ring-buffer drop count | `dashboard/` | M00035 | dashboard | true |
| F00170 | Metric `selfdef_ebpf_ringbuf_dropped_total` | `crates/selfdef-ebpf-common` | M00035 | observability_metric | true |
| F00171 | Tetragon TracingPolicy loader | `crates/selfdef-collector-tetragon` | M00036 | composite | false |
| F00172 | Tetragon TracingPolicy — `observe-sensitive-files.yaml` (operator-shipped) | `rules/tetragon/observe-sensitive-files.yaml` | M00037 | composite | true |
| F00173 | Tetragon TracingPolicy signing verification | `crates/selfdef-signing` | M00038 | composite | true |
| F00174 | Profile knob — `tetragon.signing_required = bool` | `crates/selfdef-config` | M00038 | profile | true |
| F00175 | Env var `SELFDEF_TETRAGON_SIGNING_REQUIRED` | `crates/selfdef-config` | M00038 | env_var | true |
| F00176 | Dashboard — Tetragon active TracingPolicies + signer fingerprint | `dashboard/` | M00038 | dashboard | true |
| F00177 | Suricata EVE-JSON ingest — `alert` event_type | `crates/selfdef-collector-suricata` | M00039 | composite | false |
| F00178 | Suricata EVE-JSON ingest — `fileinfo` event_type | `crates/selfdef-collector-suricata` | M00039 | composite | false |
| F00179 | Suricata EVE-JSON ingest — `dns` event_type | `crates/selfdef-collector-suricata` | M00039 | composite | false |
| F00180 | Suricata EVE-JSON ingest — `http` event_type | `crates/selfdef-collector-suricata` | M00039 | composite | false |
| F00181 | Suricata EVE-JSON ingest — `tls` event_type | `crates/selfdef-collector-suricata` | M00039 | composite | false |
| F00182 | Suricata EVE-JSON ingest — `flow` event_type | `crates/selfdef-collector-suricata` | M00039 | composite | false |
| F00183 | Suricata canary rule — SID 2100498 testmynids.org | `modules/suricata/` | M00041 | composite | true |
| F00184 | Suricata rule pack — community-rules upstream | `modules/suricata/` | M00040 | profile | true |
| F00185 | Suricata rule pack — emerging-threats upstream | `modules/suricata/` | M00040 | profile | true |
| F00186 | Suricata rule pack — selfdef custom rules | `modules/suricata/` | M00040 | profile | true |
| F00187 | Profile knob — `suricata.rule_packs = csv` | `crates/selfdef-config` | M00040 | profile | true |
| F00188 | Env var `SELFDEF_SURICATA_RULE_PACKS` | `crates/selfdef-config` | M00040 | env_var | true |
| F00189 | Dashboard — Suricata alert-rate + top-SID histogram + canary smoke status | `dashboard/` | E0016 | dashboard | true |
| F00190 | Metric `selfdef_suricata_alerts_total{sid,category,severity}` | `crates/selfdef-collector-suricata` | M00039 | observability_metric | true |
| F00191 | eventstream SSE re-ingest — internal /v1/events consumer | `crates/selfdef-collector-eventstream` | M00042 | composite | true |
| F00192 | eventstream integrity — signed event chain verification | `crates/selfdef-collector-eventstream` | M00043 | composite | true |
| F00193 | Profile knob — `eventstream.integrity_required = bool` | `crates/selfdef-config` | M00043 | profile | true |
| F00194 | Env var `SELFDEF_EVENTSTREAM_INTEGRITY_REQUIRED` | `crates/selfdef-config` | M00043 | env_var | true |
| F00195 | canary file — `/etc/selfdef/canary/<token>.txt` deployment | `crates/selfdef-collector-canary` | M00044 | composite | true |
| F00196 | canary service — fake-SSH on operator-defined port | `crates/selfdef-collector-canary` | M00045 | composite | true |
| F00197 | canary service — fake-PostgreSQL on operator-defined port | `crates/selfdef-collector-canary` | M00045 | composite | true |
| F00198 | canary token — fake API key in `~/.aws/credentials`-style file | `crates/selfdef-collector-canary` | M00046 | composite | true |
| F00199 | canary token — fake K8s service-account token | `crates/selfdef-collector-canary` | M00046 | composite | true |
| F00200 | Profile knob — `canary.tokens = csv` | `crates/selfdef-config` | E0018 | profile | true |
| F00201 | Env var `SELFDEF_CANARY_TOKENS` | `crates/selfdef-config` | E0018 | env_var | true |
| F00202 | Dashboard — canary triggers (chronological with offender source) | `dashboard/` | E0018 | dashboard | true |
| F00203 | Metric `selfdef_canary_triggers_total{token,offender_uid,offender_ip}` | `crates/selfdef-collector-canary` | E0018 | observability_metric | true |
| F00204 | Sigma rule loader — yaml → correlator-ingest | `crates/selfdef-correlator` | E0019 | composite | false |
| F00205 | Sigma category — command_and_control | `rules/sigma/command_and_control/` | M00047 | profile | true |
| F00206 | Sigma category — credential_access | `rules/sigma/credential_access/` | M00048 | profile | true |
| F00207 | Sigma category — defense_evasion | `rules/sigma/defense_evasion/` | M00049 | profile | true |
| F00208 | Sigma category — discovery | `rules/sigma/discovery/` | M00049 | profile | true |
| F00209 | Sigma category — execution | `rules/sigma/execution/` | M00049 | profile | true |
| F00210 | Sigma category — hardening | `rules/sigma/hardening/` | M00050 | profile | true |
| F00211 | Sigma category — impact | `rules/sigma/impact/` | M00050 | profile | true |
| F00212 | Sigma category — persistence | `rules/sigma/persistence/` | M00051 | profile | true |
| F00213 | Sigma category — privilege_escalation | `rules/sigma/privilege_escalation/` | M00051 | profile | true |
| F00214 | Profile knob — `sigma.categories_enabled = csv` | `crates/selfdef-config` | E0019 | profile | true |
| F00215 | Env var `SELFDEF_SIGMA_CATEGORIES` | `crates/selfdef-config` | E0019 | env_var | true |
| F00216 | Dashboard — Sigma rule activations + per-category fire-count | `dashboard/` | E0019 | dashboard | true |
| F00217 | Metric `selfdef_sigma_rule_fired_total{category,rule_id,severity}` | `crates/selfdef-correlator` | E0019 | observability_metric | true |
| F00218 | Collector backpressure — per-collector ring-buffer capacity tunable | `crates/selfdef-bus` | M00052 | profile | true |
| F00219 | Profile knob — `collectors.<name>.ring_buffer_capacity` | `crates/selfdef-config` | M00052 | profile | true |
| F00220 | Env var `SELFDEF_COLLECTOR_<NAME>_RING_CAPACITY` | `crates/selfdef-config` | M00052 | env_var | true |
| F00221 | Collector identity — every event carries collector-of-origin field | `crates/selfdef-core` Event | E0020 | data_model | false |
| F00222 | Collector contract — Event envelope conforms to `selfdef-core::Event` | `crates/selfdef-core` | E0020 | composite | false |
| F00223 | Test — auditd parser round-trips on golden EXECVE/PATH/SYSCALL fixtures | tests/ | M00027 | test | false |
| F00224 | Test — journald reader resumes from saved cursor | tests/ | M00029 | test | false |
| F00225 | Test — eBPF program loads on Debian 13 kernel 6.x | tests/ | E0014 | test | false |
| F00226 | Test — eBPF program loads on Ubuntu 24.04 kernel | tests/ | E0014 | test | false |
| F00227 | Test — Tetragon policy load with valid signature succeeds | tests/ | M00038 | test | false |
| F00228 | Test — Tetragon policy load with invalid signature is rejected | tests/ | M00038 | test | false |
| F00229 | Test — Suricata EVE-JSON parses all 6 event types | tests/ | M00039 | test | false |
| F00230 | Test — Suricata SID 2100498 canary smoke fires on testmynids.org curl | tests/ | M00041 | test | false |
| F00231 | Test — eventstream integrity verifies signed event chain | tests/ | M00043 | test | false |
| F00232 | Test — eventstream integrity rejects forged event chain | tests/ | M00043 | test | false |
| F00233 | Test — canary file trigger fires on `cat /etc/selfdef/canary/<token>.txt` | tests/ | M00044 | test | false |
| F00234 | Test — canary service trigger fires on connect to fake-SSH port | tests/ | M00045 | test | false |
| F00235 | Test — canary token trigger fires on fake-API-key use | tests/ | M00046 | test | false |
| F00236 | Test — Sigma rule loader parses every rule in `rules/sigma/**/*.yml` without error | tests/ | E0019 | test | false |
| F00237 | Test — every collector emits Event with collector-of-origin field | tests/ | F00221 | test | false |
| F00238 | Test — per-collector backpressure honors operator-tuned ring capacity | tests/ | M00052 | test | false |
| F00239 | Test — disabling all 7 collectors via modules.toml leaves daemon healthy (zero events, no errors) | tests/ | F00128 | test | false |
| F00240 | Test — enabling all 7 collectors via modules.toml produces events within 5s on stock workload | tests/ | F00128 | test | false |

## Requirements (R00241–R00480)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R00241 | Collector fabric has exactly 7 named collectors (auditd / journald / eBPF / Tetragon / Suricata / eventstream / canary) | repo `crates/selfdef-collector-*` | E0011 | non-negotiable | false | 10 |
| R00242 | Each collector lives in its own `crates/selfdef-collector-<name>` Rust crate | repo | E0011 | non-negotiable | false | 10 |
| R00243 | Each collector emits events through `selfdef-bus` | `crates/selfdef-bus` | E0011 | non-negotiable | false | 10 |
| R00244 | Each collector is operator-toggleable via `modules.toml` | `crates/selfdef-config` | E0011 | non-negotiable | true | 10 |
| R00245 | Each collector emits `selfdef_collector_events_total{collector}` Prometheus metric | every collector | F00136 | non-negotiable | true | 10 |
| R00246 | Each collector emits `selfdef_collector_errors_total{collector,kind}` Prometheus metric | every collector | F00137 | non-negotiable | true | 10 |
| R00247 | Each collector emits `selfdef_collector_dropped_total{collector}` Prometheus metric | every collector | F00138 | non-negotiable | true | 10 |
| R00248 | Each collector has operator-tunable ring-buffer capacity | `crates/selfdef-bus` | M00052 | non-negotiable | true | 10 |
| R00249 | Each collector survives daemon restart without losing in-flight events | `crates/selfdef-bus` + crate | E0011 | non-negotiable | false | 10 |
| R00250 | Each collector tags events with collector-of-origin field | `crates/selfdef-core` Event | F00221 | non-negotiable | false | 10 |
| R00251 | auditd collector reads Linux audit subsystem events | `crates/selfdef-collector-auditd` | E0012 | non-negotiable | false | 10 |
| R00252 | auditd collector parses SYSCALL audit records | `crates/selfdef-collector-auditd` | M00027 | non-negotiable | false | 10 |
| R00253 | auditd collector parses EXECVE audit records | `crates/selfdef-collector-auditd` | M00027 | non-negotiable | false | 10 |
| R00254 | auditd collector parses PATH audit records | `crates/selfdef-collector-auditd` | M00027 | non-negotiable | false | 10 |
| R00255 | auditd collector parses CWD audit records | `crates/selfdef-collector-auditd` | M00027 | non-negotiable | false | 10 |
| R00256 | auditd collector parses PROCTITLE audit records | `crates/selfdef-collector-auditd` | M00027 | non-negotiable | false | 10 |
| R00257 | auditd collector loads operator-defined audit rules into kernel | `crates/selfdef-collector-auditd` | M00028 | non-negotiable | false | 10 |
| R00258 | auditd rule preset `default` covers minimal SELinux + sudo + syscall | `crates/selfdef-collector-auditd` | F00140 | non-negotiable | true | 10 |
| R00259 | auditd rule preset `paranoid` adds filesystem + network + process-tree | `crates/selfdef-collector-auditd` | F00141 | non-negotiable | true | 10 |
| R00260 | auditd rule preset `forensic` enables everything + execve full argv | `crates/selfdef-collector-auditd` | F00142 | non-negotiable | true | 10 |
| R00261 | auditd event carries `serial` field | `crates/selfdef-collector-auditd` | F00143 | non-negotiable | false | 10 |
| R00262 | auditd event carries `timestamp` field | `crates/selfdef-collector-auditd` | F00144 | non-negotiable | false | 10 |
| R00263 | auditd event carries `audit_type` field | `crates/selfdef-collector-auditd` | F00145 | non-negotiable | false | 10 |
| R00264 | auditd event carries `pid` / `uid` / `gid` / `auid` fields | `crates/selfdef-collector-auditd` | F00146 | non-negotiable | false | 10 |
| R00265 | auditd event carries `subj` SELinux-context field | `crates/selfdef-collector-auditd` | F00147 | non-negotiable | false | 10 |
| R00266 | journald collector reads systemd journal | `crates/selfdef-collector-journald` | E0013 | non-negotiable | false | 10 |
| R00267 | journald collector uses cursor-based resumable reads | `crates/selfdef-collector-journald` | M00029 | non-negotiable | false | 10 |
| R00268 | journald collector extracts `_SYSTEMD_UNIT` field | `crates/selfdef-collector-journald` | F00148 | non-negotiable | false | 10 |
| R00269 | journald collector extracts `MESSAGE` field | `crates/selfdef-collector-journald` | F00149 | non-negotiable | false | 10 |
| R00270 | journald collector extracts `PRIORITY` field | `crates/selfdef-collector-journald` | F00150 | non-negotiable | false | 10 |
| R00271 | journald collector extracts `_PID` / `_UID` / `_GID` / `_COMM` / `_EXE` fields | `crates/selfdef-collector-journald` | F00151 | non-negotiable | false | 10 |
| R00272 | journald cursor checkpoint persists across daemon restart | `crates/selfdef-collector-journald` | F00152 | non-negotiable | false | 10 |
| R00273 | journald unit-filter operator-tunable (include + exclude lists) | `crates/selfdef-config` | F00153 | non-negotiable | true | 10 |
| R00274 | eBPF collector loads kernel-side observers via libbpf | `crates/selfdef-collector-ebpf` | E0014 | non-negotiable | false | 10 |
| R00275 | eBPF collector loads `selfdef_open_observer.bpf.c` | `bpf/selfdef-bpf/` | F00154 | non-negotiable | true | 10 |
| R00276 | eBPF collector loads `selfdef_unlink_observer.bpf.c` | `bpf/selfdef-bpf/` | F00155 | non-negotiable | true | 10 |
| R00277 | eBPF collector loads `selfdef_connect_observer.bpf.c` | `bpf/selfdef-bpf/` | F00156 | non-negotiable | true | 10 |
| R00278 | eBPF collector loads `selfdef_accept_observer.bpf.c` | `bpf/selfdef-bpf/` | F00157 | non-negotiable | true | 10 |
| R00279 | eBPF collector loads `selfdef_execve_observer.bpf.c` | `bpf/selfdef-bpf/` | F00158 | non-negotiable | true | 10 |
| R00280 | eBPF collector loads `selfdef_clone_observer.bpf.c` | `bpf/selfdef-bpf/` | F00159 | non-negotiable | true | 10 |
| R00281 | eBPF collector loads `selfdef_syscall_lat.bpf.c` latency observer | `bpf/selfdef-bpf/` | F00160 | non-negotiable | true | 10 |
| R00282 | eBPF events transport — BPF_MAP_TYPE_RINGBUF | `crates/selfdef-ebpf-common` | F00161 | non-negotiable | false | 10 |
| R00283 | eBPF pid filtering — BPF_MAP_TYPE_HASH map | `crates/selfdef-ebpf-common` | F00162 | non-negotiable | false | 10 |
| R00284 | eBPF path prefix filter — BPF_MAP_TYPE_TRIE map | `crates/selfdef-ebpf-common` | F00163 | non-negotiable | false | 10 |
| R00285 | eBPF userspace bridge uses `libbpf-rs` | `crates/selfdef-ebpf-common` | F00164 | non-negotiable | false | 10 |
| R00286 | eBPF programs operator-selectable via `ebpf.programs = csv` | `crates/selfdef-config` | F00165 | non-negotiable | true | 10 |
| R00287 | eBPF observation respects CAP_BPF + CAP_NET_ADMIN capability set | systemd unit | M00035 | non-negotiable | false | 10 |
| R00288 | eBPF observation NEVER mutates kernel state (read-only programs only) | `bpf/selfdef-bpf/` | E0014 | non-negotiable | false | 10 |
| R00289 | eBPF observation supports Debian 13 kernel 6.x | tests/ | F00225 | non-negotiable | false | 10 |
| R00290 | eBPF observation supports Ubuntu 24.04 kernel | tests/ | F00226 | non-negotiable | false | 10 |
| R00291 | eBPF ring-buffer drop count emitted as `selfdef_ebpf_ringbuf_dropped_total` | `crates/selfdef-ebpf-common` | F00170 | non-negotiable | true | 10 |
| R00292 | Tetragon collector loads kube-style TracingPolicy CRDs | `crates/selfdef-collector-tetragon` | M00036 | non-negotiable | false | 10 |
| R00293 | Tetragon ships `observe-sensitive-files.yaml` policy | `rules/tetragon/observe-sensitive-files.yaml` | M00037 | non-negotiable | true | 10 |
| R00294 | Tetragon TracingPolicy signing verification is audit-shipped opt-in feature | `crates/selfdef-signing` | M00038 | non-negotiable | true | 10 |
| R00295 | Tetragon policy load with valid signature succeeds | tests/ | F00227 | non-negotiable | false | 10 |
| R00296 | Tetragon policy load with invalid signature is rejected when signing_required=true | tests/ | F00228 | non-negotiable | false | 10 |
| R00297 | Suricata collector reads EVE-JSON output | `crates/selfdef-collector-suricata` | E0016 | non-negotiable | false | 10 |
| R00298 | Suricata collector parses `alert` event_type | `crates/selfdef-collector-suricata` | F00177 | non-negotiable | false | 10 |
| R00299 | Suricata collector parses `fileinfo` event_type | `crates/selfdef-collector-suricata` | F00178 | non-negotiable | false | 10 |
| R00300 | Suricata collector parses `dns` event_type | `crates/selfdef-collector-suricata` | F00179 | non-negotiable | false | 10 |
| R00301 | Suricata collector parses `http` event_type | `crates/selfdef-collector-suricata` | F00180 | non-negotiable | false | 10 |
| R00302 | Suricata collector parses `tls` event_type | `crates/selfdef-collector-suricata` | F00181 | non-negotiable | false | 10 |
| R00303 | Suricata collector parses `flow` event_type | `crates/selfdef-collector-suricata` | F00182 | non-negotiable | false | 10 |
| R00304 | Suricata ships canary smoke rule SID 2100498 (testmynids.org) | `modules/suricata/` | M00041 | non-negotiable | true | 10 |
| R00305 | Suricata supports rule pack `community-rules` | `modules/suricata/` | F00184 | non-negotiable | true | 10 |
| R00306 | Suricata supports rule pack `emerging-threats` | `modules/suricata/` | F00185 | non-negotiable | true | 10 |
| R00307 | Suricata supports rule pack `selfdef-custom` | `modules/suricata/` | F00186 | non-negotiable | true | 10 |
| R00308 | Suricata rule packs operator-selectable via `suricata.rule_packs = csv` | `crates/selfdef-config` | F00187 | non-negotiable | true | 10 |
| R00309 | Suricata canary smoke fires on testmynids.org curl | tests/ | F00230 | non-negotiable | false | 10 |
| R00310 | Suricata alert metric — `selfdef_suricata_alerts_total{sid,category,severity}` | `crates/selfdef-collector-suricata` | F00190 | non-negotiable | true | 10 |
| R00311 | eventstream collector re-ingests selfdef's own /v1/events SSE stream | `crates/selfdef-collector-eventstream` | M00042 | non-negotiable | true | 10 |
| R00312 | eventstream integrity verification is audit-shipped opt-in feature | `crates/selfdef-collector-eventstream` | M00043 | non-negotiable | true | 10 |
| R00313 | eventstream integrity verifies signed event chain | tests/ | F00231 | non-negotiable | false | 10 |
| R00314 | eventstream integrity rejects forged event chain when integrity_required=true | tests/ | F00232 | non-negotiable | false | 10 |
| R00315 | canary collector detects file trigger on honeyfile access | `crates/selfdef-collector-canary` | M00044 | non-negotiable | true | 10 |
| R00316 | canary collector detects network trigger on honeyservice connect | `crates/selfdef-collector-canary` | M00045 | non-negotiable | true | 10 |
| R00317 | canary collector detects token trigger on fake-API-key use | `crates/selfdef-collector-canary` | M00046 | non-negotiable | true | 10 |
| R00318 | canary file deploys to `/etc/selfdef/canary/<token>.txt` | `crates/selfdef-collector-canary` | F00195 | non-negotiable | true | 10 |
| R00319 | canary service supports fake-SSH on operator-defined port | `crates/selfdef-collector-canary` | F00196 | non-negotiable | true | 10 |
| R00320 | canary service supports fake-PostgreSQL on operator-defined port | `crates/selfdef-collector-canary` | F00197 | non-negotiable | true | 10 |
| R00321 | canary token supports fake-AWS-credentials shape | `crates/selfdef-collector-canary` | F00198 | non-negotiable | true | 10 |
| R00322 | canary token supports fake-K8s-service-account-token shape | `crates/selfdef-collector-canary` | F00199 | non-negotiable | true | 10 |
| R00323 | canary tokens operator-configurable via `canary.tokens = csv` | `crates/selfdef-config` | F00200 | non-negotiable | true | 10 |
| R00324 | canary triggers emit `selfdef_canary_triggers_total{token,offender_uid,offender_ip}` | `crates/selfdef-collector-canary` | F00203 | non-negotiable | true | 10 |
| R00325 | Sigma rule pack — command_and_control category present | `rules/sigma/command_and_control/` | M00047 | non-negotiable | true | 10 |
| R00326 | Sigma rule pack — credential_access category present | `rules/sigma/credential_access/` | M00048 | non-negotiable | true | 10 |
| R00327 | Sigma rule pack — defense_evasion category present | `rules/sigma/defense_evasion/` | M00049 | non-negotiable | true | 10 |
| R00328 | Sigma rule pack — discovery category present | `rules/sigma/discovery/` | M00049 | non-negotiable | true | 10 |
| R00329 | Sigma rule pack — execution category present | `rules/sigma/execution/` | M00049 | non-negotiable | true | 10 |
| R00330 | Sigma rule pack — hardening category present | `rules/sigma/hardening/` | M00050 | non-negotiable | true | 10 |
| R00331 | Sigma rule pack — impact category present | `rules/sigma/impact/` | M00050 | non-negotiable | true | 10 |
| R00332 | Sigma rule pack — persistence category present | `rules/sigma/persistence/` | M00051 | non-negotiable | true | 10 |
| R00333 | Sigma rule pack — privilege_escalation category present | `rules/sigma/privilege_escalation/` | M00051 | non-negotiable | true | 10 |
| R00334 | Sigma rule loader parses every rule in `rules/sigma/**/*.yml` without error | tests/ | F00236 | non-negotiable | false | 10 |
| R00335 | Sigma rule fire emits `selfdef_sigma_rule_fired_total{category,rule_id,severity}` | `crates/selfdef-correlator` | F00217 | non-negotiable | true | 10 |
| R00336 | Collector fabric integrates with `selfdef-correlator` (events feed verdict synthesis) | `crates/selfdef-correlator` | E0011 | non-negotiable | false | 10 |
| R00337 | Collector fabric integrates with `selfdef-store` (events persist for replay) | `crates/selfdef-store` | E0011 | non-negotiable | false | 10 |
| R00338 | Collector fabric integrates with `selfdef-signing` (signed-rule + signed-policy + signed-eventstream invariants) | `crates/selfdef-signing` | E0011 | non-negotiable | false | 10 |
| R00339 | Collector fabric integrates with `selfdef-responder` (events trigger responder Actions) | `crates/selfdef-responder` | E0011 | non-negotiable | false | 10 |
| R00340 | Dashboard surface — per-collector status (running / stopped / errored) | `dashboard/` | F00131 | non-negotiable | true | 10 |
| R00341 | Dashboard surface — per-collector events/sec | `dashboard/` | F00132 | non-negotiable | true | 10 |
| R00342 | Dashboard surface — eBPF program load state (per program) | `dashboard/` | F00168 | non-negotiable | true | 10 |
| R00343 | Dashboard surface — eBPF ring-buffer drop count | `dashboard/` | F00169 | non-negotiable | true | 10 |
| R00344 | Dashboard surface — Tetragon active TracingPolicies + signer fingerprint | `dashboard/` | F00176 | non-negotiable | true | 10 |
| R00345 | Dashboard surface — Suricata alert-rate + top-SID histogram + canary smoke status | `dashboard/` | F00189 | non-negotiable | true | 10 |
| R00346 | Dashboard surface — canary triggers (chronological with offender source) | `dashboard/` | F00202 | non-negotiable | true | 10 |
| R00347 | Dashboard surface — Sigma rule activations + per-category fire-count | `dashboard/` | F00216 | non-negotiable | true | 10 |
| R00348 | API `GET /v1/collectors` lists all 7 collectors with state | `crates/selfdef-api` | F00133 | non-negotiable | true | 10 |
| R00349 | API `GET /v1/collectors/{name}/stats` returns per-collector stats | `crates/selfdef-api` | F00134 | non-negotiable | true | 10 |
| R00350 | API `POST /v1/collectors/{name}/restart` restarts a single collector | `crates/selfdef-api` | F00135 | non-negotiable | true | 10 |
| R00351 | Profile knob — `collectors.enabled = csv` | `crates/selfdef-config` | F00128 | non-negotiable | true | 10 |
| R00352 | Profile knob — `collectors.<name>.ring_buffer_capacity` | `crates/selfdef-config` | F00219 | non-negotiable | true | 10 |
| R00353 | Profile knob — `ebpf.programs = csv` | `crates/selfdef-config` | F00165 | non-negotiable | true | 10 |
| R00354 | Profile knob — `tetragon.signing_required = bool` | `crates/selfdef-config` | F00174 | non-negotiable | true | 10 |
| R00355 | Profile knob — `suricata.rule_packs = csv` | `crates/selfdef-config` | F00187 | non-negotiable | true | 10 |
| R00356 | Profile knob — `eventstream.integrity_required = bool` | `crates/selfdef-config` | F00193 | non-negotiable | true | 10 |
| R00357 | Profile knob — `canary.tokens = csv` | `crates/selfdef-config` | F00200 | non-negotiable | true | 10 |
| R00358 | Profile knob — `sigma.categories_enabled = csv` | `crates/selfdef-config` | F00214 | non-negotiable | true | 10 |
| R00359 | Env var — `SELFDEF_COLLECTORS_ENABLED` | `crates/selfdef-config` | F00129 | non-negotiable | true | 10 |
| R00360 | Env var — `SELFDEF_COLLECTOR_<NAME>_RING_CAPACITY` | `crates/selfdef-config` | F00220 | non-negotiable | true | 10 |
| R00361 | Env var — `SELFDEF_EBPF_PROGRAMS` | `crates/selfdef-config` | F00166 | non-negotiable | true | 10 |
| R00362 | Env var — `SELFDEF_TETRAGON_SIGNING_REQUIRED` | `crates/selfdef-config` | F00175 | non-negotiable | true | 10 |
| R00363 | Env var — `SELFDEF_SURICATA_RULE_PACKS` | `crates/selfdef-config` | F00188 | non-negotiable | true | 10 |
| R00364 | Env var — `SELFDEF_EVENTSTREAM_INTEGRITY_REQUIRED` | `crates/selfdef-config` | F00194 | non-negotiable | true | 10 |
| R00365 | Env var — `SELFDEF_CANARY_TOKENS` | `crates/selfdef-config` | F00201 | non-negotiable | true | 10 |
| R00366 | Env var — `SELFDEF_SIGMA_CATEGORIES` | `crates/selfdef-config` | F00215 | non-negotiable | true | 10 |
| R00367 | CLI flag — `--collectors <csv>` | `crates/selfdef-cli` | F00130 | non-negotiable | true | 10 |
| R00368 | CLI flag — `--ebpf-programs <csv>` | `crates/selfdef-cli` | F00167 | non-negotiable | true | 10 |
| R00369 | Operator can disable any single collector via modules.toml | `crates/selfdef-config` | F00128 | non-negotiable | true | 10 |
| R00370 | Operator can disable all 7 collectors and the daemon remains healthy | tests/ | F00239 | non-negotiable | false | 10 |
| R00371 | Operator can enable all 7 collectors and events flow within 5s | tests/ | F00240 | non-negotiable | false | 10 |
| R00372 | Test — auditd parser round-trip on EXECVE / PATH / SYSCALL golden fixtures | tests/ | F00223 | non-negotiable | false | 10 |
| R00373 | Test — journald reader resumes from saved cursor on restart | tests/ | F00224 | non-negotiable | false | 10 |
| R00374 | Test — eBPF programs load on Debian 13 kernel 6.x | tests/ | F00225 | non-negotiable | false | 10 |
| R00375 | Test — eBPF programs load on Ubuntu 24.04 kernel | tests/ | F00226 | non-negotiable | false | 10 |
| R00376 | Test — Tetragon policy round-trip (load + reload) | tests/ | M00036 | non-negotiable | false | 10 |
| R00377 | Test — Suricata EVE-JSON parser handles all 6 event types | tests/ | F00229 | non-negotiable | false | 10 |
| R00378 | Test — Suricata canary smoke produces alert within 30s | tests/ | F00230 | non-negotiable | false | 10 |
| R00379 | Test — eventstream integrity rejects tampered event | tests/ | F00232 | non-negotiable | false | 10 |
| R00380 | Test — canary file trigger fires on first read of honeyfile | tests/ | F00233 | non-negotiable | false | 10 |
| R00381 | Test — canary service trigger fires on first connect to honeyservice | tests/ | F00234 | non-negotiable | false | 10 |
| R00382 | Test — canary token trigger fires on use of fake API key | tests/ | F00235 | non-negotiable | false | 10 |
| R00383 | Test — Sigma rule loader parses every shipped rule | tests/ | F00236 | non-negotiable | false | 10 |
| R00384 | Test — every collector emits Event envelope with collector-of-origin field | tests/ | F00237 | non-negotiable | false | 10 |
| R00385 | Test — per-collector backpressure honors configured ring capacity | tests/ | F00238 | non-negotiable | false | 10 |
| R00386 | Collector fabric is IPS-scope (selfdef domain) — sovereign-os runtime emits its own traces separately | this rule | E0011 | non-negotiable | false | 10 |
| R00387 | Collector fabric NEVER reaches into sovereign-os runtime state directly | this rule | E0011 | non-negotiable | false | 10 |
| R00388 | Cross-project boundary — sovereign-os runtime exposes a trace API; selfdef consumes it via eventstream if operator opts in | architecture | E0017 | non-negotiable | true | 10 |
| R00389 | Sigma rule loader supports operator-extensible rule paths | `crates/selfdef-config` | E0019 | non-negotiable | true | 10 |
| R00390 | Sigma rule loader rejects malformed YAML with operator-readable error | `crates/selfdef-correlator` | E0019 | non-negotiable | false | 10 |
| R00391 | Sigma rule loader validates required fields (id / title / detection / level) | `crates/selfdef-correlator` | E0019 | non-negotiable | false | 10 |
| R00392 | Sigma rule loader supports MITRE ATT&CK tag mapping | `crates/selfdef-correlator` | E0019 | non-negotiable | true | 10 |
| R00393 | auditd collector survives auditd daemon restart | `crates/selfdef-collector-auditd` | E0012 | non-negotiable | false | 10 |
| R00394 | journald collector survives systemd-journald restart | `crates/selfdef-collector-journald` | E0013 | non-negotiable | false | 10 |
| R00395 | eBPF collector survives kernel module reload | `crates/selfdef-collector-ebpf` | E0014 | non-negotiable | false | 10 |
| R00396 | Tetragon collector survives Tetragon daemon restart | `crates/selfdef-collector-tetragon` | E0015 | non-negotiable | false | 10 |
| R00397 | Suricata collector survives Suricata daemon restart | `crates/selfdef-collector-suricata` | E0016 | non-negotiable | false | 10 |
| R00398 | eventstream collector survives selfdef daemon restart (cursor) | `crates/selfdef-collector-eventstream` | E0017 | non-negotiable | false | 10 |
| R00399 | canary collector survives daemon restart (state preserved in `/var/lib/selfdef/canary/`) | `crates/selfdef-collector-canary` | E0018 | non-negotiable | false | 10 |
| R00400 | Each collector emits Event with sub-second monotonic timestamp | `crates/selfdef-core` | F00221 | non-negotiable | false | 10 |
| R00401 | Each collector tags Event with wall-clock + monotonic-clock pair | `crates/selfdef-core` | F00221 | non-negotiable | true | 10 |
| R00402 | Each collector emits Event in append-only fashion (no in-place mutation) | `crates/selfdef-core` | E0011 | non-negotiable | false | 10 |
| R00403 | Each collector emits Event with deterministic field ordering for JSON serialization | `crates/selfdef-core` | F00221 | non-negotiable | true | 10 |
| R00404 | Each collector NEVER emits operator-secret data (no /etc/shadow / no .ssh keys / no credentials.json content) | `crates/selfdef-collector-*` | E0011 | non-negotiable | false | 10 |
| R00405 | Each collector respects allow/deny path-filter (operator-tunable) | `crates/selfdef-config` | M00027 | non-negotiable | true | 10 |
| R00406 | Each collector respects allow/deny pid-filter (operator-tunable) | `crates/selfdef-config` | M00027 | non-negotiable | true | 10 |
| R00407 | Each collector respects allow/deny uid-filter (operator-tunable) | `crates/selfdef-config` | M00027 | non-negotiable | true | 10 |
| R00408 | Each collector respects allow/deny container-id-filter (operator-tunable) | `crates/selfdef-config` | M00027 | non-negotiable | true | 10 |
| R00409 | auditd integration — rule preset selectable per deployment-target | `crates/selfdef-config` | M00028 | non-negotiable | true | 10 |
| R00410 | auditd integration — rule preset overlay supports operator-custom rules | `crates/selfdef-config` | M00028 | non-negotiable | true | 10 |
| R00411 | journald integration — operator-tunable include/exclude unit filter list | `crates/selfdef-config` | F00153 | non-negotiable | true | 10 |
| R00412 | journald integration — operator-tunable priority filter (≤ warn / ≤ info / ...) | `crates/selfdef-config` | M00029 | non-negotiable | true | 10 |
| R00413 | eBPF integration — operator-tunable pid allowlist + denylist | `crates/selfdef-config` | F00162 | non-negotiable | true | 10 |
| R00414 | eBPF integration — operator-tunable path-prefix filter (`/etc/`, `/root/`, `/home/`, ...) | `crates/selfdef-config` | F00163 | non-negotiable | true | 10 |
| R00415 | eBPF integration — programs that fail verifier are logged + non-fatal | `crates/selfdef-collector-ebpf` | E0014 | non-negotiable | false | 10 |
| R00416 | eBPF integration — programs that succeed verifier are loaded atomically | `crates/selfdef-collector-ebpf` | E0014 | non-negotiable | false | 10 |
| R00417 | Tetragon integration — operator can hot-reload policy without daemon restart | `crates/selfdef-collector-tetragon` | M00036 | non-negotiable | true | 10 |
| R00418 | Tetragon integration — invalid policy refused with operator-readable error | `crates/selfdef-collector-tetragon` | M00036 | non-negotiable | false | 10 |
| R00419 | Suricata integration — operator can hot-reload rule packs without daemon restart | `crates/selfdef-collector-suricata` | M00040 | non-negotiable | true | 10 |
| R00420 | Suricata integration — rule pack version pinning supported | `crates/selfdef-config` | M00040 | non-negotiable | true | 10 |
| R00421 | eventstream integration — operator can disable re-ingest without disabling primary /v1/events | `crates/selfdef-config` | M00042 | non-negotiable | true | 10 |
| R00422 | eventstream integration — integrity verification opt-in via `eventstream.integrity_required` | `crates/selfdef-config` | F00193 | non-negotiable | true | 10 |
| R00423 | canary integration — operator-controlled deploy of canary files via `selfdefctl canary deploy` | `crates/selfdef-cli` | M00044 | non-negotiable | true | 10 |
| R00424 | canary integration — operator-controlled deploy of canary services via `selfdefctl canary service add` | `crates/selfdef-cli` | M00045 | non-negotiable | true | 10 |
| R00425 | canary integration — operator-controlled deploy of canary tokens via `selfdefctl canary token add` | `crates/selfdef-cli` | M00046 | non-negotiable | true | 10 |
| R00426 | Sigma integration — operator can hot-reload Sigma rules without daemon restart | `crates/selfdef-correlator` | E0019 | non-negotiable | true | 10 |
| R00427 | Sigma integration — operator can disable individual categories without removing rule files | `crates/selfdef-config` | F00214 | non-negotiable | true | 10 |
| R00428 | Collector fabric L1 lint — every collector has a public-API surface assertion | tests/lint | E0011 | non-negotiable | false | 10 |
| R00429 | Collector fabric L3 smoke — daemon starts with all 7 collectors enabled + healthy | tests/ | F00240 | non-negotiable | false | 10 |
| R00430 | Collector fabric L5 real-substrate — daemon runs on real Debian 13 VM with 7 collectors live | tests/ | E0011 | non-negotiable | false | 10 |
| R00431 | Collector fabric never bypasses systemd unit hardening at runtime | `packaging/systemd/` | E0011 | non-negotiable | false | 10 |
| R00432 | Collector fabric never bypasses AppArmor profile at runtime | `packaging/apparmor/` | E0011 | non-negotiable | false | 10 |
| R00433 | Collector fabric never bypasses cgroup v2 slice at runtime | `packaging/systemd/` | E0011 | non-negotiable | false | 10 |
| R00434 | Collector fabric runs with minimum capability set (CAP_BPF + CAP_NET_ADMIN + CAP_AUDIT_READ) | `packaging/systemd/` | E0011 | non-negotiable | false | 10 |
| R00435 | Collector fabric supports running as non-root with capability hand-off | `packaging/systemd/` | E0011 | preferable | true | 10 |
| R00436 | Collector fabric emits journald-recognizable structured logs | `crates/selfdef-collector-*` | E0011 | non-negotiable | false | 10 |
| R00437 | Collector fabric emits per-collector OpenTelemetry traces | `crates/selfdef-collector-*` | E0011 | preferable | true | 10 |
| R00438 | Collector fabric supports operator-readable diagnostic CLI `selfdefctl collectors status` | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00439 | Collector fabric supports operator-readable diagnostic CLI `selfdefctl collectors stats <name>` | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00440 | Collector fabric supports operator-readable diagnostic CLI `selfdefctl collectors restart <name>` | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00441 | Collector fabric supports operator-readable diagnostic CLI `selfdefctl collectors tail <name>` | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00442 | Collector fabric supports SDD-005 L1–L5 layered test harness | SDD-005 | E0011 | non-negotiable | false | 10 |
| R00443 | Collector fabric supports SDD-006 shared module-script lib for any shared scripts | SDD-006 | E0011 | non-negotiable | false | 10 |
| R00444 | Collector fabric supports SDD-008 notification orchestration when collector errors escalate | SDD-008 | E0011 | non-negotiable | false | 10 |
| R00445 | Collector fabric supports SDD-014 shared audit summary channel | SDD-014 | E0011 | non-negotiable | false | 10 |
| R00446 | Collector fabric supports SDD-016 metric naming doctrine (`selfdef_collector_*` namespace) | SDD-016 | E0011 | non-negotiable | false | 10 |
| R00447 | Collector fabric supports SDD-029 round-ledger doctrine for traceability | SDD-029 | E0011 | non-negotiable | false | 10 |
| R00448 | Collector fabric supports SDD-038 cross-repo binding doctrine (events feed sovereign-os trace consumer if operator opts in) | SDD-038 | E0017 | non-negotiable | false | 10 |
| R00449 | Each collector supports operator-tunable sampling rate (1/N events) | `crates/selfdef-config` | E0011 | preferable | true | 10 |
| R00450 | Each collector supports operator-tunable max event-rate cap (back-pressure protection) | `crates/selfdef-config` | M00052 | non-negotiable | true | 10 |
| R00451 | Each collector supports operator-tunable per-event PII redaction (hash uid / strip path tails) | `crates/selfdef-config` | E0011 | preferable | true | 10 |
| R00452 | Each collector emits operator-readable startup log with the rule pack / policy / program list loaded | `crates/selfdef-collector-*` | E0011 | non-negotiable | true | 10 |
| R00453 | Each collector emits operator-readable shutdown log with final stats (events emitted / dropped / errors) | `crates/selfdef-collector-*` | E0011 | non-negotiable | true | 10 |
| R00454 | Each collector supports `--dry-run` mode (probe sources, emit no events) | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00455 | Each collector supports `--diag` mode (verbose diagnostic output) | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00456 | Each collector respects `RUST_LOG=selfdef_collector_<name>=debug` log filter | `crates/selfdef-collector-*` | E0011 | non-negotiable | true | 10 |
| R00457 | Each collector exposes per-collector health probe via `GET /v1/collectors/<name>/healthz` | `crates/selfdef-api` | F00133 | non-negotiable | true | 10 |
| R00458 | Each collector exposes per-collector readyz probe via `GET /v1/collectors/<name>/readyz` | `crates/selfdef-api` | F00133 | non-negotiable | true | 10 |
| R00459 | UX — `selfdefctl collectors status` output ≤ 1 screen on green case | `crates/selfdef-cli` | E0011 | preferable | true | 10 |
| R00460 | UX — `selfdefctl collectors status` groups per-collector failures by severity | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00461 | UX — operator-discoverable next-step on each collector failure | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00462 | UX — `selfdefctl --json` output available for every collector verb | `crates/selfdef-cli` | E0011 | non-negotiable | true | 10 |
| R00463 | UX — collector failure surfaces in `selfdefctl doctor` summary | `crates/selfdef-cli` | E0011 | non-negotiable | false | 10 |
| R00464 | UX — collector errors emit operator-readable notification via SDD-008 orchestrator (when severity ≥ warn) | SDD-008 | E0011 | non-negotiable | true | 10 |
| R00465 | UX — dashboard shows per-collector health (running / stopped / errored / degraded) as live tiles | `dashboard/` | F00131 | non-negotiable | true | 10 |
| R00466 | UX — dashboard shows per-collector events/sec sparkline (60s window) | `dashboard/` | F00132 | non-negotiable | true | 10 |
| R00467 | UX — dashboard surfaces canary trigger as high-severity card with offender provenance | `dashboard/` | F00202 | non-negotiable | true | 10 |
| R00468 | UX — dashboard surfaces eBPF verifier-rejection as red badge on the eBPF tile | `dashboard/` | F00168 | non-negotiable | true | 10 |
| R00469 | UX — dashboard surfaces Tetragon policy-signature mismatch as red badge | `dashboard/` | F00176 | non-negotiable | true | 10 |
| R00470 | UX — dashboard surfaces Suricata rule-pack version drift as yellow badge | `dashboard/` | F00189 | non-negotiable | true | 10 |
| R00471 | Project boundary — collector fabric is selfdef-scope (IPS / host-observability); sovereign-os runtime telemetry (DCGM / GPU / KV cache) is sovereign-os-scope; the two compose at the cross-repo binding crate layer (SD-R-EVENT-LOG-1 + SD-R-MULTI-SURFACE-AUDIT-1 documented in SDD-038) | SDD-038 + this rule | E0011 | non-negotiable | false | 10 |
| R00472 | Project boundary — collector fabric NEVER imports sovereign-os crate code directly | architecture | E0011 | non-negotiable | false | 10 |
| R00473 | Project boundary — sovereign-os NEVER imports selfdef collector crate code directly | architecture | E0011 | non-negotiable | false | 10 |
| R00474 | Cross-repo bridge — when sovereign-os runtime emits a trace, selfdef MAY ingest it via eventstream collector (operator opt-in) | architecture | E0017 | non-negotiable | true | 10 |
| R00475 | Cross-repo bridge — selfdef collector emissions NEVER auto-flow into sovereign-os runtime state | architecture | E0011 | non-negotiable | false | 10 |
| R00476 | Cross-repo bridge — selfdef integration with sovereign-os respects SDD-038 cross-repo binding doctrine (typed-mirror crates only) | SDD-038 | E0011 | non-negotiable | false | 10 |
| R00477 | Cross-repo bridge — saturation invariant covers any new sovereign-os instrument; collector fabric is NOT the typed-mirror surface (collector fabric is the IPS substrate) | SDD-038 + this rule | E0011 | non-negotiable | false | 10 |
| R00478 | Documentation — every collector has a README.md describing event-shape + capability requirements + tunables | `crates/selfdef-collector-*/README.md` | E0011 | non-negotiable | true | 10 |
| R00479 | Documentation — collector fabric overview at `docs/sdd/` describes 7-collector architecture + per-collector contract | `docs/sdd/` | E0011 | non-negotiable | true | 10 |
| R00480 | Documentation — operator-facing quickstart at top-level README.md describes how to verify each collector is firing | `README.md` | E0011 | non-negotiable | true | 10 |

— End of MS002 milestone file.
