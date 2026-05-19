# MS044 — Guardian Daemon — Tetragon eBPF supervisor + SIGKILL + atomic ZFS audit logs

**Parent**: selfdef IPS daemon — boundary-enforcement layer of the cyberpunk042 ecosystem
**Source**: `~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-other-conversation-transposition.md`
- Section 10: The Native Guardian Event Loop (lines 513-588)
- Phase V: Multi-Agent Mission Control + Guardian Loop Activation (lines 712-721)
- The Auditor → physical Tetragon manifestation (dump 977-981, also catalogued narratively in sovereign-os M066)
**Cross-repo lineage**: sovereign-os M066 holds the Trinity Genesis NARRATIVE of The Auditor; **MS044 holds the SELFDEF IPS-side IMPLEMENTATION** per operator standing direction "if I talk about an IPS feature its obviously not in Sovereign-OS. Respect the projects."

## Doctrinal anchors

> "To replace the legacy Windows-centric `SecureToast.ps1` concept without introducing visual or network bloat, we introduce a lightweight, native Linux event supervisor. This daemon listens to the local Tetragon eBPF UNIX socket and acts as an autonomous circuit breaker." (dump 513-515)
> "guardian-core: High-Standard Native Security Watcher" (dump 519)
> "SOCKET_PATH = '/var/run/tetragon/tetragon.events'" (dump 524)
> "issues instant hardware-level `SIGKILL`, updating the immutable ZFS transaction logs (`tank/context/security_audit.log`) atomically." (dump 981 — Trinity Genesis Auditor manifestation)

## Projection statement

The Guardian Daemon is the physical IPS-side implementation of The Auditor (sovereign-os M066 Trinity Genesis narrative). It listens to Tetragon eBPF events via UNIX socket, classifies policy violations, and executes the 3-step **SIGKILL + atomic ZFS log + console alert** response. It runs as a Ring 0 IPS service (per MS039 trust ring topology), with operator-signed policy and chain-of-trust per MS003.

## Epics (E0441-E0450)

| epic | name | source |
|---|---|---|
| E0441 | Guardian Daemon installation — `/usr/local/bin/guardian-core` Python script + systemd unit | dump 519, 569-588 |
| E0442 | Tetragon eBPF subsystem — LLVM + clang dependencies + systemd binding | dump 712-714 |
| E0443 | UNIX socket event ingestion — `/var/run/tetragon/tetragon.events` JSON stream | dump 524, 540-552 |
| E0444 | Violation classifier — parse JSON event for action == "SIGKILL" OR process-related | dump 547-552 |
| E0445 | Response step 1 — SIGKILL via `podman kill` (instant hardware-level neutralization) | dump 527-529, 981 |
| E0446 | Response step 2 — atomic append to `/mnt/vault/context/security_audit.log` (ZFS sync=always) | dump 531-533, 981 + cross-ref sovereign-os M068 |
| E0447 | Response step 3 — native console alert (PC speaker bell via `/dev/console`) | dump 535-536 |
| E0448 | Systemd service — `guardian-core.service` (Type=simple / Restart=always / After=tetragon.service) | dump 569-588 |
| E0449 | Tetragon policy YAML — tracing policies under /etc/tetragon/tracing-policies/ | dump 714 + Phase V architecture |
| E0450 | Integration with selfdef boundary stack — Ring 0 placement / MS003 signing / M049 trace / OCSF emission | cross-ref MS003 + MS007 + MS024 + MS026 + MS037 + MS039 + M049 |

## Modules (M01123-M01148)

| module | name | source |
|---|---|---|
| M01123 | selfdef-guardian-core-installer | dump 519 |
| M01124 | selfdef-guardian-tetragon-prerequisites (llvm + clang) | dump 714 |
| M01125 | selfdef-guardian-tetragon-binary-deployer | dump 715 |
| M01126 | selfdef-guardian-tetragon-systemd-binder | dump 715-716 |
| M01127 | selfdef-guardian-unix-socket-listener | dump 524, 540-543 |
| M01128 | selfdef-guardian-event-parser | dump 545-552 |
| M01129 | selfdef-guardian-violation-classifier | dump 547-551 |
| M01130 | selfdef-guardian-sigkill-executor (podman kill) | dump 527-529 |
| M01131 | selfdef-guardian-atomic-log-appender | dump 531-533 |
| M01132 | selfdef-guardian-console-alerter (PC speaker via /dev/console) | dump 535-536 |
| M01133 | selfdef-guardian-systemd-service-manager | dump 569-588 |
| M01134 | selfdef-guardian-tetragon-policy-loader (YAML under /etc/tetragon/tracing-policies/) | dump 714 + architecture |
| M01135 | selfdef-guardian-policy-signer (MS003) | cross-ref MS003 |
| M01136 | selfdef-guardian-trace-emitter (M049) | cross-ref M049 |
| M01137 | selfdef-guardian-ocsf-emitter (Detection 2004 + Audit 1003) | cross-ref MS026 |
| M01138 | selfdef-guardian-ring-0-placement (per MS039 trust topology) | cross-ref MS039 |
| M01139 | selfdef-guardian-replay-validator | cross-ref MS009 |
| M01140 | selfdef-guardian-rollback-engine (false-positive operator restore) | cross-ref MS003 + MS041 |
| M01141 | selfdef-guardian-typed-mirror (selfdef-guardian-mirror crate) | cross-ref MS007 |
| M01142 | selfdef-guardian-zfs-log-bridge (tank/vault/context/security_audit.log) | cross-ref sovereign-os M068 |
| M01143 | selfdef-guardian-circuit-breaker-state-machine | dump 974, 977-981 |
| M01144 | selfdef-guardian-offline-survivability-engine | operator standing direction |
| M01145 | selfdef-guardian-tui-panel (selfdef tui authority panel binding) | cross-ref MS043 |
| M01146 | selfdef-guardian-cli-subcommand-set | cross-ref MS043 |
| M01147 | selfdef-guardian-cross-repo-mirror-publisher | cross-ref MS007 + sovereign-os M066 |
| M01148 | selfdef-guardian-incident-response-shortcuts | cross-ref MS043 F05137 (panic-drop-all) |

## Features (F05161-F05280)

| feature | name | source |
|---|---|---|
| F05161 | Guardian binary — installed at `/usr/local/bin/guardian-core` | dump 519 |
| F05162 | Guardian binary — Python implementation (initial; rewrite-to-Rust pending) | dump 519-562 |
| F05163 | Guardian binary — shebang `#!/usr/bin/env python3` | dump 521 |
| F05164 | Guardian binary — title: "High-Standard Native Security Watcher" | dump 519 |
| F05165 | Guardian binary — purpose: replaces SecureToast.ps1 Windows-centric concept | dump 513-514 |
| F05166 | Guardian binary — replaces with native Linux event supervisor | dump 514 |
| F05167 | Guardian binary — no visual bloat / no network bloat | dump 514 |
| F05168 | Guardian binary — autonomous circuit breaker | dump 515 |
| F05169 | Guardian binary — listens to Tetragon eBPF UNIX socket | dump 515 |
| F05170 | Guardian binary — signed via MS003 selfdef-signing | cross-ref MS003 |
| F05171 | Tetragon — install llvm dependency | dump 714 |
| F05172 | Tetragon — install clang dependency | dump 714 |
| F05173 | Tetragon — deploy Tetragon binary release | dump 715 |
| F05174 | Tetragon — bind to local systemd target | dump 715 |
| F05175 | Tetragon — `systemctl start tetragon` | dump 716 |
| F05176 | Tetragon — tracks system call transitions out of microkernel ring buffers | dump 712-713 + dump 980 |
| F05177 | Tetragon — reads raw JSON execution paths | dump 980 |
| F05178 | Tetragon — kernel includes eBPF support compiled in (M067 dependency) | cross-ref sovereign-os M067 R11260 |
| F05179 | Socket — SOCKET_PATH = "/var/run/tetragon/tetragon.events" | dump 524 |
| F05180 | Socket — Guardian opens for read in main() | dump 540-541 |
| F05181 | Socket — Guardian errors if socket missing | dump 541-543 |
| F05182 | Socket — exit code 1 on missing socket | dump 543 |
| F05183 | Socket — read raw JSON stream line-by-line | dump 545-547 |
| F05184 | Socket — try/except json.JSONDecodeError | dump 548 + 561-562 |
| F05185 | Socket — continue on malformed JSON (skip corrupt lines) | dump 562 |
| F05186 | Event parser — `event = json.loads(line)` | dump 548 |
| F05187 | Event parser — check `event.get("action") == "SIGKILL"` | dump 550 |
| F05188 | Event parser — check `"process" in event.get("action", "").lower()` | dump 550 |
| F05189 | Event parser — extract container_id from `event.get("process", {}).get("docker", "")` | dump 552 |
| F05190 | Event parser — extract process_name from `event.get("process", {}).get("binary", "")` | dump 553 |
| F05191 | Event parser — extract violated_syscall from `event.get("syscall", {}).get("name", "sys_execve")` | dump 554 |
| F05192 | Event parser — default violated_syscall to "sys_execve" | dump 554 |
| F05193 | Event parser — pass extracted fields to alert_and_neutralize() | dump 556 |
| F05194 | Classifier — violation severity ladder: SIGKILL = critical (immediate neutralization) | dump 547-551 |
| F05195 | Classifier — process-action keyword presence = high severity | dump 550 |
| F05196 | Classifier — composes with MS042 4-severity classifier (low / medium / high / critical) | cross-ref MS042 |
| F05197 | Response 1 — `subprocess.run(["podman", "kill", container_id], ...)` | dump 529 |
| F05198 | Response 1 — stdout=subprocess.DEVNULL | dump 529 |
| F05199 | Response 1 — stderr=subprocess.DEVNULL | dump 529 |
| F05200 | Response 1 — SIGKILL is "instant hardware-level" per Trinity Auditor | dump 981 |
| F05201 | Response 1 — `[CRITICAL] PERIMETER VIOLATION:` log prefix | dump 527 |
| F05202 | Response 1 — log format includes container_id / process_name / violated_syscall | dump 527 |
| F05203 | Response 1 — print to stdout for systemd journal capture | dump 527-528 |
| F05204 | Response 2 — log file path `/mnt/vault/context/security_audit.log` | dump 531 |
| F05205 | Response 2 — log file ZFS dataset = tank/vault per sovereign-os M068 | cross-ref sovereign-os M068 |
| F05206 | Response 2 — open file with mode "a" (append) | dump 531 |
| F05207 | Response 2 — log line format: `[VIOLATION] Neutralized {process_name} ({container_id}) attempting {violated_syscall}\n` | dump 532-533 |
| F05208 | Response 2 — atomic via ZFS sync=always per M068 R11433 | cross-ref sovereign-os M068 |
| F05209 | Response 2 — file mode 0640 (operator-readable, group-readable) | architecture |
| F05210 | Response 2 — log rotation policy via logrotate (daily, retain 365 days) | architecture |
| F05211 | Response 3 — native Linux audio alert | dump 535-536 |
| F05212 | Response 3 — `os.system("echo -e '\a' > /dev/console")` | dump 536 |
| F05213 | Response 3 — PC speaker bell | dump 535 |
| F05214 | Response 3 — hardware-level alert (does not depend on display server) | dump 535 |
| F05215 | Response 3 — operator-disable-able via /etc/selfdef/guardian/console-bell.toml | architecture + operator standing direction "everything can be turned on and off" |
| F05216 | Main loop — startup banner: `[*] Guardian Native Event Loop Active. Monitoring Sovereign Perimeter...` | dump 538 |
| F05217 | Main loop — open SOCKET_PATH for read | dump 540 |
| F05218 | Main loop — iterate `for line in stream:` | dump 547 |
| F05219 | Main loop — try/except wraps json.loads + alert_and_neutralize | dump 548-561 |
| F05220 | Main loop — `if __name__ == "__main__": main()` | dump 564-565 |
| F05221 | Systemd unit — file path: `/etc/systemd/system/guardian-core.service` | dump 569 |
| F05222 | Systemd unit — built into ISO at config/includes.chroot/etc/systemd/system/guardian-core.service | dump 569 |
| F05223 | Systemd unit — [Unit] Description=Sovereign Guardian Core eBPF Supervisor | dump 571 |
| F05224 | Systemd unit — After=tetragon.service | dump 572 |
| F05225 | Systemd unit — Requires=tetragon.service | dump 573 |
| F05226 | Systemd unit — [Service] Type=simple | dump 575-576 |
| F05227 | Systemd unit — ExecStart=/usr/local/bin/guardian-core | dump 581 |
| F05228 | Systemd unit — Restart=always | dump 582 |
| F05229 | Systemd unit — RestartSec=1 | dump 583 |
| F05230 | Systemd unit — [Install] WantedBy=multi-user.target | dump 585-586 |
| F05231 | Tetragon policy YAML — under /etc/tetragon/tracing-policies/ | architecture |
| F05232 | Tetragon policy YAML — operator-tailored allowlist of syscalls per container profile | architecture + operator standing direction |
| F05233 | Tetragon policy YAML — signed via MS003 selfdef-signing | cross-ref MS003 |
| F05234 | Tetragon policy YAML — versioned at /etc/tetragon/tracing-policies/<profile>-<ts>.yaml | architecture |
| F05235 | Tetragon policy YAML — operator can disable per-profile (toggle) | operator standing direction |
| F05236 | Tetragon policy YAML — schema validated at load time | architecture |
| F05237 | Tetragon policy YAML — composes with MS040 six-profile authority matrix | cross-ref MS040 |
| F05238 | Tetragon policy YAML — composes with MS042 tool authority declaration | cross-ref MS042 |
| F05239 | Tetragon policy YAML — composes with MS043 IPS operator surface (CLI) | cross-ref MS043 |
| F05240 | Tetragon policy YAML — every reload signed + emits OCSF Configuration Change 5001 | cross-ref MS003 + MS026 |
| F05241 | Ring 0 placement — Guardian runs as Ring 0 IPS service per MS039 trust topology | cross-ref MS039 |
| F05242 | Ring 0 placement — Guardian has CAP_SYS_ADMIN + CAP_BPF | architecture + cross-ref MS039 R09205 |
| F05243 | Ring 0 placement — Guardian process runs as systemd unit child of PID 1 | cross-ref MS039 R09204 |
| F05244 | Ring 0 placement — Guardian exempt from L0 observer recursion | cross-ref MS039 F04598 |
| F05245 | Ring 0 placement — Guardian state exposed read-only via MS007 mirror | cross-ref MS007 + MS039 F04600 |
| F05246 | Trace emitter — every event emits M049 13-field span | cross-ref M049 |
| F05247 | Trace emitter — span includes: socket-event-id / action / container-id / process-name / violated-syscall / timestamp / response-taken | cross-ref M049 |
| F05248 | Trace emitter — deterministic field order for MS009 replay | cross-ref MS009 |
| F05249 | Trace emitter — routes to M049 observability pipeline | cross-ref M049 |
| F05250 | OCSF emitter — every violation emits Detection Finding class 2004 | cross-ref MS026 |
| F05251 | OCSF emitter — every quarantine action emits Audit Activity class 1003 | cross-ref MS026 |
| F05252 | OCSF emitter — every SIGKILL emits System Activity class 1001 (process kill) | cross-ref MS026 |
| F05253 | OCSF emitter — emission via M049 pipeline | cross-ref M049 |
| F05254 | Replay validator — verifies historical Guardian event chain integrity | cross-ref MS009 |
| F05255 | Replay validator — detects missing/forged SIGKILL responses | cross-ref MS003 + MS009 |
| F05256 | Replay validator — emits OCSF Detection 2004 on chain break | cross-ref MS026 |
| F05257 | Replay validator — runs daily as systemd timer | cross-ref MS009 |
| F05258 | Replay validator — failures halt new Guardian-initiated SIGKILLs until resolved | architecture |
| F05259 | Rollback — operator can restore quarantined container via MS003-signed request | cross-ref MS003 + MS041 |
| F05260 | Rollback — restore emits OCSF Audit Activity 1003 + M049 trace | cross-ref MS026 + M049 |
| F05261 | Rollback — restore composes with MS042 quarantine-restore action | cross-ref MS042 F05055 |
| F05262 | Typed mirror — selfdef-guardian-mirror crate under MS007 8/8 SATURATED | cross-ref MS007 |
| F05263 | Typed mirror — GuardianEvent struct {ts, action, container_id, process_name, violated_syscall, response_taken, signature} | cross-ref MS007 |
| F05264 | Typed mirror — GuardianPolicyState enum {Loaded, Active, ReloadPending, Halted} | cross-ref MS007 |
| F05265 | Typed mirror — schema_version "1.0.0" | cross-ref MS007 |
| F05266 | Typed mirror — signed via MS003 | cross-ref MS003 |
| F05267 | ZFS bridge — log path tank/vault/context/security_audit.log per sovereign-os M068 dataset hierarchy | cross-ref sovereign-os M068 F05719 |
| F05268 | ZFS bridge — sync=always on tank/vault for atomic writes | cross-ref sovereign-os M068 R11432 |
| F05269 | ZFS bridge — log immutability via append-only + ZFS snapshot retention | cross-ref MS037 + sovereign-os M068 |
| F05270 | ZFS bridge — log digest signed via MS003 periodically (hourly snapshot of digest chain) | cross-ref MS003 |
| F05271 | Offline survivability — Guardian runs without sovereign-os runtime present | operator standing direction "Respect the projects" + MS043 |
| F05272 | Offline survivability — Guardian buffers OCSF events to /var/log/selfdef/guardian/buffer.log if M049 unreachable | cross-ref MS043 R10223 |
| F05273 | Offline survivability — buffer drained automatically when M049 becomes reachable | cross-ref MS043 R10225 |
| F05274 | TUI binding — selfdef tui authority panel includes Guardian event counter | cross-ref MS043 |
| F05275 | TUI binding — Guardian last-N events visible in TUI footer (per MS043 R10241) | cross-ref MS043 |
| F05276 | CLI binding — `selfdef guardian status` returns daemon state | cross-ref MS043 architecture |
| F05277 | CLI binding — `selfdef guardian policy reload` reloads Tetragon YAML (operator-signed) | cross-ref MS003 + MS043 |
| F05278 | CLI binding — `selfdef guardian events --since <duration>` tails recent events | cross-ref MS043 |
| F05279 | Incident response — single-key "halt-all-guardian" (operator-only emergency) | cross-ref MS043 F05137-F05140 |
| F05280 | Closing — MS044 covers dump 513-588 + 712-721 + 977-981 verbatim Auditor IPS-side implementation | dump 513-588 + 712-721 + 977-981 |

## Requirements (R10321-R10560)

| req | description | source | feature | priority | exception | sub-reqs |
|---|---|---|---|---|---|---|
| R10321 | Doctrinal — Guardian replaces SecureToast.ps1 Windows-centric concept | dump 513-514 | F05165 | non-negotiable | false | 10 |
| R10322 | Doctrinal — Guardian = lightweight native Linux event supervisor | dump 514 | F05166 | non-negotiable | false | 10 |
| R10323 | Doctrinal — Guardian has no visual bloat, no network bloat | dump 514 | F05167 | non-negotiable | false | 10 |
| R10324 | Doctrinal — Guardian listens to local Tetragon eBPF UNIX socket | dump 515 | F05169 | non-negotiable | false | 10 |
| R10325 | Doctrinal — Guardian acts as autonomous circuit breaker | dump 515 | F05168 | non-negotiable | false | 10 |
| R10326 | Doctrinal — Guardian issues instant hardware-level SIGKILL (Trinity Auditor manifestation) | dump 981 | F05200 | non-negotiable | false | 10 |
| R10327 | Doctrinal — Guardian updates immutable ZFS transaction logs atomically | dump 981 | F05208 | non-negotiable | false | 10 |
| R10328 | Doctrinal — log path tank/context/security_audit.log (Trinity narrative) / tank/vault/context/security_audit.log (M068 dataset hierarchy refinement) | dump 981 + cross-ref sovereign-os M068 | F05204 | non-negotiable | false | 10 |
| R10329 | Doctrinal — Guardian is selfdef IPS-side implementation of sovereign-os M066 Trinity Auditor | operator standing direction "Respect the projects" + cross-ref sovereign-os M066 | F05161 | non-negotiable | false | 10 |
| R10330 | Doctrinal — narrative lineage in M066; IPS implementation in MS044 (this milestone) | architecture + operator standing direction | F05161 | non-negotiable | false | 10 |
| R10331 | Binary — installed at /usr/local/bin/guardian-core | dump 519 | F05161 | non-negotiable | false | 10 |
| R10332 | Binary — Python implementation initial (Rust rewrite scheduled) | dump 519-562 | F05162 | non-negotiable | false | 10 |
| R10333 | Binary — shebang `#!/usr/bin/env python3` | dump 521 | F05163 | non-negotiable | false | 10 |
| R10334 | Binary — module docstring "High-Standard Native Security Watcher" | dump 519 | F05164 | non-negotiable | false | 10 |
| R10335 | Binary — signed via MS003 selfdef-signing | cross-ref MS003 | F05170 | non-negotiable | false | 10 |
| R10336 | Binary — binary signature verified by selfdef-signing at install | cross-ref MS003 | F05170 | non-negotiable | false | 10 |
| R10337 | Binary — binary digest emitted via M049 trace on start | cross-ref M049 | F05216 | non-negotiable | false | 10 |
| R10338 | Binary — binary emits OCSF System Activity class 1001 on start | cross-ref MS026 | F05216 | non-negotiable | false | 10 |
| R10339 | Binary — Python deps minimal (stdlib only — json + os + sys + subprocess) | dump 522-523 | F05162 | non-negotiable | false | 10 |
| R10340 | Binary — no third-party imports (security minimization) | dump 522-523 + architecture | F05162 | non-negotiable | false | 10 |
| R10341 | Tetragon — install llvm via apt-get | dump 714 | F05171 | non-negotiable | false | 10 |
| R10342 | Tetragon — install clang via apt-get | dump 714 | F05172 | non-negotiable | false | 10 |
| R10343 | Tetragon — deploy Tetragon binary release | dump 715 | F05173 | non-negotiable | false | 10 |
| R10344 | Tetragon — bind to local systemd target | dump 715 | F05174 | non-negotiable | false | 10 |
| R10345 | Tetragon — `systemctl start tetragon` | dump 716 | F05175 | non-negotiable | false | 10 |
| R10346 | Tetragon — tracks syscall transitions out of microkernel ring buffers | dump 712-713 + 980 | F05176 | non-negotiable | false | 10 |
| R10347 | Tetragon — reads raw JSON execution paths | dump 980 | F05177 | non-negotiable | false | 10 |
| R10348 | Tetragon — kernel ships with eBPF support (M067 dependency) | cross-ref sovereign-os M067 R11260 | F05178 | non-negotiable | false | 10 |
| R10349 | Tetragon — health-check via `systemctl is-active tetragon` | architecture | F05174 | non-negotiable | false | 10 |
| R10350 | Tetragon — Guardian halts if Tetragon unhealthy (Requires= in systemd unit) | dump 573 | F05225 | non-negotiable | false | 10 |
| R10351 | Socket — SOCKET_PATH = "/var/run/tetragon/tetragon.events" verbatim | dump 524 | F05179 | non-negotiable | false | 10 |
| R10352 | Socket — Guardian opens for read in main() | dump 540-541 | F05180 | non-negotiable | false | 10 |
| R10353 | Socket — errors if socket missing (file not exists) | dump 541-543 | F05181 | non-negotiable | false | 10 |
| R10354 | Socket — exit code 1 on missing socket | dump 543 | F05182 | non-negotiable | false | 10 |
| R10355 | Socket — error message format: `Error: Tetragon event pipe not initialized at {SOCKET_PATH}` | dump 542 | F05181 | non-negotiable | false | 10 |
| R10356 | Socket — read raw JSON stream line-by-line via `for line in stream:` | dump 547 | F05183 | non-negotiable | false | 10 |
| R10357 | Socket — try/except wraps json.loads + handler call | dump 548-561 | F05184 | non-negotiable | false | 10 |
| R10358 | Socket — except json.JSONDecodeError → continue (skip corrupt lines) | dump 561-562 | F05185 | non-negotiable | false | 10 |
| R10359 | Socket — Guardian reconnects on socket disappearance (systemd Restart=always) | dump 582 | F05228 | non-negotiable | false | 10 |
| R10360 | Socket — reconnect emits M049 trace + OCSF System Activity 1001 | cross-ref M049 + MS026 | F05359 | non-negotiable | false | 10 |
| R10361 | Parser — `event = json.loads(line)` per dump | dump 548 | F05186 | non-negotiable | false | 10 |
| R10362 | Parser — check `event.get("action") == "SIGKILL"` | dump 550 | F05187 | non-negotiable | false | 10 |
| R10363 | Parser — OR check `"process" in event.get("action", "").lower()` | dump 550 | F05188 | non-negotiable | false | 10 |
| R10364 | Parser — extract container_id from event.get("process", {}).get("docker", "") | dump 552 | F05189 | non-negotiable | false | 10 |
| R10365 | Parser — extract process_name from event.get("process", {}).get("binary", "") | dump 553 | F05190 | non-negotiable | false | 10 |
| R10366 | Parser — extract violated_syscall from event.get("syscall", {}).get("name", "sys_execve") | dump 554 | F05191 | non-negotiable | false | 10 |
| R10367 | Parser — default violated_syscall to "sys_execve" | dump 554 | F05192 | non-negotiable | false | 10 |
| R10368 | Parser — pass extracted fields to alert_and_neutralize() | dump 556 | F05193 | non-negotiable | false | 10 |
| R10369 | Parser — extraction failures default to empty string (graceful) | dump 552-554 | F05193 | non-negotiable | false | 10 |
| R10370 | Parser — parsed event signed via MS003 before response (chain-of-trust) | cross-ref MS003 | F05193 | non-negotiable | false | 10 |
| R10371 | Classifier — SIGKILL action = critical severity (immediate neutralization) | dump 547-551 | F05194 | non-negotiable | false | 10 |
| R10372 | Classifier — process-action keyword presence = high severity | dump 550 | F05195 | non-negotiable | false | 10 |
| R10373 | Classifier — composes with MS042 4-severity classifier | cross-ref MS042 | F05196 | non-negotiable | false | 10 |
| R10374 | Classifier — severity emitted in M049 trace span | cross-ref M049 | F05246 | non-negotiable | false | 10 |
| R10375 | Classifier — severity persisted in audit log line | architecture + dump 532 | F05207 | non-negotiable | false | 10 |
| R10376 | Response 1 — `subprocess.run(["podman", "kill", container_id], ...)` | dump 529 | F05197 | non-negotiable | false | 10 |
| R10377 | Response 1 — stdout=subprocess.DEVNULL | dump 529 | F05198 | non-negotiable | false | 10 |
| R10378 | Response 1 — stderr=subprocess.DEVNULL | dump 529 | F05199 | non-negotiable | false | 10 |
| R10379 | Response 1 — SIGKILL is "instant hardware-level" per Trinity Auditor | dump 981 | F05200 | non-negotiable | false | 10 |
| R10380 | Response 1 — log prefix `[CRITICAL] PERIMETER VIOLATION:` | dump 527 | F05201 | non-negotiable | false | 10 |
| R10381 | Response 1 — log includes container_id / process_name / violated_syscall | dump 527 | F05202 | non-negotiable | false | 10 |
| R10382 | Response 1 — print to stdout for systemd journal capture | dump 527-528 | F05203 | non-negotiable | false | 10 |
| R10383 | Response 1 — emits OCSF System Activity class 1001 (process kill) | cross-ref MS026 | F05252 | non-negotiable | false | 10 |
| R10384 | Response 1 — emits M049 13-field trace span | cross-ref M049 | F05246 | non-negotiable | false | 10 |
| R10385 | Response 1 — atomic: SIGKILL response completes before next event read | architecture | F05197 | non-negotiable | false | 10 |
| R10386 | Response 2 — log file path `/mnt/vault/context/security_audit.log` | dump 531 | F05204 | non-negotiable | false | 10 |
| R10387 | Response 2 — ZFS dataset = tank/vault per sovereign-os M068 | cross-ref sovereign-os M068 F05719 | F05205 | non-negotiable | false | 10 |
| R10388 | Response 2 — open with mode "a" (append) | dump 531 | F05206 | non-negotiable | false | 10 |
| R10389 | Response 2 — line format verbatim: `[VIOLATION] Neutralized {process_name} ({container_id}) attempting {violated_syscall}\n` | dump 532-533 | F05207 | non-negotiable | false | 10 |
| R10390 | Response 2 — atomic via ZFS sync=always per M068 R11432 | cross-ref sovereign-os M068 | F05208 | non-negotiable | false | 10 |
| R10391 | Response 2 — file mode 0640 | architecture | F05209 | non-negotiable | false | 10 |
| R10392 | Response 2 — logrotate daily, retain 365 days | architecture | F05210 | non-negotiable | false | 10 |
| R10393 | Response 2 — log digest signed via MS003 hourly | cross-ref MS003 | F05270 | non-negotiable | false | 10 |
| R10394 | Response 2 — log immutable via append-only + ZFS snapshot | cross-ref MS037 + sovereign-os M068 | F05269 | non-negotiable | false | 10 |
| R10395 | Response 2 — emits OCSF Audit Activity class 1003 | cross-ref MS026 | F05251 | non-negotiable | false | 10 |
| R10396 | Response 3 — `os.system("echo -e '\a' > /dev/console")` | dump 536 | F05212 | non-negotiable | false | 10 |
| R10397 | Response 3 — PC speaker bell (hardware-level audio alert) | dump 535 | F05211 | non-negotiable | false | 10 |
| R10398 | Response 3 — hardware-level alert (does not depend on display server) | dump 535 | F05214 | non-negotiable | false | 10 |
| R10399 | Response 3 — operator-disable-able via /etc/selfdef/guardian/console-bell.toml | architecture + operator standing direction | F05215 | non-negotiable | false | 10 |
| R10400 | Response 3 — disable does NOT skip response 1 + response 2 | architecture + operator standing direction | F05215 | non-negotiable | false | 10 |
| R10401 | Main loop — startup banner verbatim: `[*] Guardian Native Event Loop Active. Monitoring Sovereign Perimeter...` | dump 538 | F05216 | non-negotiable | false | 10 |
| R10402 | Main loop — opens SOCKET_PATH for read | dump 540 | F05217 | non-negotiable | false | 10 |
| R10403 | Main loop — iterates `for line in stream:` | dump 547 | F05218 | non-negotiable | false | 10 |
| R10404 | Main loop — try/except wraps json.loads + alert_and_neutralize | dump 548-561 | F05219 | non-negotiable | false | 10 |
| R10405 | Main loop — entry guard `if __name__ == "__main__": main()` | dump 564-565 | F05220 | non-negotiable | false | 10 |
| R10406 | Main loop — handles SIGTERM gracefully (cleanup + exit 0) | architecture | F05216 | non-negotiable | false | 10 |
| R10407 | Main loop — handles SIGINT gracefully (cleanup + exit 0) | architecture | F05216 | non-negotiable | false | 10 |
| R10408 | Main loop — emits M049 trace per iteration | cross-ref M049 | F05246 | non-negotiable | false | 10 |
| R10409 | Systemd unit — file `/etc/systemd/system/guardian-core.service` | dump 569 | F05221 | non-negotiable | false | 10 |
| R10410 | Systemd unit — built into ISO at config/includes.chroot path | dump 569 | F05222 | non-negotiable | false | 10 |
| R10411 | Systemd unit — [Unit] Description=Sovereign Guardian Core eBPF Supervisor | dump 571 | F05223 | non-negotiable | false | 10 |
| R10412 | Systemd unit — After=tetragon.service | dump 572 | F05224 | non-negotiable | false | 10 |
| R10413 | Systemd unit — Requires=tetragon.service | dump 573 | F05225 | non-negotiable | false | 10 |
| R10414 | Systemd unit — [Service] Type=simple | dump 576 | F05226 | non-negotiable | false | 10 |
| R10415 | Systemd unit — ExecStart=/usr/local/bin/guardian-core | dump 581 | F05227 | non-negotiable | false | 10 |
| R10416 | Systemd unit — Restart=always | dump 582 | F05228 | non-negotiable | false | 10 |
| R10417 | Systemd unit — RestartSec=1 | dump 583 | F05229 | non-negotiable | false | 10 |
| R10418 | Systemd unit — [Install] WantedBy=multi-user.target | dump 586 | F05230 | non-negotiable | false | 10 |
| R10419 | Systemd unit — signed via MS003 selfdef-signing | cross-ref MS003 | F05221 | non-negotiable | false | 10 |
| R10420 | Systemd unit — `systemctl enable guardian-core.service` at install | architecture | F05230 | non-negotiable | false | 10 |
| R10421 | Tetragon policy — files under /etc/tetragon/tracing-policies/ | architecture + dump 714 | F05231 | non-negotiable | false | 10 |
| R10422 | Tetragon policy — operator-tailored allowlist of syscalls per container profile | architecture | F05232 | non-negotiable | false | 10 |
| R10423 | Tetragon policy — signed via MS003 | cross-ref MS003 | F05233 | non-negotiable | false | 10 |
| R10424 | Tetragon policy — versioned at /etc/tetragon/tracing-policies/<profile>-<ts>.yaml | architecture | F05234 | non-negotiable | false | 10 |
| R10425 | Tetragon policy — operator can disable per-profile (toggle) | operator standing direction "everything can be turned on and off" | F05235 | non-negotiable | false | 10 |
| R10426 | Tetragon policy — schema-validated at load | architecture | F05236 | non-negotiable | false | 10 |
| R10427 | Tetragon policy — schema validator emits OCSF Detection 2004 on malformed | cross-ref MS026 | F05236 | non-negotiable | false | 10 |
| R10428 | Tetragon policy — composes with MS040 six-profile authority matrix | cross-ref MS040 | F05237 | non-negotiable | false | 10 |
| R10429 | Tetragon policy — composes with MS042 tool authority declaration | cross-ref MS042 | F05238 | non-negotiable | false | 10 |
| R10430 | Tetragon policy — composes with MS043 IPS operator CLI | cross-ref MS043 | F05239 | non-negotiable | false | 10 |
| R10431 | Tetragon policy — every reload signed + emits OCSF Configuration Change 5001 | cross-ref MS003 + MS026 | F05240 | non-negotiable | false | 10 |
| R10432 | Tetragon policy — reload via `selfdef guardian policy reload` CLI subcommand | cross-ref MS043 | F05277 | non-negotiable | false | 10 |
| R10433 | Ring 0 — Guardian = Ring 0 IPS service per MS039 trust topology | cross-ref MS039 | F05241 | non-negotiable | false | 10 |
| R10434 | Ring 0 — Guardian has CAP_SYS_ADMIN | cross-ref MS039 R09205 | F05242 | non-negotiable | false | 10 |
| R10435 | Ring 0 — Guardian has CAP_BPF | architecture + cross-ref MS039 | F05242 | non-negotiable | false | 10 |
| R10436 | Ring 0 — Guardian process = systemd unit child of PID 1 | cross-ref MS039 R09204 | F05243 | non-negotiable | false | 10 |
| R10437 | Ring 0 — Guardian exempt from L0 observer recursion (avoid feedback loop) | cross-ref MS039 F04598 | F05244 | non-negotiable | false | 10 |
| R10438 | Ring 0 — Guardian state read-only via MS007 mirror | cross-ref MS007 + MS039 | F05245 | non-negotiable | false | 10 |
| R10439 | Ring 0 — Guardian capability_word trust_ring=0 | cross-ref MS035 + MS039 | F05241 | non-negotiable | false | 10 |
| R10440 | Ring 0 — Guardian mutates ruleset only via L5/L6 commit pipeline | cross-ref MS039 R09207 | F05241 | non-negotiable | false | 10 |
| R10441 | Trace emitter — every event emits M049 13-field span | cross-ref M049 | F05246 | non-negotiable | false | 10 |
| R10442 | Trace emitter — span includes socket-event-id | cross-ref M049 | F05247 | non-negotiable | false | 10 |
| R10443 | Trace emitter — span includes action | cross-ref M049 | F05247 | non-negotiable | false | 10 |
| R10444 | Trace emitter — span includes container-id | cross-ref M049 | F05247 | non-negotiable | false | 10 |
| R10445 | Trace emitter — span includes process-name | cross-ref M049 | F05247 | non-negotiable | false | 10 |
| R10446 | Trace emitter — span includes violated-syscall | cross-ref M049 | F05247 | non-negotiable | false | 10 |
| R10447 | Trace emitter — span includes timestamp | cross-ref M049 | F05247 | non-negotiable | false | 10 |
| R10448 | Trace emitter — span includes response-taken | cross-ref M049 | F05247 | non-negotiable | false | 10 |
| R10449 | Trace emitter — span deterministic for MS009 replay | cross-ref MS009 | F05248 | non-negotiable | false | 10 |
| R10450 | Trace emitter — routes to M049 observability pipeline | cross-ref M049 | F05249 | non-negotiable | false | 10 |
| R10451 | OCSF — every violation emits Detection Finding class 2004 | cross-ref MS026 | F05250 | non-negotiable | false | 10 |
| R10452 | OCSF — every quarantine emits Audit Activity class 1003 | cross-ref MS026 | F05251 | non-negotiable | false | 10 |
| R10453 | OCSF — every SIGKILL emits System Activity class 1001 | cross-ref MS026 | F05252 | non-negotiable | false | 10 |
| R10454 | OCSF — emission via M049 pipeline | cross-ref M049 | F05253 | non-negotiable | false | 10 |
| R10455 | OCSF — emission deterministic per MS009 replay | cross-ref MS009 | F05253 | non-negotiable | false | 10 |
| R10456 | Replay validator — verifies historical Guardian event chain integrity | cross-ref MS009 | F05254 | non-negotiable | false | 10 |
| R10457 | Replay validator — detects missing SIGKILL responses | cross-ref MS003 + MS009 | F05255 | non-negotiable | false | 10 |
| R10458 | Replay validator — detects forged signatures | cross-ref MS003 + MS009 | F05255 | non-negotiable | false | 10 |
| R10459 | Replay validator — emits OCSF Detection 2004 on chain break | cross-ref MS026 | F05256 | non-negotiable | false | 10 |
| R10460 | Replay validator — runs daily as systemd timer | cross-ref MS009 | F05257 | non-negotiable | false | 10 |
| R10461 | Replay validator — failures halt new Guardian SIGKILLs until resolved | architecture | F05258 | non-negotiable | false | 10 |
| R10462 | Rollback — operator restore quarantined container via MS003-signed request | cross-ref MS003 + MS041 | F05259 | non-negotiable | false | 10 |
| R10463 | Rollback — restore emits OCSF Audit Activity 1003 + M049 trace | cross-ref MS026 + M049 | F05260 | non-negotiable | false | 10 |
| R10464 | Rollback — restore composes with MS042 quarantine-restore action | cross-ref MS042 F05055 | F05261 | non-negotiable | false | 10 |
| R10465 | Rollback — restore requires double-confirmation (operator key + typed phrase) | cross-ref MS043 R10233 | F05259 | non-negotiable | false | 10 |
| R10466 | Rollback — restore logged in MS009 audit chain | cross-ref MS009 | F05259 | non-negotiable | false | 10 |
| R10467 | Typed mirror — selfdef-guardian-mirror under MS007 8/8 SATURATED | cross-ref MS007 | F05262 | non-negotiable | false | 10 |
| R10468 | Typed mirror — GuardianEvent struct fields {ts, action, container_id, process_name, violated_syscall, response_taken, signature} | cross-ref MS007 | F05263 | non-negotiable | false | 10 |
| R10469 | Typed mirror — GuardianPolicyState enum {Loaded, Active, ReloadPending, Halted} | cross-ref MS007 | F05264 | non-negotiable | false | 10 |
| R10470 | Typed mirror — schema_version "1.0.0" | cross-ref MS007 | F05265 | non-negotiable | false | 10 |
| R10471 | Typed mirror — signed via MS003 | cross-ref MS003 | F05266 | non-negotiable | false | 10 |
| R10472 | Typed mirror — re-exported via sovereign-os cargo workspace | cross-ref MS007 | F05262 | non-negotiable | false | 10 |
| R10473 | Typed mirror — no_std friendly | architecture | F05262 | non-negotiable | false | 10 |
| R10474 | Typed mirror — serde + bincode derives present | architecture | F05262 | non-negotiable | false | 10 |
| R10475 | Typed mirror — schema-breaking changes require schema_version bump | architecture + cross-ref MS007 | F05265 | non-negotiable | false | 10 |
| R10476 | ZFS bridge — log path tank/vault/context/security_audit.log per M068 hierarchy | cross-ref sovereign-os M068 | F05267 | non-negotiable | false | 10 |
| R10477 | ZFS bridge — sync=always on tank/vault for atomic writes | cross-ref sovereign-os M068 R11432 | F05268 | non-negotiable | false | 10 |
| R10478 | ZFS bridge — log immutability via append-only + ZFS snapshot retention | cross-ref MS037 + sovereign-os M068 | F05269 | non-negotiable | false | 10 |
| R10479 | ZFS bridge — log digest signed via MS003 hourly (digest chain) | cross-ref MS003 | F05270 | non-negotiable | false | 10 |
| R10480 | ZFS bridge — digest chain verified by MS009 replay validator | cross-ref MS009 + MS003 | F05254 | non-negotiable | false | 10 |
| R10481 | Offline — Guardian runs without sovereign-os runtime present | operator standing direction "Respect the projects" + MS043 R10217 | F05271 | non-negotiable | false | 10 |
| R10482 | Offline — Guardian buffers OCSF events to /var/log/selfdef/guardian/buffer.log if M049 unreachable | cross-ref MS043 R10223 | F05272 | non-negotiable | false | 10 |
| R10483 | Offline — buffer drained automatically when M049 becomes reachable | cross-ref MS043 R10225 | F05273 | non-negotiable | false | 10 |
| R10484 | Offline — buffered events MS003-signed at write time | cross-ref MS003 | F05272 | non-negotiable | false | 10 |
| R10485 | Offline — buffer retention 365 days minimum | cross-ref MS037 | F05272 | non-negotiable | false | 10 |
| R10486 | TUI — selfdef tui authority panel includes Guardian event counter | cross-ref MS043 R10142-R10149 | F05274 | non-negotiable | false | 10 |
| R10487 | TUI — Guardian last-N events visible in TUI footer | cross-ref MS043 R10241 | F05275 | non-negotiable | false | 10 |
| R10488 | TUI — operator can drill into Guardian event detail via Enter | cross-ref MS043 | F05274 | non-negotiable | false | 10 |
| R10489 | CLI — `selfdef guardian status` returns daemon state | cross-ref MS043 | F05276 | non-negotiable | false | 10 |
| R10490 | CLI — `selfdef guardian policy reload` reloads Tetragon YAML (operator-signed) | cross-ref MS003 + MS043 | F05277 | non-negotiable | false | 10 |
| R10491 | CLI — `selfdef guardian events --since <duration>` tails recent events | cross-ref MS043 | F05278 | non-negotiable | false | 10 |
| R10492 | CLI — `selfdef guardian policy list` lists installed Tetragon policies | architecture + cross-ref MS043 | F05231 | non-negotiable | false | 10 |
| R10493 | CLI — `selfdef guardian policy show <profile>` shows specific policy | architecture | F05231 | non-negotiable | false | 10 |
| R10494 | CLI — `selfdef guardian restore <container-id>` restores false-positive (operator-signed) | cross-ref MS003 + MS041 | F05259 | non-negotiable | false | 10 |
| R10495 | CLI — all guardian subcommands emit M049 trace | cross-ref M049 | F05246 | non-negotiable | false | 10 |
| R10496 | CLI — all guardian subcommands signed via MS003 | cross-ref MS003 | F05170 | non-negotiable | false | 10 |
| R10497 | Incident — single-key "halt-all-guardian" (operator-only emergency) | cross-ref MS043 F05137-F05140 | F05279 | non-negotiable | false | 10 |
| R10498 | Incident — halt-all-guardian double-confirms via operator key + typed phrase | cross-ref MS043 R10233 | F05279 | non-negotiable | false | 10 |
| R10499 | Incident — halt emits OCSF Detection 2004 + Audit 1003 + M049 trace | cross-ref MS026 + M049 | F05279 | non-negotiable | false | 10 |
| R10500 | Incident — halt logged separately at /var/log/selfdef/break-glass/ | cross-ref MS043 R10232 | F05279 | non-negotiable | false | 10 |
| R10501 | Boundary — Guardian Daemon IMPLEMENTATION lives in selfdef MS044 (this milestone) | operator standing direction "Respect the projects" | F05161 | non-negotiable | false | 10 |
| R10502 | Boundary — Guardian Daemon NARRATIVE lives in sovereign-os M066 Trinity Genesis | cross-ref sovereign-os M066 | F05161 | non-negotiable | false | 10 |
| R10503 | Boundary — sovereign-os runtime READS Guardian state via MS007 mirror only | cross-ref MS007 | F05245 | non-negotiable | false | 10 |
| R10504 | Boundary — sovereign-os runtime NEVER mutates Guardian state directly | operator standing direction | F05245 | non-negotiable | false | 10 |
| R10505 | Boundary — sovereign-os M060 dashboards (D-16 audit + D-17 quarantine) consume Guardian mirror | cross-ref sovereign-os M060 | F05262 | non-negotiable | false | 10 |
| R10506 | Boundary — info-hub knowledge layer treats Guardian state as read-only context | operator standing direction "second-brain" | F05262 | non-negotiable | false | 10 |
| R10507 | Boundary — Guardian Daemon NEVER calls sovereign-os APIs | operator standing direction | F05271 | non-negotiable | false | 10 |
| R10508 | Boundary — Guardian Daemon is the PRIMARY IPS supervisor for container/process activity | operator standing direction + Trinity Auditor | F05168 | non-negotiable | false | 10 |
| R10509 | Boundary — Guardian Daemon composes with MS024 (eBPF + nftables) | cross-ref MS024 | F05176 | non-negotiable | false | 10 |
| R10510 | Boundary — Guardian Daemon composes with MS037 (filesystem boundary; ZFS audit log writes) | cross-ref MS037 + sovereign-os M068 | F05204 | non-negotiable | false | 10 |
| R10511 | Composition — Guardian composes with MS035 capability tokens (Ring 0 trust) | cross-ref MS035 + MS039 | F05241 | non-negotiable | false | 10 |
| R10512 | Composition — Guardian composes with MS036 sandbox tiers (kills Tier A/B/C/D containers) | cross-ref MS036 | F05197 | non-negotiable | false | 10 |
| R10513 | Composition — Guardian composes with MS038 network boundary (network violation detection) | cross-ref MS038 | F05176 | non-negotiable | false | 10 |
| R10514 | Composition — Guardian composes with MS039 authority levels (every event = L0 Observe → L4 Execute SIGKILL) | cross-ref MS039 | F05241 | non-negotiable | false | 10 |
| R10515 | Composition — Guardian composes with MS040 profile envelopes (policy varies per profile) | cross-ref MS040 | F05237 | non-negotiable | false | 10 |
| R10516 | Composition — Guardian composes with MS041 commit authority (Guardian SIGKILL = L5 Commit) | cross-ref MS041 | F05197 | non-negotiable | false | 10 |
| R10517 | Composition — Guardian composes with MS042 tool authority (violation = declaration-vs-observed mismatch) | cross-ref MS042 | F05196 | non-negotiable | false | 10 |
| R10518 | Composition — Guardian composes with MS043 operator surface (CLI + TUI + minimal-web) | cross-ref MS043 | F05276 | non-negotiable | false | 10 |
| R10519 | Composition — Guardian composes with sovereign-os M058 hardware-aware scheduler | cross-ref sovereign-os M058 | F05197 | non-negotiable | false | 10 |
| R10520 | Composition — Guardian composes with sovereign-os M068 ZFS storage (tank/vault dataset) | cross-ref sovereign-os M068 | F05267 | non-negotiable | false | 10 |
| R10521 | Performance — Guardian event-to-SIGKILL latency `<` 100ms p95 | architecture | F05197 | non-negotiable | false | 10 |
| R10522 | Performance — Guardian event-to-log-append latency `<` 50ms p95 | architecture | F05206 | non-negotiable | false | 10 |
| R10523 | Performance — Guardian event-to-trace latency `<` 100ms p95 | cross-ref M049 | F05246 | non-negotiable | false | 10 |
| R10524 | Performance — Guardian sustained event throughput `>=` 1000 events/sec | architecture | F05183 | non-negotiable | false | 10 |
| R10525 | Performance — Guardian memory footprint `<` 50MB RSS | architecture | F05161 | non-negotiable | false | 10 |
| R10526 | Performance — Guardian CPU overhead `<` 5% on Ryzen 9 9900X | architecture | F05161 | non-negotiable | false | 10 |
| R10527 | Performance — replay validator daily run `<` 60s on 365-day chain | cross-ref MS009 | F05254 | non-negotiable | false | 10 |
| R10528 | Performance — typed-mirror publication latency `<` 100ms p95 | cross-ref MS007 | F05262 | non-negotiable | false | 10 |
| R10529 | Telemetry — Guardian event count emitted via M049 | cross-ref M049 | F05246 | non-negotiable | false | 10 |
| R10530 | Telemetry — Guardian SIGKILL count emitted via M049 | cross-ref M049 | F05197 | non-negotiable | false | 10 |
| R10531 | Telemetry — Guardian violation severity distribution emitted via M049 | cross-ref M049 | F05194 | non-negotiable | false | 10 |
| R10532 | Telemetry — Guardian policy reload count emitted via M049 | cross-ref M049 | F05240 | non-negotiable | false | 10 |
| R10533 | Telemetry — Guardian socket-reconnect count emitted via M049 | cross-ref M049 | F05359 | non-negotiable | false | 10 |
| R10534 | Telemetry — Guardian replay validator pass-rate emitted via M049 | cross-ref M049 | F05254 | non-negotiable | false | 10 |
| R10535 | Telemetry — Guardian rollback (restore) count emitted via M049 (high-priority alert) | cross-ref M049 | F05259 | non-negotiable | false | 10 |
| R10536 | Operational — Guardian systemd unit `systemctl enable guardian-core.service` at install | architecture | F05230 | non-negotiable | false | 10 |
| R10537 | Operational — Guardian refuses to start with chain-break detected | cross-ref MS009 | F05258 | non-negotiable | false | 10 |
| R10538 | Operational — Guardian refuses to start with missing MS003 keys | cross-ref MS003 | F05170 | non-negotiable | false | 10 |
| R10539 | Operational — Guardian refuses to start with missing Tetragon socket | dump 541-543 | F05181 | non-negotiable | false | 10 |
| R10540 | Operational — Guardian refuses to start with missing tank/vault dataset | cross-ref sovereign-os M068 | F05267 | non-negotiable | false | 10 |
| R10541 | Operational — Guardian readiness probe at /run/selfdef/guardian/ready | architecture | F05216 | non-negotiable | false | 10 |
| R10542 | Operational — Guardian liveness probe at /run/selfdef/guardian/alive | architecture | F05216 | non-negotiable | false | 10 |
| R10543 | Operational — Guardian honors SIGHUP for policy reload | architecture + dump 716 | F05277 | non-negotiable | false | 10 |
| R10544 | Operational — Guardian honors SIGTERM for graceful drain | architecture | F05406 | non-negotiable | false | 10 |
| R10545 | Operational — Guardian exit code 1 on init failure | dump 543 | F05182 | non-negotiable | false | 10 |
| R10546 | Doctrinal preservation — operator words "autonomous circuit breaker" verbatim | dump 515 | F05168 | non-negotiable | false | 10 |
| R10547 | Doctrinal preservation — Auditor → physical Tetragon manifestation verbatim per M066 | cross-ref sovereign-os M066 | F05161 | non-negotiable | false | 10 |
| R10548 | Doctrinal preservation — "hardware-level SIGKILL" verbatim from dump 981 | dump 981 | F05200 | non-negotiable | false | 10 |
| R10549 | Doctrinal preservation — `[CRITICAL] PERIMETER VIOLATION` log prefix verbatim | dump 527 | F05201 | non-negotiable | false | 10 |
| R10550 | Doctrinal preservation — `[VIOLATION] Neutralized` log line format verbatim | dump 532 | F05207 | non-negotiable | false | 10 |
| R10551 | Doctrinal preservation — `Sovereign Guardian Core eBPF Supervisor` description verbatim | dump 571 | F05223 | non-negotiable | false | 10 |
| R10552 | Doctrinal preservation — operator words "Respect the projects" applied (Auditor IPS implementation in selfdef) | operator standing direction | F05161 | non-negotiable | false | 10 |
| R10553 | Doctrinal preservation — verbatim quotes never paraphrased | operator standing direction | F05161 | non-negotiable | false | 10 |
| R10554 | Doctrinal preservation — info-hub indexes Guardian Daemon as second-brain entry | operator standing direction "second-brain" | F05161 | non-negotiable | false | 10 |
| R10555 | Closing — MS044 covers dump 513-588 + 712-721 + 977-981 verbatim Auditor IPS-side implementation | dump 513-588 + 712-721 + 977-981 | F05280 | non-negotiable | false | 10 |
| R10556 | Closing — selfdef catalog at 44/44 milestones | architecture | F05280 | non-negotiable | false | 10 |
| R10557 | Closing — combined ecosystem 112 milestones (sovereign-os 68 + selfdef 44) | architecture | F05280 | non-negotiable | false | 10 |
| R10558 | Closing — combined R-rows ~22120 (R10560 selfdef + R11560 sovereign-os) | architecture | F05280 | non-negotiable | false | 10 |
| R10559 | Closing — every R-row carries 10 hard non-negotiable sub-requirements | operator standing direction | F05161 | non-negotiable | false | 10 |
| R10560 | Closing — MS044 covers Guardian Daemon scope verbatim; sovereign-os M070 Dual-CCD Cache Topology next | dump 513-981 + operator standing direction | F05280 | non-negotiable | false | 10 |

## Sub-requirements accounting

Every R-row carries 10 hard non-negotiable sub-requirements. Total = 240 R × 10 = **2,400 sub-requirements** for MS044.

## Cross-references

- **sovereign-os M066** — Trinity Framework Genesis (The Auditor narrative; MS044 = IPS-side implementation)
- **sovereign-os M067** — Custom Kernel Build (kernel ships eBPF support)
- **sovereign-os M068** — ZFS Storage Architecture (tank/vault dataset for security audit log)
- **sovereign-os M058** — hardware-aware scheduler (Guardian process scheduling)
- **sovereign-os M049** — observability + trace pipeline
- **sovereign-os M060** — cockpit + dashboards (D-16 audit + D-17 quarantine consume Guardian mirror)
- **MS003** — selfdef-signing (signs every event + policy + chain)
- **MS007** — typed-mirror crate scheme (selfdef-guardian-mirror)
- **MS009** — replay validator
- **MS024** — eBPF + nftables (Guardian uses Tetragon eBPF)
- **MS026** — observability + OCSF event emission
- **MS035** — capability tokens (Ring 0 trust)
- **MS036** — sandbox tiers (Guardian kills containers from any tier)
- **MS037** — filesystem boundary (Guardian writes to ZFS-mounted /mnt/vault)
- **MS038** — network boundary (Guardian detects network violations)
- **MS039** — authority levels + trust rings (Guardian = Ring 0)
- **MS040** — profile envelopes (policy varies per profile)
- **MS041** — commit authority (Guardian SIGKILL = L5 Commit, restore composes)
- **MS042** — tool authority (Guardian violation = declaration-vs-observed mismatch)
- **MS043** — IPS operator surface (CLI + TUI + minimal-web integration)

## Schema

```
schema_version: "1.0.0"
milestone_id: MS044
parent: selfdef
epics: 10
modules: 26
features: 120
requirements: 240
sub_requirements_per_requirement: 10
total_sub_requirements: 2400
source_dump_lines:
  - 513-588 (Section 10: Native Guardian Event Loop)
  - 712-721 (Phase V: Multi-Agent Mission Control + Guardian Loop Activation)
  - 977-981 (The Auditor → physical Tetragon manifestation per Trinity Genesis)
cross_repo_mirror: sovereign-os/M066 (narrative)
typed_mirror_crate: selfdef-guardian-mirror
guardian_response_protocol:
  step_1: SIGKILL via podman kill (instant hardware-level neutralization)
  step_2: atomic append to tank/vault/context/security_audit.log (ZFS sync=always)
  step_3: PC speaker bell via /dev/console (operator-disable-able)
systemd_unit: /etc/systemd/system/guardian-core.service
binary_path: /usr/local/bin/guardian-core
socket_path: /var/run/tetragon/tetragon.events
catalog_status:
  selfdef: 44/44 milestones (now extends prior 43)
  sovereign_os: 68/68 milestones
  combined: 112 milestones
```
