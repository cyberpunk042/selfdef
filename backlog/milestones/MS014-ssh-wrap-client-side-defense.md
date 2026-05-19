# MS014 — SSH-wrap — client-side defense when YOU are the client

> Parent: `backlog/milestones/INDEX.md` row MS014.
> Source: `crates/selfdef-ssh-wrap/` (4 source modules: argv.rs 235 lines / events.rs 204 lines / main.rs 155 lines / policy.rs 327 lines; 921 lines total; Cargo.toml description "Client-side SSH wrapper: policy enforcement + session events.") + `docs/src/ops/ssh-wrap-install.md` (5-step install procedure + env-var overrides + caveats) + `packaging/ssh-wrap-policy.toml.example` (TOML schema with [defaults] + per-host overrides) + `docs/src/dev/collector.md` (eventstream collector consumes selfdef-ssh-wrap JSONL). All entries below extract verbatim from these source files. No invention.

## Epics (E0141–E0150)

| Epic ID | Phrase | Source |
|---|---|---|
| E0141 | Mission — Client-side SSH wrapper; policy enforcement + session events; drop-in replacement for `ssh`; install binary on PATH and point symlink at it; existing scripts/tooling that exec `ssh` route through wrapper transparently | `crates/selfdef-ssh-wrap/Cargo.toml` description + `docs/src/ops/ssh-wrap-install.md` § "drop-in replacement" |
| E0142 | Install procedure (5 steps) — (1) build binary `cargo build --release -p selfdef-ssh-wrap` + install to `/usr/local/bin/`; (2) shadow `ssh` for user via `ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh` + ensure `~/.local/bin` precedes `/usr/bin` in PATH; (3) drop policy file to `~/.config/selfdef/ssh-wrap.toml`; (4) wire events into daemon via `[collectors.eventstream]` reading from `~/.local/share/selfdef/ssh-wrap.jsonl`; (5) sanity-check (`ssh -V` passthrough / `ssh user@host` wrap engaged / `ssh -A user@host` strips agent forwarding with policy-strip event / tail event log) | `docs/src/ops/ssh-wrap-install.md` § 1–5 |
| E0143 | Argv module (`src/argv.rs`, 235 lines) — parses ssh argv, identifies passthrough vs intercept cases (-V no-op, `-A` agent-forward strip, `-Y/-X` X11 strip, `-L/-R/-D` port-forward strip, target host extraction) | `crates/selfdef-ssh-wrap/src/argv.rs` |
| E0144 | Policy module (`src/policy.rs`, 327 lines) — `PolicyFile` struct (defaults: HostPolicy + hosts: HashMap<String, HostPolicy>); `HostPolicy` struct (7 fields: forward_agent / forward_x11 / port_forwarding / strict_host_key / exit_on_forward_failure / connect_timeout_secs / server_alive_interval_secs); `secure_defaults()` (paranoid client baseline); `merge_over()` (per-host overrides over defaults); host-pattern matching (exact / `*.suffix` glob / `prefix*` glob — intentionally simple, no regex, no recursion) | `crates/selfdef-ssh-wrap/src/policy.rs` |
| E0145 | Events module (`src/events.rs`, 204 lines) — emits OCSF events to `~/.local/share/selfdef/ssh-wrap.jsonl`; event types (session-start / session-end / policy-strip / connection-failed / host-key-changed) | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/ops/ssh-wrap-install.md` |
| E0146 | Main binary (`src/main.rs`, 155 lines) — parses argv → applies policy → emits events → execs `SELFDEF_SSH_PATH` (default `/usr/bin/ssh`); pass-through case (`ssh -V`) does not engage wrap | `crates/selfdef-ssh-wrap/src/main.rs` |
| E0147 | Secure defaults (paranoid client baseline) — forward_agent=false / forward_x11=false / port_forwarding=false / strict_host_key="accept-new" / exit_on_forward_failure=true / connect_timeout_secs=20 / server_alive_interval_secs=30; "default policy denies agent forwarding, X11 forwarding, and port forwarding for every host; per-host blocks opt specific hosts in" | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` + `packaging/ssh-wrap-policy.toml.example` |
| E0148 | Per-host overrides — patterns supported = exact host / `*.suffix` / `prefix*`; 3 example overrides (`git.internal.example.com` forward_agent=true for git push / `*.internal` port_forwarding=true / `ci.example.com` forward_x11=true for GUI test); "leave defaults off, opt hosts in below" | `packaging/ssh-wrap-policy.toml.example` per-host section + `crates/selfdef-ssh-wrap/src/policy.rs` § "Host pattern matching" |
| E0149 | Environment variable overrides — `SELFDEF_SSH_PATH=/usr/bin/ssh` (real ssh binary to exec; default `/usr/bin/ssh`) / `SELFDEF_SSH_POLICY=/path/to/policy.toml` (override policy location) / `SELFDEF_SSH_EVENT_LOG=/path/to/events.jsonl` (override event log path) | `docs/src/ops/ssh-wrap-install.md` § "Environment variable overrides" |
| E0150 | Caveats + defense-in-depth + collector integration — wrapper can't see what happens inside an established session (connection lifecycle + args only, NOT remote shell activity); host key change detection left to ssh itself (`StrictHostKeyChecking=accept-new` default; "REMOTE HOST IDENTIFICATION HAS CHANGED" message comes from ssh on stderr); agent forwarding inside already-established session (`~C -A`) has no wrapper visibility — set `AllowAgentForwarding no` on the *server* side as defense-in-depth; selfdef-collector-eventstream tails the JSONL into the daemon's event store; T1098 Account Manipulation detection coverage via `defense_evasion/ssh_wrap_policy_strip.yml` rule | `docs/src/ops/ssh-wrap-install.md` § Caveats + `docs/src/dev/collector.md` + `docs/src/detect/attack_coverage.md` |

## Modules (M00343–M00368)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00343 | Crate `selfdef-ssh-wrap` workspace member — `[package] name = "selfdef-ssh-wrap"` | `crates/selfdef-ssh-wrap/Cargo.toml` | E0141 |
| M00344 | Crate dependencies — selfdef-core / anyhow / serde / serde_json / toml / time | `crates/selfdef-ssh-wrap/Cargo.toml` | E0141 |
| M00345 | Crate dev-dependencies — tempfile | `crates/selfdef-ssh-wrap/Cargo.toml` | E0141 |
| M00346 | Binary `selfdef-ssh-wrap` (path = `src/main.rs`) | `crates/selfdef-ssh-wrap/Cargo.toml` `[[bin]]` | E0146 |
| M00347 | Build step — `cargo build --release -p selfdef-ssh-wrap` | `docs/src/ops/ssh-wrap-install.md` § 1 | E0142 |
| M00348 | Install step — `sudo install -m 0755 target/release/selfdef-ssh-wrap /usr/local/bin/` | `docs/src/ops/ssh-wrap-install.md` § 1 | E0142 |
| M00349 | Shadow step — `ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh` + `~/.local/bin` precedes `/usr/bin` in PATH | `docs/src/ops/ssh-wrap-install.md` § 2 | E0142 |
| M00350 | Policy file path — `~/.config/selfdef/ssh-wrap.toml` (default) | `docs/src/ops/ssh-wrap-install.md` § 3 + `crates/selfdef-ssh-wrap/src/policy.rs` § header | E0144 |
| M00351 | Policy example source — `packaging/ssh-wrap-policy.toml.example` | `docs/src/ops/ssh-wrap-install.md` § 3 + `packaging/ssh-wrap-policy.toml.example` | E0144 |
| M00352 | Event log path — `~/.local/share/selfdef/ssh-wrap.jsonl` (default) | `docs/src/ops/ssh-wrap-install.md` § 4 | E0145 |
| M00353 | Collector wiring — `/etc/selfdef/selfdef.toml` `[collectors.eventstream]` enabled=true + paths=["…ssh-wrap.jsonl"] + read_from="end" | `docs/src/ops/ssh-wrap-install.md` § 4 | E0145 |
| M00354 | PolicyFile struct — fields defaults (HostPolicy) + hosts (HashMap<String, HostPolicy>) | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile | E0144 |
| M00355 | HostPolicy struct — 7 fields (forward_agent / forward_x11 / port_forwarding / strict_host_key / exit_on_forward_failure / connect_timeout_secs / server_alive_interval_secs) all Option-typed | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | E0144 |
| M00356 | secure_defaults() — paranoid client baseline (forward_agent=false / forward_x11=false / port_forwarding=false / strict_host_key="accept-new" / exit_on_forward_failure=true / connect_timeout_secs=20 / server_alive_interval_secs=30) | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy::secure_defaults | E0147 |
| M00357 | merge_over() — per-host override merges over default base | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy::merge_over | E0148 |
| M00358 | Host pattern — exact host match | `crates/selfdef-ssh-wrap/src/policy.rs` § "Host pattern matching" | E0148 |
| M00359 | Host pattern — `*.suffix` glob match | `crates/selfdef-ssh-wrap/src/policy.rs` § "Host pattern matching" | E0148 |
| M00360 | Host pattern — `prefix*` glob match | `crates/selfdef-ssh-wrap/src/policy.rs` § "Host pattern matching" | E0148 |
| M00361 | Host pattern principle — "intentionally simple: exact match, `*.suffix` glob, or `prefix*` glob. No regex, no recursion, no surprises." | `crates/selfdef-ssh-wrap/src/policy.rs` § header | E0148 |
| M00362 | Env-var override — `SELFDEF_SSH_PATH` (real ssh binary; default `/usr/bin/ssh`) | `docs/src/ops/ssh-wrap-install.md` § Env-var overrides | E0149 |
| M00363 | Env-var override — `SELFDEF_SSH_POLICY` (override policy location) | `docs/src/ops/ssh-wrap-install.md` § Env-var overrides | E0149 |
| M00364 | Env-var override — `SELFDEF_SSH_EVENT_LOG` (override event log path) | `docs/src/ops/ssh-wrap-install.md` § Env-var overrides | E0149 |
| M00365 | Caveat — wrapper observes connection lifecycle + args, NOT remote shell activity inside an established session | `docs/src/ops/ssh-wrap-install.md` § Caveats | E0150 |
| M00366 | Caveat — host key change detection left to ssh itself (StrictHostKeyChecking=accept-new default; wrapper logs failed exit code; "REMOTE HOST IDENTIFICATION HAS CHANGED" message comes from ssh on stderr) | `docs/src/ops/ssh-wrap-install.md` § Caveats | E0150 |
| M00367 | Caveat — `~C -A` (in-session agent forwarding) has no wrapper visibility; defense-in-depth = set `AllowAgentForwarding no` on the *server* side | `docs/src/ops/ssh-wrap-install.md` § Caveats | E0150 |
| M00368 | Detection coverage — T1098 Account Manipulation rule `defense_evasion/ssh_wrap_policy_strip.yml`; selfdef component label `selfdef.ssh-wrap` | `docs/src/detect/attack_coverage.md` | E0150 |

## Features (F01561–F01680)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F01561 | Crate name — `selfdef-ssh-wrap` | `crates/selfdef-ssh-wrap/Cargo.toml` | E0141 | composite | false |
| F01562 | Crate description — "Client-side SSH wrapper: policy enforcement + session events." | `crates/selfdef-ssh-wrap/Cargo.toml` | E0141 | composite | false |
| F01563 | Workspace-pinned version / edition / rust-version / license / repository / authors / publish | `crates/selfdef-ssh-wrap/Cargo.toml` | M00343 | composite | false |
| F01564 | Lints inherited from workspace | `crates/selfdef-ssh-wrap/Cargo.toml` `[lints]` | M00343 | composite | false |
| F01565 | Dependency — selfdef-core (workspace) | `crates/selfdef-ssh-wrap/Cargo.toml` | M00344 | composite | true |
| F01566 | Dependency — anyhow (workspace) | `crates/selfdef-ssh-wrap/Cargo.toml` | M00344 | composite | true |
| F01567 | Dependency — serde (workspace) | `crates/selfdef-ssh-wrap/Cargo.toml` | M00344 | composite | true |
| F01568 | Dependency — serde_json (workspace) | `crates/selfdef-ssh-wrap/Cargo.toml` | M00344 | composite | true |
| F01569 | Dependency — toml (workspace; for policy file parsing) | `crates/selfdef-ssh-wrap/Cargo.toml` | M00344 | composite | true |
| F01570 | Dependency — time (workspace; for event timestamps) | `crates/selfdef-ssh-wrap/Cargo.toml` | M00344 | composite | true |
| F01571 | Dev-dependency — tempfile (for unit tests) | `crates/selfdef-ssh-wrap/Cargo.toml` | M00345 | composite | true |
| F01572 | Binary target — `selfdef-ssh-wrap` (`path = "src/main.rs"`) | `crates/selfdef-ssh-wrap/Cargo.toml` `[[bin]]` | M00346 | composite | false |
| F01573 | Source module — `src/argv.rs` (235 lines) | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | composite | false |
| F01574 | Source module — `src/events.rs` (204 lines) | `crates/selfdef-ssh-wrap/src/events.rs` | E0145 | composite | false |
| F01575 | Source module — `src/main.rs` (155 lines) | `crates/selfdef-ssh-wrap/src/main.rs` | E0146 | composite | false |
| F01576 | Source module — `src/policy.rs` (327 lines) | `crates/selfdef-ssh-wrap/src/policy.rs` | E0144 | composite | false |
| F01577 | Total source size — 921 lines across 4 modules | `crates/selfdef-ssh-wrap/src/` | E0141 | composite | false |
| F01578 | Install step 1 — Build via `cargo build --release -p selfdef-ssh-wrap` | `docs/src/ops/ssh-wrap-install.md` § 1 | M00347 | composite | true |
| F01579 | Install step 1 — Install binary via `sudo install -m 0755 target/release/selfdef-ssh-wrap /usr/local/bin/` | `docs/src/ops/ssh-wrap-install.md` § 1 | M00348 | composite | true |
| F01580 | Install step 2 — `mkdir -p ~/.local/bin` | `docs/src/ops/ssh-wrap-install.md` § 2 | M00349 | composite | true |
| F01581 | Install step 2 — `ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh` | `docs/src/ops/ssh-wrap-install.md` § 2 | M00349 | composite | true |
| F01582 | Install step 2 — `export PATH="$HOME/.local/bin:$PATH"` in ~/.zshrc or ~/.bashrc | `docs/src/ops/ssh-wrap-install.md` § 2 | M00349 | composite | true |
| F01583 | Install step 2 verification — `which ssh` prints `/home/<you>/.local/bin/ssh` | `docs/src/ops/ssh-wrap-install.md` § 2 | M00349 | composite | false |
| F01584 | Install step 2 effect — existing scripts and tooling that exec `ssh` route through wrapper transparently | `docs/src/ops/ssh-wrap-install.md` § 2 | E0141 | composite | false |
| F01585 | Install step 3 — `mkdir -p ~/.config/selfdef` | `docs/src/ops/ssh-wrap-install.md` § 3 | M00350 | composite | true |
| F01586 | Install step 3 — `cp packaging/ssh-wrap-policy.toml.example ~/.config/selfdef/ssh-wrap.toml` | `docs/src/ops/ssh-wrap-install.md` § 3 | M00350 | composite | true |
| F01587 | Default policy denies — agent forwarding | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01588 | Default policy denies — X11 forwarding | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01589 | Default policy denies — port forwarding | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01590 | Default policy applies per every host (operator opts hosts in via per-host blocks) | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` § header | E0148 | composite | false |
| F01591 | Install step 4 — `[collectors.eventstream]` enabled=true | `docs/src/ops/ssh-wrap-install.md` § 4 | M00353 | composite | true |
| F01592 | Install step 4 — paths = ["/home/<you>/.local/share/selfdef/ssh-wrap.jsonl"] | `docs/src/ops/ssh-wrap-install.md` § 4 | M00353 | composite | true |
| F01593 | Install step 4 — read_from = "end" | `docs/src/ops/ssh-wrap-install.md` § 4 | M00353 | composite | true |
| F01594 | Install step 4 — daemon needs read access to event log (run daemon as user OR `chmod 0644` + setgid directory) | `docs/src/ops/ssh-wrap-install.md` § 4 | M00353 | composite | false |
| F01595 | Install step 5 sanity check — `ssh -V` passes through, no wrap | `docs/src/ops/ssh-wrap-install.md` § 5 | E0142 | composite | true |
| F01596 | Install step 5 sanity check — `ssh user@example.com` wrap engaged: events appended + policy applied | `docs/src/ops/ssh-wrap-install.md` § 5 | E0142 | composite | true |
| F01597 | Install step 5 sanity check — `ssh -A user@example.com` wrap strips `-A` + emits a policy-strip event | `docs/src/ops/ssh-wrap-install.md` § 5 | E0146 | composite | true |
| F01598 | Install step 5 sanity check — `tail ~/.local/share/selfdef/ssh-wrap.jsonl` shows recent events | `docs/src/ops/ssh-wrap-install.md` § 5 | M00352 | composite | true |
| F01599 | Env var override — `SELFDEF_SSH_PATH` (default `/usr/bin/ssh`) | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | M00362 | composite | true |
| F01600 | Env var override — `SELFDEF_SSH_POLICY` (override policy location) | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | M00363 | composite | true |
| F01601 | Env var override — `SELFDEF_SSH_EVENT_LOG` (override event log path) | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | M00364 | composite | true |
| F01602 | PolicyFile field — `defaults` (HostPolicy) | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile | M00354 | composite | false |
| F01603 | PolicyFile field — `hosts` (HashMap<String, HostPolicy>; default empty) | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile | M00354 | composite | false |
| F01604 | PolicyFile default impl — defaults: HostPolicy::secure_defaults(), hosts: HashMap::new() | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile::default | M00354 | composite | false |
| F01605 | HostPolicy field — forward_agent: Option<bool> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | M00355 | composite | true |
| F01606 | HostPolicy field — forward_x11: Option<bool> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | M00355 | composite | true |
| F01607 | HostPolicy field — port_forwarding: Option<bool> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | M00355 | composite | true |
| F01608 | HostPolicy field — strict_host_key: Option<String> ("yes" \| "accept-new" \| "no") | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | M00355 | composite | true |
| F01609 | HostPolicy field — exit_on_forward_failure: Option<bool> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | M00355 | composite | true |
| F01610 | HostPolicy field — connect_timeout_secs: Option<u32> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | M00355 | composite | true |
| F01611 | HostPolicy field — server_alive_interval_secs: Option<u32> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | M00355 | composite | true |
| F01612 | HostPolicy default impl — all 7 fields None | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy::default | M00355 | composite | false |
| F01613 | secure_defaults() value — forward_agent: Some(false) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01614 | secure_defaults() value — forward_x11: Some(false) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01615 | secure_defaults() value — port_forwarding: Some(false) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01616 | secure_defaults() value — strict_host_key: Some("accept-new") | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01617 | secure_defaults() value — exit_on_forward_failure: Some(true) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01618 | secure_defaults() value — connect_timeout_secs: Some(20) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01619 | secure_defaults() value — server_alive_interval_secs: Some(30) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | M00356 | composite | false |
| F01620 | merge_over() — per-host override merges over default base via Option::or chain | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | M00357 | composite | false |
| F01621 | merge_over field — forward_agent: self.forward_agent.or(base.forward_agent) | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | M00357 | composite | false |
| F01622 | merge_over field — forward_x11: self.forward_x11.or(base.forward_x11) | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | M00357 | composite | false |
| F01623 | merge_over field — port_forwarding: self.port_forwarding.or(base.port_forwarding) | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | M00357 | composite | false |
| F01624 | merge_over field — strict_host_key: self.strict_host_key.clone().or_else(...) | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | M00357 | composite | false |
| F01625 | merge_over field — exit_on_forward_failure | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | M00357 | composite | false |
| F01626 | merge_over field — connect_timeout_secs | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | M00357 | composite | false |
| F01627 | merge_over field — server_alive_interval_secs | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | M00357 | composite | false |
| F01628 | Host pattern — exact host match (e.g. `git.internal.example.com`) | `crates/selfdef-ssh-wrap/src/policy.rs` § header + `packaging/ssh-wrap-policy.toml.example` | M00358 | composite | true |
| F01629 | Host pattern — `*.suffix` glob match (e.g. `*.internal`) | `crates/selfdef-ssh-wrap/src/policy.rs` § header + `packaging/ssh-wrap-policy.toml.example` | M00359 | composite | true |
| F01630 | Host pattern — `prefix*` glob match | `crates/selfdef-ssh-wrap/src/policy.rs` § header | M00360 | composite | true |
| F01631 | Host pattern principle — "no regex, no recursion, no surprises" | `crates/selfdef-ssh-wrap/src/policy.rs` § header | M00361 | composite | false |
| F01632 | Example per-host override — `[hosts."git.internal.example.com"]` forward_agent=true (trusted dev box for git push) | `packaging/ssh-wrap-policy.toml.example` | E0148 | composite | true |
| F01633 | Example per-host override — `[hosts."*.internal"]` port_forwarding=true | `packaging/ssh-wrap-policy.toml.example` | E0148 | composite | true |
| F01634 | Example per-host override — `[hosts."ci.example.com"]` forward_x11=true (CI runner GUI test) | `packaging/ssh-wrap-policy.toml.example` | E0148 | composite | true |
| F01635 | Policy ethos — "Recommended: leave them off, opt hosts in below" | `packaging/ssh-wrap-policy.toml.example` `[defaults]` comment | E0148 | composite | false |
| F01636 | Event log path — `~/.local/share/selfdef/ssh-wrap.jsonl` | `docs/src/ops/ssh-wrap-install.md` § 4 | M00352 | composite | false |
| F01637 | Event format — OCSF events appended JSONL | `docs/src/ops/ssh-wrap-install.md` § 4 | E0145 | composite | false |
| F01638 | Eventstream collector consumes the JSONL into daemon's event store | `docs/src/ops/ssh-wrap-install.md` § 4 + `docs/src/dev/collector.md` | E0145 | composite | true |
| F01639 | Eventstream collector source row — "Tails any JSONL of pre-formed selfdef Events. Used by selfdef-ssh-wrap and by modules invoking selfdefctl events emit." | `docs/src/dev/collector.md` | E0145 | composite | false |
| F01640 | Caveat — wrapper observes connection lifecycle + args you passed, NOT remote shell activity | `docs/src/ops/ssh-wrap-install.md` § Caveats | M00365 | composite | false |
| F01641 | Caveat — host key change detection left to ssh itself | `docs/src/ops/ssh-wrap-install.md` § Caveats | M00366 | composite | false |
| F01642 | Caveat — StrictHostKeyChecking=accept-new is the default policy | `docs/src/ops/ssh-wrap-install.md` § Caveats | M00366 | composite | false |
| F01643 | Caveat — when ssh refuses connection due to changed host keys, wrapper logs failed exit code | `docs/src/ops/ssh-wrap-install.md` § Caveats | M00366 | composite | false |
| F01644 | Caveat — "REMOTE HOST IDENTIFICATION HAS CHANGED" message comes from ssh on stderr | `docs/src/ops/ssh-wrap-install.md` § Caveats | M00366 | composite | false |
| F01645 | Caveat — `~C -A` (in-session agent forwarding) has no wrapper visibility | `docs/src/ops/ssh-wrap-install.md` § Caveats | M00367 | composite | false |
| F01646 | Defense-in-depth — set `AllowAgentForwarding no` on the *server* side | `docs/src/ops/ssh-wrap-install.md` § Caveats | M00367 | composite | true |
| F01647 | T1098 Account Manipulation detection rule — `persistence/sudoers_tamper.yml` | `docs/src/detect/attack_coverage.md` | E0150 | composite | true |
| F01648 | T1098 Account Manipulation detection rule — `defense_evasion/ssh_wrap_policy_strip.yml` | `docs/src/detect/attack_coverage.md` | M00368 | composite | true |
| F01649 | Component label — `selfdef.ssh-wrap` (mapped to T1098) | `docs/src/detect/attack_coverage.md` | M00368 | composite | false |
| F01650 | Inventory row — `selfdef-ssh-wrap` is the drop-in `ssh` wrapper that emits events | `docs/review/10-inventory.md` | E0141 | composite | false |
| F01651 | Argv parsing — passthrough cases (e.g. `ssh -V`, `ssh --help`) do NOT engage wrap | `crates/selfdef-ssh-wrap/src/argv.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | E0143 | composite | false |
| F01652 | Argv parsing — intercept cases (host present, possibly with policy-violating flags) engage wrap | `crates/selfdef-ssh-wrap/src/argv.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | E0143 | composite | false |
| F01653 | Argv parsing — `-A` flag = agent forwarding intent (strip if policy denies) | `crates/selfdef-ssh-wrap/src/argv.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | E0143 | composite | true |
| F01654 | Argv parsing — `-X` / `-Y` flag = X11 forwarding intent (strip if policy denies) | `crates/selfdef-ssh-wrap/src/argv.rs` + `packaging/ssh-wrap-policy.toml.example` | E0143 | composite | true |
| F01655 | Argv parsing — `-L` / `-R` / `-D` flag = port forwarding intent (strip if policy denies) | `crates/selfdef-ssh-wrap/src/argv.rs` + `packaging/ssh-wrap-policy.toml.example` | E0143 | composite | true |
| F01656 | Argv parsing — extract target host (e.g. `user@example.com` → `example.com`) | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | composite | false |
| F01657 | Event — session-start (engaged wrap on host X with effective policy P) | `crates/selfdef-ssh-wrap/src/events.rs` | E0145 | composite | true |
| F01658 | Event — session-end (host X, exit code N, duration D) | `crates/selfdef-ssh-wrap/src/events.rs` | E0145 | composite | true |
| F01659 | Event — policy-strip (host X, stripped flag F, reason "policy denies") | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/detect/attack_coverage.md` ssh_wrap_policy_strip.yml | E0145 + M00368 | composite | true |
| F01660 | Event — connection-failed (host X, exit code N, ssh stderr captured) | `crates/selfdef-ssh-wrap/src/events.rs` | E0145 | composite | true |
| F01661 | Event — host-key-changed (host X; detected by ssh; wrapper observes failed exit code) | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/ops/ssh-wrap-install.md` § Caveats | E0145 + M00366 | composite | true |
| F01662 | main.rs — parses argv → applies policy → emits events → execs SELFDEF_SSH_PATH | `crates/selfdef-ssh-wrap/src/main.rs` | M00346 | composite | false |
| F01663 | main.rs — exec via execvp (replaces process; child inherits ssh's stdio) | `crates/selfdef-ssh-wrap/src/main.rs` | M00346 | composite | false |
| F01664 | Pass-through case — `ssh -V` does NOT load policy or emit events | `crates/selfdef-ssh-wrap/src/main.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | M00346 | composite | false |
| F01665 | Single-user laptop deployment — daemon runs as user; reads event log directly | `docs/src/ops/ssh-wrap-install.md` § 4 | M00353 | composite | true |
| F01666 | Multi-user deployment — `chmod 0644` event log + setgid directory in between for newly-appended lines | `docs/src/ops/ssh-wrap-install.md` § 4 | M00353 | composite | true |
| F01667 | Cross-repo binding — selfdef-ssh-wrap is selfdef-scope only; sovereign-os MAY consume policy-strip events via MS004 E0036 Oracle-Triage but does NOT import the crate directly | architecture + MS004 E0036 + MS007 | E0141 | composite | false |
| F01668 | Cross-shell integration — wrap works with zsh / bash / fish (PATH-shadow pattern is shell-agnostic) | `docs/src/ops/ssh-wrap-install.md` § 2 | M00349 | composite | true |
| F01669 | Policy precedence — env-var SELFDEF_SSH_POLICY > default `~/.config/selfdef/ssh-wrap.toml` > built-in `secure_defaults()` | `docs/src/ops/ssh-wrap-install.md` § Env var overrides + `crates/selfdef-ssh-wrap/src/policy.rs` | M00362 + M00363 | composite | false |
| F01670 | Event-log precedence — env-var SELFDEF_SSH_EVENT_LOG > default `~/.local/share/selfdef/ssh-wrap.jsonl` | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | M00364 | composite | false |
| F01671 | SSH-binary precedence — env-var SELFDEF_SSH_PATH > default `/usr/bin/ssh` | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | M00362 | composite | false |
| F01672 | Policy parse — TOML format via `toml` crate (workspace dep) | `crates/selfdef-ssh-wrap/Cargo.toml` + `crates/selfdef-ssh-wrap/src/policy.rs` | M00344 | composite | false |
| F01673 | Event serialization — JSON format via `serde_json` crate (workspace dep) | `crates/selfdef-ssh-wrap/Cargo.toml` + `crates/selfdef-ssh-wrap/src/events.rs` | M00344 | composite | false |
| F01674 | Event timestamps — via `time` crate (workspace dep) | `crates/selfdef-ssh-wrap/Cargo.toml` + `crates/selfdef-ssh-wrap/src/events.rs` | M00344 | composite | false |
| F01675 | Error handling — via `anyhow` crate (workspace dep) | `crates/selfdef-ssh-wrap/Cargo.toml` | M00344 | composite | false |
| F01676 | Integration with MS002 collector fabric — selfdef-collector-eventstream tails the JSONL | MS002 + `docs/src/dev/collector.md` | E0145 + M00353 | composite | false |
| F01677 | Integration with MS003 correlator — policy-strip events feed correlation rules | MS003 + `docs/src/detect/attack_coverage.md` ssh_wrap_policy_strip.yml | M00368 | composite | false |
| F01678 | Integration with MS006 modules — agent-guard module may add policy-rate-limit on ssh-wrap calls | MS006 + agent-guard | E0150 | composite | false |
| F01679 | Composite — selfdef-ssh-wrap is the client-side defense when YOU are the client (per INDEX MS014 row); inverts the usual selfdef host-defense posture: instead of defending the host from a remote attacker, it defends the operator's outbound ssh from operator-mistake / supply-chain / hostile-remote agent | INDEX.md MS014 row + `crates/selfdef-ssh-wrap/` | E0141 | composite | false |
| F01680 | Composite — selfdef-ssh-wrap design ethos — drop-in replacement via PATH shadow + secure paranoid defaults + per-host opt-in + OCSF events into daemon + simple host-pattern matching ("no regex, no recursion, no surprises") + documented caveats (in-session activity invisible; defense-in-depth via server-side AllowAgentForwarding) + MITRE T1098 detection coverage | `crates/selfdef-ssh-wrap/` + `docs/src/ops/ssh-wrap-install.md` + `docs/src/detect/attack_coverage.md` | E0141 + E0150 | composite | false |

## Requirements (R03121–R03360)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R03121 | Crate `selfdef-ssh-wrap` exists at `crates/selfdef-ssh-wrap/` | `crates/selfdef-ssh-wrap/` | M00343 | non-negotiable | false | 10 |
| R03122 | Crate Cargo.toml description — "Client-side SSH wrapper: policy enforcement + session events." | `crates/selfdef-ssh-wrap/Cargo.toml` | F01562 | non-negotiable | false | 10 |
| R03123 | Crate is a workspace member with version / edition / rust-version / license / repository / authors / publish pinned via workspace | `crates/selfdef-ssh-wrap/Cargo.toml` | F01563 | non-negotiable | false | 10 |
| R03124 | Crate lints inherited from workspace | `crates/selfdef-ssh-wrap/Cargo.toml` `[lints]` | F01564 | non-negotiable | false | 10 |
| R03125 | Crate depends on selfdef-core | `crates/selfdef-ssh-wrap/Cargo.toml` | F01565 | non-negotiable | true | 10 |
| R03126 | Crate depends on anyhow | `crates/selfdef-ssh-wrap/Cargo.toml` | F01566 | non-negotiable | true | 10 |
| R03127 | Crate depends on serde | `crates/selfdef-ssh-wrap/Cargo.toml` | F01567 | non-negotiable | true | 10 |
| R03128 | Crate depends on serde_json | `crates/selfdef-ssh-wrap/Cargo.toml` | F01568 | non-negotiable | true | 10 |
| R03129 | Crate depends on toml | `crates/selfdef-ssh-wrap/Cargo.toml` | F01569 | non-negotiable | true | 10 |
| R03130 | Crate depends on time | `crates/selfdef-ssh-wrap/Cargo.toml` | F01570 | non-negotiable | true | 10 |
| R03131 | Crate dev-depends on tempfile | `crates/selfdef-ssh-wrap/Cargo.toml` | F01571 | non-negotiable | true | 10 |
| R03132 | Binary target name — `selfdef-ssh-wrap` | `crates/selfdef-ssh-wrap/Cargo.toml` `[[bin]]` | M00346 | non-negotiable | false | 10 |
| R03133 | Binary path — `src/main.rs` | `crates/selfdef-ssh-wrap/Cargo.toml` `[[bin]]` | M00346 | non-negotiable | false | 10 |
| R03134 | Source module `src/argv.rs` exists | `crates/selfdef-ssh-wrap/src/argv.rs` | F01573 | non-negotiable | false | 10 |
| R03135 | Source module `src/events.rs` exists | `crates/selfdef-ssh-wrap/src/events.rs` | F01574 | non-negotiable | false | 10 |
| R03136 | Source module `src/main.rs` exists | `crates/selfdef-ssh-wrap/src/main.rs` | F01575 | non-negotiable | false | 10 |
| R03137 | Source module `src/policy.rs` exists | `crates/selfdef-ssh-wrap/src/policy.rs` | F01576 | non-negotiable | false | 10 |
| R03138 | Install step 1 — `cargo build --release -p selfdef-ssh-wrap` | `docs/src/ops/ssh-wrap-install.md` § 1 | F01578 | non-negotiable | true | 10 |
| R03139 | Install step 1 — `sudo install -m 0755 target/release/selfdef-ssh-wrap /usr/local/bin/` | `docs/src/ops/ssh-wrap-install.md` § 1 | F01579 | non-negotiable | true | 10 |
| R03140 | Install step 2 — `mkdir -p ~/.local/bin` | `docs/src/ops/ssh-wrap-install.md` § 2 | F01580 | non-negotiable | true | 10 |
| R03141 | Install step 2 — `ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh` | `docs/src/ops/ssh-wrap-install.md` § 2 | F01581 | non-negotiable | true | 10 |
| R03142 | Install step 2 — ensure `~/.local/bin` precedes `/usr/bin` in PATH | `docs/src/ops/ssh-wrap-install.md` § 2 | F01582 | non-negotiable | false | 10 |
| R03143 | Install step 2 verification — `which ssh` prints `/home/<you>/.local/bin/ssh` | `docs/src/ops/ssh-wrap-install.md` § 2 | F01583 | non-negotiable | false | 10 |
| R03144 | Install step 2 effect — existing scripts and tooling that exec `ssh` route through wrapper transparently | `docs/src/ops/ssh-wrap-install.md` § 2 | F01584 | non-negotiable | false | 10 |
| R03145 | Install step 3 — `mkdir -p ~/.config/selfdef` | `docs/src/ops/ssh-wrap-install.md` § 3 | F01585 | non-negotiable | true | 10 |
| R03146 | Install step 3 — `cp packaging/ssh-wrap-policy.toml.example ~/.config/selfdef/ssh-wrap.toml` | `docs/src/ops/ssh-wrap-install.md` § 3 | F01586 | non-negotiable | true | 10 |
| R03147 | Default policy denies agent forwarding | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01587 | non-negotiable | false | 10 |
| R03148 | Default policy denies X11 forwarding | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01588 | non-negotiable | false | 10 |
| R03149 | Default policy denies port forwarding | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01589 | non-negotiable | false | 10 |
| R03150 | Default policy applies per every host (operator opts hosts in via per-host blocks) | `packaging/ssh-wrap-policy.toml.example` | F01590 | non-negotiable | false | 10 |
| R03151 | Install step 4 collectors block — enabled=true | `docs/src/ops/ssh-wrap-install.md` § 4 | F01591 | non-negotiable | true | 10 |
| R03152 | Install step 4 collectors block — paths includes `~/.local/share/selfdef/ssh-wrap.jsonl` | `docs/src/ops/ssh-wrap-install.md` § 4 | F01592 | non-negotiable | true | 10 |
| R03153 | Install step 4 collectors block — read_from="end" | `docs/src/ops/ssh-wrap-install.md` § 4 | F01593 | non-negotiable | true | 10 |
| R03154 | Install step 4 — daemon needs read access to event log | `docs/src/ops/ssh-wrap-install.md` § 4 | F01594 | non-negotiable | false | 10 |
| R03155 | Sanity check 1 — `ssh -V` passes through (no wrap engaged) | `docs/src/ops/ssh-wrap-install.md` § 5 | F01595 | non-negotiable | false | 10 |
| R03156 | Sanity check 2 — `ssh user@example.com` wrap engaged (events appended + policy applied) | `docs/src/ops/ssh-wrap-install.md` § 5 | F01596 | non-negotiable | false | 10 |
| R03157 | Sanity check 3 — `ssh -A user@example.com` wrap strips `-A` + emits a policy-strip event | `docs/src/ops/ssh-wrap-install.md` § 5 | F01597 | non-negotiable | false | 10 |
| R03158 | Sanity check 4 — tail of event log shows recent events | `docs/src/ops/ssh-wrap-install.md` § 5 | F01598 | non-negotiable | false | 10 |
| R03159 | Env var override — `SELFDEF_SSH_PATH` (real ssh binary; default `/usr/bin/ssh`) | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01599 | non-negotiable | true | 10 |
| R03160 | Env var override — `SELFDEF_SSH_POLICY` (override policy location) | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01600 | non-negotiable | true | 10 |
| R03161 | Env var override — `SELFDEF_SSH_EVENT_LOG` (override event log path) | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01601 | non-negotiable | true | 10 |
| R03162 | PolicyFile struct field — `defaults: HostPolicy` | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile | F01602 | non-negotiable | false | 10 |
| R03163 | PolicyFile struct field — `hosts: HashMap<String, HostPolicy>` | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile | F01603 | non-negotiable | false | 10 |
| R03164 | PolicyFile default — defaults = HostPolicy::secure_defaults() | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile::default | F01604 | non-negotiable | false | 10 |
| R03165 | PolicyFile default — hosts = HashMap::new() | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile::default | F01604 | non-negotiable | false | 10 |
| R03166 | HostPolicy field — forward_agent: Option<bool> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | F01605 | non-negotiable | true | 10 |
| R03167 | HostPolicy field — forward_x11: Option<bool> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | F01606 | non-negotiable | true | 10 |
| R03168 | HostPolicy field — port_forwarding: Option<bool> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | F01607 | non-negotiable | true | 10 |
| R03169 | HostPolicy field — strict_host_key: Option<String> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | F01608 | non-negotiable | true | 10 |
| R03170 | HostPolicy strict_host_key values — "yes" / "accept-new" / "no" | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy comment | F01608 | non-negotiable | true | 10 |
| R03171 | HostPolicy field — exit_on_forward_failure: Option<bool> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | F01609 | non-negotiable | true | 10 |
| R03172 | HostPolicy field — connect_timeout_secs: Option<u32> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | F01610 | non-negotiable | true | 10 |
| R03173 | HostPolicy field — server_alive_interval_secs: Option<u32> | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy | F01611 | non-negotiable | true | 10 |
| R03174 | HostPolicy default — all 7 fields None | `crates/selfdef-ssh-wrap/src/policy.rs` HostPolicy::default | F01612 | non-negotiable | false | 10 |
| R03175 | secure_defaults() — forward_agent: Some(false) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01613 | non-negotiable | false | 10 |
| R03176 | secure_defaults() — forward_x11: Some(false) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01614 | non-negotiable | false | 10 |
| R03177 | secure_defaults() — port_forwarding: Some(false) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01615 | non-negotiable | false | 10 |
| R03178 | secure_defaults() — strict_host_key: Some("accept-new".into()) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01616 | non-negotiable | false | 10 |
| R03179 | secure_defaults() — exit_on_forward_failure: Some(true) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01617 | non-negotiable | false | 10 |
| R03180 | secure_defaults() — connect_timeout_secs: Some(20) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01618 | non-negotiable | false | 10 |
| R03181 | secure_defaults() — server_alive_interval_secs: Some(30) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01619 | non-negotiable | false | 10 |
| R03182 | merge_over() — per-host override merges over base via Option::or chain | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | F01620 | non-negotiable | false | 10 |
| R03183 | merge_over forward_agent — `self.forward_agent.or(base.forward_agent)` | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | F01621 | non-negotiable | false | 10 |
| R03184 | merge_over forward_x11 — `self.forward_x11.or(base.forward_x11)` | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | F01622 | non-negotiable | false | 10 |
| R03185 | merge_over port_forwarding — `self.port_forwarding.or(base.port_forwarding)` | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | F01623 | non-negotiable | false | 10 |
| R03186 | merge_over strict_host_key — clone()-then-or-else (because String not Copy) | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | F01624 | non-negotiable | false | 10 |
| R03187 | merge_over exit_on_forward_failure — Option::or chain | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | F01625 | non-negotiable | false | 10 |
| R03188 | merge_over connect_timeout_secs — Option::or chain | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | F01626 | non-negotiable | false | 10 |
| R03189 | merge_over server_alive_interval_secs — Option::or chain | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over | F01627 | non-negotiable | false | 10 |
| R03190 | Host pattern matching supports — exact host match | `crates/selfdef-ssh-wrap/src/policy.rs` § header | F01628 | non-negotiable | true | 10 |
| R03191 | Host pattern matching supports — `*.suffix` glob match | `crates/selfdef-ssh-wrap/src/policy.rs` § header | F01629 | non-negotiable | true | 10 |
| R03192 | Host pattern matching supports — `prefix*` glob match | `crates/selfdef-ssh-wrap/src/policy.rs` § header | F01630 | non-negotiable | true | 10 |
| R03193 | Host pattern matching principle — intentionally simple; no regex; no recursion; no surprises | `crates/selfdef-ssh-wrap/src/policy.rs` § header | F01631 | non-negotiable | false | 10 |
| R03194 | Example per-host — `[hosts."git.internal.example.com"]` forward_agent=true | `packaging/ssh-wrap-policy.toml.example` | F01632 | non-negotiable | true | 10 |
| R03195 | Example per-host — `[hosts."*.internal"]` port_forwarding=true | `packaging/ssh-wrap-policy.toml.example` | F01633 | non-negotiable | true | 10 |
| R03196 | Example per-host — `[hosts."ci.example.com"]` forward_x11=true | `packaging/ssh-wrap-policy.toml.example` | F01634 | non-negotiable | true | 10 |
| R03197 | Policy ethos — "leave them off, opt hosts in below" | `packaging/ssh-wrap-policy.toml.example` `[defaults]` comment | F01635 | non-negotiable | false | 10 |
| R03198 | Event log path default — `~/.local/share/selfdef/ssh-wrap.jsonl` | `docs/src/ops/ssh-wrap-install.md` § 4 | F01636 | non-negotiable | false | 10 |
| R03199 | Event format — OCSF JSONL (one event per line) | `docs/src/ops/ssh-wrap-install.md` § 4 + `crates/selfdef-ssh-wrap/src/events.rs` | F01637 | non-negotiable | false | 10 |
| R03200 | Collector eventstream consumes the JSONL into daemon's event store | `docs/src/ops/ssh-wrap-install.md` § 4 + `docs/src/dev/collector.md` | F01638 | non-negotiable | true | 10 |
| R03201 | Eventstream collector documentation row — selfdef-collector-eventstream tails any JSONL of pre-formed selfdef Events | `docs/src/dev/collector.md` | F01639 | non-negotiable | false | 10 |
| R03202 | Caveat — wrapper observes connection lifecycle + args you passed, NOT remote shell activity | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01640 | non-negotiable | false | 10 |
| R03203 | Caveat — host key change detection is left to ssh itself | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01641 | non-negotiable | false | 10 |
| R03204 | Caveat — `StrictHostKeyChecking=accept-new` is the default policy | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01642 | non-negotiable | false | 10 |
| R03205 | Caveat — when ssh refuses due to changed host keys, wrapper logs the failed exit code | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01643 | non-negotiable | false | 10 |
| R03206 | Caveat — "REMOTE HOST IDENTIFICATION HAS CHANGED" message comes from ssh on stderr | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01644 | non-negotiable | false | 10 |
| R03207 | Caveat — agent forwarding inside an already-established session (`~C -A`) has no wrapper visibility | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01645 | non-negotiable | false | 10 |
| R03208 | Defense-in-depth — set `AllowAgentForwarding no` on the *server* side | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01646 | non-negotiable | true | 10 |
| R03209 | MITRE T1098 detection rule — `persistence/sudoers_tamper.yml` | `docs/src/detect/attack_coverage.md` | F01647 | non-negotiable | true | 10 |
| R03210 | MITRE T1098 detection rule — `defense_evasion/ssh_wrap_policy_strip.yml` | `docs/src/detect/attack_coverage.md` | F01648 | non-negotiable | true | 10 |
| R03211 | Component label — `selfdef.ssh-wrap` (mapped to T1098) | `docs/src/detect/attack_coverage.md` | F01649 | non-negotiable | false | 10 |
| R03212 | Inventory row — `selfdef-ssh-wrap` is "drop-in ssh wrapper that emits events" | `docs/review/10-inventory.md` | F01650 | non-negotiable | false | 10 |
| R03213 | Argv passthrough case — `ssh -V` does NOT engage wrap | `crates/selfdef-ssh-wrap/src/argv.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | F01651 | non-negotiable | false | 10 |
| R03214 | Argv passthrough case — `ssh --help` does NOT engage wrap | `crates/selfdef-ssh-wrap/src/argv.rs` | F01651 | non-negotiable | false | 10 |
| R03215 | Argv intercept case — host present engages wrap | `crates/selfdef-ssh-wrap/src/argv.rs` | F01652 | non-negotiable | false | 10 |
| R03216 | Argv flag — `-A` triggers policy.forward_agent check (strip if denied) | `crates/selfdef-ssh-wrap/src/argv.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | F01653 | non-negotiable | true | 10 |
| R03217 | Argv flag — `-X` triggers policy.forward_x11 check (strip if denied) | `crates/selfdef-ssh-wrap/src/argv.rs` | F01654 | non-negotiable | true | 10 |
| R03218 | Argv flag — `-Y` triggers policy.forward_x11 check (strip if denied) | `crates/selfdef-ssh-wrap/src/argv.rs` | F01654 | non-negotiable | true | 10 |
| R03219 | Argv flag — `-L` triggers policy.port_forwarding check (strip if denied) | `crates/selfdef-ssh-wrap/src/argv.rs` | F01655 | non-negotiable | true | 10 |
| R03220 | Argv flag — `-R` triggers policy.port_forwarding check (strip if denied) | `crates/selfdef-ssh-wrap/src/argv.rs` | F01655 | non-negotiable | true | 10 |
| R03221 | Argv flag — `-D` triggers policy.port_forwarding check (strip if denied) | `crates/selfdef-ssh-wrap/src/argv.rs` | F01655 | non-negotiable | true | 10 |
| R03222 | Argv extract — target host (e.g. `user@example.com` → `example.com`) | `crates/selfdef-ssh-wrap/src/argv.rs` | F01656 | non-negotiable | false | 10 |
| R03223 | Event type — session-start (engaged wrap on host X with effective policy P) | `crates/selfdef-ssh-wrap/src/events.rs` | F01657 | non-negotiable | true | 10 |
| R03224 | Event type — session-end (host X, exit code N, duration D) | `crates/selfdef-ssh-wrap/src/events.rs` | F01658 | non-negotiable | true | 10 |
| R03225 | Event type — policy-strip (host X, stripped flag F, reason "policy denies") | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/detect/attack_coverage.md` | F01659 | non-negotiable | true | 10 |
| R03226 | Event type — connection-failed (host X, exit code N, captured ssh stderr) | `crates/selfdef-ssh-wrap/src/events.rs` | F01660 | non-negotiable | true | 10 |
| R03227 | Event type — host-key-changed (host X; detected by ssh; wrapper observes failed exit code) | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/ops/ssh-wrap-install.md` § Caveats | F01661 | non-negotiable | true | 10 |
| R03228 | main.rs flow — parse argv | `crates/selfdef-ssh-wrap/src/main.rs` | F01662 | non-negotiable | false | 10 |
| R03229 | main.rs flow — apply policy | `crates/selfdef-ssh-wrap/src/main.rs` | F01662 | non-negotiable | false | 10 |
| R03230 | main.rs flow — emit events | `crates/selfdef-ssh-wrap/src/main.rs` | F01662 | non-negotiable | false | 10 |
| R03231 | main.rs flow — exec SELFDEF_SSH_PATH (default `/usr/bin/ssh`) | `crates/selfdef-ssh-wrap/src/main.rs` + `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01662 | non-negotiable | false | 10 |
| R03232 | main.rs exec semantics — execvp replaces process; child inherits ssh's stdio | `crates/selfdef-ssh-wrap/src/main.rs` | F01663 | non-negotiable | false | 10 |
| R03233 | Pass-through case — `ssh -V` does NOT load policy or emit events | `crates/selfdef-ssh-wrap/src/main.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | F01664 | non-negotiable | false | 10 |
| R03234 | Single-user laptop deployment — daemon runs as user; reads event log directly | `docs/src/ops/ssh-wrap-install.md` § 4 | F01665 | non-negotiable | true | 10 |
| R03235 | Multi-user deployment — `chmod 0644` event log + setgid directory in between for newly-appended lines | `docs/src/ops/ssh-wrap-install.md` § 4 | F01666 | non-negotiable | true | 10 |
| R03236 | Project boundary — selfdef-ssh-wrap is selfdef-scope only | architecture | F01667 | non-negotiable | false | 10 |
| R03237 | Project boundary — sovereign-os MAY consume policy-strip events via MS004 E0036 Oracle-Triage | architecture + MS004 E0036 | F01667 | non-negotiable | false | 10 |
| R03238 | Project boundary — sovereign-os does NOT import selfdef-ssh-wrap crate directly | architecture + MS007 + SDD-038 | F01667 | non-negotiable | false | 10 |
| R03239 | Cross-shell integration — wrap works with zsh / bash / fish (PATH-shadow pattern is shell-agnostic) | `docs/src/ops/ssh-wrap-install.md` § 2 | F01668 | non-negotiable | true | 10 |
| R03240 | Policy precedence — env-var SELFDEF_SSH_POLICY > default `~/.config/selfdef/ssh-wrap.toml` | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01669 | non-negotiable | false | 10 |
| R03241 | Policy precedence — default `~/.config/selfdef/ssh-wrap.toml` > built-in `secure_defaults()` | `crates/selfdef-ssh-wrap/src/policy.rs` PolicyFile::default | F01669 | non-negotiable | false | 10 |
| R03242 | Event-log precedence — env-var SELFDEF_SSH_EVENT_LOG > default `~/.local/share/selfdef/ssh-wrap.jsonl` | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01670 | non-negotiable | false | 10 |
| R03243 | SSH-binary precedence — env-var SELFDEF_SSH_PATH > default `/usr/bin/ssh` | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01671 | non-negotiable | false | 10 |
| R03244 | Policy parsing — TOML format via `toml` workspace dep | `crates/selfdef-ssh-wrap/Cargo.toml` + `crates/selfdef-ssh-wrap/src/policy.rs` | F01672 | non-negotiable | false | 10 |
| R03245 | Event serialization — JSON via `serde_json` workspace dep | `crates/selfdef-ssh-wrap/Cargo.toml` + `crates/selfdef-ssh-wrap/src/events.rs` | F01673 | non-negotiable | false | 10 |
| R03246 | Event timestamps — via `time` workspace dep | `crates/selfdef-ssh-wrap/Cargo.toml` + `crates/selfdef-ssh-wrap/src/events.rs` | F01674 | non-negotiable | false | 10 |
| R03247 | Error handling — via `anyhow` workspace dep | `crates/selfdef-ssh-wrap/Cargo.toml` | F01675 | non-negotiable | false | 10 |
| R03248 | Integration with MS002 — selfdef-collector-eventstream tails the ssh-wrap JSONL | MS002 + `docs/src/dev/collector.md` | F01676 | non-negotiable | false | 10 |
| R03249 | Integration with MS003 — policy-strip events feed correlator rules | MS003 + `docs/src/detect/attack_coverage.md` | F01677 | non-negotiable | false | 10 |
| R03250 | Integration with MS006 — agent-guard module may add policy-rate-limit on ssh-wrap calls | MS006 + agent-guard | F01678 | non-negotiable | false | 10 |
| R03251 | Inversion — SSH-wrap is the client-side defense when YOU are the client | INDEX.md MS014 row | F01679 | non-negotiable | false | 10 |
| R03252 | Inversion — defends operator's outbound ssh from operator-mistake / supply-chain / hostile-remote agent | F01679 + `crates/selfdef-ssh-wrap/` | F01679 | non-negotiable | false | 10 |
| R03253 | Design ethos — drop-in replacement via PATH shadow | `docs/src/ops/ssh-wrap-install.md` § 2 | F01680 | non-negotiable | false | 10 |
| R03254 | Design ethos — secure paranoid defaults | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01680 | non-negotiable | false | 10 |
| R03255 | Design ethos — per-host opt-in | `packaging/ssh-wrap-policy.toml.example` | F01680 | non-negotiable | false | 10 |
| R03256 | Design ethos — OCSF events into daemon | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/dev/collector.md` | F01680 | non-negotiable | false | 10 |
| R03257 | Design ethos — simple host-pattern matching ("no regex, no recursion, no surprises") | `crates/selfdef-ssh-wrap/src/policy.rs` § header | F01680 | non-negotiable | false | 10 |
| R03258 | Design ethos — documented caveats (in-session activity invisible) | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01680 | non-negotiable | false | 10 |
| R03259 | Design ethos — defense-in-depth via server-side AllowAgentForwarding | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01680 | non-negotiable | false | 10 |
| R03260 | Design ethos — MITRE T1098 detection coverage | `docs/src/detect/attack_coverage.md` | F01680 | non-negotiable | false | 10 |
| R03261 | TOML schema — `[defaults]` block | `packaging/ssh-wrap-policy.toml.example` | F01587 + F01588 + F01589 | non-negotiable | false | 10 |
| R03262 | TOML schema — `[hosts."<pattern>"]` blocks (per-host overrides) | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` | F01628 + F01629 + F01630 | non-negotiable | false | 10 |
| R03263 | TOML schema — `forward_agent` (bool) field | `packaging/ssh-wrap-policy.toml.example` | F01605 | non-negotiable | true | 10 |
| R03264 | TOML schema — `forward_x11` (bool) field | `packaging/ssh-wrap-policy.toml.example` | F01606 | non-negotiable | true | 10 |
| R03265 | TOML schema — `port_forwarding` (bool) field | `packaging/ssh-wrap-policy.toml.example` | F01607 | non-negotiable | true | 10 |
| R03266 | TOML schema — `strict_host_key` (string) field | `packaging/ssh-wrap-policy.toml.example` | F01608 | non-negotiable | true | 10 |
| R03267 | TOML schema — `exit_on_forward_failure` (bool) field | `packaging/ssh-wrap-policy.toml.example` | F01609 | non-negotiable | true | 10 |
| R03268 | TOML schema — `connect_timeout_secs` (u32) field | `packaging/ssh-wrap-policy.toml.example` | F01610 | non-negotiable | true | 10 |
| R03269 | TOML schema — `server_alive_interval_secs` (u32) field | `packaging/ssh-wrap-policy.toml.example` | F01611 | non-negotiable | true | 10 |
| R03270 | Event JSONL — append-only (events.rs appends; never rewrites) | `crates/selfdef-ssh-wrap/src/events.rs` | E0145 | non-negotiable | false | 10 |
| R03271 | Event JSONL — one event per line | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/ops/ssh-wrap-install.md` § 4 | F01637 | non-negotiable | false | 10 |
| R03272 | Event JSONL — newline-delimited JSON (Open Cybersecurity Schema Framework / OCSF shape) | `docs/src/ops/ssh-wrap-install.md` § 4 + `crates/selfdef-ssh-wrap/src/events.rs` | F01637 | non-negotiable | false | 10 |
| R03273 | Daemon read access — single-user laptop case acceptable (daemon as user) | `docs/src/ops/ssh-wrap-install.md` § 4 | F01665 | non-negotiable | true | 10 |
| R03274 | Daemon read access — multi-user case requires `chmod 0644` + setgid directory | `docs/src/ops/ssh-wrap-install.md` § 4 | F01666 | non-negotiable | true | 10 |
| R03275 | Cargo workspace member — `crates/selfdef-ssh-wrap` is registered in workspace `Cargo.toml` | repo state (workspace Cargo.toml) | M00343 | non-negotiable | false | 10 |
| R03276 | Build target — release profile (`--release` flag in install doc) | `docs/src/ops/ssh-wrap-install.md` § 1 | F01578 | non-negotiable | false | 10 |
| R03277 | Install permission — 0755 (executable) on `/usr/local/bin/selfdef-ssh-wrap` | `docs/src/ops/ssh-wrap-install.md` § 1 | F01579 | non-negotiable | false | 10 |
| R03278 | Install path — `/usr/local/bin/` (system-wide; not `~/.local/bin/` for the binary itself) | `docs/src/ops/ssh-wrap-install.md` § 1 | F01579 | non-negotiable | false | 10 |
| R03279 | PATH-shadow location — `~/.local/bin/ssh` (user-scoped symlink) | `docs/src/ops/ssh-wrap-install.md` § 2 | F01581 | non-negotiable | false | 10 |
| R03280 | PATH-shadow target — `/usr/local/bin/selfdef-ssh-wrap` (the installed binary) | `docs/src/ops/ssh-wrap-install.md` § 2 | F01581 | non-negotiable | false | 10 |
| R03281 | PATH-shadow precedence — `~/.local/bin` MUST precede `/usr/bin` in PATH for wrap to engage | `docs/src/ops/ssh-wrap-install.md` § 2 | F01582 | non-negotiable | false | 10 |
| R03282 | Detection coverage — wrap policy-strip event maps to MITRE T1098 (Account Manipulation) | `docs/src/detect/attack_coverage.md` | F01649 | non-negotiable | false | 10 |
| R03283 | Detection coverage — wrap policy-strip event correlator rule `defense_evasion/ssh_wrap_policy_strip.yml` | `docs/src/detect/attack_coverage.md` | F01648 | non-negotiable | false | 10 |
| R03284 | Detection coverage — wrap sits alongside `persistence/sudoers_tamper.yml` in T1098 coverage matrix | `docs/src/detect/attack_coverage.md` | F01647 | non-negotiable | false | 10 |
| R03285 | Argv responsibilities — distinguish passthrough (no host) vs intercept (host present) | `crates/selfdef-ssh-wrap/src/argv.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | E0143 | non-negotiable | false | 10 |
| R03286 | Argv responsibilities — identify policy-relevant flags (-A / -X / -Y / -L / -R / -D) | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03287 | Argv responsibilities — extract target host for policy lookup | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03288 | Argv responsibilities — preserve non-policy-relevant flags (port, identity-file, options) untouched | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03289 | Argv responsibilities — handle `--` end-of-options sentinel correctly | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03290 | Argv responsibilities — handle bundled short flags (e.g. `-AX` = `-A -X`) | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03291 | Argv responsibilities — handle `-o ForwardAgent=yes` long-form options (equivalent to `-A`) | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03292 | Argv responsibilities — handle `-o ForwardX11=yes` long-form options (equivalent to `-X`) | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03293 | Argv responsibilities — handle `-o LocalForward=...` / `-o RemoteForward=...` / `-o DynamicForward=...` long-form options | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03294 | Argv responsibilities — invariant: wrap output argv is a valid `ssh` invocation | `crates/selfdef-ssh-wrap/src/argv.rs` | E0143 | non-negotiable | false | 10 |
| R03295 | Events responsibilities — produce OCSF-shaped events | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/ops/ssh-wrap-install.md` § 4 | E0145 | non-negotiable | false | 10 |
| R03296 | Events responsibilities — append to event log atomically (O_APPEND semantics) | `crates/selfdef-ssh-wrap/src/events.rs` | E0145 | non-negotiable | false | 10 |
| R03297 | Events responsibilities — survive missing log directory (mkdir-if-needed) | `crates/selfdef-ssh-wrap/src/events.rs` | E0145 | non-negotiable | false | 10 |
| R03298 | Events responsibilities — never panic on event-emission failure (best-effort logging) | `crates/selfdef-ssh-wrap/src/events.rs` | E0145 | non-negotiable | false | 10 |
| R03299 | Policy responsibilities — load policy from $SELFDEF_SSH_POLICY OR `~/.config/selfdef/ssh-wrap.toml` OR built-in `secure_defaults()` | `crates/selfdef-ssh-wrap/src/policy.rs` | E0144 | non-negotiable | false | 10 |
| R03300 | Policy responsibilities — resolve effective policy for target host via merge_over(default) over per-host pattern match | `crates/selfdef-ssh-wrap/src/policy.rs` merge_over + § header | E0144 | non-negotiable | false | 10 |
| R03301 | Policy responsibilities — first-match wins for overlapping host patterns | `crates/selfdef-ssh-wrap/src/policy.rs` | E0148 | non-negotiable | false | 10 |
| R03302 | Policy responsibilities — never panic on TOML parse failure (return error with file:line) | `crates/selfdef-ssh-wrap/src/policy.rs` + `anyhow` | E0144 | non-negotiable | false | 10 |
| R03303 | main.rs responsibilities — pass-through when no host (`ssh -V`, `ssh --help`) | `crates/selfdef-ssh-wrap/src/main.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | F01664 | non-negotiable | false | 10 |
| R03304 | main.rs responsibilities — engage wrap when host present | `crates/selfdef-ssh-wrap/src/main.rs` | F01662 | non-negotiable | false | 10 |
| R03305 | main.rs responsibilities — replace process via execvp (NOT spawn + wait) | `crates/selfdef-ssh-wrap/src/main.rs` | F01663 | non-negotiable | false | 10 |
| R03306 | main.rs responsibilities — return ssh's exit code (via execvp; on exec failure return 127) | `crates/selfdef-ssh-wrap/src/main.rs` | F01663 | non-negotiable | false | 10 |
| R03307 | main.rs responsibilities — emit session-start event BEFORE exec | `crates/selfdef-ssh-wrap/src/main.rs` + `crates/selfdef-ssh-wrap/src/events.rs` | F01657 | non-negotiable | false | 10 |
| R03308 | main.rs responsibilities — emit policy-strip events BEFORE exec | `crates/selfdef-ssh-wrap/src/main.rs` + `crates/selfdef-ssh-wrap/src/events.rs` | F01659 | non-negotiable | false | 10 |
| R03309 | main.rs responsibilities — session-end + exit-code events are NOT emitted (execvp replaces the process; ssh exits directly) | `crates/selfdef-ssh-wrap/src/main.rs` | F01658 | non-negotiable | false | 10 |
| R03310 | MS014 integration with MS001 (daemon core) — daemon ingests ssh-wrap events via collector | MS001 + MS002 eventstream | F01676 | non-negotiable | false | 10 |
| R03311 | MS014 integration with MS002 (collector fabric) — selfdef-collector-eventstream is the bridge | MS002 + `docs/src/dev/collector.md` | F01676 | non-negotiable | false | 10 |
| R03312 | MS014 integration with MS003 (correlator) — policy-strip events match correlator rules | MS003 + `docs/src/detect/attack_coverage.md` | F01677 | non-negotiable | false | 10 |
| R03313 | MS014 integration with MS004 (14 integrations) — Oracle-Triage MS004 E0036 may surface cross-repo escalations for ssh-wrap events | MS004 E0036 + architecture | F01667 | non-negotiable | false | 10 |
| R03314 | MS014 integration with MS006 (14 functional modules) — agent-guard module may rate-limit ssh-wrap invocations | MS006 + agent-guard | F01678 | non-negotiable | false | 10 |
| R03315 | MS014 integration with MS007 (cross-repo typed mirrors) — selfdef-ssh-wrap is NOT itself a cross-repo crate; events flow via documented JSONL contract | MS007 + SDD-038 | F01667 | non-negotiable | false | 10 |
| R03316 | MS014 integration with MS009 (audit cycles) — phase-6/-7 crate audit covers selfdef-ssh-wrap; docs audit covers ssh-wrap-install.md + ssh-wrap-policy.toml.example | MS009 phase-6/-7 | M00343 | non-negotiable | false | 10 |
| R03317 | MS014 integration with MS013 (27-SDD charter framework) — selfdef-ssh-wrap implementation has NO dedicated SDD today (codified in install doc + policy example + source); future SDD slot available if scope grows | MS013 + `docs/sdd/` ledger | E0141 | non-negotiable | false | 10 |
| R03318 | Project boundary — selfdef-ssh-wrap is selfdef-scope only | architecture | F01667 | non-negotiable | false | 10 |
| R03319 | Project boundary — sovereign-os MAY consume policy-strip events via MS004 E0036 Oracle-Triage | MS004 E0036 + architecture | F01667 | non-negotiable | false | 10 |
| R03320 | Project boundary — sovereign-os does NOT import the crate directly (per MS007 + SDD-038 doctrine) | MS007 + SDD-038 + architecture | F01667 | non-negotiable | false | 10 |
| R03321 | Cross-shell — wrap PATH-shadow pattern works with zsh | `docs/src/ops/ssh-wrap-install.md` § 2 | F01668 | non-negotiable | true | 10 |
| R03322 | Cross-shell — wrap PATH-shadow pattern works with bash | `docs/src/ops/ssh-wrap-install.md` § 2 | F01668 | non-negotiable | true | 10 |
| R03323 | Cross-shell — wrap PATH-shadow pattern works with fish (operator sets fish_user_paths) | `docs/src/ops/ssh-wrap-install.md` § 2 (shell-agnostic) | F01668 | non-negotiable | true | 10 |
| R03324 | Disable mechanism — operator MAY temporarily disable wrap by `unset PATH; export PATH=/usr/bin:/bin` (bypasses PATH-shadow) | `docs/src/ops/ssh-wrap-install.md` § 2 (PATH-shadow inversion) | E0150 | non-negotiable | false | 10 |
| R03325 | Disable mechanism — operator MAY explicitly call `/usr/bin/ssh` to bypass wrap for one invocation | architecture (absolute-path bypass) | E0150 | non-negotiable | false | 10 |
| R03326 | Disable mechanism — operator MAY remove `~/.local/bin/ssh` symlink to disable wrap permanently | `docs/src/ops/ssh-wrap-install.md` § 2 inverse | E0150 | non-negotiable | false | 10 |
| R03327 | Disable mechanism — operator MAY set SELFDEF_SSH_PATH to a different binary (e.g. tester ssh) | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01599 | non-negotiable | false | 10 |
| R03328 | Auditing — every policy-strip event MUST be observable in the event log | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | F01659 | non-negotiable | false | 10 |
| R03329 | Auditing — every session-start event MUST include the effective policy snapshot | `crates/selfdef-ssh-wrap/src/events.rs` | F01657 | non-negotiable | false | 10 |
| R03330 | Auditing — wrap MUST NOT log secrets (no private key path content; no SSH agent socket content) | `crates/selfdef-ssh-wrap/src/events.rs` + security ethos | F01680 | non-negotiable | false | 10 |
| R03331 | Auditing — wrap MUST NOT log full argv (sanitize identity-file paths if needed) | `crates/selfdef-ssh-wrap/src/events.rs` + security ethos | F01680 | non-negotiable | false | 10 |
| R03332 | Auditing — wrap MAY log redacted argv (e.g. `-i ****` instead of `-i /home/user/.ssh/id_ed25519`) | `crates/selfdef-ssh-wrap/src/events.rs` + security ethos | F01680 | non-negotiable | false | 10 |
| R03333 | Auditing — wrap event timestamps MUST be UTC ISO-8601 (via `time` workspace dep) | `crates/selfdef-ssh-wrap/src/events.rs` + `crates/selfdef-ssh-wrap/Cargo.toml` | F01674 | non-negotiable | false | 10 |
| R03334 | Auditing — wrap event format MUST be OCSF-compliant (Open Cybersecurity Schema Framework) | `crates/selfdef-ssh-wrap/src/events.rs` + `docs/src/ops/ssh-wrap-install.md` § 4 | F01637 | non-negotiable | false | 10 |
| R03335 | Composite test — `ssh -V` flow exits non-zero only if real ssh exits non-zero (no wrap interference) | `crates/selfdef-ssh-wrap/src/main.rs` + `docs/src/ops/ssh-wrap-install.md` § 5 | F01664 | non-negotiable | false | 10 |
| R03336 | Composite test — `ssh -A user@example.com` strips `-A` AND emits policy-strip event AND execs ssh | `docs/src/ops/ssh-wrap-install.md` § 5 + `crates/selfdef-ssh-wrap/src/main.rs` | F01597 + F01659 | non-negotiable | false | 10 |
| R03337 | Composite test — `ssh user@gitserver.internal.example.com` engages wrap with effective policy from `[hosts."*.internal"]` override | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` | F01633 | non-negotiable | false | 10 |
| R03338 | Composite test — TOML parse failure → operator-readable error citing file:line | `crates/selfdef-ssh-wrap/src/policy.rs` + `anyhow` | R03302 | non-negotiable | false | 10 |
| R03339 | Composite test — missing log directory → mkdir-if-needed; event still written | `crates/selfdef-ssh-wrap/src/events.rs` | R03297 | non-negotiable | false | 10 |
| R03340 | Composite test — daemon-side collector ingest verified by `cat ~/.local/share/selfdef/ssh-wrap.jsonl \| tail -3` | `docs/src/ops/ssh-wrap-install.md` § 5 | F01598 | non-negotiable | false | 10 |
| R03341 | Documentation — `docs/src/ops/ssh-wrap-install.md` is the operator-facing install guide | `docs/src/SUMMARY.md` + `docs/src/ops/ssh-wrap-install.md` | E0142 | non-negotiable | false | 10 |
| R03342 | Documentation — `docs/src/ops/config.md` references `ssh-wrap-install.md` | `docs/src/ops/config.md` | E0142 | non-negotiable | false | 10 |
| R03343 | Documentation — `docs/src/detect/attack_coverage.md` carries T1098 → ssh-wrap policy-strip mapping | `docs/src/detect/attack_coverage.md` | M00368 | non-negotiable | false | 10 |
| R03344 | Documentation — `docs/src/dev/collector.md` carries eventstream-collector → ssh-wrap JSONL mapping | `docs/src/dev/collector.md` | F01639 | non-negotiable | false | 10 |
| R03345 | Documentation — `docs/review/10-inventory.md` carries selfdef-ssh-wrap "drop-in ssh wrapper" inventory row | `docs/review/10-inventory.md` | F01650 | non-negotiable | false | 10 |
| R03346 | Operator interaction model — operator runs `ssh ...` as normal; wrap engages transparently | `docs/src/ops/ssh-wrap-install.md` § 2 | F01584 | non-negotiable | false | 10 |
| R03347 | Operator interaction model — operator edits `~/.config/selfdef/ssh-wrap.toml` to add per-host overrides | `docs/src/ops/ssh-wrap-install.md` § 3 + `packaging/ssh-wrap-policy.toml.example` | F01586 | non-negotiable | false | 10 |
| R03348 | Operator interaction model — operator tails `~/.local/share/selfdef/ssh-wrap.jsonl` for events | `docs/src/ops/ssh-wrap-install.md` § 5 | F01598 | non-negotiable | false | 10 |
| R03349 | Operator interaction model — operator queries daemon (via selfdefctl) for aggregated ssh-wrap events once eventstream collector is wired | `docs/src/ops/ssh-wrap-install.md` § 4 | F01638 | non-negotiable | false | 10 |
| R03350 | Operator interaction model — operator uses env-var overrides for one-off runs (e.g. testing) | `docs/src/ops/ssh-wrap-install.md` § Env var overrides | F01599 + F01600 + F01601 | non-negotiable | false | 10 |
| R03351 | Security ethos — wrap defaults to deny (forward_agent / forward_x11 / port_forwarding all false) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | E0147 | non-negotiable | false | 10 |
| R03352 | Security ethos — operator opts hosts in (positive list); never opts hosts out (negative list) | `packaging/ssh-wrap-policy.toml.example` + `crates/selfdef-ssh-wrap/src/policy.rs` | F01635 | non-negotiable | false | 10 |
| R03353 | Security ethos — strict_host_key default "accept-new" balances usability (auto-add new hosts) with safety (refuse changed hosts) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` + `docs/src/ops/ssh-wrap-install.md` § Caveats | F01616 | non-negotiable | false | 10 |
| R03354 | Security ethos — exit_on_forward_failure default true (ssh refuses to start if forwarding setup fails) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01617 | non-negotiable | false | 10 |
| R03355 | Security ethos — connect_timeout_secs default 20 (refuses to wait indefinitely on unreachable hosts) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01618 | non-negotiable | false | 10 |
| R03356 | Security ethos — server_alive_interval_secs default 30 (detects half-closed connections) | `crates/selfdef-ssh-wrap/src/policy.rs` `secure_defaults()` | F01619 | non-negotiable | false | 10 |
| R03357 | Security ethos — defense-in-depth pattern (client-side wrap + server-side AllowAgentForwarding no) | `docs/src/ops/ssh-wrap-install.md` § Caveats | F01646 | non-negotiable | false | 10 |
| R03358 | Inversion — MS014 is the FIRST milestone where selfdef defends the CLIENT (not the host) — inverts the host-defense posture of MS001-MS013 | INDEX.md MS014 row + `crates/selfdef-ssh-wrap/` | F01679 | non-negotiable | false | 10 |
| R03359 | Inversion — same techniques (policy / events / daemon-side correlation) apply at client and host sides; selfdef-ssh-wrap proves the architecture is symmetric | `crates/selfdef-ssh-wrap/` + MS002/MS003 | F01679 | non-negotiable | false | 10 |
| R03360 | Composite — selfdef-ssh-wrap is the client-side defense crate (drop-in `ssh` replacement; secure paranoid defaults; per-host opt-in; OCSF events into daemon; documented caveats; MITRE T1098 detection coverage; 4 source modules totalling 921 lines); inverts the host-defense posture; integrates with MS001-MS003 + MS004 E0036 + MS006 + MS007 + MS009 + MS013; cross-repo binding via documented JSONL contract (NOT direct crate import) | `crates/selfdef-ssh-wrap/` + `docs/src/ops/ssh-wrap-install.md` + `docs/src/detect/attack_coverage.md` + `packaging/ssh-wrap-policy.toml.example` | E0141 + E0142 + E0143 + E0144 + E0145 + E0146 + E0147 + E0148 + E0149 + E0150 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS013: 13920 + 2400 = 16320 sub-requirements when MS014 lands

## Cross-references

- Crate root: `crates/selfdef-ssh-wrap/` (Cargo.toml + src/{argv.rs, events.rs, main.rs, policy.rs})
- Install doc: `docs/src/ops/ssh-wrap-install.md`
- Policy example: `packaging/ssh-wrap-policy.toml.example`
- Detection coverage: `docs/src/detect/attack_coverage.md` (MITRE T1098 + `defense_evasion/ssh_wrap_policy_strip.yml`)
- Collector contract: `docs/src/dev/collector.md` (eventstream collector tails ssh-wrap JSONL)
- Inventory row: `docs/review/10-inventory.md`
- Adjacent milestones: MS002 collector fabric (eventstream) / MS003 correlator (policy-strip rule) / MS006 agent-guard (rate-limiting) / MS013 27-SDD charter framework (future SDD slot if scope grows)
