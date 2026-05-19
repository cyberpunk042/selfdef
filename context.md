# context.md — selfdef journey state + positioning + what's ahead

> **Read me first after every compaction.** This file is the operator-requested re-orientation surface for selfdef (2026-05-19). Mirrored from sovereign-os/context.md per the two-ultimate-solutions doctrine — both repos share the operator framing, each from its own POV.
>
> Authoritative full picture: see `cyberpunk042/sovereign-os/context.md` (same operator-state-of-the-art, this file is the selfdef-anchored view).

## The two ultimate solutions (operator framing, verbatim 2026-05-19)

> "Continue Endlessly to toward the two ultimate solutions and their perfectioning and high UX/Developer Experience."

This repo is **Solution 2 — `selfdef`** — the IPS daemon. Boundary enforcement + Guardian + operator surface. **Independent** (boots without sovereign-os per MS043 R10217-R10225 offline-survivability) AND **combining** (publishes 9 MS007 mirror crates for sovereign-os cockpit consumption).

`cyberpunk042/sovereign-os` is **Solution 1** — the runtime/cockpit. `cyberpunk042/devops-solutions-information-hub` is the **third piece** = read-only second-brain.

## Where we are right now (selfdef, 2026-05-19 snapshot)

### Catalog phase — COMPLETE

| metric | target | actual | status |
|---|---|---|---|
| Milestones | n/a | 45 (MS001-MS045) | ✓ |
| R-rows | 10,000+ (combined with sovereign-os) | ~11,200 (selfdef alone) | ✓ |
| Latest milestone | MS045 | UX coherence test harness validating MS043 240 R-rows | ✓ |

### Backward-sweep phase — COMPLETE

- MS010 file-level canon-update annotation applied (commit `6a2f6ef`) per 6 redefinitions in sovereign-os M061.

### Implementation status

| artifact | status | reference |
|---|---|---|
| 12-channel notify set (write/wall/ntfy/signal/discord/slack/smtp/thehive + shared-audit-summary + integration-orchestrator + notifier-engine + notifier-orchestrator) | ✓ shipped | `CHANGELOG.md` channel inventory |
| `selfdefctl notify resend <event_id>` escalation triage | ✓ shipped | `CHANGELOG.md` PR #173 |
| `selfdef-integration-write` per-user TTY channel | ✓ shipped | `CHANGELOG.md` PR #170 |
| 8/8 SATURATED mirror crates (auth-tier / bashrc-install / history-sink / dashboard-manifest / surface-manifest / ux-checklist / audit-manifest / doc-manifest) | ✓ shipped | `crates/selfdef-{auth-tier,...}/Cargo.toml` |
| selfdef-rules-mirror (MS043 D-12 networking source, 1 of 9 mirror crates) | ✓ shipped (7 passing tests) | `crates/selfdef-rules-mirror/` (commit a0b35e6) |
| selfdef-grants-mirror (MS043 D-13 fs/network/capability grants source, 2 of 9) | ✓ shipped (8 passing tests) | `crates/selfdef-grants-mirror/` |
| selfdef-capability-mirror (MS043 D-14 capability_word tokens source, 3 of 9) | ✓ shipped (11 passing tests) | `crates/selfdef-capability-mirror/` |
| selfdef-sandbox-mirror (MS043 D-15 MS036 tier A/B/C/D allocations source, 4 of 9) | ✓ shipped (11 passing tests) | `crates/selfdef-sandbox-mirror/` |
| MS024 eBPF + nftables | catalog ✓ / impl partial (eBPF programs in `bpf/`) | `crates/selfdef-collector-ebpf/` |
| MS026 OCSF observability | catalog ✓ / impl ongoing | `crates/selfdef-collector-*/` |
| Multi-environment Discord/Slack/Signal/Telegram/SMTP/TheHive integrations | ✓ shipped | `crates/selfdef-integration-*/` |
| Guardian Daemon `/usr/local/bin/guardian-core` Python impl (MS044) | catalog ✓ / impl pending | `backlog/milestones/MS044-*` |
| MS045 UX coherence test harness `/usr/bin/selfdef-ux-harness` impl | catalog ✓ / impl pending | `backlog/milestones/MS045-*` |
| 9 D-12..D-18 mirror crates (selfdef-rules / -grants / -capability / -sandbox / -audit / -quarantine / -trust-score / -cli / -tui) | catalog ✓ (MS043 R10182-R10193) / impl pending | `backlog/milestones/MS043-*` |

## What's ahead (selfdef forward queue)

Per "little piece by little piece" — next tractable selfdef deliverables:

1. **MS044 Guardian Daemon** Python impl at `/usr/local/bin/guardian-core`
   - 3-step response protocol: SIGKILL via `podman kill` → atomic ZFS audit log append → console bell
   - systemd unit at `/etc/systemd/system/guardian-core.service` (After=Requires=tetragon.service / Type=simple / Restart=always)
   - Tetragon eBPF UNIX socket listener at `/var/run/tetragon/tetragon.events`
2. **MS045 UX coherence test harness** binary at `/usr/bin/selfdef-ux-harness`
   - L1 schema/lint validators for CLI subcommand list + TUI panels + minimal-web panels + mirror crate list
   - CLI startup p95 <50ms benchmark across 1000 runs
   - TUI keyboard replayer via PTY (j/k/h/l/Enter/q/?/P/F)
   - Web contrast checker (WCAG 2.1 AA 4.5:1 via pa11y)
   - Web keyboard replayer (Tab/arrow/Enter/Esc via Playwright)
3. **9 MS007 mirror crates** for sovereign-os D-12..D-18 cockpit dashboards:
   - `crates/selfdef-rules-mirror/` (Ring 0-4 nftables rules)
   - `crates/selfdef-grants-mirror/` (filesystem grants)
   - ~~`crates/selfdef-capability-mirror/`~~ ✓ shipped 2026-05-19 (capability_word tokens, 11 passing tests)
   - ~~`crates/selfdef-sandbox-mirror/`~~ ✓ shipped 2026-05-19 (MS036 tier A/B/C/D allocations, 11 passing tests)
   - `crates/selfdef-audit-mirror/` (MS009 chain status)
   - `crates/selfdef-quarantine-mirror/` (MS042 quarantined tools)
   - `crates/selfdef-trust-score-mirror/` (per-tool trust history)
   - `crates/selfdef-cli-mirror/` (CLI invocation schemas)
   - `crates/selfdef-tui-mirror/` (TUI panel schemas)
4. **selfdef CLI subcommand completion** — bash + fish + zsh per MS043 R10134 — install in `.deb` package

## What NOT to do — operator standing rules (mirror)

Same rules as sovereign-os/context.md. Verbatim:

1. **"you cannot invent crap"** — every selfdef R-row traces to source.
2. **"do not minimize the work in selfdef"** — full 240-R-row pattern per milestone.
3. **"Respect the projects"** — IPS features stay HERE; sovereign-os features stay THERE.
4. **"Knowledge is the second-brain / information-hub"** — info-hub READ-ONLY.
5. **"layered ON TOP OF prior direction — never discarded"** — additive only.
6. **"NO random trash please"** — sovereignty-clean. No invention.
7. **"you cannot re-invent what UX mean"** — match existing CLI/TUI patterns.
8. **"DISABLE_AUTOCOMPACT=1 sacrosanct"** — never substitute.
9. **"never include model identifier in commit messages / PR bodies / pushed artifacts"** — chat replies only.
10. **"the AI does NOT decide when it's complete"** — operator-controlled.

## Hook integration — ACTUALLY WIRED 2026-05-19

This file is referenced by **live, working hooks** (verified post-edit):

- `~/.claude/session-start-context.sh` detects both `/home/user/sovereign-os/context.md` and `/home/user/selfdef/context.md` and emits a `systemMessage` JSON pointing the model at both files. Wired into `SessionStart` hook in `~/.claude/settings.json`.
- `~/.claude/post-compact-reorient.sh` uses the same detection logic on `PostCompact` events.
- Canonical templates in `~/.claude/env-bootstrap/templates/` — `apply.sh` reinstalls if drift detected. Template-vs-live drift zero post-wire.

Smoke-tested via `bash ~/.claude/session-start-context.sh` — emits valid JSON pointing to both repos' context.md.

After compaction:
1. Read this file
2. Read `cyberpunk042/sovereign-os/context.md` for full ecosystem picture
3. Pick next item from "What's ahead" forward queue
4. Execute one tractable deliverable
5. Update this file before ending turn

## Recent commits (most recent first)

- `cdc9064` — MS045 UX coherence test harness milestone (240 R-rows)
- `0b5a648` — MS044 Guardian Daemon catalog milestone (240 R-rows)
- `6a2f6ef` — Patch Pass A MS010 canon-update annotation
- `eb04ed9` — MS043 IPS operator surface — CLI + TUI + dashboard-mirror exports
- `470b375` — MS042 Tool authority — declaration-vs-observed discipline (catalog close)
- `a96661d` — MS041 Commit authority — durable-change discipline
- `2835824` — MS040 Authority and profiles — six-profile authority matrix
- `d686ccc` — MS039 Authority levels (L0..L6) + trust rings (Ring 0..4) — IPS-side projection

Earlier history: see `git log --oneline backlog/milestones/` and `CHANGELOG.md`.

## Reference table — operator quotes that shape the work

Same as sovereign-os/context.md. Single source of truth for the operator's standing direction lives at the sovereign-os file; this file mirrors the table by reference.

---

**Last updated**: 2026-05-19 (commit `cdc9064` + this file)
**Authoritative full picture**: `cyberpunk042/sovereign-os/context.md`
**Next AI session**: read this file → read sovereign-os/context.md → pick next item from selfdef forward queue → execute → update this file.
