# M060 cockpit-mirror producers — selfdef-side operator guide

Selfdef is the canonical **producer** half of the M060 cockpit-mirror
chain — the daemon-resident registries + their export loop write
read-only JSON artifacts to `/run/sovereign-os/selfdef-mirror/*.json`
that the sovereign-os cockpit consumes for the D-02..D-18 dashboards.

This doc covers the **selfdef side** of that wire (sovereign-os consumer
setup is documented in
[`sovereign-os/docs/operator/m060-deployment-guide.md`](https://github.com/cyberpunk042/sovereign-os/blob/main/docs/operator/m060-deployment-guide.md)).
Per the operator's standing rule (2026-05-19):

> *"if I talk about an IPS feature it's obviously not in Sovereign-OS"*

Every artifact described here is a selfdef IPS state surface; the
sovereign-os cockpit renders it READ-ONLY (R10212) and never mutates.

---

## TL;DR — what an operator does

```bash
# 1. Set the mirror directory in /etc/selfdef/selfdef.toml.
sudo tee -a /etc/selfdef/selfdef.toml > /dev/null <<'EOF'

[deployment]
selfdef_mirror_dir = "/run/sovereign-os/selfdef-mirror"
EOF

# 2. Reload the daemon.
sudo systemctl restart selfdefd

# 3. (Producer one-shot for the cli-mirror — see "Producer wiring".)
sudo systemctl start selfdef-cli-mirror-emit.service

# 4. Watch the artifacts appear.
ls -l /run/sovereign-os/selfdef-mirror/
journalctl -u selfdefd -n 50 | grep -i M060
```

---

## What gets published (current chain — 11 artifacts)

The daemon's `mirror_export_loop` (re-publishing every 30s by default)
writes the following files atomically (tempfile + `rename(2)`) when the
underlying state surface exists. Every artifact carries a wire-stable
`schema_version` (1.0.0) + an honest-offline fallback (file is absent
when the operator hasn't onboarded the domain yet — never a fabricated
empty-online state).

| File | Domain | Producer surface | Onboarding step | Sovereign-os dashboard |
|---|---|---|---|---|
| `active-profile.json` | D-02 | flex-profile state (`/var/lib/selfdef/flex-profile.json`) | always-published; defaults to the R09535 Private envelope when no file exists | D-02 profile-choices |
| `grants.json` | D-13 | `selfdef-grant-registry` (`/var/lib/selfdef/grants.json`) | `selfdefctl grants issue …` | D-13 filesystem-grants |
| `capability-tokens.json` | D-14 | `selfdef-capability-registry` (`/var/lib/selfdef/capability-tokens.json`) | `selfdefctl capability-tokens issue …` | D-14 capability-tokens |
| `sandboxes.json` | D-15 | `selfdef-sandbox-registry` (`/var/lib/selfdef/sandboxes.json`) | `selfdefctl sandboxes allocate …` | D-15 sandboxes |
| `audit.json` | D-16 | `selfdef-audit-registry` (`/var/lib/selfdef/audit.json`) | daemon-populated — every IPS authority decision / OCSF event closes a span | D-16 audit-chain |
| `quarantine.json` | D-17 | `selfdef-quarantine-registry` (`/var/lib/selfdef/quarantine.json`) | daemon-populated — MS042 declaration-vs-observed detection | D-17 quarantine |
| `trust-scores.json` | D-18 | `selfdef-trust-score-registry` (`/var/lib/selfdef/trust-scores.json`) | daemon-populated (scoring loop) — operator-issued `selfdefctl trust-scores admit …` also valid | D-18 trust-scores |
| `rules.json` | D-12 | `selfdef-rules-registry` (`/var/lib/selfdef/rules.json`) | daemon-populated — nft collector projects `nft list ruleset --json` into Ring 0..4 RuleEntry | D-12 network-edge / edge-firewall |
| `tui.json` | TUI-layout | `selfdef-tui-mirror::canonical_snapshot` (static, in-process) | always-published — canonical 4-panel layout per MS043 R10141 | sovereign-os minimal-web mirror |
| `cli.json` | D-CLI | `selfdef-cli-mirror` schema, walked by selfdefctl's live `clap::Command` tree | `selfdefctl cli-mirror snapshot --output /var/lib/selfdef/cli-mirror.json` (via systemd one-shot — see below) | sovereign-os CLI-introspection cockpit (D-XX) |
| `m060-health.json` | health | `selfdef-api::m060_health` (in-process aggregator over the resident registries) | always-published once the api crate is running | sovereign-os master-dashboard health banner |

Per-artifact failure modes ALL follow the same contract: warn-logged
into the daemon journal, **never** fatal. Subsequent ticks re-attempt;
the operator's only visible signal is the dashboard's "last update"
timestamp drifting + the per-domain mirror-status banner flipping to
offline. Prometheus counters at `<api>/metrics`
(`selfdef_m060_publish_total{artifact,outcome}`) make it observable
without staring at the journal.

---

## Producer wiring

Two production patterns are in play:

### Pattern A — resident-store producers (8 of 11)

For grants / capability-tokens / sandboxes / audit / quarantine /
trust-scores / rules / active-profile, the operator-mutation verbs and
the daemon's own detection loops populate the state file at
`/var/lib/selfdef/<domain>.json`. The mirror-export loop reads that
file every 30s and republishes it to the mirror dir. No additional
producer wiring needed — onboarding the domain happens naturally as
the operator issues their first grant / token / sandbox / etc., or as
the daemon's collectors observe their first event.

### Pattern B — schema-walk producers (3 of 11)

For tui-layout, cli-mirror, and m060-health the source-of-truth isn't
operator-mutation state but a **schema** that lives inside a binary
(selfdefctl's clap tree for cli, selfdef-tui-mirror's canonical layout
for tui, selfdef-api's resident-registry aggregator for health).

- **tui.json** — static, in-process. No producer wiring needed.
- **m060-health.json** — in-process, in the api crate. No producer
  wiring needed; the http path `/v1/m060/health` is served alongside
  the file.
- **cli.json** — needs a producer step because selfdefd doesn't link
  selfdefctl's clap tree. Two paths, **resident-store preferred**:
  1. **Resident store** (recommended). The systemd one-shot
     `selfdef-cli-mirror-emit.service` runs
     `selfdefctl cli-mirror snapshot --output PATH` on every install /
     upgrade (kicked from the debian postinst). The artifact lands at
     `/var/lib/selfdef/cli-mirror.json`. The daemon's
     `cli_mirror_publisher` re-reads on a 5-min debounce so
     post-upgrade refreshes propagate.
  2. **Shell-out fallback** (legacy). If the resident store is
     absent, selfdefd shells out to `selfdefctl cli-mirror snapshot
     --json` once at startup + caches the bytes. Works but PATH-
     dependent + doesn't pick up post-upgrade clap changes until the
     daemon restarts.

To force a fresh emit (e.g., after manually rebuilding selfdefctl):

```bash
sudo systemctl start selfdef-cli-mirror-emit.service
journalctl -u selfdef-cli-mirror-emit.service -n 20
```

To relocate the cli-mirror resident store, override both the producer
unit's `Environment=` and the daemon's reader env in one place:

```ini
# /etc/systemd/system/selfdef-cli-mirror-emit.service.d/override.conf
[Service]
Environment=SELFDEF_CLI_MIRROR_PATH=/srv/selfdef/cli-mirror.json
```

```ini
# /etc/systemd/system/selfdefd.service.d/override.conf
[Service]
Environment=SELFDEF_CLI_MIRROR_PATH=/srv/selfdef/cli-mirror.json
```

The two **must** stay in sync; the contract test
`m060_cli_mirror_emit_unit_contract.rs` locks the unit's defaults
against `selfdef_cli_mirror::DEFAULT_STATE_PATH` at compile time.

---

## Verification recipes

```bash
# 1. Every artifact's wire-shape (smoke-test).
for f in active-profile grants capability-tokens sandboxes audit \
         quarantine trust-scores rules tui cli; do
    path=/run/sovereign-os/selfdef-mirror/$f.json
    if [ -f "$path" ]; then
        echo -n "$f: "
        python3 -c "import json; d=json.load(open('$path')); \
            print('schema='+d.get('schema_version','?'), \
                  'captured_at='+d.get('captured_at','—'))"
    else
        echo "$f: offline (no resident store yet)"
    fi
done

# 2. Health endpoint (in-process, served by selfdef-api).
curl -s http://localhost:7700/v1/m060/health | jq '.summary'

# 3. Prometheus counters (rolling per-artifact publish success/failure).
curl -s http://localhost:7700/metrics | grep selfdef_m060_publish_total

# 4. Cross-cutting doctor — exit 0 if every artifact in the resident
#    set published this tick, non-zero with per-domain diagnosis if not.
selfdefctl doctor --m060-health
```

---

## Failure-mode → log-line crib sheet

| Symptom | Journal line (DEBUG/WARN) | Fix |
|---|---|---|
| `cli.json` missing despite producer one-shot started | `cli-mirror publisher: resident store schema-version drift` | Stale `/var/lib/selfdef/cli-mirror.json` from a pre-bump selfdefctl. Re-run `systemctl start selfdef-cli-mirror-emit.service`. |
| `cli.json` missing + no resident store | `cli-mirror publisher: selfdefctl not on PATH` | Install or symlink `/usr/bin/selfdefctl`. Daemon caches PATH-failure for its lifetime; restart selfdefd after fix. |
| `audit.json` missing after operator decisions | `mirror export: audit store unreadable` | Check `ls -l /var/lib/selfdef/audit.json` — owner must be `selfdef:selfdef` per the postinst contract. |
| All mirror files stale | (no log) | `selfdef_mirror_dir` config knob missing or unwritable. Check `[deployment].selfdef_mirror_dir` in `/etc/selfdef/selfdef.toml` + that the path is writable by the `selfdef` user. |
| Mirror file present but schema mismatch warned at consumer | sovereign-os reader logs `schema mismatch: expected 1.0.0 got X.Y.Z` | Major-version drift between selfdef (producer) and sovereign-os (consumer). Co-upgrade. |

---

## Project boundary (R10212 — sacrosanct)

- IPS state mutation lives in **selfdef**: `selfdefctl` verbs +
  `selfdefd` collector / scoring / audit loops.
- sovereign-os renders the published mirrors **READ-ONLY**. Every
  webapp button that looks like a mutation (e.g. "release quarantine"
  on D-17) is in reality a *copy-to-clipboard* helper that pastes
  the corresponding `selfdefctl + minisign -S` command. The webapp
  itself never POSTs to selfdef.
- The export is **one-directional**: selfdef → mirror dir →
  sovereign-os reads. There is no reverse channel.

Drift on either side fails contract tests on BOTH sides — the binding
is wire-level, not just doctrine. See:

- selfdef-side: `crates/selfdef-daemon/tests/m060_cli_mirror_emit_unit_contract.rs` (8 tests on the shipped systemd unit)
- sovereign-os side: `tests/lint/test_m060_cross_repo_chain_contract.py` (per-domain contract fixtures × 11)

---

## Operator runbook references

- **Setup**: this document (selfdef side) +
  `sovereign-os/docs/operator/m060-deployment-guide.md` (cockpit side).
- **Incident response**: see the "Incident-response surface ladder"
  section in `sovereign-os/docs/operator/m060-deployment-guide.md`
  (line ~242 — the surface-ladder operators use when a mirror goes red).
- **Alert runbook**: see the "Alert runbook" section in
  `sovereign-os/docs/operator/m060-deployment-guide.md` (line ~287 —
  the 5 Prometheus alerts on the chain-health observability stack,
  with per-alert pager-actionable diagnoses).
- **CLI**: `selfdefctl m060-doctor`, `selfdefctl m060-metrics`,
  `selfdefctl doctor --m060-health`.
