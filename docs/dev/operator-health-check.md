# `selfdefctl doctor` — operator health check

A single verb that verifies the cross-cutting policy state every
post-audit security feature depends on. Operators run it
post-deploy, on a cron, or in CI to catch state drift before it
matters.

`doctor` is **complementary** to `selfdefctl modules check`:

| Verb | What it covers |
| --- | --- |
| `selfdefctl modules check` | per-module health via each module's `check.sh` — is tetragon running, is the bridge up, is integrity-sentinel's baseline current? |
| `selfdefctl doctor` | cross-cutting state — rule signing, API token mode, eventstream JSONL integrity, RBAC posture summary |

Neither subsumes the other. Most operators want both.

## Categories

### `signing` — rule-signing posture

When `[security].require_signed_rules = true`:

- Verifies the public key at `[security].signing_public_key_file` loads cleanly.
- Walks `[correlator].rules_dir` and runs `Verifier::verify_detached_file` on every `*.yml` / `*.yaml` (skipping `*.tests.yaml` fixtures).
- Reports any rule whose `.minisig` is missing or fails verification as `FAIL`.

When signing is off, reports `skip` with the reason.

### `api` — token-file posture

When `[api].enabled = true` and `[api].token_file` is set:

- The file must exist.
- The file must be **mode 0600**.
- The file must be non-empty.

This catches the common operator drift after a manual `chmod` or a CI step that re-creates the file with default umask. Pair with `selfdefctl api rotate-token` for the recommended path that always writes 0600.

### `eventstream` — JSONL path integrity

When `[collectors.eventstream].integrity_check = true`:

- For every path in `[collectors.eventstream].paths`, runs the same checks the collector will run at startup (not world-writable, owned by a daemon-allowed UID).
- Mirrors the F-2026-026 follow-up so operators can pre-flight the integrity gate before the daemon refuses to tail a path.

### `rbac` — agent-guard pod-label scope summary

Reads `/etc/selfdef/modules/agent-guard.toml` (if present). When `scope = "pod-label"`, emits a `warn:` pointing the operator at `selfdefctl rbac check --probe` for the actual cluster RBAC verification (doctor doesn't probe — that's a deliberate operator action, not something a healthcheck should do without consent).

## Output formats

### Human (default)

Markdown-ish text with `## <category>` headings and `[status] check-name: detail` lines, plus a summary count:

```
# selfdefctl doctor

## api
  [  ok] token file: /etc/selfdef/api.token mode 0600

## eventstream
  [skip] integrity: [collectors.eventstream] disabled or integrity_check = false

## rbac
  [skip] agent-guard scope: /etc/selfdef/modules/agent-guard.toml not present — agent-guard not installed

## signing
  [skip] rule signing: [security].require_signed_rules = false

summary: 1 ok, 0 warn, 0 fail, 3 skip (4 total)
```

### JSON-lines (`--json`)

One JSON object per check, for CI / monitoring integration:

```json
{"category":"signing","name":"rule signing","status":"skip","detail":"[security].require_signed_rules = false"}
{"category":"api","name":"token file","status":"ok","detail":"/etc/selfdef/api.token mode 0600"}
...
```

Status values: `"ok"`, `"warn"`, `"FAIL"`, `"skip"`.

## Environment overrides

`selfdefctl doctor` reads a small set of env vars to support
testing / reproduction:

| Variable | Effect |
| --- | --- |
| `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` | When set to a path, the `rbac` category reads the agent-guard scope from `<path>` instead of `/etc/selfdef/modules/agent-guard.toml`. Use this to reproduce a doctor bug against a staged tempdir config without touching `/etc/`. **Test-only**; production callers leave this unset. F-2027-018. |

The doctor's `--help` output references this table.

## Exit codes

- `0` — no `FAIL` results.
- `1` — at least one `FAIL`.

`warn` and `skip` never trigger non-zero exit. `warn` is for non-blocking observations (e.g. the agent-guard `rbac` summary pointer); `skip` is for not-applicable checks (opt-in features that are off).

## Suggested integration

### Post-deploy smoke check

```sh
selfdefctl doctor || {
    echo "selfdef deployment has cross-cutting state failures" >&2
    exit 1
}
```

### Periodic health check via systemd timer

**The `selfdef-doctor.service` + `selfdef-doctor.timer` units ship with
the package** (cargo-deb installs to `/lib/systemd/system/`). To enable:

```sh
sudo systemctl enable --now selfdef-doctor.timer
systemctl list-timers selfdef-doctor.timer
journalctl -u selfdef-doctor.service -n 50
```

The shipped units are hardened beyond a hand-rolled minimum:

- `Type=oneshot` (each run = distinct journald entry for triage)
- `After=selfdefd.service zfs-mount.service` (audit-log paths reachable
  for the watchdog-set checks)
- `User=root Group=root` (doctor is read-only; root reads root-only paths)
- Hardening: `NoNewPrivileges=true`, `ProtectSystem=strict`,
  `ReadOnlyPaths=/etc/selfdef /etc/tetragon /usr/local/bin /usr/share/selfdef`,
  `ProtectKernelTunables=true`, `ProtectKernelLogs=true`,
  `ProtectControlGroups=true`,
  `RestrictAddressFamilies=AF_UNIX` (doctor is read-only with no network),
  `LockPersonality=true`, `RestrictNamespaces=true`,
  `RestrictRealtime=true`, `RestrictSUIDSGID=true`,
  `SystemCallArchitectures=native`
- Timer: `OnBootSec=10min` (let services settle) + `OnUnitActiveSec=1h`
  (hourly) + `RandomizedDelaySec=5min` (fleet load spread) +
  `Persistent=true` (catch up after host downtime) +
  `StartLimitIntervalSec=60s` + `StartLimitBurst=10` (cap restart-storm)

The shipped units carry an L2 bats test suite
(`packaging/test/L2-doctor-timer.bats`, 23 tests) gating their surface
against drift. If you need to customize, prefer a systemd drop-in
(`systemctl edit selfdef-doctor.timer`) over forking the unit — the
drop-in survives package upgrades.

See `packaging/systemd/selfdef-doctor.{service,timer}` for the
authoritative shipped definitions.

### CI consumption

```sh
selfdefctl doctor --json | jq -e '. | select(.status == "FAIL")' > /tmp/doctor-fails.json
if [[ -s /tmp/doctor-fails.json ]]; then
    cat /tmp/doctor-fails.json
    exit 1
fi
```

## Tests

`crates/selfdef-cli/tests/cli_doctor.rs` ships 6 integration tests covering:

- All cross-cutting opt-ins off → every category reports `skip`, exit 0.
- API token at `0600` → `ok`; at `0644` → `FAIL` with mode in detail.
- Rule signing on without a key path → `FAIL` with the unset-key diagnostic.
- Eventstream integrity on with a world-writable path → `FAIL`.
- `--json` emits one JSON object per check covering every expected category.
