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

`/etc/systemd/system/selfdef-doctor.service`:

```ini
[Unit]
Description=Run selfdefctl doctor

[Service]
Type=oneshot
ExecStart=/usr/bin/selfdefctl doctor
StandardOutput=journal
```

`/etc/systemd/system/selfdef-doctor.timer`:

```ini
[Unit]
Description=Hourly selfdefctl doctor

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

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
