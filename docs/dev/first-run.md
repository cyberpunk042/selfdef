# selfdef first-run

This is the operator's walkthrough for standing up a fresh
selfdef deployment. The new `selfdefctl init` family of
subcommands handles the bootstrap; this doc explains what each
one does and what the operator should do next.

For the bookend — verifying a deployment after the fact — see
`docs/dev/operator-health-check.md` (`selfdefctl doctor`).

## TL;DR

```sh
sudo selfdefctl init config        # writes /etc/selfdef/selfdef.toml
sudo selfdefctl init modules       # writes /etc/selfdef/modules.toml
sudo systemctl enable --now selfdefd
sudo selfdefctl modules apply
selfdefctl doctor
```

That's enough for a minimal deployment with the daemon running,
selected modules applied, and the cross-cutting checks reporting
clean (or pointing at what still needs attention).

## `selfdefctl init config`

Writes a starter `/etc/selfdef/selfdef.toml` with:

- `[daemon]` — `log_level = "info"`, `log_format = "text"`.
- `[store]` — hot store at `/var/lib/selfdef/state.sqlite`.
- `[correlator]` — enabled, `rules_dir = "/etc/selfdef/rules"`.
- `[notifier]` — empty channel list. Add `"ntfy"` /
  `"signal"` after the matching `[notifier.<name>]` block is
  configured (see the exhaustive example at
  `/usr/share/selfdef/selfdef.toml.example`).
- `[responder]` — `allowed_actions = ["notify"]`, `dry_run = true`.
  Flip `dry_run = false` after verifying the rule + notifier
  chain works end-to-end.
- `[api]` — disabled.
- `[security]` — `require_signed_rules = false`. Every
  audit-shipped opt-in is off in the starter; turn them on
  after following the matching runbook.
- `[collectors.eventstream]` — disabled.

### Flags

- `--output <path>` — write to a non-default location (useful for
  test rollouts).
- `--force` — overwrite an existing file. Default is
  refuse-to-clobber.

The file is written atomically (tempfile → fsync → rename →
chmod 0644). A crash mid-write leaves the previous file intact.

## `selfdefctl init modules`

Writes a starter `/etc/selfdef/modules.toml` listing every
shipped module commented out, each with a short description and
a pointer to its per-module config path. The operator opts in
by uncommenting:

```toml
[modules.tetragon]
config = "/etc/selfdef/modules/tetragon.toml"
```

After editing, preview with:

```sh
selfdefctl modules apply --dry-run
```

Same `--output` / `--force` semantics as `init config`.

## `selfdefctl init checklist`

Prints the first-run operator checklist to stdout — a one-page
reference covering:

1. Daemon config (`init config`)
2. Module selection (`init modules`)
3. Daemon start (`systemctl enable --now selfdefd`)
4. Module apply (`modules apply`)
5. Cross-cutting verification (`doctor`)
6. **Optional**: rule signing (`docs/dev/signing.md`)
7. **Optional**: API token rotation
8. **Optional**: eventstream integrity
9. **Optional**: TracingPolicy signing
10. **Optional**: agent-guard pod-label RBAC (`docs/dev/rbac-posture.md`)
11. Periodic health check via systemd timer

Read-only; no filesystem effects. Pipe to `tee` if you want a
local copy.

## Why the starter ships every opt-in OFF

Every audit-shipped security feature has an operator-side cost
(generate a signing key, deploy a public key, rotate tokens,
verify RBAC posture). Defaulting them on would either fail at
startup (no key on disk) or silently degrade (every rule
"signed" by an empty key). Defaulting them off + documenting
the explicit `selfdefctl init checklist` flow lets the operator
turn each one on after they've followed the matching runbook
and have the on-disk state in place.

`selfdefctl doctor` then verifies the opt-ins the operator
actually turned on, and stays silent (skip) on the ones they
didn't. Together: init writes the minimum viable config, the
checklist walks the operator through each opt-in, doctor
verifies the result.

## Tests

`crates/selfdef-cli/tests/cli_init.rs` ships 7 integration
tests covering:

- `init_config_writes_starter_file_at_0644`
- `init_config_refuses_to_overwrite_without_force`
- `init_config_force_overwrites_existing_file`
- `init_modules_writes_starter_with_every_module_commented_out`
  — also asserts every `[modules.<slug>]` header in the
  starter is commented; no module is silently activated.
- `init_modules_refuses_to_overwrite_without_force`
- `init_checklist_prints_to_stdout_without_filesystem_effects`
- `init_config_creates_parent_directories`
