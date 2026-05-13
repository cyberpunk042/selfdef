# Installation

selfdef ships as a Debian package targeting Debian 13+ and
Ubuntu 24.04+. The package installs the daemon binary
(`/usr/bin/selfdefd`), the admin CLI (`/usr/bin/selfdefctl`),
the systemd unit, the AppArmor profile, the example config,
and the modules catalog under `/usr/share/selfdef/modules/`.

## From a release artifact

```bash
TAG=v0.1.0
REPO=cyberpunk042/selfdef

curl -fLO https://github.com/$REPO/releases/download/$TAG/selfdef_${TAG#v}_amd64.deb
sudo dpkg -i selfdef_${TAG#v}_amd64.deb
sudo systemctl enable --now selfdefd
selfdefctl status
```

Verify the artifact's signature first — see
[Verifying a release](./verify_release.md).

## From source

```bash
cargo build --release --locked
cargo install cargo-deb
cargo deb -p selfdef-daemon
sudo dpkg -i target/debian/selfdef-daemon_*.deb
```

## What the postinst does

`packaging/debian/postinst` (run automatically on install):

- Creates the `selfdef:selfdef` system user (no shell, no
  writable home).
- Creates `/var/lib/selfdef`, `/var/log/selfdef`,
  `/etc/selfdef`, `/etc/selfdef/secrets` with conservative
  modes (`0750 root:selfdef` for config; `0750
  selfdef:selfdef` for state and logs).
- Copies `config/selfdef.toml.example` to
  `/etc/selfdef/selfdef.toml` only if no config exists.
- Reloads the AppArmor profile if `apparmor_parser` is
  available.
- Reloads systemd. Does **not** auto-start the service —
  enable when the operator is ready.

## Activating modules

Edit `/etc/selfdef/modules.toml` to declare which modules run
on this host. A typical AI-machine setup:

```toml
[modules.detect-host]
[modules.tetragon]
[modules.agent-guard]
[modules.observability]
[modules.integrity-sentinel]
```

Then apply:

```bash
sudo selfdefctl modules apply --dry-run   # preview
sudo selfdefctl modules apply             # for real
sudo selfdefctl modules check             # verify
```

Each module's per-module config goes at
`/etc/selfdef/modules/<slug>.toml` (or
`<slug>.<instance>.toml` for instanced modules — see the
respective module README).

## Daemon startup

```bash
sudo systemctl enable --now selfdefd
journalctl -u selfdefd -f
selfdefctl status
selfdefctl events tail -n 20
```

By default the daemon runs every collector disabled, the
API disabled, and the responder in `dry_run = true` mode.
Edit `/etc/selfdef/selfdef.toml` and `systemctl restart
selfdefd` (or `kill -HUP $(pidof selfdefd)` for a rule
hot-reload that doesn't bounce the process).

For the per-feature config knobs — collectors, correlator,
notifier, responder, API, NATS bridge — see
[Configuration](./config.md). For notifications specifically
see [Notifications](./notifications.md).

## Removing

```bash
sudo systemctl disable --now selfdefd
sudo selfdefctl modules uninstall --confirm $(hostname)
sudo apt remove selfdef-daemon
```

The `modules uninstall` step tears down each active module's
state in reverse dependency order. The Debian package's
`postrm` does **not** remove `/var/lib/selfdef` or
`/etc/selfdef/` — operator-owned state survives package
removal.
