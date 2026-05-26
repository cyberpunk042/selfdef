# grub-config-watchdog

Boot + daily delta of the GRUB config **source** (`/etc/grub.d/*`
generator scripts + `/etc/default/grub`) against a learned
baseline, plus an ownership + suspicious-pattern scan and
`GRUB_CMDLINE_LINUX` extraction. Catches a rogue boot-config
edit before it takes effect. MITRE **T1542.003** (Bootkit) /
**T1037** / **T1601** (Modify System Image).

## Why this matters

`/etc/grub.d/*` are generator scripts run **as root** by
`grub-mkconfig` / `update-grub` to build `grub.cfg`. A rogue
script (or an edit to `40_custom`) executes at config-regen and
can inject a hidden menuentry, chainload a malicious loader,
copy a trojaned initrd into `/boot`, or add kernel params to
every entry.

`/etc/default/grub` holds `GRUB_CMDLINE_LINUX[_DEFAULT]`. An
attacker who adds `init=/bin/sh` (or `init=/tmp/x`) there
**hijacks PID 1** on the next boot:

```
GRUB_CMDLINE_LINUX="quiet init=/tmp/.payload"
```

That change is **invisible to `kernel-cmdline-watchdog`** (which
reads the LIVE `/proc/cmdline`) until the reboot — this module
watches the SOURCE that defines the next boot's cmdline, so it
catches the edit immediately.

## Watched

- `/etc/grub.d/*` — generator scripts (hash + owner:mode +
  suspicious patterns).
- `/etc/default/grub` (+ `/etc/default/grub.d/*`) — hash +
  extracted `GRUB_CMDLINE_LINUX[_DEFAULT]` values.

No-ops cleanly if neither exists (`event:no_grub_config`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any grub-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No grub config | `ok` | `no_grub_config` |
| No delta | `ok` | `grub_config_intact` |
| A script / default added, changed, or removed | `warn` | `grub_config_changed` |
| A grub.d script world-writable/non-root/with a suspicious pattern, OR an `init=` param in GRUB_CMDLINE | `alert` | `grub_config_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each grub.d script + default
  file.
- `own:<script>:<owner:mode>` — grub.d script ownership (a
  world-writable / non-root generator script runs attacker code
  as root at update-grub).
- `susp:<script>:<pattern>` — suspicious exec pattern in a
  grub.d script.
- `cmdline:<key>:<value>` — `GRUB_CMDLINE_LINUX[_DEFAULT]` value;
  an `init=` token (PID-1 hijack) flags `alert`.

## Cadence

`OnBootSec=19min` + `OnCalendar=*-*-* 07:40:00` — extends the
staggered ladder after access-conf (07:35). A malicious
`GRUB_CMDLINE` / grub.d edit takes effect on the next
`update-grub` + reboot, so the boot catch confirms the source
after a restart.

## MITRE coverage

- **T1542.003** Pre-OS Boot: Bootkit — modifying the boot
  configuration / loader.
- **T1037** Boot or Logon Initialization Scripts — grub.d
  scripts run at config-regen; `init=` runs at boot.
- **T1601** Modify System Image (adjacent) — altering the boot
  chain's effective config.

## Operator workflow

```bash
journalctl -t selfdef-grub-config -n 1 --no-pager
journalctl -t selfdef-grub-config-detail --since "1 day ago"

# Inventory
ls -la /etc/grub.d/
grep -E '^GRUB_CMDLINE_LINUX' /etc/default/grub

# Investigate a suspicious alert
# - init= in GRUB_CMDLINE? a writable/non-root grub.d script?
ls -l /etc/grub.d/<script>; head -40 /etc/grub.d/<script>
# Remove/repair, regenerate grub.cfg, re-baseline:
sudo $EDITOR /etc/default/grub        # drop the init= param
sudo update-grub                      # or grub2-mkconfig -o /boot/grub2/grub.cfg
sudo rm /var/lib/selfdef/grub-config-baseline.tsv
sudo systemctl start selfdef-grub-config.service

# Re-baseline after a legit kernel-param change (you added
# mitigations=off, etc.): re-run the service once.
sudo rm /var/lib/selfdef/grub-config-baseline.tsv
sudo systemctl start selfdef-grub-config.service
```

## Caveats

- **Package/kernel updates rewrite grub.d + default** → benign
  `warn`; re-baseline. The `suspicious` tier (writable/non-root
  script, injection pattern, `init=`) is the high-confidence one.
- **The generated `grub.cfg`** is regenerated from this source;
  watching the SOURCE catches the edit one regen earlier. aide-
  bridge / integrity-sentinel on `/boot/grub*/grub.cfg` is the
  generated-artifact complement.
- **Daily+boot cadence** misses an inject-regen-revert within the
  window; an audit-rules watch on `/etc/grub.d` + `/etc/default/
  grub` writes is the real-time complement.
- **Distros differ** (`/boot/grub` vs `/boot/grub2`, `update-grub`
  vs `grub2-mkconfig`); this watches the common `/etc/grub.d` +
  `/etc/default/grub` source paths.

## Coexistence

- **kernel-cmdline-watchdog**: reads the LIVE `/proc/cmdline`
  (this-boot reality); this watches the SOURCE that defines the
  NEXT boot's cmdline. Together: what's running now + what the
  next boot will run.
- **bootloader-password-detect**: the GRUB password (edit-
  protection); this watches the config it protects.
- **secure-boot-status**: the firmware trust chain; this is the
  bootloader-config layer above it.
- **boot-script-watchdog / aide-bridge**: rc.local/init.d + /boot
  artifact integrity; this is the GRUB-config-source semantic
  view.
