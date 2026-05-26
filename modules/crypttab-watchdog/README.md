# crypttab-watchdog

Boot + daily delta of `/etc/crypttab` against a learned baseline,
plus an ownership + keyscript/keyfile scan. Catches a rogue
key-acquisition program run as root at early boot. MITRE
**T1037** (Boot Initialization Scripts) / **T1552** (Unsecured
Credentials).

## Why this matters

crypttab maps encrypted volumes; the `keyscript=` option runs a
program **as root** at early boot to obtain the volume key:

```
data /dev/sda2 none luks,keyscript=/tmp/.getkey   # root exec at boot
data /dev/sda2 /tmp/.key luks                      # key from a writable path
```

A rogue keyscript is root-exec-at-boot persistence; a keyfile
under a writable path is key theft or substitution.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any crypttab change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No crypttab | `ok` | `no_crypttab` |
| No delta | `ok` | `crypttab_intact` |
| An entry / file added, removed, or changed | `warn` | `crypttab_changed` |
| A keyscript or keyfile under /tmp /home /dev/shm, world-writable, or bare/relative; or a world-writable/non-root crypttab | `alert` | `crypttab_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of crypttab.
- `own:<path>:<owner:mode>` — owner + mode.
- `crypt:<target>:<src>|<keyfile>|<keyscript>` — each entry's
  source device, keyfile, and keyscript (from the options field).

## Cadence

`OnBootSec=44min` + `OnCalendar=*-*-* 09:45:00` — extends the
staggered ladder after inittab (09:40). A rogue keyscript runs at
the next boot's volume unlock, so the boot catch confirms
crypttab after a restart.

## MITRE coverage

- **T1037** Boot or Logon Initialization Scripts — the keyscript
  runs as root at early boot.
- **T1552** Unsecured Credentials — a keyfile under a writable
  path is a stealable/substitutable volume key.
- **T1059.004** — the keyscript is command execution.

## Operator workflow

```bash
journalctl -t selfdef-crypttab -n 1 --no-pager
journalctl -t selfdef-crypttab-detail --since "1 day ago"

# Inventory
grep -vE '^\s*#|^\s*$' /etc/crypttab 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/crypttab        # fix the keyscript/keyfile path
sudo rm /var/lib/selfdef/crypttab-baseline.tsv
sudo systemctl start selfdef-crypttab.service
```

## Caveats

- **Legit keyscripts exist** (TPM/Yubikey unlock helpers in
  /usr/lib or /lib); a new entry fires `warn`, and the tmp/
  writable keyscript/keyfile tier is the high-confidence alert.
  Re-baseline a vetted keyscript.
- **No encrypted volumes** → `no_crypttab` no-op.
- **Daily+boot cadence** misses an inject-reboot-revert within the
  window; an audit-rules watch on `/etc/crypttab` writes is the
  real-time complement.

## Coexistence

- **swap-encryption-detect**: verifies swap is encrypted (reads
  crypttab for that purpose); this watches crypttab for rogue
  keyscript/keyfile tampering. Complementary crypttab views.
- **boot-script / grub-config / inittab watchdogs**: the early-boot
  exec family — this adds the volume-unlock keyscript surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  crypttab + the keyscript binaries; this adds the per-entry
  keyscript/keyfile semantic view.
