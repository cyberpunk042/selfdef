# systemd-generator-watchdog

Boot + daily delta of the admin/local/runtime systemd generator
directories against a learned baseline, plus an ownership +
suspicious-pattern scan. Catches a generator that runs as root
at the very start of boot. MITRE **T1543** / **T1546** (Event
Triggered Execution).

## Why this matters

systemd **generators** are small executables that systemd runs
**as root, very early** in boot — before any unit is started —
to synthesize units dynamically. A binary or script dropped into
a generator dir runs as root at the earliest point of boot,
before most monitoring is up, and is easy to overlook next to
units and timers:

```
cp /tmp/g /etc/systemd/system-generators/00-evil
chmod +x /etc/systemd/system-generators/00-evil
# → executed as root at the start of the next boot
```

These dirs are **normally empty** on a typical host, so any new
generator is high-signal.

## Watched directories

| Directory | Watched | Why |
|---|---|---|
| `/etc/systemd/{system,user}-generators` | **yes** | admin; the attacker-writable path |
| `/usr/local/lib/systemd/{system,user}-generators` | **yes** | local |
| `/run/systemd/{system,user}-generators` | **yes** | runtime |
| `/usr/lib/systemd/system-generators` | **no** | package-managed; integrity-sentinel covers it (mirrors the udev-rules / modprobe decisions) |

No-ops cleanly if none of the watched dirs exist
(`event:no_generator_dirs`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any generator-dir change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No generator dirs present | `ok` | `no_generator_dirs` |
| No delta | `ok` | `systemd_generator_intact` |
| A generator changed or removed | `warn` | `systemd_generator_changed` |
| A NEW generator file | `alert` | `systemd_generator_new` |
| A generator world-writable / non-root-owned, or with a suspicious pattern | `alert` | `systemd_generator_suspicious` |

A NEW generator is alert-grade on its own (these dirs are
normally empty); ownership/pattern anomalies escalate to the
suspicious event.

## What's recorded

- `file:<gen>:<sha12>` — hash of each generator.
- `own:<gen>:<owner:mode>` — owner + mode (world-writable /
  non-root = hijackable into root-at-early-boot exec).
- `susp:<gen>:<pattern>` — a suspicious exec pattern in a text
  generator (binaries are covered by the new/ownership checks).

## Cadence

`OnBootSec=21min` + `OnCalendar=*-*-* 07:50:00` — extends the
staggered ladder after at-jobs (07:45). A generator runs at the
very start of the next boot, so the boot catch confirms the dirs
after a restart.

## MITRE coverage

- **T1543** Create or Modify System Process — a generator
  synthesizes/controls units as root at boot.
- **T1546** Event Triggered Execution — generator execution is
  triggered by systemd's early-boot manager start.
- **T1037** Boot or Logon Initialization Scripts — runs at the
  earliest boot stage.
- **T1059.004** — a script generator's body is shell execution.

## Operator workflow

```bash
journalctl -t selfdef-systemd-generator -n 1 --no-pager
journalctl -t selfdef-systemd-generator-detail --since "1 day ago"

# Inventory (normally empty)
ls -la /etc/systemd/system-generators /etc/systemd/user-generators \
       /usr/local/lib/systemd/system-generators \
       /run/systemd/system-generators 2>/dev/null

# Investigate a new/suspicious generator
ls -l <gen>; file <gen>; head -40 <gen>   # script? binary?
# Remove + re-baseline:
sudo rm <gen>
sudo rm /var/lib/selfdef/systemd-generator-baseline.tsv
sudo systemctl start selfdef-systemd-generator.service

# Re-baseline after a legit local generator (rare, operator-
# installed): re-run the service once.
```

## Caveats

- **Package generators live in `/usr/lib`** (not watched) — so
  the watched dirs being empty is the norm, and a new file is
  genuinely notable. A legit operator-installed local generator
  in `/usr/local/lib` fires `alert` (new) once; re-baseline.
- **Daily+boot cadence** misses an inject-reboot-revert within
  the window; an audit-rules watch on the generator dirs' writes
  is the real-time complement.
- **Binary generators** are covered by hash + ownership + the
  new-file check (the pattern scan applies only to text ones);
  aide-bridge / integrity-sentinel give byte-level integrity.

## Coexistence

- **systemd-unit-watchdog**: watches the UNITS; this watches the
  GENERATORS that synthesize units before any unit runs — an
  earlier and stealthier surface. Together they cover the
  generator → unit pipeline.
- **boot-script-watchdog**: rc.local/init.d (legacy boot exec);
  generators are the systemd-native early-boot exec. Both boot
  surfaces.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the generator files; this adds the new-file + ownership +
  pattern semantic view.
