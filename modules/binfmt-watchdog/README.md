# binfmt-watchdog

Boot + daily delta of the `binfmt_misc` interpreter registrations
against a learned baseline, plus an ownership + interpreter-path
scan. Catches a registration that makes the kernel run an attacker
interpreter whenever a matching file type is executed. MITRE
**T1546** / **T1574**.

## Why this matters

`systemd-binfmt` applies these at boot:

- `/etc/binfmt.d/*.conf` — admin registrations
- `/run/binfmt.d/*.conf` — runtime registrations

Each line registers an **interpreter** the kernel invokes whenever a
file matching a magic-byte signature (type `M`) or filename
extension (type `E`) is executed. The line format — the **first
character is the field delimiter** (conventionally `:`) — is:

```
:name:type:offset:magic:mask:INTERPRETER:flags
```

A planted registration whose `INTERPRETER` is an attacker payload is
**execution-flow hijack + persistence**: every time a matching file
type runs (e.g. any `.py`, any Java `.class`, any file with a chosen
magic prefix), the attacker's interpreter runs first. The `C` flag
additionally runs the interpreter with the **target binary's
credentials** — including setuid — which is a privilege-escalation
amplifier.

This is distinct from:

- **modprobe-config-watchdog** / **modules-load-watchdog** — kernel
  *modules*, not userspace interpreters.
- exec-dir watchdogs (cron/hooks/etc.) — this is **interpreter
  registration**, not a hook script that runs on a schedule/event.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any binfmt registration change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No binfmt.d registrations present | `ok` | `no_binfmt` |
| No delta | `ok` | `binfmt_intact` |
| A registration added / changed / removed | `warn` | `binfmt_changed` |
| A `.conf` world-writable/non-root, OR an interpreter under `/tmp` `/var/tmp` `/dev/shm` `/home`, OR a non-absolute interpreter | `alert` | `binfmt_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.conf`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `intr:<path>:<interpreter>` — each registered interpreter path
  (field 7, parsed with the line's own first-char delimiter).

## Cadence

`OnBootSec=57min` + `OnCalendar=*-*-* 10:50:00` — extends the
staggered ladder after ca-certificates-hooks (10:45). A planted
registration takes effect at the next `systemd-binfmt` apply and
then on every execution of a matching file type, so the daily catch
bounds dwell time; the boot catch confirms the registration set
after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — executing a matching file
  type is the trigger.
- **T1574** Hijack Execution Flow — the kernel routes execution
  through the registered interpreter.
- **T1059** — the interpreter is arbitrary code run on behalf of the
  caller.

## Operator workflow

```bash
journalctl -t selfdef-binfmt -n 1 --no-pager
journalctl -t selfdef-binfmt-detail --since "1 day ago"

# Inventory the registrations and the live kernel view
cat /etc/binfmt.d/*.conf /run/binfmt.d/*.conf 2>/dev/null
ls -la /proc/sys/fs/binfmt_misc/ 2>/dev/null      # live registrations
for r in /proc/sys/fs/binfmt_misc/*; do
  [ -f "$r" ] && [ "$(basename "$r")" != register ] && \
  [ "$(basename "$r")" != status ] && echo "== $r ==" && cat "$r"; done

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/binfmt.d/<file>.conf
sudo rm /var/lib/selfdef/binfmt-baseline.tsv
sudo systemctl start selfdef-binfmt.service
```

## Caveats

- **Legitimate registrations exist** (qemu-user-static for foreign
  architectures registers many `qemu-*` interpreters; Java, Mono,
  WSL-interop); a new root-owned registration with an absolute,
  non-writable interpreter fires `warn` (re-baseline). The
  writable/non-absolute/non-root tiers are the high-confidence alert.
- **/usr/lib/binfmt.d is not watched** — it is package-managed
  (integrity-sentinel / aide-bridge territory); this module watches
  the admin/runtime `/etc` + `/run` dirs an attacker would write to.
- **Source dirs vs live kernel state:** this watches the `.conf`
  source. A registration written directly to
  `/proc/sys/fs/binfmt_misc/register` (not via a `.conf`) is visible
  only in the live `/proc` view — inventory it as shown above.
- **Daily+boot cadence** misses a register-trigger-unregister inside
  the window; an audit-rules watch on the binfmt.d dirs' writes is
  the real-time complement.

## Coexistence

- **modprobe-config-watchdog / modules-load-watchdog**: kernel
  module load surfaces; this is the userspace interpreter
  registration surface.
- **suid-sgid-watchdog**: the `C`-flag credential amplifier ties
  binfmt to setuid abuse — together they cover interpreter-via-setuid
  escalation.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  `.conf` files; this adds the interpreter-path + ownership view.
