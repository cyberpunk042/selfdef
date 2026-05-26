# tmpfiles-watchdog

Boot + daily delta of the `systemd-tmpfiles` declarations against a
learned baseline, plus an ownership + semantic scan. Catches a
declaration that mints a setuid-root file (or other privileged
artifact) at boot. MITRE **T1546** / **T1574** / **T1548**.

## Why this matters

`systemd-tmpfiles-setup` runs these **as root** at boot, and the
`systemd-tmpfiles-clean` timer runs daily:

- `/etc/tmpfiles.d/*.conf` — admin declarations
- `/run/tmpfiles.d/*.conf` — runtime declarations

Line format: `Type Path Mode User Group Age Argument`. Each line
creates or sets a file (`f`/`F`/`w`), directory (`d`/`D`), symlink
(`L`/`L+`), fifo (`p`), device node (`c`/`b`), or **copies** a file
into place (`C`) — with an explicit `Mode`/`User`/`Group`.

A planted entry can:

- mint a **setuid-root file** (`f /usr/local/bin/x 4755 root root -`),
- create a **world-writable dir** in a `PATH` location,
- plant a **symlink hijack** into a sensitive path (`L`),
- **copy** an attacker file over a trusted one (`C`),

…and because tmpfiles is idempotent, the artifact **returns at every
boot** even if a defender removes it. This is the **file**-creation
peer of the boot-time-creation family:

- **sysusers-watchdog** — accounts/groups,
- **modules-load-watchdog** — kernel modules,
- **binfmt-watchdog** — interpreters,
- **tmpfiles-watchdog** — files/dirs/symlinks (this module).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any tmpfiles declaration change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No admin/runtime tmpfiles.d present | `ok` | `no_tmpfiles` |
| No delta | `ok` | `tmpfiles_intact` |
| An entry added / changed / removed | `warn` | `tmpfiles_changed` |
| A `.conf` world-writable/non-root, OR an entry whose Mode sets the SETUID bit | `alert` | `tmpfiles_suspicious` |

The SETUID check flags a 4-digit Mode whose high digit carries the
suid (4) bit — `4755`, `6755`, `4700`, … Common-and-legit
**setgid** (`2755`, e.g. `/var/log/journal`) and **sticky** (`1777`,
e.g. `/tmp`) modes are deliberately **not** flagged.

## What's recorded

- `file:<path>:<sha12>` — hash of each `.conf`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `ent:<path>:<type>:<target>:<mode>` — each declaration entry.

## Cadence

`OnBootSec=59min` + `OnCalendar=*-*-* 11:00:00` — extends the
staggered ladder after sysusers (10:55). A planted declaration
re-applies its artifact at the next `systemd-tmpfiles` run, so the
daily catch bounds dwell time; the boot catch confirms the
declaration set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — boot-time application is the
  trigger; the planted artifact persists.
- **T1574** Hijack Execution Flow — a symlink/copy can redirect a
  trusted path.
- **T1548** Abuse Elevation Control Mechanism — a setuid-root file
  minted here is direct privilege escalation.

## Operator workflow

```bash
journalctl -t selfdef-tmpfiles -n 1 --no-pager
journalctl -t selfdef-tmpfiles-detail --since "1 day ago"

# Inventory + dry-run what tmpfiles would apply
cat /etc/tmpfiles.d/*.conf /run/tmpfiles.d/*.conf 2>/dev/null
systemd-tmpfiles --create --dry-run 2>/dev/null

# Hunt setuid declarations specifically
grep -hE '^[a-zA-Z+!-]+\s+\S+\s+~?[4567][0-7]{3}\b' \
     /etc/tmpfiles.d/*.conf /run/tmpfiles.d/*.conf 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/tmpfiles.d/<file>.conf
sudo rm /var/lib/selfdef/tmpfiles-baseline.tsv
sudo systemctl start selfdef-tmpfiles.service
```

## Caveats

- **Packages ship many legitimate declarations** (creating `/run`
  and `/var` dirs with setgid `2755` or sticky `1777`); these are
  **not** flagged. A new root-owned entry with an ordinary mode
  fires `warn` (re-baseline). The setuid-mode / world-writable /
  non-root tiers are the high-confidence alert.
- **/usr/lib/tmpfiles.d is not watched** — it is package-managed
  (integrity-sentinel / aide-bridge territory); this module watches
  the admin/runtime `/etc` + `/run` dirs an attacker would write to.
- **`C` (copy) and `L` (symlink) entries are tracked but not
  alerted by default** — legit uses are common, and the source/target
  vary widely; review them in the `ent:` records and the dry-run.
- **Quoted paths with spaces** make the positional Mode column
  unreliable for that one line; such entries are rare. Cross-check
  with `systemd-tmpfiles --create --dry-run`.
- **Daily+boot cadence** misses a declare-apply-undeclare inside the
  window; an audit-rules watch on the tmpfiles.d dirs' writes is the
  real-time complement.

## Coexistence

- **sysusers / modules-load / binfmt watchdogs**: the other
  boot-time declarative-creation surfaces; this is the file/dir/
  symlink one.
- **suid-sgid-watchdog / world-writable-watchdog**: watch the live
  filesystem for the *artifacts*; this watches the *declaration* that
  recreates them at boot — catch the source before the next boot
  re-mints it.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  `.conf` files; this adds the semantic (setuid-mode) view.
