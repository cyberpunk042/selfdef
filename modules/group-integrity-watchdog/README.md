# group-integrity-watchdog

Daily + boot delta of `/etc/group` membership against a
learned baseline, with a privileged-group denylist where
ADDING a member is a root-equivalent privilege escalation.
Distinct from `account-watchdog` (which tracks passwd /
uid=0 / sudo-roster) — this covers the FULL group set,
including the non-sudo groups that grant root-equivalent
power.

## Why this matters

Several Linux groups confer root-equivalent capability
WITHOUT appearing in the sudo/wheel roster that
account-watchdog watches. Adding an attacker's account to
one is a stealthy escalation:

| Group | What membership grants |
|---|---|
| `docker` / `lxd` / `podman` | spawn a container that bind-mounts host `/` as root → trivially root the host. THE canonical "non-root root" group. |
| `disk` | raw read/write of block devices → read `/etc/shadow` straight off the raw filesystem, or patch a binary on disk. |
| `shadow` | read `/etc/shadow` (all password hashes). |
| `kvm` / `libvirt` | VM management → VM-escape + host-disk-image access surface. |
| `adm` / `systemd-journal` | read all system logs (broad info disclosure). |
| `video` / `render` | GPU/DRM device access. |

`account-watchdog` catches a new account or a sudo-group
add; this catches the `usermod -aG docker attacker` that
neither the passwd diff nor the sudo-roster diff sees.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any group-membership change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| Membership change in a non-privileged group | `warn` | `group_membership_changed` |
| A member ADDED to a privileged (denylist) group | `alert` | `privileged_group_member_added` |

## Privileged-group denylist

`docker`, `lxd`, `podman`, `disk`, `shadow`, `kvm`,
`libvirt`, `libvirtd`, `adm`, `systemd-journal`, `video`,
`render`, `sudo`, `wheel`, `root`.

## What's recorded

`group  member` per line, covering BOTH the group-file
member list AND users whose PRIMARY gid is the group
(primary-gid members don't appear in the group's member
field, so a naive `/etc/group` grep would miss them).

## Cadence

`OnBootSec=8min` + `OnCalendar=*-*-* 06:40:00` — extends
the staggered ladder after crontab-allow (06:30) +
ssh-hostkey (06:35); boot catch confirms membership after
a restart.

## MITRE coverage

- **T1098** Account Manipulation — PRIMARY; adding a user
  to a privileged group is the manipulation.
- **T1548** Abuse Elevation Control Mechanism — docker/disk
  group membership IS an elevation mechanism.
- **T1611** Escape to Host — docker/lxd group → container →
  host root is the escape path.
- **T1078.003** Valid Accounts: Local Accounts — the
  group-empowered account is a privileged foothold.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-group-integrity -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-group-integrity-detail --since "1 day ago"

# Manual inventory of the dangerous groups
for g in docker lxd disk shadow kvm adm; do
    getent group "$g" 2>/dev/null
done

# Investigate an alert
id <member>; groups <member>
# Was this a legit admin action? If not → remove + investigate:
sudo gpasswd -d <member> docker

# Re-baseline after a legit membership change
sudo rm /var/lib/selfdef/group-integrity-baseline.tsv
sudo systemctl start selfdef-group-integrity.service
```

## Caveats

- **Package installs add service accounts to groups**
  (e.g. installing libvirt adds qemu to kvm) → fires once,
  then re-baseline absorbs it. Confirm it's a package
  action, not an attacker.
- **Legit operator grants** (adding a dev to the docker
  group) fire `privileged_group_member_added` — that's
  correct: docker membership IS root-equivalent and
  deserves a deliberate, logged decision. Re-baseline
  after confirming.
- **Daily+boot cadence** misses an add-act-remove within
  the window; audit-rules watching /etc/group writes is
  the real-time complement.
- **LDAP/SSSD groups** resolved via NSS but not in
  /etc/group aren't covered (local files only) — a future
  getent-group enhancement could include them.

## Coexistence

- **account-watchdog**: the matched sibling — account-
  watchdog tracks passwd entries + uid=0 + sudo/wheel/admin
  roster; this tracks the FULL group set incl. docker/disk/
  shadow/kvm (the non-sudo root-equivalent groups). Run
  both for complete account+group capability coverage.
- **sudoers-integrity-watchdog + crontab-allow-watchdog**:
  the capability-grant detector family — sudo rule grant /
  schedule-roster grant / privileged-group grant. All catch
  the GRANT before the action.
- **service-account-lock**: complementary — locks service-
  account shells; this detects them being added to
  powerful groups.
- **audit-rules**: real-time write watch on /etc/group;
  this is the periodic parsed-membership delta backstop.
