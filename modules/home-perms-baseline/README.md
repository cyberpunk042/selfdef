# home-perms-baseline

Tightens each `/home/<user>` directory to `0750` (group
profile) or `0700` (strict) so local users can't browse
each other's home directories. The default distro mode
`0755` leaves every home world-readable. CIS 6.2.x.

## Why this matters

On a multi-user host, a `0755` home directory means any
local user — including a compromised low-privilege service
account (`www-data`, `nobody`) — can `ls ~otheruser` and
read any world-readable file inside: SSH keys with weak
perms, `.bash_history`, config files with embedded
credentials, `.netrc`, cached tokens.

Tightening the home dir to `0750` (group can enter, world
cannot) or `0700` (owner only) closes the cross-user
browsing path at the top-level directory regardless of the
individual files' modes.

## Profiles

| Profile | Mode | Effect |
|---|---|---|
| `group` (default) | 0750 | owner rwx, group rx, world none |
| `strict` | 0700 | owner only |

## Safety properties

- **Only ever tightens** — if a home is already stricter
  than the target (e.g. 0700 when target is 0750), it's
  left alone. The module never loosens permissions.
- **Skips system accounts** — only acts on uid >= 1000
  (override `SELFDEF_HOME_MINUID`) with a home under
  `/home/`.
- **Skips operator-prefixed accounts** (`operator`,
  `operator-*`, `selfdef`, `selfdef-*`) — selfdef never
  touches operator-owned identities.
- **Backs up** the pre-change modes to
  `/var/lib/selfdef/home-perms.bak`; uninstall restores
  them exactly.

## MITRE coverage

- **T1083** File and Directory Discovery — blocks
  cross-user home enumeration.
- **T1552.001** Unsecured Credentials: Credentials In
  Files — a world-readable home is the path to another
  user's credential files.
- **T1078** Valid Accounts — reading another user's SSH
  key / token from their browsable home enables account
  takeover.
- **T1006** Direct Volume Access — narrows the readable
  surface for a low-priv attacker.

## Operator workflow

```bash
# Inspect current home modes
awk -F: '$3>=1000 && $6 ~ /^\/home\//{print $1" "$6}' /etc/passwd \
  | while read u d; do [ -d "$d" ] && stat -c '%a %n' "$d"; done

# Apply (group = 0750)
sudo selfdefctl modules apply home-perms-baseline

# Verify
sudo selfdefctl modules check home-perms-baseline

# Switch to strict (0700)
sudo sed -i 's/^profile.*/profile = "strict"/' \
    /etc/selfdef/modules/home-perms-baseline.toml
sudo selfdefctl modules apply home-perms-baseline
```

## Caveats

- **Shared-group workflows**: if users intentionally share
  files via a common group (e.g. a `devs` group reading
  each other's project dirs), `0750` works only when the
  group is set right; `0700` (strict) breaks it. Use
  `group` on collaborative hosts.
- **Web/content servers**: if a service reads from a
  user's home (e.g. `~user/public_html` served by Apache
  userdir), tightening the home dir blocks it. Those hosts
  need per-case ACLs, not this blanket module.
- **New users**: this module acts at apply time;
  `login-defs`/`useradd` `HOME_MODE` governs NEW home
  creation (set separately). Re-apply after adding users,
  or rely on the daily check to flag drift.
- **Does not recurse** — only the top-level home dir mode
  is changed (that's the CIS control + the effective
  browsing gate). Individual file modes are governed by
  umask-baseline.

## Coexistence

- **umask-baseline**: complementary — umask-baseline makes
  NEW files owner-tight; this makes the home DIRECTORY
  itself non-browsable. Together: tight dir + tight files.
- **login-defs-baseline**: complementary — sets HOME_MODE
  for newly-created accounts; this fixes existing ones.
- **account-watchdog**: complementary — detects new
  accounts; re-apply this module to tighten their homes.
- **world-writable-watchdog + unowned-files-watchdog**:
  complementary permission/ownership detection across the
  broader tree.
