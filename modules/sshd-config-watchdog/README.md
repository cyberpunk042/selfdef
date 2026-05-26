# sshd-config-watchdog

Boot + daily delta of the **effective** sshd configuration
(`sshd -T` merged output for a curated security-directive set) +
a content hash of `sshd_config` and `sshd_config.d/*` against a
learned baseline. Catches a dangerous directive added via any
file or a backdoor `Match` block. MITRE **T1098.004** /
**T1556** / **T1505** (server config for persistent access).

## Why this matters

sshd is the primary remote-access surface. `ssh-hardening`
writes + checks the directives **it** manages; `ssh-authkeys-
watchdog` watches key files. Neither catches a dangerous
directive added via an unmanaged drop-in or a `Match` block:

```
echo 'PermitRootLogin yes'                >> /etc/ssh/sshd_config.d/zz.conf
echo 'AuthorizedKeysCommand /tmp/getkeys' >> /etc/ssh/sshd_config.d/zz.conf
printf 'Match User svc\n  ForceCommand /tmp/x\n' >> /etc/ssh/sshd_config
```

`AuthorizedKeysCommand` and `ForceCommand` are **sshd exec
vectors** — sshd runs them, so a writable/tmp target is remote
code-exec. `PermitRootLogin yes` / `PermitEmptyPasswords yes`
reopen the front door. A `Match` block can scope a backdoor to a
single account so it is invisible in the global config.

## How it watches

1. **Effective config** — `sshd -T` dumps the merged global
   config; the watchdog records a curated set of
   security-relevant directives. This catches a change no matter
   which file caused it (sshd_config or any drop-in).
2. **File hashes** — `sshd_config` + each `sshd_config.d/*.conf`
   are hashed. `sshd -T` shows only the GLOBAL config, so
   `Match` blocks live only in the files; the hash surfaces them
   (and any other edit).

If the host has no sshd binary and no `sshd_config`, the module
no-ops cleanly (`event:no_sshd`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any sshd-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No sshd present | `ok` | `no_sshd` |
| No delta | `ok` | `sshd_config_intact` |
| Any effective directive changed / file hash changed | `warn` | `sshd_config_changed` |
| `permitrootlogin yes`, `permitemptypasswords yes`, or an `authorizedkeyscommand`/`forcecommand` target under /tmp /home /dev/shm, world-writable, or bare | `alert` | `sshd_config_dangerous_directive` |

## Watched directives (curated)

`permitrootlogin`, `passwordauthentication`,
`permitemptypasswords`, `pubkeyauthentication`,
`authorizedkeyscommand`(+user), `forcecommand`, `permittunnel`,
`allowtcpforwarding`, `gatewayports`, `x11forwarding`, `usepam`,
`kbdinteractiveauthentication`, `challengeresponseauthentication`,
`authorizedkeysfile`, `allowusers`/`allowgroups`/`denyusers`/
`denygroups`, `permituserenvironment`, `acceptenv`, `subsystem`,
`allowagentforwarding`, `streamlocalbindunlink`, `maxauthtries`,
`logingracetime`.

(The file-hash backstop catches anything outside this set,
including `Match` blocks.)

## Cadence

`OnBootSec=14min` + `OnCalendar=*-*-* 07:15:00` — extends the
staggered ladder after modprobe-config (07:10). A config change
takes effect on the next sshd reload/restart, so the boot catch
confirms the effective config after a restart.

## MITRE coverage

- **T1098.004** Account Manipulation: SSH Authorized Keys — an
  `AuthorizedKeysCommand` pointing at an attacker script feeds
  arbitrary keys; `authorized_keys` files are
  ssh-authkeys-watchdog's job, the COMMAND is this one's.
- **T1556** Modify Authentication Process —
  `PermitRootLogin`/`PermitEmptyPasswords`/auth-method changes.
- **T1505.003**-adjacent — sshd is the server; a `ForceCommand`/
  drop-in backdoor is server-config persistence.
- **T1059.004** — `ForceCommand`/`AuthorizedKeysCommand` are
  shell execution by sshd.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-sshd-config -n 1 --no-pager
journalctl -t selfdef-sshd-config-detail --since "1 day ago"

# Effective config (what sshd actually uses)
sudo sshd -T | grep -iE 'permitroot|password|authorizedkeyscommand|forcecommand|permitempty'

# Match blocks (NOT in sshd -T global dump)
sudo grep -rniE '^\s*match|forcecommand|authorizedkeyscommand' \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null

# Investigate a dangerous_directive alert, then re-baseline:
sudo $EDITOR /etc/ssh/sshd_config.d/<file>.conf   # remove the line
sudo sshd -t && sudo systemctl reload sshd        # validate + apply
sudo rm /var/lib/selfdef/sshd-config-baseline.tsv
sudo systemctl start selfdef-sshd-config.service

# Re-baseline after a legit hardening change (e.g. you tightened
# a directive): re-run the service once.
sudo rm /var/lib/selfdef/sshd-config-baseline.tsv
sudo systemctl start selfdef-sshd-config.service
```

## Caveats

- **`sshd -T` requires a readable host key + valid config**; if
  it fails (broken config), the module falls back to file hashes
  only — still catches the edit, just without the effective-value
  semantics. Run `sshd -t` to see why `-T` failed.
- **Package updates / hardening reruns** change the config →
  benign `warn`; re-baseline. The `dangerous_directive` tier is
  the high-confidence one.
- **Daily+boot cadence** misses an inject-reload-revert within
  the window; an audit-rules watch on `/etc/ssh/` writes is the
  real-time complement.

## Coexistence

- **ssh-hardening**: writes + checks the directives it manages
  (PermitRootLogin no, password auth off, strong KEX); this
  catches anything added OUTSIDE that managed set, via any
  drop-in or Match block. Run both: hardening sets the floor,
  this detects regressions + additions.
- **ssh-authkeys-watchdog**: watches `authorized_keys` FILES
  (T1098.004 keys); this watches the `AuthorizedKeysCommand`
  that can SUPPLY keys dynamically + the rest of the effective
  config. Complementary halves of the key-injection surface.
- **ssh-hostkey-watchdog / ssh-moduli-harden**: host-key + KEX
  parameter integrity; this is the policy-directive view.
- **audit-rules**: real-time writes to `/etc/ssh/` within the
  daily window this snapshot misses.
