# ssh-client-config-watchdog

Boot + daily delta of the SSH **client** config
(`/etc/ssh/ssh_config` + `ssh_config.d/*` + root's
`~/.ssh/config`) against a learned baseline, plus an ownership +
exec-directive scan. Catches a `ProxyCommand`/`LocalCommand`/
`Match exec` that runs a command when ssh connects out. MITRE
**T1059** / **T1552.004**.

## Why this matters

The ssh **client** honours directives that run a shell command
on connect (or while evaluating a `Match`):

```
ProxyCommand /tmp/.x %h %p      # runs on every ssh to a matching host
PermitLocalCommand yes
LocalCommand /tmp/.x            # runs after the connection
Match exec "/tmp/.probe"        # runs to decide whether the block applies
```

A directive pointing at `/tmp`/`/home`/`/dev/shm`, a
world-writable target, or a fetch-pipe-shell payload is
exec-on-ssh-out — a lateral-movement / persistence hook that
fires whenever root (or a service) initiates ssh.
`sshd-config-watchdog` covers the SERVER side; this watches the
outbound CLIENT side that those modules miss.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any client-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No ssh client config | `ok` | `no_ssh_client_config` |
| No delta | `ok` | `ssh_client_config_intact` |
| A file / directive added, removed, or changed | `warn` | `ssh_client_config_changed` |
| An exec directive whose target is under /tmp /home /dev/shm, world-writable, or bare/relative; a fetch-pipe-shell payload; or a world-writable/non-root config | `alert` | `ssh_client_config_exec_directive` |

## What's recorded

- `file:<path>:<sha12>` — hash of each client config file.
- `own:<path>:<owner:mode>` — owner + mode.
- `exec:<path>:<directive>:<prog>` — the program of each
  `ProxyCommand` / `LocalCommand` / `Match exec` directive (first
  token).

A `ProxyCommand` to a normal bastion (`ssh bastion -W %h:%p`) is
benign; one pointing at a tmp/writable target or carrying a
shell-injection payload is the signature.

## Cadence

`OnBootSec=29min` + `OnCalendar=*-*-* 08:30:00` — extends the
staggered ladder after xinetd (08:25). An exec directive fires on
the next outbound ssh, so the boot catch confirms the config
after a restart.

## MITRE coverage

- **T1059.004** Command and Scripting Interpreter: Unix Shell —
  ProxyCommand/LocalCommand/Match-exec are shell execution.
- **T1552.004** Unsecured Credentials: Private Keys (adjacent) —
  a malicious ProxyCommand can siphon the session / credentials
  during connect.
- **T1556**-adjacent — tampering the client to MITM the operator's
  outbound ssh.

## Operator workflow

```bash
journalctl -t selfdef-ssh-client-config -n 1 --no-pager
journalctl -t selfdef-ssh-client-config-detail --since "1 day ago"

# Inventory
grep -rniE 'ProxyCommand|LocalCommand|PermitLocalCommand|Match.*exec' \
     /etc/ssh/ssh_config /etc/ssh/ssh_config.d/ /root/.ssh/config 2>/dev/null

# Investigate an exec_directive alert
# - Is the ProxyCommand/LocalCommand target under /tmp or writable?
sudo $EDITOR <file>        # remove the rogue directive
sudo rm /var/lib/selfdef/ssh-client-config-baseline.tsv
sudo systemctl start selfdef-ssh-client-config.service
```

## Caveats

- **Legit ProxyCommand/ProxyJump bastions** are common and
  benign; the alert tier fires only on a suspicious target
  (tmp/writable/bare) or a payload pattern, not on a normal
  ProxyCommand. Other changes are `warn` (review).
- **Per-user `~/.ssh/config`** beyond `/root` is out of scope
  here (root is the high-value target); extend via
  `SELFDEF_SSHCLIENT_ROOT` for a specific account.
- **Daily+boot cadence** misses an inject-connect-revert within
  the window; an audit-rules watch on `/etc/ssh/ssh_config*` +
  `~/.ssh/config` writes is the real-time complement.

## Coexistence

- **sshd-config-watchdog**: the SERVER config (inbound); this is
  the CLIENT config (outbound). Together they cover both ends of
  ssh.
- **ssh-authkeys-watchdog**: authorized_keys (who may come IN);
  this watches what runs when you go OUT.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the config files; this adds the exec-directive + ownership
  semantic view.
