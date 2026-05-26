# wireguard-config-watchdog

Boot + daily delta of the WireGuard configs against a learned
baseline, plus an ownership + hook-command + key-exposure scan.
Catches a root-exec tunnel hook and private-key exposure. MITRE
**T1546** / **T1552.001**.

## Why this matters

`wg-quick up <iface>` runs these directives from each
`/etc/wireguard/*.conf` **as root** when a tunnel is brought up or
down:

- `PostUp = <cmd>` / `PreUp = <cmd>`
- `PostDown = <cmd>` / `PreDown = <cmd>`

A planted hook is **root-exec-on-tunnel-event persistence** — it
fires every time the tunnel comes up (boot, reconnect, `wg-quick
up`). Legit hooks set up routing/firewall (`iptables`, `nft`, `ip`,
`sysctl`); a malicious one runs a payload from `/tmp` or pipes
`curl | sh`.

Separately, each `.conf` holds the interface `[Interface]
PrivateKey`. A **world-readable** `.conf` is private-key exposure —
any local user can read the key and impersonate the tunnel. This
module flags both concerns over the same file set.

This is distinct from **vpn-bridge** (the functional multi-instance
VPN module); this is the detection watchdog over the on-disk
configs.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any WireGuard config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No WireGuard configs present | `ok` | `no_wireguard` |
| No delta | `ok` | `wireguard_intact` |
| A config / hook added / changed / removed | `warn` | `wireguard_changed` |
| A `.conf` world-writable/non-root, world-readable with a PrivateKey, OR a hook command under `/tmp` `/var/tmp` `/dev/shm` `/home` or with an injection pattern | `alert` | `wireguard_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.conf`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `hook:<path>:<directive>:<cmd>` — each `PostUp`/`PreUp`/
  `PostDown`/`PreDown` command (parsed case-insensitively).

## Cadence

`OnBootSec=62min` + `OnCalendar=*-*-* 11:15:00` — extends the
staggered ladder after sshrc (11:10). A planted hook fires the next
time the tunnel is brought up, so the daily catch bounds dwell time;
the boot catch confirms the config set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — tunnel up/down is the
  trigger for the hook.
- **T1552.001** Unsecured Credentials: Credentials In Files — a
  world-readable config leaks the interface private key.
- **T1059.004** — the hook is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-wireguard -n 1 --no-pager
journalctl -t selfdef-wireguard-detail --since "1 day ago"

# Inventory hooks + perms
ls -la /etc/wireguard/*.conf 2>/dev/null
grep -inE '^(PostUp|PreUp|PostDown|PreDown)\s*=' /etc/wireguard/*.conf 2>/dev/null

# Fix key exposure + re-baseline after a deliberate edit:
sudo chmod 0600 /etc/wireguard/*.conf
sudo rm /var/lib/selfdef/wireguard-config-baseline.tsv
sudo systemctl start selfdef-wireguard.service
```

## Caveats

- **Legit PostUp/PostDown hooks are common** (firewall/routing
  setup); they do not match the injection/tmp-exec patterns. A new
  hook still fires `warn` (re-baseline). The tmp-exec / injection /
  writable / key-exposure tiers are the high-confidence alert.
- **`wg-quick` parses keys case-insensitively**, so this module
  matches `PostUp`/`postup`/etc. case-insensitively too.
- **`wg setconf` / NetworkManager-managed tunnels** may not use
  `/etc/wireguard/*.conf`; those configs live elsewhere and are out
  of scope here.
- **Daily+boot cadence** misses a drop-up-revert inside the window;
  an audit-rules watch on `/etc/wireguard` writes is the real-time
  complement.

## Coexistence

- **vpn-bridge**: the functional multi-instance VPN module; this is
  the config-integrity watchdog over its on-disk state.
- **network-dispatcher-watchdog / dhclient / dhcpcd hooks**: other
  network-event root-exec surfaces; this is the WireGuard tunnel-up
  hook surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  `.conf` files; this adds the hook-command + key-exposure view.
