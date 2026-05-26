# openvpn-config-watchdog

Boot + daily delta of the OpenVPN configs against a learned
baseline, plus an ownership + script-directive + key-exposure scan.
Catches a root-exec VPN-event script and private-key exposure.
MITRE **T1546** / **T1552.001**.

## Why this matters

OpenVPN runs the command of these directives **as root** (gated by
`script-security`) on connect / route / auth events, in each
`/etc/openvpn/**/*.conf` or `*.ovpn`:

- `up`, `down`, `route-up`, `route-pre-down`, `ipchange`
- `client-connect`, `client-disconnect`, `learn-address`
- `tls-verify`, `auth-user-pass-verify`

A planted script directive is **root-exec-on-VPN-event
persistence** — it fires whenever the tunnel connects, a route
changes, or a client authenticates. (`script-security 3` further
exposes credentials to the script via the environment.)

Separately, `.conf`/`.ovpn` files often carry **inline `<key>` /
`<tls-crypt>` / `<tls-auth>` material** or a `secret <file>` static
key. A **world-readable** config is private-key exposure.

This is the OpenVPN sibling of **wireguard-config-watchdog**
(different VPN, different config format), and distinct from
**vpn-bridge** (the functional module) — this is the detection
watchdog over the on-disk configs.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any OpenVPN config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No OpenVPN configs present | `ok` | `no_openvpn` |
| No delta | `ok` | `openvpn_intact` |
| A config / script directive added / changed / removed | `warn` | `openvpn_changed` |
| A config world-writable/non-root, world-readable with inline key material, OR a script command under `/tmp` `/var/tmp` `/dev/shm` `/home` or with an injection pattern | `alert` | `openvpn_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each config.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `scr:<path>:<directive>:<cmd>` — each script directive command
  (parsed case-insensitively).

## Cadence

`OnBootSec=63min` + `OnCalendar=*-*-* 11:20:00` — extends the
staggered ladder after wireguard (11:15). A planted directive fires
the next time the tunnel/client connects, so the daily catch bounds
dwell time; the boot catch confirms the config set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — connect/route/auth events
  trigger the script.
- **T1552.001** Unsecured Credentials: Credentials In Files — a
  world-readable config leaks inline key material.
- **T1059.004** — the directive command is shell execution run as
  root.

## Operator workflow

```bash
journalctl -t selfdef-openvpn -n 1 --no-pager
journalctl -t selfdef-openvpn-detail --since "1 day ago"

# Inventory script directives + perms + secrecy
ls -la /etc/openvpn/ /etc/openvpn/client/ /etc/openvpn/server/ 2>/dev/null
grep -rinE '^(up|down|route-up|client-connect|client-disconnect|learn-address|tls-verify|auth-user-pass-verify)\s' \
     /etc/openvpn/ 2>/dev/null

# Fix key exposure + re-baseline after a deliberate edit:
sudo chmod 0600 /etc/openvpn/**/*.conf
sudo rm /var/lib/selfdef/openvpn-config-baseline.tsv
sudo systemctl start selfdef-openvpn.service
```

## Caveats

- **Legit `up`/`down` scripts are common** (`update-resolv-conf`,
  `update-systemd-resolved`); they live under `/etc/openvpn` and do
  not match the injection/tmp-exec patterns. A new directive still
  fires `warn` (re-baseline). The tmp-exec / injection / writable /
  key-exposure tiers are the high-confidence alert.
- **`script-security` level is not itself alerted** — `2` is
  required for any of these scripts to run at all; `3` (env-passed
  creds) is riskier but sometimes legitimate. Review it in context.
- **NetworkManager-managed OpenVPN** stores config under
  `/etc/NetworkManager/system-connections` (a different surface) and
  is out of scope here.
- **Daily+boot cadence** misses a drop-connect-revert inside the
  window; an audit-rules watch on `/etc/openvpn` writes is the
  real-time complement.

## Coexistence

- **wireguard-config-watchdog**: the WireGuard sibling; together
  they cover both major VPNs' on-disk hook + key surfaces.
- **vpn-bridge**: the functional multi-instance VPN module; this is
  the config-integrity watchdog over its state.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  configs; this adds the script-directive + key-exposure view.
