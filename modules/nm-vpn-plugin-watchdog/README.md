# nm-vpn-plugin-watchdog

Boot + daily delta of the NetworkManager VPN plugin descriptors
against a learned baseline, plus an ownership + plugin-path scan.
Catches a descriptor that loads attacker code into the root
NetworkManager process. MITRE **T1574**.

## Why this matters

NetworkManager runs **as root** and loads the service plugin `.so` /
helper named in each `/etc/NetworkManager/VPN/*.name` descriptor when
a VPN of that service type is used:

```
[VPN Connection]
name=openvpn
service=org.freedesktop.NetworkManager.openvpn
program=/usr/lib/NetworkManager/nm-openvpn-service

[libnm]
plugin=/usr/lib/x86_64-linux-gnu/NetworkManager/libnm-vpn-plugin-openvpn.so
```

- `plugin=` (in `[libnm]`) is the `.so` loaded **into the root
  NetworkManager process**.
- `program=` is the service helper binary run as root.

A planted `.name` with `plugin=/tmp/evil.so` (or a writable
`program=`) loads attacker code into root NM. This is distinct from
**network-dispatcher-watchdog** (dispatcher.d event scripts) and the
**dhclient/dhcpcd hook** watchdogs; this is the NM VPN
service-plugin-load surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any NM VPN plugin change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No NM VPN descriptors present | `ok` | `no_nm_vpn` |
| No delta | `ok` | `nm_vpn_intact` |
| A descriptor / key added / changed / removed | `warn` | `nm_vpn_changed` |
| A `.name` world-writable/non-root, OR a `plugin`/`program` path under `/tmp` `/var/tmp` `/dev/shm` `/home` or relative-with-slash | `alert` | `nm_vpn_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.name`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `plugin:<path>:<so>` — the `[libnm] plugin=` shared object.
- `program:<path>:<bin>` — the service helper binary.

## Cadence

`OnBootSec=75min` + `OnCalendar=*-*-* 12:30:00` — extends the
staggered ladder after krb5-plugins (12:25). A planted descriptor
takes effect the next time NetworkManager loads its VPN plugins, so
the daily catch bounds dwell time; the boot catch confirms the
descriptor set after a restart.

## MITRE coverage

- **T1574** Hijack Execution Flow — a writable `plugin`/`program`
  path loads attacker code into root NetworkManager.
- **T1543** Create or Modify System Process — NM is a long-running
  root daemon; the plugin runs within it.

## Operator workflow

```bash
journalctl -t selfdef-nm-vpn-plugin -n 1 --no-pager
journalctl -t selfdef-nm-vpn-plugin-detail --since "1 day ago"

# Inventory
grep -inE '^\s*(plugin|program|service)\s*=' /etc/NetworkManager/VPN/*.name 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/NetworkManager/VPN/<name>.name
sudo rm /var/lib/selfdef/nm-vpn-plugin-baseline.tsv
sudo systemctl start selfdef-nm-vpn-plugin.service
```

## Caveats

- **Distro VPN plugin packages ship legitimate `.name` files**
  (openvpn, openconnect, wireguard, vpnc, strongswan) with standard
  absolute `/usr/lib` plugin/program paths; these are not flagged. A
  new descriptor still fires `warn` (re-baseline). The
  writable/relative-path / writable / non-root tiers are the
  high-confidence alert.
- **`/usr/lib/NetworkManager/VPN` is not watched** — it is
  package-managed (integrity-sentinel / aide-bridge territory); this
  module watches the admin-droppable `/etc/NetworkManager/VPN`.
- **`[GNOME] properties=`/`auth-dialog=`** GUI `.so` (loaded into the
  user's connection editor, not root NM) are not alerted here — the
  root-loaded `plugin`/`program` are the high-value keys.
- **Daily+boot cadence** misses a drop-connect-revert inside the
  window; an audit-rules watch on `/etc/NetworkManager/VPN` writes is
  the real-time complement.

## Coexistence

- **network-dispatcher-watchdog / dhclient-hooks / dhcpcd-hooks**:
  network-event exec surfaces; this is the NM VPN plugin-load
  surface.
- **wireguard-config-watchdog / openvpn-config-watchdog**: the VPN
  *config* (PostUp / up scripts); this is the NM *plugin descriptor*
  that loads the VPN backend into root NM.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  `.name` files; this adds the plugin/program-path semantic view.
