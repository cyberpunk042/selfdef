# listening-ports-watchdog

Daily delta of the host's listening TCP/UDP socket set
against a learned baseline. A NEW listening port is one
of the highest-signal indicators of a backdoor, reverse-
shell listener, or unauthorized service — this module
surfaces it.

## Why this matters

After an attacker lands on a host, a very common next
step is to open a listener:
- A bind shell (`nc -lvp 4444 -e /bin/bash`).
- A reverse-shell relay or SOCKS proxy for lateral
  movement.
- An unauthorized service (crypto miner control port,
  data-staging HTTP endpoint).

Every one of these creates a NEW listening socket that
wasn't there in the host's known-good baseline. Diffing
the listen-set daily catches it mechanically, regardless
of how the attacker hid the process.

This complements `suid-sgid-watchdog` (on-disk artifact
delta) with a runtime-network-surface delta.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0; operator-pull via journalctl |
| `enforce` | exit 1 on any ADDED listener → systemd unit failed → notifier engine (removed listeners never alert — that's operator cleanup) |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan (baseline write) | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| 1–2 added listeners | `warn` | `new_listener` |
| 3+ added listeners | `alert` | `mass_new_listeners` |

## Baseline file

`/var/lib/selfdef/listening-ports-baseline.tsv` (mode
0600). Format: `proto<TAB>local_addr:port` per line.

- First scan creates it.
- Not auto-rotated — operator-driven. To accept the
  current listen-set as new baseline:
  ```bash
  sudo rm /var/lib/selfdef/listening-ports-baseline.tsv
  sudo systemctl start selfdef-listening-ports.service
  ```
- Preserved across uninstall (forensic).

## What's recorded

The stable identity is `proto + local_addr:port` — the
ephemeral peer side + PID are deliberately excluded (PIDs
churn across reboots). The owning process IS captured in
the `selfdef-listening-ports-detail` log lines via
`ss -p` where resolvable, for operator drill-down.

## Cadence

`OnBootSec=5min` + `OnUnitActiveSec=6h` + 5min jitter,
`Persistent=true`. Boot catch confirms the listen-set
after every restart; 6h refresh bounds detection latency
for a mid-day backdoor.

## MITRE coverage

- **T1571** Non-Standard Port — a backdoor on an unusual
  port shows up immediately as an added listener.
- **T1571 / T1090** Proxy — SOCKS / relay listeners
  surfaced.
- **T1059** Command and Scripting Interpreter — bind
  shells (nc -e, socat) create the listener this catches.
- **T1205** Traffic Signaling — port-knock daemons /
  backdoor listeners.
- **T1043** (legacy) Commonly Used Port — even a backdoor
  hiding on a common port shows as added IF it wasn't in
  the baseline.

## Operator workflow

```bash
# Last scan summary
journalctl -t selfdef-listening-ports -n 1 --no-pager

# Per-listener detail (with owning process)
journalctl -t selfdef-listening-ports-detail --since "1 day ago"

# Manual current listen-set
ss -tulpn

# Investigate an added listener
sudo ss -tulpn 'sport = :4444'
sudo lsof -i :4444

# Re-baseline (after operator-installed a legit new service)
sudo rm /var/lib/selfdef/listening-ports-baseline.tsv
sudo systemctl start selfdef-listening-ports.service
journalctl -t selfdef-listening-ports -n 1   # expect baseline_initial
```

## Caveats

- **Ephemeral/dynamic listeners**: some apps (rpc, some
  container runtimes) bind random high ports that change
  across restarts → recurring add/remove churn. Operator
  re-baselines after the app is stable, OR scopes the
  app's port range out (future enhancement).
- **Operator-installed services** legitimately add
  listeners → fire `new_listener` once. Operator
  confirms + re-baselines.
- **6h cadence** means a backdoor opened + closed within
  the window between scans may be missed. Pair with
  tetragon (real-time socket-creation eBPF) for
  sub-second detection on critical hosts.
- **ss must be installed** (iproute2). check.sh + the
  scanner require it.

## Coexistence

- **suid-sgid-watchdog**: complementary delta detection —
  on-disk setuid artifacts vs runtime network listeners.
  Same baseline+delta+severity structure.
- **fail2ban-bridge + ssh-hardening**: those defend the
  KNOWN listeners (ssh); this catches the UNKNOWN ones.
- **tetragon**: real-time socket-creation eBPF for
  sub-second backdoor-bind detection; this module is the
  catch-anyway daily backstop.
- **rpcbind-disable + avahi-disable + nscd-disable**:
  those REMOVE known unnecessary listeners (shrinking the
  baseline); this watches for NEW ones appearing.
- **suricata**: network-flow IDS; complementary to the
  host-side listen-set view.
