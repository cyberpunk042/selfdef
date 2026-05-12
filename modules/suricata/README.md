# suricata

Inline IDS via [Suricata](https://suricata.io/), with two attachment
modes selectable per host. Depends on `bridge-l2` for the FORWARD
hook chain; reuses the existing `selfdef-collector-suricata` for
piping `eve.json` into the daemon's event bus.

## Scope of this module

This module owns:

1. **Attachment**: how Suricata sees traffic.
   - In `host-ids` profile: an nftables rule in `bridge-l2`'s
     `forward_hook` chain pushes packets to NFQUEUE; Suricata reads
     them. **Fail-OPEN**: if Suricata is down, packets pass (`bypass`).
   - In `opnsense-bridge` profile: AF_PACKET copy-mode — Suricata
     reads frames off the bridge member NICs directly. **Read-only**:
     forwarding doesn't depend on Suricata being up.
2. **Service state**: `systemctl enable --now suricata`.
3. **Pointer to eve.json**: the path is exposed in
   `/etc/selfdef/modules/suricata.toml` so the daemon's collector
   reads from the same place this module writes to.

This module **does not** own `/etc/suricata/suricata.yaml`. Managing
the whole Suricata config is brittle and distro-specific; the operator
is expected to have a baseline `suricata.yaml` shipped by their
package. See [§ Required suricata.yaml fragments](#required-suricatayaml-fragments)
below for what needs to be there.

## Profiles

| Profile           | Mode           | Failure mode | Use case |
| ----------------- | -------------- | ------------ | -------- |
| `host-ids`        | NFQUEUE        | fail-OPEN (`bypass`) | Single host, you want filtering on the forwarding path. |
| `opnsense-bridge` | AF_PACKET copy | read-only    | OPNsense is the firewall; Suricata is just observing the bridge. |

## Config

```toml
[modules.suricata]
profile          = "host-ids"
queue_num        = 0
eve_json_path    = "/var/log/suricata/eve.json"
enable_collector = true        # wire selfdef-collector-suricata to eve.json
interfaces       = []          # used by opnsense-bridge profile (AF_PACKET)
```

## Required `suricata.yaml` fragments

For **`host-ids`** (NFQUEUE):

```yaml
nfq:
  mode: accept
  fail-open: yes        # match the nftables `bypass` keyword
  batchcount: 20
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
```

For **`opnsense-bridge`** (AF_PACKET copy-mode):

```yaml
af-packet:
  - interface: eno1       # whichever NICs you put in bridge-l2.members
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    use-mmap: yes
    tpacket-v3: yes
  - interface: eno2
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
```

`check.sh` does **not** verify the contents of `suricata.yaml`. If
Suricata fails to start because of a config mismatch, you'll see it
in `journalctl -u suricata`.

## Idempotency & dry-run

Same contract as every module. `SELFDEF_DRY_RUN=1` short-circuits all
state-changing calls. Re-running on a host already at target state is
a no-op (final status line: `"skipped"`).

## Uninstall

`uninstall.sh` removes the nftables NFQUEUE rule (if present) and
stops + disables `suricata.service`. It does **not** purge the
Suricata package, `/etc/suricata/`, or any captured `eve.json` data.

## Caveats

- NFQUEUE mode + heavy traffic: queue overflow drops packets even
  with `bypass`, because by the time the kernel decides to bypass it
  has already enqueued. Tune `queue-bypass` and the queue depth in
  suricata.yaml. (Out of scope for this module's defaults.)
- AF_PACKET copy-mode sees pre-routing frames; it cannot drop. That's
  the trade for the read-only failure mode.
- Suricata 7.x and 6.x have different `eve.json` schemas in a few
  places; the existing `selfdef-collector-suricata` is tested against
  both, but a custom suricata.yaml could shape events differently.
