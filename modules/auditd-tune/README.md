# auditd-tune

Tunes the `auditd` userspace daemon for the audit-rules workload.
Replaces `/etc/audit/auditd.conf` (auditd doesn't honor a conf.d
pattern) and bumps `kernel.audit_backlog_limit` via `auditctl -b`.

**Why this is critical**: without proper buffer + flush sizing,
the kernel audit subsystem DROPS records under load — a silent
visibility gap that breaks every other selfdef detection module
relying on the auditd collector. Selfdef ships `audit-rules` with
extensive watch directives; without `auditd-tune` you risk
"audit-rules detects something, kernel drops the record, selfdef
never sees it."

## Profiles

| Profile | Event-rate target | Buffer | Log retention | Disk-full action |
|---|---|---|---|---|
| `standard` (default) | ~10-50 events/sec (audit-rules `base`) | backlog_limit=8192 | 100MB × 10 = 1GB | SUSPEND |
| `high-volume` | ~500-5000 events/sec (audit-rules `paranoid`) | backlog_limit=65536 | 500MB × 20 = 10GB | SUSPEND |

Both profiles:
- Disable remote audit forwarding (`tcp_listen_port` empty).
- `log_format=ENRICHED` (auditd writes pid/uid/comm enrichment
  selfdef-collector-auditd's parser depends on).
- `flush=INCREMENTAL_ASYNC` (batched fsync; the operator-readable
  trade-off between durability + throughput).
- `disp_qos=lossy` (when the dispatcher backpressures, the kernel
  side stays unblocked — important under sustained load).
- `disk_full_action=SUSPEND` (stop logging; don't HALT the host).
  Operators on high-assurance hosts can flip to HALT via a
  /etc/selfdef/audit/operator-overrides.conf (future).

## Operator-original backup

On first apply, `/etc/audit/auditd.conf` is backed up to
`/etc/audit/auditd.conf.selfdef-backup` (mode 0640). Uninstall
restores from this backup IF the current file is selfdef-managed
(header marker check).

## Kernel backlog limit

`kernel.audit_backlog_limit` is the kernel-side queue size for
audit records BEFORE auditd reads them. Default 1024 — far too
small for selfdef's workload. We bump it via `auditctl -b <N>`:

| Profile | backlog_limit | Memory cost |
|---|---|---|
| standard | 8192 (8x default) | ~16 MiB kernel memory |
| high-volume | 65536 (64x default) | ~128 MiB kernel memory |

Operator override via `SELFDEF_AUDITD_BACKLOG_LIMIT` env var.

## Lost-record monitoring

`auditctl -s` reports a `lost` counter — number of records the
kernel dropped because the backlog filled. The check.sh probe
surfaces this as a log line; selfdef-collector-journald picks it
up + the correlator alerts on `lost > 0`.

When you see lost records, the fix is either:
1. Bump backlog_limit (cheap memory cost)
2. Downgrade audit-rules from paranoid → base (fewer events at
   the kernel side)
3. Investigate whether a runaway process is generating false-
   positive event volume

## Coexistence

- **audit-rules** (depends_on): writes /etc/audit/rules.d/
  drop-ins. auditd-tune replaces /etc/audit/auditd.conf. The
  two files are orthogonal — different paths, different schemas,
  loaded by different parts of the audit subsystem.
- **kernel-lockdown**: doesn't touch audit-related sysctls.
  Compatible.
- **selfdef-collector-auditd**: ingests `/var/log/audit/audit.log`
  which both this module's log_file directive and the OS-default
  point at. Path-compatible.

## Recovery

If audit-rules + auditd-tune apply in the wrong order (audit-rules
applies but auditd refuses to start because operator-modified
auditd.conf was already broken), selfdef's apply.sh runs auditd-
tune AFTER audit-rules (phase=post + depends_on=["audit-rules"]),
which restarts auditd with the selfdef-tuned config. Operator can
also manually:

```bash
sudo systemctl restart auditd
sudo auditctl -s   # verify backlog_limit + lost=0
sudo journalctl -u auditd -n 20  # check for startup errors
```
