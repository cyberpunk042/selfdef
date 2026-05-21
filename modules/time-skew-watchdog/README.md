# time-skew-watchdog

systemd-timer-driven clock-drift detection sidecar for the
`chrony-baseline` module. Probes `chronyc tracking` every 5
minutes (with 30s jitter) + emits a structured JSON event tagged
`selfdef-time-skew` to the journal. Pairs with chrony-baseline:
chrony-baseline keeps the clock right; this watchdog detects when
chrony itself reports drift or loses time-source confidence.

## Why this matters

T1070.006 Timestomp + T1565.001 Stored Data Manipulation depend
on the operator's clock being trustworthy. A subtle attack vector
is to compromise chrony's upstream (or DNS-spoof the pool) so
chronyd quietly drifts. chrony-baseline blocks the >1h step
attack via `maxchange`; the watchdog catches sub-step drift the
correlator can investigate.

## Event severity ladder

| Severity | Condition |
|---|---|
| `ok` | last_offset_ms ≤ 100 AND rms_offset_ms ≤ 50 AND root_dispersion_s ≤ 1.0 |
| `warn` | 100 < last_offset_ms ≤ 500 |
| `alert` | last_offset_ms > 500 OR root_dispersion_s > 1.0 |
| `high` | `chronyc tracking` itself failed (daemon down / unreachable) |

Thresholds are operator-tunable via env vars in the systemd
service drop-in:
- `SELFDEF_TIME_OFFSET_WARN_MS` (default 100)
- `SELFDEF_TIME_OFFSET_ALERT_MS` (default 500)
- `SELFDEF_TIME_DISPERSION_ALERT_S` (default 1.0)

## Event schema

Every probe emits ONE syslog/journald line tagged
`selfdef-time-skew` with a JSON payload:

```json
{
  "tag": "selfdef-time-skew",
  "severity": "ok",
  "event": "tracking_ok",
  "ref_id": "<chrony reference ID>",
  "stratum": "<stratum number>",
  "last_offset_ms": 12.345,
  "rms_offset_ms": 8.910,
  "root_dispersion_s": 0.123
}
```

selfdef-collector-journald ingests these. The selfdef-correlator
matches on `tag=selfdef-time-skew` + `severity in (warn, alert,
high)` to dispatch to the notifier surfaces.

## Service hardening

The service unit applies defense-in-depth (the probe is a small
bash one-shot but locked down anyway):
- `NoNewPrivileges=true`
- `ProtectSystem=strict` + `ProtectHome=true`
- `PrivateTmp=true` + `PrivateDevices=true`
- `RestrictAddressFamilies=AF_UNIX` (chrony control via socket)
- `SystemCallFilter=@system-service`
- `ReadOnlyPaths=/var/run/chrony` (read chrony's control sock only)
- `ReadWritePaths=/dev/log` (logger writes to /dev/log)

## Failure semantics

- `severity=alert` → script exits 1 → `systemctl status
  selfdef-time-skew-watchdog.service` shows a `failed` state
  the operator can `journalctl -u` for the JSON detail.
- `severity=warn` → script exits 0 (journal-only signal)
- `severity=ok` → script exits 0 silently

The timer is `Persistent=true` so missed runs (host was asleep)
catch up on resume.

## Coexistence

The probe queries chronyc read-only via `/var/run/chrony/chronyd.sock`.
It does NOT modify chrony's state. Multiple instances of the
watchdog timer on the same host are safe.

## Why systemd timer + bash, not a Rust crate?

A 60-line bash script + systemd unit is the minimum-viable shape
for a 5-minute-cadence probe. A future Rust rewrite gains:
- pyo3-style bus event emission (vs logger(1) + journald-collector
  hop)
- richer error classification
- shared crate with selfdef-friction-audit's tracking model

The bash version ships TODAY end-to-end; the Rust rewrite is a
future SDD when the operator gates the work.
