#!/bin/bash
# selfdef-cron-textfile — emit Prometheus node_exporter textfile
# gauges for cron + systemd-timer persistence catalogs.
#
# Surfaces real IPS-host operator visibility: tracks the complete
# set of scheduled persistence vectors that an attacker could use
# to maintain access — cron entries (/etc/cron.*, /var/spool/cron/*)
# + systemd timers. Pairs with kernel-modules (12th sibling) at the
# rootkit-detection axis: kernel-modules catches in-kernel rootkits,
# this catches userspace persistence (cron-based reverse shells,
# scheduled backdoors, malicious timers).
#
# Why this is page-worthy:
# - per-user cron entry count drift = attacker dropped a crontab
# - /etc/cron.d/ file count drift = root-level scheduled entry
# - systemd timer count drift = malicious .timer + .service pair
#
# Runs every 60s via the companion timer. 15th sibling observer.
#
# Honest-offline: when /etc/cron.* + /var/spool/cron + systemctl
# are inaccessible, emit sentinel.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_CRON_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-cron.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_cron_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_cron_textfile_emit_failed gauge\n'
    printf 'selfdef_cron_textfile_emit_failed 1\n'
    printf '# HELP selfdef_cron_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_cron_last_run_unix gauge\n'
    printf 'selfdef_cron_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# /etc/cron.d/ — root-level scheduled entries (highest IPS risk).
cron_d_files=0
if [ -d /etc/cron.d ]; then
  cron_d_files="$(find /etc/cron.d -maxdepth 1 -type f 2>/dev/null | wc -l)"
fi

# /etc/cron.{hourly,daily,weekly,monthly} — periodic root cron.
cron_periodic_files=0
for sub in hourly daily weekly monthly; do
  if [ -d "/etc/cron.$sub" ]; then
    n="$(find "/etc/cron.$sub" -maxdepth 1 -type f 2>/dev/null | wc -l)"
    cron_periodic_files=$(( cron_periodic_files + n ))
  fi
done

# /var/spool/cron/{crontabs,}/* — per-user crontabs.
user_crontabs=0
for d in /var/spool/cron/crontabs /var/spool/cron; do
  if [ -d "$d" ]; then
    n="$(find "$d" -maxdepth 1 -type f 2>/dev/null | wc -l)"
    user_crontabs=$(( user_crontabs + n ))
  fi
done

# Total cron entry lines (counting actionable rules, not comments).
cron_total_entries=0
for path in /etc/cron.d/* /etc/crontab /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$path" ] || continue
  n="$(grep -cE '^[^#[:space:]]' "$path" 2>/dev/null || echo 0)"
  cron_total_entries=$(( cron_total_entries + n ))
done

# Systemd timers — modern persistence vector.
systemd_timers_total=0
if command -v systemctl >/dev/null 2>&1; then
  # --no-legend strips column-headers; we count rows.
  systemd_timers_total="$(systemctl list-timers --all --no-legend --no-pager 2>/dev/null \
    | grep -cE '\.timer$|\.timer ' || true)"
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_cron_d_files Count of files in /etc/cron.d/ (root-level scheduled entries).\n'
  printf '# TYPE selfdef_cron_d_files gauge\n'
  printf 'selfdef_cron_d_files %d\n' "$cron_d_files"

  printf '# HELP selfdef_cron_periodic_files Count of files in /etc/cron.{hourly,daily,weekly,monthly}.\n'
  printf '# TYPE selfdef_cron_periodic_files gauge\n'
  printf 'selfdef_cron_periodic_files %d\n' "$cron_periodic_files"

  printf '# HELP selfdef_cron_user_crontabs Count of per-user crontabs in /var/spool/cron/.\n'
  printf '# TYPE selfdef_cron_user_crontabs gauge\n'
  printf 'selfdef_cron_user_crontabs %d\n' "$user_crontabs"

  printf '# HELP selfdef_cron_total_entries Total actionable cron entry lines across all surfaces.\n'
  printf '# TYPE selfdef_cron_total_entries gauge\n'
  printf 'selfdef_cron_total_entries %d\n' "$cron_total_entries"

  printf '# HELP selfdef_systemd_timers_total Count of systemd .timer units (active or inactive).\n'
  printf '# TYPE selfdef_systemd_timers_total gauge\n'
  printf 'selfdef_systemd_timers_total %d\n' "$systemd_timers_total"

  printf '# HELP selfdef_cron_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
  printf '# TYPE selfdef_cron_last_run_unix gauge\n'
  printf 'selfdef_cron_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_cron_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_cron_textfile_emit_failed gauge\n'
  printf 'selfdef_cron_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
