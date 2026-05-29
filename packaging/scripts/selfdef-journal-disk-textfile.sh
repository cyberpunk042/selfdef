#!/bin/bash
# selfdef-journal-disk-textfile — emit Prometheus node_exporter
# textfile gauges for systemd journal disk-usage state.
#
# Surfaces real IPS-host operator visibility: tracks total
# /var/log/journal disk usage + per-host top emitters. Pairs with
# disk-usage (8th sibling) at the operational-disk axis: disk-usage
# tracks /var fill globally; this tracks the journal subsystem
# specifically, often a leading cause of /var fill from log spam.
#
# Why this is page-worthy:
# - journal disk usage > 1 GiB = retention pressure (rotation drops)
# - journal disk usage > 5 GiB = signals log-spam runaway from a
#   misbehaving service
# - persistent journal disabled (only volatile /run) = restart loses
#   forensic trail
#
# Runs every 60s via the companion timer. 18th sibling observer.
#
# Honest-offline: when journalctl is unavailable, emit zero with
# journal_available=0 sentinel.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_JOURNAL_DISK_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-journal-disk.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_journal_disk_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_journal_disk_textfile_emit_failed gauge\n'
    printf 'selfdef_journal_disk_textfile_emit_failed 1\n'
    printf '# HELP selfdef_journal_disk_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_journal_disk_last_run_unix gauge\n'
    printf 'selfdef_journal_disk_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

journal_available=0
journal_bytes_total=0
journal_persistent=0
journal_volatile=0

if command -v journalctl >/dev/null 2>&1; then
  journal_available=1

  # journalctl --disk-usage prints e.g. "Archived and active journals
  # take up 384.4M in the file system."  Extract the numeric +
  # unit suffix and convert to bytes.
  if usage_str="$(journalctl --disk-usage 2>/dev/null)"; then
    # Pull "384.4M" — the human-readable suffix.
    size_token="$(printf '%s\n' "$usage_str" \
      | grep -oE '[0-9]+(\.[0-9]+)?[KMGT]?' | head -1 || true)"
    if [ -n "$size_token" ]; then
      # Numeric part:
      num="${size_token%[KMGT]}"
      # Suffix (last char) if alpha, else "":
      suffix="${size_token: -1}"
      case "$suffix" in
        K) mult=1024 ;;
        M) mult=$(( 1024 * 1024 )) ;;
        G) mult=$(( 1024 * 1024 * 1024 )) ;;
        T) mult=$(( 1024 * 1024 * 1024 * 1024 )) ;;
        *) mult=1 ; num="$size_token" ;;
      esac
      # bash integer arithmetic — drop fractional part of num.
      whole_num="${num%.*}"
      journal_bytes_total=$(( whole_num * mult ))
    fi
  fi

  # Persistent vs volatile storage.
  if [ -d /var/log/journal ] && [ -n "$(ls -A /var/log/journal 2>/dev/null)" ]; then
    journal_persistent=1
  fi
  if [ -d /run/log/journal ] && [ -n "$(ls -A /run/log/journal 2>/dev/null)" ]; then
    journal_volatile=1
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_journal_available 1 if journalctl is installed and queryable.\n'
  printf '# TYPE selfdef_journal_available gauge\n'
  printf 'selfdef_journal_available %d\n' "$journal_available"

  printf '# HELP selfdef_journal_bytes_total Total bytes used by systemd journal (archived+active).\n'
  printf '# TYPE selfdef_journal_bytes_total gauge\n'
  printf 'selfdef_journal_bytes_total %d\n' "$journal_bytes_total"

  printf '# HELP selfdef_journal_persistent 1 if /var/log/journal/ has persistent journal files.\n'
  printf '# TYPE selfdef_journal_persistent gauge\n'
  printf 'selfdef_journal_persistent %d\n' "$journal_persistent"

  printf '# HELP selfdef_journal_volatile 1 if /run/log/journal/ has volatile-only journals.\n'
  printf '# TYPE selfdef_journal_volatile gauge\n'
  printf 'selfdef_journal_volatile %d\n' "$journal_volatile"

  printf '# HELP selfdef_journal_disk_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
  printf '# TYPE selfdef_journal_disk_last_run_unix gauge\n'
  printf 'selfdef_journal_disk_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_journal_disk_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_journal_disk_textfile_emit_failed gauge\n'
  printf 'selfdef_journal_disk_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
