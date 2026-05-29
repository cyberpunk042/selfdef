#!/bin/bash
# selfdef-fail2ban-textfile — emit Prometheus node_exporter
# textfile gauges for fail2ban defensive-response state.
#
# Surfaces real IPS-host operator visibility: tracks fail2ban-server
# alive-state, active-jail count, per-jail current/total ban counters.
# Auth-events (11th sibling) counts failed login attempts; this
# (13th sibling) counts the DEFENSIVE RESPONSE — bans actually
# applied by fail2ban. Together they form a complete IPS pair:
# attack-detected (auth-events) + attack-mitigated (fail2ban).
#
# Runs every 60s via the companion timer. 13th sibling observer.
#
# Honest-offline: when fail2ban-client is uninstalled or the daemon
# is down, emit fail2ban_server_alive=0 + sentinel.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_FAIL2BAN_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-fail2ban.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_fail2ban_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_fail2ban_textfile_emit_failed gauge\n'
    printf 'selfdef_fail2ban_textfile_emit_failed 1\n'
    printf '# HELP selfdef_fail2ban_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_fail2ban_last_run_unix gauge\n'
    printf 'selfdef_fail2ban_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — fail2ban-client must exist (honest-offline if not).
if ! command -v fail2ban-client >/dev/null 2>&1; then
  tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_fail2ban_server_alive 1 if fail2ban-server responds to ping (-1 if fail2ban-client missing).\n'
    printf '# TYPE selfdef_fail2ban_server_alive gauge\n'
    printf 'selfdef_fail2ban_server_alive -1\n'
    printf '# HELP selfdef_fail2ban_jails_active Count of active fail2ban jails.\n'
    printf '# TYPE selfdef_fail2ban_jails_active gauge\n'
    printf 'selfdef_fail2ban_jails_active 0\n'
    printf '# HELP selfdef_fail2ban_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_fail2ban_last_run_unix gauge\n'
    printf 'selfdef_fail2ban_last_run_unix %d\n' "$(date +%s)"
    printf '# HELP selfdef_fail2ban_textfile_emit_failed Wrapper exited unhealthy (0 = honest-offline emission).\n'
    printf '# TYPE selfdef_fail2ban_textfile_emit_failed gauge\n'
    printf 'selfdef_fail2ban_textfile_emit_failed 0\n'
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
  trap - ERR
  exit 0
fi

# fail2ban-server ping — daemon alive.
server_alive=0
if fail2ban-client ping >/dev/null 2>&1; then
  server_alive=1
fi

# Collect jail list (CSV) — empty when server down.
jails_csv=""
jails_active=0
if [ "$server_alive" -eq 1 ]; then
  jails_csv="$(fail2ban-client status 2>/dev/null \
    | awk -F: '/Jail list/ {gsub(/[ \t]/, "", $2); print $2}')"
  if [ -n "$jails_csv" ]; then
    jails_active="$(echo "$jails_csv" | tr ',' '\n' | grep -c .)"
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_fail2ban_server_alive 1 if fail2ban-server responds to ping (0 = down, -1 = client missing).\n'
  printf '# TYPE selfdef_fail2ban_server_alive gauge\n'
  printf 'selfdef_fail2ban_server_alive %d\n' "$server_alive"

  printf '# HELP selfdef_fail2ban_jails_active Count of active fail2ban jails.\n'
  printf '# TYPE selfdef_fail2ban_jails_active gauge\n'
  printf 'selfdef_fail2ban_jails_active %d\n' "$jails_active"

  # Per-jail counters (current bans + total bans since fail2ban-server start).
  total_bans_sum=0
  current_bans_sum=0
  if [ -n "$jails_csv" ]; then
    printf '# HELP selfdef_fail2ban_jail_current_bans Currently-banned IP count for this jail.\n'
    printf '# TYPE selfdef_fail2ban_jail_current_bans gauge\n'
    printf '# HELP selfdef_fail2ban_jail_total_bans Total IPs banned since fail2ban-server start.\n'
    printf '# TYPE selfdef_fail2ban_jail_total_bans gauge\n'
    IFS=','
    for jail in $jails_csv; do
      [ -z "$jail" ] && continue
      status="$(fail2ban-client status "$jail" 2>/dev/null || true)"
      current="$(echo "$status" \
        | awk -F: '/Currently banned/ {gsub(/[ \t]/, "", $2); print $2; exit}')"
      total="$(echo "$status" \
        | awk -F: '/Total banned/ {gsub(/[ \t]/, "", $2); print $2; exit}')"
      current="${current:-0}"
      total="${total:-0}"
      printf 'selfdef_fail2ban_jail_current_bans{jail="%s"} %d\n' "$jail" "$current"
      printf 'selfdef_fail2ban_jail_total_bans{jail="%s"} %d\n' "$jail" "$total"
      current_bans_sum=$(( current_bans_sum + current ))
      total_bans_sum=$(( total_bans_sum + total ))
    done
    unset IFS
  fi

  printf '# HELP selfdef_fail2ban_current_bans_sum Sum of currently-banned IPs across all jails.\n'
  printf '# TYPE selfdef_fail2ban_current_bans_sum gauge\n'
  printf 'selfdef_fail2ban_current_bans_sum %d\n' "$current_bans_sum"

  printf '# HELP selfdef_fail2ban_total_bans_sum Sum of total-ever-banned IPs across all jails (since server start).\n'
  printf '# TYPE selfdef_fail2ban_total_bans_sum gauge\n'
  printf 'selfdef_fail2ban_total_bans_sum %d\n' "$total_bans_sum"

  printf '# HELP selfdef_fail2ban_last_run_unix Wall-clock seconds of last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_fail2ban_last_run_unix gauge\n'
  printf 'selfdef_fail2ban_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_fail2ban_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_fail2ban_textfile_emit_failed gauge\n'
  printf 'selfdef_fail2ban_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
