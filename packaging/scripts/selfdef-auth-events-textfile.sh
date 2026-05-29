#!/bin/bash
# selfdef-auth-events-textfile — emit Prometheus node_exporter
# textfile gauges for host auth-event activity (login attempts,
# sudo invocations, ssh sessions).
#
# Surfaces real IPS-host operator visibility: tracks login auth
# failures + sudo invocations + ssh accept-failures over the last
# rolling window via journalctl. Operators detect brute-force or
# privilege-escalation attempts before they succeed.
#
# Runs every 60s via the companion selfdef-auth-events-textfile.timer.
# Sister to the 6 existing observer wrappers (cli-mirror + m060 +
# four-watchdog + modules + daemon-process + apparmor) — same atomic
# write + honest-offline discipline.
#
# Auth-event observability is a load-bearing IPS surface: a brute-
# force attack against ssh would silently rack up failed-auth
# events that no other alarm fires on. This observer surfaces them
# to Prometheus where the consumer-side alerts page on rate spikes.
#
# Honest-offline: when journalctl is absent OR returns an error,
# emit a sentinel gauge — never silently emit zeroed counts that
# would mask an active attack as "0 auth events".
#
# Environment:
#   SELFDEF_AUTH_EVENTS_TEXTFILE_PATH (default
#     /var/lib/node_exporter/textfile_collector/selfdef-auth-events.prom)
#   SELFDEF_AUTH_EVENTS_WINDOW (default 5m — journalctl --since arg)
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_AUTH_EVENTS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-auth-events.prom}"
WINDOW="${SELFDEF_AUTH_EVENTS_WINDOW:-5m}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_auth_events_textfile_emit_failed Wrapper exited unhealthy (journalctl absent OR errored).\n'
    printf '# TYPE selfdef_auth_events_textfile_emit_failed gauge\n'
    printf 'selfdef_auth_events_textfile_emit_failed 1\n'
    printf '# HELP selfdef_auth_events_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_auth_events_last_run_unix gauge\n'
    printf 'selfdef_auth_events_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — journalctl available.
if ! command -v journalctl >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

# Tally auth events in the rolling window. journalctl --since takes
# expressions like "5m ago". Capture stderr so a missing journal
# (transient namespace) emits the sentinel rather than crashing the
# wrapper.
if ! journal_body="$(journalctl --since "$WINDOW ago" --no-pager --output=cat \
                                 --facility=auth,authpriv 2>/dev/null)"; then
  emit_failure_sentinel
  exit 2
fi

# Tally counts by pattern. The wrapper looks for the standard
# pam_unix / sshd / sudo log signatures. Counts are intentionally
# generous-pattern (favor false positives over missing real events).
login_failures="$(echo "$journal_body" \
  | grep -cE 'authentication failure|FAILED LOGIN|Failed password' \
  || true)"
login_successes="$(echo "$journal_body" \
  | grep -cE 'session opened|Accepted password|Accepted publickey' \
  || true)"
sudo_invocations="$(echo "$journal_body" \
  | grep -cE 'sudo:[ ]+\S+ : ' \
  || true)"
ssh_invalid_users="$(echo "$journal_body" \
  | grep -cE 'Invalid user' \
  || true)"
ssh_refused_keys="$(echo "$journal_body" \
  | grep -cE 'no matching key exchange|key_lookup_failed' \
  || true)"
total_events="$(echo "$journal_body" | grep -c '' || echo 0)"

# Build textfile in temp + atomic rename.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_auth_events_login_failures Count of authentication failures in the rolling window.\n'
  printf '# TYPE selfdef_auth_events_login_failures gauge\n'
  printf 'selfdef_auth_events_login_failures{window="%s"} %d\n' "$WINDOW" "$login_failures"

  printf '# HELP selfdef_auth_events_login_successes Count of successful logins in the rolling window.\n'
  printf '# TYPE selfdef_auth_events_login_successes gauge\n'
  printf 'selfdef_auth_events_login_successes{window="%s"} %d\n' "$WINDOW" "$login_successes"

  printf '# HELP selfdef_auth_events_sudo_invocations Count of sudo invocations in the rolling window.\n'
  printf '# TYPE selfdef_auth_events_sudo_invocations gauge\n'
  printf 'selfdef_auth_events_sudo_invocations{window="%s"} %d\n' "$WINDOW" "$sudo_invocations"

  printf '# HELP selfdef_auth_events_ssh_invalid_users Count of ssh invalid-user attempts in the rolling window.\n'
  printf '# TYPE selfdef_auth_events_ssh_invalid_users gauge\n'
  printf 'selfdef_auth_events_ssh_invalid_users{window="%s"} %d\n' "$WINDOW" "$ssh_invalid_users"

  printf '# HELP selfdef_auth_events_ssh_refused_keys Count of ssh key-exchange refusals in the rolling window.\n'
  printf '# TYPE selfdef_auth_events_ssh_refused_keys gauge\n'
  printf 'selfdef_auth_events_ssh_refused_keys{window="%s"} %d\n' "$WINDOW" "$ssh_refused_keys"

  printf '# HELP selfdef_auth_events_total Total auth-facility log events in the rolling window.\n'
  printf '# TYPE selfdef_auth_events_total gauge\n'
  printf 'selfdef_auth_events_total{window="%s"} %d\n' "$WINDOW" "$total_events"

  printf '# HELP selfdef_auth_events_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_auth_events_last_run_unix gauge\n'
  printf 'selfdef_auth_events_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_auth_events_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_auth_events_textfile_emit_failed gauge\n'
  printf 'selfdef_auth_events_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
