#!/bin/bash
# selfdef-listening-sockets-textfile — emit Prometheus node_exporter
# textfile gauges for the host's listening socket surface.
#
# Surfaces real IPS-host operator visibility: tracks per-protocol
# LISTEN socket counts (TCP/TCP6/UDP/UDP6) + total listener count.
# Operators detect unexpected listeners (post-exploitation backdoors,
# accidentally-exposed dev servers, drifted-from-baseline daemons).
#
# Runs every 60s via the companion timer. 9th sibling observer.
# Same atomic write + honest-offline discipline as the 8 siblings
# (cli-mirror + m060 + four-watchdog + modules + daemon-process +
# apparmor + auth-events + systemd-units).
#
# Listening-socket observation is load-bearing IPS surface: a
# post-exploitation backdoor opens a new listener. selfdef cannot
# enforce listener policy without the host's nftables config —
# but it CAN detect drift from the operator's baseline + page on
# unexpected exposure.
#
# Honest-offline: when `ss` is absent OR /proc/net/tcp is
# unreadable, emit sentinel gauge — never silently emit zeroed
# counts that would mask an active listener as "0 sockets".
#
# Environment:
#   SELFDEF_LISTENING_SOCKETS_TEXTFILE_PATH (default
#     /var/lib/node_exporter/textfile_collector/selfdef-listening-sockets.prom)
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_LISTENING_SOCKETS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-listening-sockets.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_listening_sockets_textfile_emit_failed Wrapper exited unhealthy (ss absent OR /proc/net unreadable).\n'
    printf '# TYPE selfdef_listening_sockets_textfile_emit_failed gauge\n'
    printf 'selfdef_listening_sockets_textfile_emit_failed 1\n'
    printf '# HELP selfdef_listening_sockets_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_listening_sockets_last_run_unix gauge\n'
    printf 'selfdef_listening_sockets_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — ss (iproute2) preferred; netstat is a viable
# fallback but ss is the modern default. /proc/net/tcp{,6} +
# /proc/net/udp{,6} are the ultimate fallback.
if ! command -v ss >/dev/null 2>&1; then
  # Fallback path: parse /proc/net/* directly. We require at least
  # /proc/net/tcp readable.
  if ! [ -r /proc/net/tcp ]; then
    emit_failure_sentinel
    exit 2
  fi
fi

# Tally listening sockets per protocol. ss output is `Netid State
# Recv-Q Send-Q LocalAddress:Port PeerAddress:Port`.
if command -v ss >/dev/null 2>&1; then
  # ss -H suppresses header; -l lists listening; -t = TCP; -u = UDP;
  # -4/-6 force address family. Counting per-protocol separately
  # gives us deterministic state for the gauge.
  tcp_count="$(ss -H -ltn4 2>/dev/null | wc -l || echo 0)"
  tcp6_count="$(ss -H -ltn6 2>/dev/null | wc -l || echo 0)"
  udp_count="$(ss -H -lun4 2>/dev/null | wc -l || echo 0)"
  udp6_count="$(ss -H -lun6 2>/dev/null | wc -l || echo 0)"
else
  # Fallback: parse /proc/net/tcp + tcp6 + udp + udp6. State 0A = LISTEN.
  tcp_count="$(awk 'NR>1 && $4=="0A" {n++} END{print n+0}' /proc/net/tcp 2>/dev/null || echo 0)"
  tcp6_count="$(awk 'NR>1 && $4=="0A" {n++} END{print n+0}' /proc/net/tcp6 2>/dev/null || echo 0)"
  # UDP doesn't have a true LISTEN state — count all entries.
  udp_count="$(awk 'NR>1 {n++} END{print n+0}' /proc/net/udp 2>/dev/null || echo 0)"
  udp6_count="$(awk 'NR>1 {n++} END{print n+0}' /proc/net/udp6 2>/dev/null || echo 0)"
fi

total_listeners=$(( tcp_count + tcp6_count + udp_count + udp6_count ))

# Build textfile in temp + atomic rename.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_listening_sockets_tcp Count of TCP IPv4 LISTEN sockets.\n'
  printf '# TYPE selfdef_listening_sockets_tcp gauge\n'
  printf 'selfdef_listening_sockets_tcp %d\n' "$tcp_count"

  printf '# HELP selfdef_listening_sockets_tcp6 Count of TCP IPv6 LISTEN sockets.\n'
  printf '# TYPE selfdef_listening_sockets_tcp6 gauge\n'
  printf 'selfdef_listening_sockets_tcp6 %d\n' "$tcp6_count"

  printf '# HELP selfdef_listening_sockets_udp Count of UDP IPv4 sockets (no true LISTEN state).\n'
  printf '# TYPE selfdef_listening_sockets_udp gauge\n'
  printf 'selfdef_listening_sockets_udp %d\n' "$udp_count"

  printf '# HELP selfdef_listening_sockets_udp6 Count of UDP IPv6 sockets.\n'
  printf '# TYPE selfdef_listening_sockets_udp6 gauge\n'
  printf 'selfdef_listening_sockets_udp6 %d\n' "$udp6_count"

  printf '# HELP selfdef_listening_sockets_total Total listener count across all protocols.\n'
  printf '# TYPE selfdef_listening_sockets_total gauge\n'
  printf 'selfdef_listening_sockets_total %d\n' "$total_listeners"

  printf '# HELP selfdef_listening_sockets_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_listening_sockets_last_run_unix gauge\n'
  printf 'selfdef_listening_sockets_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_listening_sockets_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_listening_sockets_textfile_emit_failed gauge\n'
  printf 'selfdef_listening_sockets_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
