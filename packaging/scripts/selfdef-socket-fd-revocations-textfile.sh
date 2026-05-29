#!/bin/bash
# selfdef-socket-fd-revocations-textfile — emit Prometheus
# node_exporter textfile gauges for the SDD-073 socket-fd
# revocation state.
#
# 27th sibling (OnBootSec=810s). Extends the IPS-octet
# observability set to the nonet at the per-connection
# severance axis:
#   19th — blockset                (SDD-065 network perimeter)
#   20th — quarantine              (SDD-066 process single-pid)
#   21st — revocations             (SDD-067 shell-session)
#   22nd — token-revocations       (SDD-068 API/web token)
#   23rd — mfa-grant-revocations   (SDD-069 MFA grant)
#   24th — netns-isolations        (SDD-070 kernel-containment)
#   25th — mount-bindings          (SDD-071 filesystem-binding)
#   26th — process-tree-freezes    (SDD-072 process-graph)
#   27th — socket-fd-revocations   (SDD-073 per-connection, this wrapper)
#
# State sources:
#   /var/lib/selfdef/socket-fd-revocations/active.json
#   /var/lib/selfdef/socket-fd-revocations/pending-restores.json
#
# Plus the SDD-073-specific labeled gauge:
#   selfdef_socket_fd_revocations_by_protocol{protocol="tcp|unix|netlink"}
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_SOCKET_FD_REVOCATIONS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-socket-fd-revocations.prom}"
STATE_DIR="${SELFDEF_SOCKET_FD_REVOCATIONS_STATE_DIR:-/var/lib/selfdef/socket-fd-revocations}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_socket_fd_revocations_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_socket_fd_revocations_textfile_emit_failed gauge\n'
    printf 'selfdef_socket_fd_revocations_textfile_emit_failed 1\n'
    printf '# HELP selfdef_socket_fd_revocations_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_socket_fd_revocations_last_run_unix gauge\n'
    printf 'selfdef_socket_fd_revocations_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
active_count=0
pending_restores=0
stale_count=0
tcp_count=0
unix_count=0
netlink_count=0
any_count=0
oldest_expiry_unix=0

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
      stale_count="$(jq -r '[.[] | select(.handle | type == "object" and has("Stale"))] | length' "$active_json" 2>/dev/null || echo 0)"
      tcp_count="$(jq -r '[.[] | select(.protocol == "Tcp")] | length' "$active_json" 2>/dev/null || echo 0)"
      unix_count="$(jq -r '[.[] | select(.protocol == "Unix")] | length' "$active_json" 2>/dev/null || echo 0)"
      netlink_count="$(jq -r '[.[] | select(.protocol == "Netlink")] | length' "$active_json" 2>/dev/null || echo 0)"
      any_count="$(jq -r '[.[] | select(.protocol == "Any")] | length' "$active_json" 2>/dev/null || echo 0)"
    else
      active_count="$(grep -oE '"pid":[0-9]+' "$active_json" 2>/dev/null | wc -l || true)"
    fi
  fi

  if [ -r "$pending_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      pending_restores="$(jq -r 'length' "$pending_json" 2>/dev/null || echo 0)"
      oldest_expiry_unix="$(jq -r 'map(.seconds_remaining // 0) | min // 0' "$pending_json" 2>/dev/null || echo 0)"
      if [ "$oldest_expiry_unix" -gt 0 ]; then
        oldest_expiry_unix=$(( $(date +%s) + oldest_expiry_unix ))
      fi
    else
      pending_restores="$(grep -oE '"pid":[0-9]+' "$pending_json" 2>/dev/null | wc -l || true)"
    fi
  fi
fi

tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_socket_fd_revocations_state_dir_present 1 if state dir exists.\n'
  printf '# TYPE selfdef_socket_fd_revocations_state_dir_present gauge\n'
  printf 'selfdef_socket_fd_revocations_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_socket_fd_revocations_active_count Currently-active socket-fd revocation handles.\n'
  printf '# TYPE selfdef_socket_fd_revocations_active_count gauge\n'
  printf 'selfdef_socket_fd_revocations_active_count %d\n' "$active_count"

  printf '# HELP selfdef_socket_fd_revocations_stale_count Handles that came back Stale (inode-race detected; revoke skipped).\n'
  printf '# TYPE selfdef_socket_fd_revocations_stale_count gauge\n'
  printf 'selfdef_socket_fd_revocations_stale_count %d\n' "$stale_count"

  printf '# HELP selfdef_socket_fd_revocations_by_protocol Active handles broken down by socket protocol.\n'
  printf '# TYPE selfdef_socket_fd_revocations_by_protocol gauge\n'
  printf 'selfdef_socket_fd_revocations_by_protocol{protocol="tcp"} %d\n' "$tcp_count"
  printf 'selfdef_socket_fd_revocations_by_protocol{protocol="unix"} %d\n' "$unix_count"
  printf 'selfdef_socket_fd_revocations_by_protocol{protocol="netlink"} %d\n' "$netlink_count"
  printf 'selfdef_socket_fd_revocations_by_protocol{protocol="any"} %d\n' "$any_count"

  printf '# HELP selfdef_socket_fd_revocations_pending_restores Pending operator-restore decisions in the SDD-073 queue.\n'
  printf '# TYPE selfdef_socket_fd_revocations_pending_restores gauge\n'
  printf 'selfdef_socket_fd_revocations_pending_restores %d\n' "$pending_restores"

  printf '# HELP selfdef_socket_fd_revocations_oldest_expiry_unix Unix timestamp of soonest auto-restore.\n'
  printf '# TYPE selfdef_socket_fd_revocations_oldest_expiry_unix gauge\n'
  printf 'selfdef_socket_fd_revocations_oldest_expiry_unix %d\n' "$oldest_expiry_unix"

  printf '# HELP selfdef_socket_fd_revocations_last_run_unix Observer freshness.\n'
  printf '# TYPE selfdef_socket_fd_revocations_last_run_unix gauge\n'
  printf 'selfdef_socket_fd_revocations_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_socket_fd_revocations_textfile_emit_failed Wrapper exited unhealthy (0 on success).\n'
  printf '# TYPE selfdef_socket_fd_revocations_textfile_emit_failed gauge\n'
  printf 'selfdef_socket_fd_revocations_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
