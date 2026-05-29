#!/bin/bash
# selfdef-process-tree-freezes-textfile — emit Prometheus
# node_exporter textfile gauges for the SDD-072 process-tree
# freeze state.
#
# 26th sibling (OnBootSec=780s). Extends the IPS-septet
# observability set to the octet at the process-graph
# containment axis:
#   19th — blockset                (SDD-065 network)
#   20th — quarantine              (SDD-066 process single-pid)
#   21st — revocations             (SDD-067 shell-session)
#   22nd — token-revocations       (SDD-068 API/web token)
#   23rd — mfa-grant-revocations   (SDD-069 MFA grant)
#   24th — netns-isolations        (SDD-070 kernel-containment)
#   25th — mount-bindings          (SDD-071 filesystem-binding)
#   26th — process-tree-freezes    (SDD-072 process-graph, this wrapper)
#
# State sources (same shape as 21st..25th siblings):
#   /var/lib/selfdef/process-tree-freezes/active.json
#   /var/lib/selfdef/process-tree-freezes/pending-thaws.json
#
# Plus the SDD-072-specific extra gauge:
#   selfdef_process_tree_freezes_frozen_pid_count — sum of
#   frozen_pid_count across all active handles (a freeze of one
#   handle can cover many pids; observability needs both counts).
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_PROCESS_TREE_FREEZES_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-process-tree-freezes.prom}"
STATE_DIR="${SELFDEF_PROCESS_TREE_FREEZES_STATE_DIR:-/var/lib/selfdef/process-tree-freezes}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_process_tree_freezes_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_process_tree_freezes_textfile_emit_failed gauge\n'
    printf 'selfdef_process_tree_freezes_textfile_emit_failed 1\n'
    printf '# HELP selfdef_process_tree_freezes_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_process_tree_freezes_last_run_unix gauge\n'
    printf 'selfdef_process_tree_freezes_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
active_count=0
pending_thaws=0
frozen_pid_count=0
oldest_expiry_unix=0

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-thaws.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
      frozen_pid_count="$(jq -r 'map(.frozen_pid_count // 1) | add // 0' "$active_json" 2>/dev/null || echo 0)"
    else
      active_count="$(grep -oE '"root_pid":[0-9]+' "$active_json" 2>/dev/null | wc -l || true)"
      # No jq → conservative fallback: assume one pid per handle.
      frozen_pid_count="$active_count"
    fi
  fi

  if [ -r "$pending_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      pending_thaws="$(jq -r 'length' "$pending_json" 2>/dev/null || echo 0)"
      oldest_expiry_unix="$(jq -r 'map(.seconds_remaining // 0) | min // 0' "$pending_json" 2>/dev/null || echo 0)"
      if [ "$oldest_expiry_unix" -gt 0 ]; then
        oldest_expiry_unix=$(( $(date +%s) + oldest_expiry_unix ))
      fi
    else
      pending_thaws="$(grep -oE '"root_pid":[0-9]+' "$pending_json" 2>/dev/null | wc -l || true)"
    fi
  fi
fi

tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_process_tree_freezes_state_dir_present 1 if state dir exists.\n'
  printf '# TYPE selfdef_process_tree_freezes_state_dir_present gauge\n'
  printf 'selfdef_process_tree_freezes_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_process_tree_freezes_active_count Currently-active process-tree-freeze handles.\n'
  printf '# TYPE selfdef_process_tree_freezes_active_count gauge\n'
  printf 'selfdef_process_tree_freezes_active_count %d\n' "$active_count"

  printf '# HELP selfdef_process_tree_freezes_frozen_pid_count Sum of frozen pids across all active handles (one handle can cover many pids).\n'
  printf '# TYPE selfdef_process_tree_freezes_frozen_pid_count gauge\n'
  printf 'selfdef_process_tree_freezes_frozen_pid_count %d\n' "$frozen_pid_count"

  printf '# HELP selfdef_process_tree_freezes_pending_thaws Pending operator-thaw decisions in the SDD-072 queue.\n'
  printf '# TYPE selfdef_process_tree_freezes_pending_thaws gauge\n'
  printf 'selfdef_process_tree_freezes_pending_thaws %d\n' "$pending_thaws"

  printf '# HELP selfdef_process_tree_freezes_oldest_expiry_unix Unix timestamp of soonest auto-thaw.\n'
  printf '# TYPE selfdef_process_tree_freezes_oldest_expiry_unix gauge\n'
  printf 'selfdef_process_tree_freezes_oldest_expiry_unix %d\n' "$oldest_expiry_unix"

  printf '# HELP selfdef_process_tree_freezes_last_run_unix Observer freshness.\n'
  printf '# TYPE selfdef_process_tree_freezes_last_run_unix gauge\n'
  printf 'selfdef_process_tree_freezes_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_process_tree_freezes_textfile_emit_failed Wrapper exited unhealthy (0 on success).\n'
  printf '# TYPE selfdef_process_tree_freezes_textfile_emit_failed gauge\n'
  printf 'selfdef_process_tree_freezes_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
