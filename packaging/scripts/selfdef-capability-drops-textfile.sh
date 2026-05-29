#!/bin/bash
# selfdef-capability-drops-textfile — emit Prometheus
# node_exporter textfile gauges for the SDD-075 per-process
# capability-drop state.
#
# 29th sibling (OnBootSec=870s). Extends the IPS-dectet
# observability set to the undectet at the per-process
# privilege-set axis:
#   19th — blockset                (SDD-065 network perimeter)
#   20th — quarantine              (SDD-066 process single-pid)
#   21st — revocations             (SDD-067 shell-session)
#   22nd — token-revocations       (SDD-068 API/web token)
#   23rd — mfa-grant-revocations   (SDD-069 MFA grant)
#   24th — netns-isolations        (SDD-070 kernel-containment)
#   25th — mount-bindings          (SDD-071 filesystem-binding)
#   26th — process-tree-freezes    (SDD-072 process-graph)
#   27th — socket-fd-revocations   (SDD-073 per-connection)
#   28th — env-scrubs              (SDD-074 in-memory secret)
#   29th — capability-drops        (SDD-075 per-process privilege, this wrapper)
#
# State sources:
#   /var/lib/selfdef/capability-drops/active.json
#   /var/lib/selfdef/capability-drops/pending-restores.json
#
# Plus the SDD-075-specific labeled gauge:
#   selfdef_capability_drops_by_cap{cap="CAP_NET_ADMIN|CAP_SYS_PTRACE|..."}
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_CAPABILITY_DROPS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-capability-drops.prom}"
STATE_DIR="${SELFDEF_CAPABILITY_DROPS_STATE_DIR:-/var/lib/selfdef/capability-drops}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_capability_drops_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_capability_drops_textfile_emit_failed gauge\n'
    printf 'selfdef_capability_drops_textfile_emit_failed 1\n'
    printf '# HELP selfdef_capability_drops_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_capability_drops_last_run_unix gauge\n'
    printf 'selfdef_capability_drops_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
active_count=0
pending_restores=0
redundant_count=0
caps_dropped_total=0
oldest_expiry_unix=0
declare -A cap_breakdown=()

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
      redundant_count="$(jq -r '[.[] | select(.handle | type == "object" and has("Redundant"))] | length' "$active_json" 2>/dev/null || echo 0)"
      caps_dropped_total="$(jq -r 'map(.caps_dropped // 0) | add // 0' "$active_json" 2>/dev/null || echo 0)"
      # Build per-cap counter by extracting each entry's caps array
      # and counting occurrences across all active handles.
      while IFS= read -r cap; do
        [ -z "$cap" ] && continue
        cap_breakdown[$cap]=$(( ${cap_breakdown[$cap]:-0} + 1 ))
      done < <(jq -r '.[] | .caps[]?' "$active_json" 2>/dev/null)
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
  printf '# HELP selfdef_capability_drops_state_dir_present 1 if state dir exists.\n'
  printf '# TYPE selfdef_capability_drops_state_dir_present gauge\n'
  printf 'selfdef_capability_drops_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_capability_drops_active_count Currently-active capability-drop handles.\n'
  printf '# TYPE selfdef_capability_drops_active_count gauge\n'
  printf 'selfdef_capability_drops_active_count %d\n' "$active_count"

  printf '# HELP selfdef_capability_drops_redundant_count Handles that came back Redundant (all requested caps already absent).\n'
  printf '# TYPE selfdef_capability_drops_redundant_count gauge\n'
  printf 'selfdef_capability_drops_redundant_count %d\n' "$redundant_count"

  printf '# HELP selfdef_capability_drops_caps_dropped_total Sum of caps actually dropped across all active handles.\n'
  printf '# TYPE selfdef_capability_drops_caps_dropped_total gauge\n'
  printf 'selfdef_capability_drops_caps_dropped_total %d\n' "$caps_dropped_total"

  printf '# HELP selfdef_capability_drops_by_cap Active drops broken down by capability name (sum across all handles).\n'
  printf '# TYPE selfdef_capability_drops_by_cap gauge\n'
  # `${!cap_breakdown[@]+x}` expansion is the bash-safe empty-array
  # check under `set -u`.
  if [ -n "${cap_breakdown[*]+x}" ] && [ "${#cap_breakdown[@]}" -gt 0 ]; then
    for cap in "${!cap_breakdown[@]}"; do
      printf 'selfdef_capability_drops_by_cap{cap="%s"} %d\n' "$cap" "${cap_breakdown[$cap]}"
    done
  else
    printf 'selfdef_capability_drops_by_cap{cap="none"} 0\n'
  fi

  printf '# HELP selfdef_capability_drops_pending_restores Pending operator-restore decisions in the SDD-075 queue.\n'
  printf '# TYPE selfdef_capability_drops_pending_restores gauge\n'
  printf 'selfdef_capability_drops_pending_restores %d\n' "$pending_restores"

  printf '# HELP selfdef_capability_drops_oldest_expiry_unix Unix timestamp of soonest auto-restore.\n'
  printf '# TYPE selfdef_capability_drops_oldest_expiry_unix gauge\n'
  printf 'selfdef_capability_drops_oldest_expiry_unix %d\n' "$oldest_expiry_unix"

  printf '# HELP selfdef_capability_drops_last_run_unix Observer freshness.\n'
  printf '# TYPE selfdef_capability_drops_last_run_unix gauge\n'
  printf 'selfdef_capability_drops_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_capability_drops_textfile_emit_failed Wrapper exited unhealthy (0 on success).\n'
  printf '# TYPE selfdef_capability_drops_textfile_emit_failed gauge\n'
  printf 'selfdef_capability_drops_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
