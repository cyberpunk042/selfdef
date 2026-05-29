#!/bin/bash
# selfdef-kernel-keyring-evictions-textfile — emit Prometheus
# node_exporter textfile gauges for the SDD-076 kernel-keyring
# eviction state.
#
# 30th sibling (OnBootSec=900s). Extends the IPS-undectet
# observability set to the duodectet at the kernel-keyring axis:
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
#   29th — capability-drops        (SDD-075 per-process privilege)
#   30th — kernel-keyring-evictions (SDD-076 kernel-keyring, this wrapper)
#
# State sources:
#   /var/lib/selfdef/kernel-keyring-evictions/active.json
#   /var/lib/selfdef/kernel-keyring-evictions/pending-restores.json
#
# Plus the SDD-076-specific labeled gauge:
#   selfdef_kernel_keyring_evictions_by_type{type="user|logon|keyring|..."}
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_KERNEL_KEYRING_EVICTIONS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-kernel-keyring-evictions.prom}"
STATE_DIR="${SELFDEF_KERNEL_KEYRING_EVICTIONS_STATE_DIR:-/var/lib/selfdef/kernel-keyring-evictions}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_kernel_keyring_evictions_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_kernel_keyring_evictions_textfile_emit_failed gauge\n'
    printf 'selfdef_kernel_keyring_evictions_textfile_emit_failed 1\n'
    printf '# HELP selfdef_kernel_keyring_evictions_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_kernel_keyring_evictions_last_run_unix gauge\n'
    printf 'selfdef_kernel_keyring_evictions_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
active_count=0
pending_restores=0
not_found_count=0
keys_evicted_total=0
oldest_expiry_unix=0
declare -A type_breakdown=()

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
      not_found_count="$(jq -r '[.[] | select(.handle | type == "object" and has("NotFound"))] | length' "$active_json" 2>/dev/null || echo 0)"
      keys_evicted_total="$(jq -r 'map(.keys_evicted // 0) | add // 0' "$active_json" 2>/dev/null || echo 0)"
      while IFS= read -r kt; do
        [ -z "$kt" ] && continue
        type_breakdown[$kt]=$(( ${type_breakdown[$kt]:-0} + 1 ))
      done < <(jq -r '.[] | .key_type' "$active_json" 2>/dev/null)
    else
      active_count="$(grep -oE '"key_spec":' "$active_json" 2>/dev/null | wc -l || true)"
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
      pending_restores="$(grep -oE '"key_spec":' "$pending_json" 2>/dev/null | wc -l || true)"
    fi
  fi
fi

tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_kernel_keyring_evictions_state_dir_present 1 if state dir exists.\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_state_dir_present gauge\n'
  printf 'selfdef_kernel_keyring_evictions_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_kernel_keyring_evictions_active_count Currently-active kernel-keyring-eviction handles.\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_active_count gauge\n'
  printf 'selfdef_kernel_keyring_evictions_active_count %d\n' "$active_count"

  printf '# HELP selfdef_kernel_keyring_evictions_not_found_count Handles that came back NotFound (target key absent at evict-time).\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_not_found_count gauge\n'
  printf 'selfdef_kernel_keyring_evictions_not_found_count %d\n' "$not_found_count"

  printf '# HELP selfdef_kernel_keyring_evictions_keys_evicted_total Sum of kernel-keyring entries invalidated/unlinked across all active handles.\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_keys_evicted_total gauge\n'
  printf 'selfdef_kernel_keyring_evictions_keys_evicted_total %d\n' "$keys_evicted_total"

  printf '# HELP selfdef_kernel_keyring_evictions_by_type Active evictions broken down by kernel key type (sum across all handles).\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_by_type gauge\n'
  if [ -n "${type_breakdown[*]+x}" ] && [ "${#type_breakdown[@]}" -gt 0 ]; then
    for kt in "${!type_breakdown[@]}"; do
      printf 'selfdef_kernel_keyring_evictions_by_type{type="%s"} %d\n' "$kt" "${type_breakdown[$kt]}"
    done
  else
    printf 'selfdef_kernel_keyring_evictions_by_type{type="none"} 0\n'
  fi

  printf '# HELP selfdef_kernel_keyring_evictions_pending_restores Pending operator-restore decisions in the SDD-076 queue.\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_pending_restores gauge\n'
  printf 'selfdef_kernel_keyring_evictions_pending_restores %d\n' "$pending_restores"

  printf '# HELP selfdef_kernel_keyring_evictions_oldest_expiry_unix Unix timestamp of soonest auto-restore.\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_oldest_expiry_unix gauge\n'
  printf 'selfdef_kernel_keyring_evictions_oldest_expiry_unix %d\n' "$oldest_expiry_unix"

  printf '# HELP selfdef_kernel_keyring_evictions_last_run_unix Observer freshness.\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_last_run_unix gauge\n'
  printf 'selfdef_kernel_keyring_evictions_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_kernel_keyring_evictions_textfile_emit_failed Wrapper exited unhealthy (0 on success).\n'
  printf '# TYPE selfdef_kernel_keyring_evictions_textfile_emit_failed gauge\n'
  printf 'selfdef_kernel_keyring_evictions_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
