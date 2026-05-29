#!/bin/bash
# selfdef-bpf-map-element-clears-textfile — emit Prometheus
# node_exporter textfile gauges for the SDD-078 BPF map element
# clear state.
#
# 32nd sibling (OnBootSec=960s). Extends the IPS-tridectet
# observability set to the quattuordectet at the eBPF map state axis:
#   19th — blockset                   (SDD-065 network perimeter)
#   20th — quarantine                 (SDD-066 process single-pid)
#   21st — revocations                (SDD-067 shell-session)
#   22nd — token-revocations          (SDD-068 API/web token)
#   23rd — mfa-grant-revocations      (SDD-069 MFA grant)
#   24th — netns-isolations           (SDD-070 kernel-containment)
#   25th — mount-bindings             (SDD-071 filesystem-binding)
#   26th — process-tree-freezes       (SDD-072 process-graph)
#   27th — socket-fd-revocations      (SDD-073 per-connection)
#   28th — env-scrubs                 (SDD-074 in-memory secret)
#   29th — capability-drops           (SDD-075 per-process privilege)
#   30th — kernel-keyring-evictions   (SDD-076 kernel-keyring)
#   31st — apparmor-profile-pivots    (SDD-077 MAC policy)
#   32nd — bpf-map-element-clears     (SDD-078 eBPF map state, this wrapper)
#
# State sources:
#   /var/lib/selfdef/bpf-map-element-clears/active.json
#   /var/lib/selfdef/bpf-map-element-clears/pending-restores.json
#
# Plus SDD-078-specific labeled gauges:
#   selfdef_bpf_map_element_clears_by_scope{scope="element|all"}
#   selfdef_bpf_map_element_clears_by_map_name{map="..."}
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_BPF_MAP_ELEMENT_CLEARS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-bpf-map-element-clears.prom}"
STATE_DIR="${SELFDEF_BPF_MAP_ELEMENT_CLEARS_STATE_DIR:-/var/lib/selfdef/bpf-map-element-clears}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_bpf_map_element_clears_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_bpf_map_element_clears_textfile_emit_failed gauge\n'
    printf 'selfdef_bpf_map_element_clears_textfile_emit_failed 1\n'
    printf '# HELP selfdef_bpf_map_element_clears_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_bpf_map_element_clears_last_run_unix gauge\n'
    printf 'selfdef_bpf_map_element_clears_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
active_count=0
pending_restores=0
map_not_found_count=0
ambiguous_name_count=0
access_denied_count=0
elements_cleared_total=0
oldest_expiry_unix=0
declare -A scope_breakdown=()
declare -A map_breakdown=()

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
      map_not_found_count="$(jq -r '[.[] | select(.handle | type == "object" and has("MapNotFound"))] | length' "$active_json" 2>/dev/null || echo 0)"
      ambiguous_name_count="$(jq -r '[.[] | select(.handle | type == "object" and has("AmbiguousName"))] | length' "$active_json" 2>/dev/null || echo 0)"
      access_denied_count="$(jq -r '[.[] | select(.handle | type == "object" and has("BpfMapAccessDenied"))] | length' "$active_json" 2>/dev/null || echo 0)"
      elements_cleared_total="$(jq -r 'map(.elements_cleared // 0) | add // 0' "$active_json" 2>/dev/null || echo 0)"
      while IFS= read -r sc; do
        [ -z "$sc" ] && continue
        sc_lower=$(printf '%s' "$sc" | tr '[:upper:]' '[:lower:]')
        scope_breakdown[$sc_lower]=$(( ${scope_breakdown[$sc_lower]:-0} + 1 ))
      done < <(jq -r '.[] | .scope' "$active_json" 2>/dev/null)
      # Map-name aggregation: derive from map_spec using a small extractor
      # — for Path specs, take basename; for Id/Name specs, take the value.
      while IFS= read -r ms; do
        [ -z "$ms" ] && continue
        if [[ "$ms" == /sys/fs/bpf/* ]]; then
          mn="${ms##*/}"
        elif [[ "$ms" == id:* ]]; then
          mn="id-${ms#id:}"
        elif [[ "$ms" == name:* ]]; then
          mn="${ms#name:}"
        else
          mn="unknown"
        fi
        map_breakdown[$mn]=$(( ${map_breakdown[$mn]:-0} + 1 ))
      done < <(jq -r '.[] | .map_spec' "$active_json" 2>/dev/null)
    else
      active_count="$(grep -oE '"map_spec":' "$active_json" 2>/dev/null | wc -l || true)"
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
      pending_restores="$(grep -oE '"map_spec":' "$pending_json" 2>/dev/null | wc -l || true)"
    fi
  fi
fi

tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_bpf_map_element_clears_state_dir_present 1 if state dir exists.\n'
  printf '# TYPE selfdef_bpf_map_element_clears_state_dir_present gauge\n'
  printf 'selfdef_bpf_map_element_clears_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_bpf_map_element_clears_active_count Currently-active BPF map element clear handles.\n'
  printf '# TYPE selfdef_bpf_map_element_clears_active_count gauge\n'
  printf 'selfdef_bpf_map_element_clears_active_count %d\n' "$active_count"

  printf '# HELP selfdef_bpf_map_element_clears_map_not_found_count Handles that came back MapNotFound (map_spec did not resolve).\n'
  printf '# TYPE selfdef_bpf_map_element_clears_map_not_found_count gauge\n'
  printf 'selfdef_bpf_map_element_clears_map_not_found_count %d\n' "$map_not_found_count"

  printf '# HELP selfdef_bpf_map_element_clears_ambiguous_name_count Handles that came back AmbiguousName (name:<x> resolved to >1 map).\n'
  printf '# TYPE selfdef_bpf_map_element_clears_ambiguous_name_count gauge\n'
  printf 'selfdef_bpf_map_element_clears_ambiguous_name_count %d\n' "$ambiguous_name_count"

  printf '# HELP selfdef_bpf_map_element_clears_access_denied_count Handles that came back BpfMapAccessDenied (EPERM/EACCES).\n'
  printf '# TYPE selfdef_bpf_map_element_clears_access_denied_count gauge\n'
  printf 'selfdef_bpf_map_element_clears_access_denied_count %d\n' "$access_denied_count"

  printf '# HELP selfdef_bpf_map_element_clears_elements_cleared_total Sum of BPF map elements actually deleted across all active handles.\n'
  printf '# TYPE selfdef_bpf_map_element_clears_elements_cleared_total gauge\n'
  printf 'selfdef_bpf_map_element_clears_elements_cleared_total %d\n' "$elements_cleared_total"

  printf '# HELP selfdef_bpf_map_element_clears_by_scope Active BPF map element clears broken down by scope (element|all).\n'
  printf '# TYPE selfdef_bpf_map_element_clears_by_scope gauge\n'
  if [ -n "${scope_breakdown[*]+x}" ] && [ "${#scope_breakdown[@]}" -gt 0 ]; then
    for sc in "${!scope_breakdown[@]}"; do
      printf 'selfdef_bpf_map_element_clears_by_scope{scope="%s"} %d\n' "$sc" "${scope_breakdown[$sc]}"
    done
  else
    printf 'selfdef_bpf_map_element_clears_by_scope{scope="none"} 0\n'
  fi

  printf '# HELP selfdef_bpf_map_element_clears_by_map_name Active BPF map element clears broken down by map basename/id/name.\n'
  printf '# TYPE selfdef_bpf_map_element_clears_by_map_name gauge\n'
  if [ -n "${map_breakdown[*]+x}" ] && [ "${#map_breakdown[@]}" -gt 0 ]; then
    for mn in "${!map_breakdown[@]}"; do
      printf 'selfdef_bpf_map_element_clears_by_map_name{map="%s"} %d\n' "$mn" "${map_breakdown[$mn]}"
    done
  else
    printf 'selfdef_bpf_map_element_clears_by_map_name{map="none"} 0\n'
  fi

  printf '# HELP selfdef_bpf_map_element_clears_pending_restores Pending operator-restore decisions in the SDD-078 queue.\n'
  printf '# TYPE selfdef_bpf_map_element_clears_pending_restores gauge\n'
  printf 'selfdef_bpf_map_element_clears_pending_restores %d\n' "$pending_restores"

  printf '# HELP selfdef_bpf_map_element_clears_oldest_expiry_unix Unix timestamp of soonest auto-restore.\n'
  printf '# TYPE selfdef_bpf_map_element_clears_oldest_expiry_unix gauge\n'
  printf 'selfdef_bpf_map_element_clears_oldest_expiry_unix %d\n' "$oldest_expiry_unix"

  printf '# HELP selfdef_bpf_map_element_clears_last_run_unix Observer freshness.\n'
  printf '# TYPE selfdef_bpf_map_element_clears_last_run_unix gauge\n'
  printf 'selfdef_bpf_map_element_clears_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_bpf_map_element_clears_textfile_emit_failed Wrapper exited unhealthy (0 on success).\n'
  printf '# TYPE selfdef_bpf_map_element_clears_textfile_emit_failed gauge\n'
  printf 'selfdef_bpf_map_element_clears_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
