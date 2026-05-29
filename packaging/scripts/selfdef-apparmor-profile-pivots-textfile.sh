#!/bin/bash
# selfdef-apparmor-profile-pivots-textfile — emit Prometheus
# node_exporter textfile gauges for the SDD-077 AppArmor live
# profile-pivot state.
#
# 31st sibling (OnBootSec=930s). Extends the IPS-duodectet
# observability set to the tridectet at the MAC (Mandatory
# Access Control) policy axis:
#   19th — blockset                  (SDD-065 network perimeter)
#   20th — quarantine                (SDD-066 process single-pid)
#   21st — revocations               (SDD-067 shell-session)
#   22nd — token-revocations         (SDD-068 API/web token)
#   23rd — mfa-grant-revocations     (SDD-069 MFA grant)
#   24th — netns-isolations          (SDD-070 kernel-containment)
#   25th — mount-bindings            (SDD-071 filesystem-binding)
#   26th — process-tree-freezes      (SDD-072 process-graph)
#   27th — socket-fd-revocations     (SDD-073 per-connection)
#   28th — env-scrubs                (SDD-074 in-memory secret)
#   29th — capability-drops          (SDD-075 per-process privilege)
#   30th — kernel-keyring-evictions  (SDD-076 kernel-keyring)
#   31st — apparmor-profile-pivots   (SDD-077 MAC policy, this wrapper)
#
# State sources:
#   /var/lib/selfdef/apparmor-profile-pivots/active.json
#   /var/lib/selfdef/apparmor-profile-pivots/pending-restores.json
#
# Plus SDD-077-specific labeled gauges:
#   selfdef_apparmor_profile_pivots_by_target_profile{profile="..."}
#   selfdef_apparmor_profile_pivots_by_scope{scope="profile|hat"}
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_APPARMOR_PROFILE_PIVOTS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-apparmor-profile-pivots.prom}"
STATE_DIR="${SELFDEF_APPARMOR_PROFILE_PIVOTS_STATE_DIR:-/var/lib/selfdef/apparmor-profile-pivots}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_apparmor_profile_pivots_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_apparmor_profile_pivots_textfile_emit_failed gauge\n'
    printf 'selfdef_apparmor_profile_pivots_textfile_emit_failed 1\n'
    printf '# HELP selfdef_apparmor_profile_pivots_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_apparmor_profile_pivots_last_run_unix gauge\n'
    printf 'selfdef_apparmor_profile_pivots_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
active_count=0
pending_restores=0
denied_count=0
no_target_count=0
stale_count=0
oldest_expiry_unix=0
declare -A profile_breakdown=()
declare -A scope_breakdown=()

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
      denied_count="$(jq -r '[.[] | select(.handle | type == "object" and has("Denied"))] | length' "$active_json" 2>/dev/null || echo 0)"
      no_target_count="$(jq -r '[.[] | select(.handle | type == "object" and has("NoTarget"))] | length' "$active_json" 2>/dev/null || echo 0)"
      stale_count="$(jq -r '[.[] | select(.handle | type == "object" and has("Stale"))] | length' "$active_json" 2>/dev/null || echo 0)"
      while IFS= read -r tp; do
        [ -z "$tp" ] && continue
        profile_breakdown[$tp]=$(( ${profile_breakdown[$tp]:-0} + 1 ))
      done < <(jq -r '.[] | .target_profile' "$active_json" 2>/dev/null)
      while IFS= read -r sc; do
        [ -z "$sc" ] && continue
        # jq emits "Profile"/"Hat"; lowercase for the gauge label.
        sc_lower=$(printf '%s' "$sc" | tr '[:upper:]' '[:lower:]')
        scope_breakdown[$sc_lower]=$(( ${scope_breakdown[$sc_lower]:-0} + 1 ))
      done < <(jq -r '.[] | .scope' "$active_json" 2>/dev/null)
    else
      active_count="$(grep -oE '"target_profile":' "$active_json" 2>/dev/null | wc -l || true)"
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
      pending_restores="$(grep -oE '"target_profile":' "$pending_json" 2>/dev/null | wc -l || true)"
    fi
  fi
fi

tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_apparmor_profile_pivots_state_dir_present 1 if state dir exists.\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_state_dir_present gauge\n'
  printf 'selfdef_apparmor_profile_pivots_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_apparmor_profile_pivots_active_count Currently-active AppArmor profile-pivot handles.\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_active_count gauge\n'
  printf 'selfdef_apparmor_profile_pivots_active_count %d\n' "$active_count"

  printf '# HELP selfdef_apparmor_profile_pivots_denied_count Handles that came back Denied (current profile forbids change_profile).\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_denied_count gauge\n'
  printf 'selfdef_apparmor_profile_pivots_denied_count %d\n' "$denied_count"

  printf '# HELP selfdef_apparmor_profile_pivots_no_target_count Handles that came back NoTarget (target profile not loaded in kernel).\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_no_target_count gauge\n'
  printf 'selfdef_apparmor_profile_pivots_no_target_count %d\n' "$no_target_count"

  printf '# HELP selfdef_apparmor_profile_pivots_stale_count Handles that came back Stale (target pid died before write).\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_stale_count gauge\n'
  printf 'selfdef_apparmor_profile_pivots_stale_count %d\n' "$stale_count"

  printf '# HELP selfdef_apparmor_profile_pivots_by_target_profile Active profile-pivots broken down by target AppArmor profile.\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_by_target_profile gauge\n'
  if [ -n "${profile_breakdown[*]+x}" ] && [ "${#profile_breakdown[@]}" -gt 0 ]; then
    for tp in "${!profile_breakdown[@]}"; do
      printf 'selfdef_apparmor_profile_pivots_by_target_profile{profile="%s"} %d\n' "$tp" "${profile_breakdown[$tp]}"
    done
  else
    printf 'selfdef_apparmor_profile_pivots_by_target_profile{profile="none"} 0\n'
  fi

  printf '# HELP selfdef_apparmor_profile_pivots_by_scope Active profile-pivots broken down by scope (profile|hat).\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_by_scope gauge\n'
  if [ -n "${scope_breakdown[*]+x}" ] && [ "${#scope_breakdown[@]}" -gt 0 ]; then
    for sc in "${!scope_breakdown[@]}"; do
      printf 'selfdef_apparmor_profile_pivots_by_scope{scope="%s"} %d\n' "$sc" "${scope_breakdown[$sc]}"
    done
  else
    printf 'selfdef_apparmor_profile_pivots_by_scope{scope="none"} 0\n'
  fi

  printf '# HELP selfdef_apparmor_profile_pivots_pending_restores Pending operator-restore decisions in the SDD-077 queue.\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_pending_restores gauge\n'
  printf 'selfdef_apparmor_profile_pivots_pending_restores %d\n' "$pending_restores"

  printf '# HELP selfdef_apparmor_profile_pivots_oldest_expiry_unix Unix timestamp of soonest auto-restore.\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_oldest_expiry_unix gauge\n'
  printf 'selfdef_apparmor_profile_pivots_oldest_expiry_unix %d\n' "$oldest_expiry_unix"

  printf '# HELP selfdef_apparmor_profile_pivots_last_run_unix Observer freshness.\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_last_run_unix gauge\n'
  printf 'selfdef_apparmor_profile_pivots_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_apparmor_profile_pivots_textfile_emit_failed Wrapper exited unhealthy (0 on success).\n'
  printf '# TYPE selfdef_apparmor_profile_pivots_textfile_emit_failed gauge\n'
  printf 'selfdef_apparmor_profile_pivots_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
