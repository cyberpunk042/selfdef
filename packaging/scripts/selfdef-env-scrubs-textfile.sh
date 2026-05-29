#!/bin/bash
# selfdef-env-scrubs-textfile — emit Prometheus node_exporter
# textfile gauges for the SDD-074 process-env scrub state.
#
# 28th sibling (OnBootSec=840s). Extends the IPS-nonet
# observability set to the dectet at the in-memory secret-
# residency axis:
#   19th — blockset                (SDD-065 network)
#   20th — quarantine              (SDD-066 process single-pid)
#   21st — revocations             (SDD-067 shell-session)
#   22nd — token-revocations       (SDD-068 API/web token)
#   23rd — mfa-grant-revocations   (SDD-069 MFA grant)
#   24th — netns-isolations        (SDD-070 kernel-containment)
#   25th — mount-bindings          (SDD-071 filesystem-binding)
#   26th — process-tree-freezes    (SDD-072 process-graph)
#   27th — socket-fd-revocations   (SDD-073 per-connection)
#   28th — env-scrubs              (SDD-074 in-memory secret, this wrapper)
#
# State sources:
#   /var/lib/selfdef/env-scrubs/active.json
#   /var/lib/selfdef/env-scrubs/pending-restores.json
#
# Plus the SDD-074-specific:
#   selfdef_env_scrubs_vars_scrubbed_total — sum of
#   vars_scrubbed across all active handles (observability needs
#   both handle-count and total-vars-affected).
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_ENV_SCRUBS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-env-scrubs.prom}"
STATE_DIR="${SELFDEF_ENV_SCRUBS_STATE_DIR:-/var/lib/selfdef/env-scrubs}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_env_scrubs_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_env_scrubs_textfile_emit_failed gauge\n'
    printf 'selfdef_env_scrubs_textfile_emit_failed 1\n'
    printf '# HELP selfdef_env_scrubs_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_env_scrubs_last_run_unix gauge\n'
    printf 'selfdef_env_scrubs_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
active_count=0
pending_restores=0
no_match_count=0
vars_scrubbed_total=0
oldest_expiry_unix=0

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
      no_match_count="$(jq -r '[.[] | select(.handle | type == "object" and has("NoMatch"))] | length' "$active_json" 2>/dev/null || echo 0)"
      vars_scrubbed_total="$(jq -r 'map(.vars_scrubbed // 0) | add // 0' "$active_json" 2>/dev/null || echo 0)"
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
  printf '# HELP selfdef_env_scrubs_state_dir_present 1 if state dir exists.\n'
  printf '# TYPE selfdef_env_scrubs_state_dir_present gauge\n'
  printf 'selfdef_env_scrubs_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_env_scrubs_active_count Currently-active env-scrub handles.\n'
  printf '# TYPE selfdef_env_scrubs_active_count gauge\n'
  printf 'selfdef_env_scrubs_active_count %d\n' "$active_count"

  printf '# HELP selfdef_env_scrubs_no_match_count Handles that came back NoMatch (target process had none of the requested vars).\n'
  printf '# TYPE selfdef_env_scrubs_no_match_count gauge\n'
  printf 'selfdef_env_scrubs_no_match_count %d\n' "$no_match_count"

  printf '# HELP selfdef_env_scrubs_vars_scrubbed_total Sum of vars actually scrubbed across all active handles.\n'
  printf '# TYPE selfdef_env_scrubs_vars_scrubbed_total gauge\n'
  printf 'selfdef_env_scrubs_vars_scrubbed_total %d\n' "$vars_scrubbed_total"

  printf '# HELP selfdef_env_scrubs_pending_restores Pending operator-restore decisions in the SDD-074 queue.\n'
  printf '# TYPE selfdef_env_scrubs_pending_restores gauge\n'
  printf 'selfdef_env_scrubs_pending_restores %d\n' "$pending_restores"

  printf '# HELP selfdef_env_scrubs_oldest_expiry_unix Unix timestamp of soonest auto-restore.\n'
  printf '# TYPE selfdef_env_scrubs_oldest_expiry_unix gauge\n'
  printf 'selfdef_env_scrubs_oldest_expiry_unix %d\n' "$oldest_expiry_unix"

  printf '# HELP selfdef_env_scrubs_last_run_unix Observer freshness.\n'
  printf '# TYPE selfdef_env_scrubs_last_run_unix gauge\n'
  printf 'selfdef_env_scrubs_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_env_scrubs_textfile_emit_failed Wrapper exited unhealthy (0 on success).\n'
  printf '# TYPE selfdef_env_scrubs_textfile_emit_failed gauge\n'
  printf 'selfdef_env_scrubs_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
