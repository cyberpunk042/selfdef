#!/bin/bash
# selfdef-token-revocations-textfile — emit Prometheus node_exporter
# textfile gauges for the SDD-068 API/web-token revocation state.
#
# 22nd sibling observer (OnBootSec=660s). Completes the IPS-quartet
# observability set:
#   19th — blockset (SDD-065 network)
#   20th — quarantine (SDD-066 process)
#   21st — revocations (SDD-067 shell-session)
#   22nd — token-revocations (SDD-068 API/web token, this wrapper)
#
# State sources (same shape as 21st sibling revocations):
#   /var/lib/selfdef/token-revocations/active.json
#   /var/lib/selfdef/token-revocations/pending-restores.json
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_TOKEN_REVOCATIONS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-token-revocations.prom}"
STATE_DIR="${SELFDEF_TOKEN_REVOCATIONS_STATE_DIR:-/var/lib/selfdef/token-revocations}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_token_revocations_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_token_revocations_textfile_emit_failed gauge\n'
    printf 'selfdef_token_revocations_textfile_emit_failed 1\n'
    printf '# HELP selfdef_token_revocations_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_token_revocations_last_run_unix gauge\n'
    printf 'selfdef_token_revocations_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
token_revocations_active_count=0
token_revocations_pending_restores=0
token_revocations_oldest_expiry_unix=0

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      token_revocations_active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
    else
      token_revocations_active_count="$(grep -oE '"principal":"[^"]+"' "$active_json" 2>/dev/null | wc -l || true)"
    fi
  fi

  if [ -r "$pending_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      token_revocations_pending_restores="$(jq -r 'length' "$pending_json" 2>/dev/null || echo 0)"
      token_revocations_oldest_expiry_unix="$(jq -r 'map(.seconds_remaining // 0) | min // 0' "$pending_json" 2>/dev/null || echo 0)"
      if [ "$token_revocations_oldest_expiry_unix" -gt 0 ]; then
        token_revocations_oldest_expiry_unix=$(( $(date +%s) + token_revocations_oldest_expiry_unix ))
      fi
    else
      token_revocations_pending_restores="$(grep -oE '"principal":"[^"]+"' "$pending_json" 2>/dev/null | wc -l || true)"
    fi
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_token_revocations_state_dir_present 1 if /var/lib/selfdef/token-revocations exists (selfdefd bootstrapped).\n'
  printf '# TYPE selfdef_token_revocations_state_dir_present gauge\n'
  printf 'selfdef_token_revocations_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_token_revocations_active_count Currently-active token revocation handles.\n'
  printf '# TYPE selfdef_token_revocations_active_count gauge\n'
  printf 'selfdef_token_revocations_active_count %d\n' "$token_revocations_active_count"

  printf '# HELP selfdef_token_revocations_pending_restores Pending operator-restore decisions in the SDD-068 queue.\n'
  printf '# TYPE selfdef_token_revocations_pending_restores gauge\n'
  printf 'selfdef_token_revocations_pending_restores %d\n' "$token_revocations_pending_restores"

  printf '# HELP selfdef_token_revocations_oldest_expiry_unix Unix timestamp of the soonest auto-restore (0 if none).\n'
  printf '# TYPE selfdef_token_revocations_oldest_expiry_unix gauge\n'
  printf 'selfdef_token_revocations_oldest_expiry_unix %d\n' "$token_revocations_oldest_expiry_unix"

  printf '# HELP selfdef_token_revocations_last_run_unix Wall-clock seconds of last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_token_revocations_last_run_unix gauge\n'
  printf 'selfdef_token_revocations_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_token_revocations_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_token_revocations_textfile_emit_failed gauge\n'
  printf 'selfdef_token_revocations_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
