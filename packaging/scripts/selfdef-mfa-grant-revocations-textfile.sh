#!/bin/bash
# selfdef-mfa-grant-revocations-textfile — emit Prometheus node_exporter
# textfile gauges for the SDD-069 MFA-grant revocation state.
#
# 23rd sibling (OnBootSec=690s). Completes the IPS-pentet
# observability set:
#   19th — blockset                (SDD-065 network)
#   20th — quarantine              (SDD-066 process)
#   21st — revocations             (SDD-067 shell-session)
#   22nd — token-revocations       (SDD-068 API/web token)
#   23rd — mfa-grant-revocations   (SDD-069 MFA grant, this wrapper)
#
# State sources (same shape as 21st/22nd siblings):
#   /var/lib/selfdef/mfa-grant-revocations/active.json
#   /var/lib/selfdef/mfa-grant-revocations/pending-restores.json
#
# Honest-offline: state-dir absent → emit state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_MFA_GRANT_REVOCATIONS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-mfa-grant-revocations.prom}"
STATE_DIR="${SELFDEF_MFA_GRANT_REVOCATIONS_STATE_DIR:-/var/lib/selfdef/mfa-grant-revocations}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_mfa_grant_revocations_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_mfa_grant_revocations_textfile_emit_failed gauge\n'
    printf 'selfdef_mfa_grant_revocations_textfile_emit_failed 1\n'
    printf '# HELP selfdef_mfa_grant_revocations_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_mfa_grant_revocations_last_run_unix gauge\n'
    printf 'selfdef_mfa_grant_revocations_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
active_count=0
pending_restores=0
oldest_expiry_unix=0

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
    else
      active_count="$(grep -oE '"principal":"[^"]+"' "$active_json" 2>/dev/null | wc -l || true)"
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
      pending_restores="$(grep -oE '"principal":"[^"]+"' "$pending_json" 2>/dev/null | wc -l || true)"
    fi
  fi
fi

tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_mfa_grant_revocations_state_dir_present 1 if state dir exists.\n'
  printf '# TYPE selfdef_mfa_grant_revocations_state_dir_present gauge\n'
  printf 'selfdef_mfa_grant_revocations_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_mfa_grant_revocations_active_count Currently-active MFA-grant revocation handles.\n'
  printf '# TYPE selfdef_mfa_grant_revocations_active_count gauge\n'
  printf 'selfdef_mfa_grant_revocations_active_count %d\n' "$active_count"

  printf '# HELP selfdef_mfa_grant_revocations_pending_restores Pending operator-restore decisions in the SDD-069 queue.\n'
  printf '# TYPE selfdef_mfa_grant_revocations_pending_restores gauge\n'
  printf 'selfdef_mfa_grant_revocations_pending_restores %d\n' "$pending_restores"

  printf '# HELP selfdef_mfa_grant_revocations_oldest_expiry_unix Unix timestamp of soonest auto-restore.\n'
  printf '# TYPE selfdef_mfa_grant_revocations_oldest_expiry_unix gauge\n'
  printf 'selfdef_mfa_grant_revocations_oldest_expiry_unix %d\n' "$oldest_expiry_unix"

  printf '# HELP selfdef_mfa_grant_revocations_last_run_unix Observer freshness.\n'
  printf '# TYPE selfdef_mfa_grant_revocations_last_run_unix gauge\n'
  printf 'selfdef_mfa_grant_revocations_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_mfa_grant_revocations_textfile_emit_failed Wrapper exited unhealthy (0 on success).\n'
  printf '# TYPE selfdef_mfa_grant_revocations_textfile_emit_failed gauge\n'
  printf 'selfdef_mfa_grant_revocations_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
