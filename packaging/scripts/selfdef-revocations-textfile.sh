#!/bin/bash
# selfdef-revocations-textfile — emit Prometheus node_exporter
# textfile gauges for the SDD-067 session-revocation state.
#
# Surfaces real IPS-host operator visibility for the SDD-067
# session-revocation action layer (selfdef-session-revocation-
# backend at selfdef commit de6b25b).
#
# Pairs with blockset observer (19th sibling, SDD-065) +
# quarantine observer (20th sibling, SDD-066) — the trio of
# enforcement-layer surfaces.
#
# State sources:
#   /var/lib/selfdef/revocations/active.json — selfdefd-published
#     snapshot of active revocation handles (written by selfdefd
#     poll of the backend).
#   /var/lib/selfdef/revocations/pending-restores.json — operator
#     decision queue.
#
# Runs every 60s via the companion timer. 21st sibling observer.
#
# Honest-offline: when the state dir doesn't exist (selfdefd
# hasn't bootstrapped) emit zero with state_dir_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_REVOCATIONS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-revocations.prom}"
STATE_DIR="${SELFDEF_REVOCATIONS_STATE_DIR:-/var/lib/selfdef/revocations}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_revocations_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_revocations_textfile_emit_failed gauge\n'
    printf 'selfdef_revocations_textfile_emit_failed 1\n'
    printf '# HELP selfdef_revocations_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_revocations_last_run_unix gauge\n'
    printf 'selfdef_revocations_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

state_dir_present=0
revocations_active_count=0
revocations_pending_restores=0
revocations_oldest_expiry_unix=0

if [ -d "$STATE_DIR" ]; then
  state_dir_present=1
  active_json="$STATE_DIR/active.json"
  pending_json="$STATE_DIR/pending-restores.json"

  # Active-handle count — JSON array length. Use jq if available;
  # else count top-level "user":"..." occurrences as honest-best-
  # effort (works for the InMemoryBackend dump shape).
  if [ -r "$active_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      revocations_active_count="$(jq -r 'length' "$active_json" 2>/dev/null || echo 0)"
    else
      revocations_active_count="$(grep -oE '"user":"[^"]+"' "$active_json" 2>/dev/null | wc -l || true)"
    fi
  fi

  if [ -r "$pending_json" ]; then
    if command -v jq >/dev/null 2>&1; then
      revocations_pending_restores="$(jq -r 'length' "$pending_json" 2>/dev/null || echo 0)"
      revocations_oldest_expiry_unix="$(jq -r 'map(.seconds_remaining // 0) | min // 0' "$pending_json" 2>/dev/null || echo 0)"
      if [ "$revocations_oldest_expiry_unix" -gt 0 ]; then
        revocations_oldest_expiry_unix=$(( $(date +%s) + revocations_oldest_expiry_unix ))
      fi
    else
      revocations_pending_restores="$(grep -oE '"user":"[^"]+"' "$pending_json" 2>/dev/null | wc -l || true)"
    fi
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_revocations_state_dir_present 1 if /var/lib/selfdef/revocations exists (selfdefd bootstrapped).\n'
  printf '# TYPE selfdef_revocations_state_dir_present gauge\n'
  printf 'selfdef_revocations_state_dir_present %d\n' "$state_dir_present"

  printf '# HELP selfdef_revocations_active_count Currently-active revocation handles.\n'
  printf '# TYPE selfdef_revocations_active_count gauge\n'
  printf 'selfdef_revocations_active_count %d\n' "$revocations_active_count"

  printf '# HELP selfdef_revocations_pending_restores Pending operator-restore decisions in the SDD-067 queue.\n'
  printf '# TYPE selfdef_revocations_pending_restores gauge\n'
  printf 'selfdef_revocations_pending_restores %d\n' "$revocations_pending_restores"

  printf '# HELP selfdef_revocations_oldest_expiry_unix Unix timestamp of the soonest auto-restore (0 if none).\n'
  printf '# TYPE selfdef_revocations_oldest_expiry_unix gauge\n'
  printf 'selfdef_revocations_oldest_expiry_unix %d\n' "$revocations_oldest_expiry_unix"

  printf '# HELP selfdef_revocations_last_run_unix Wall-clock seconds of last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_revocations_last_run_unix gauge\n'
  printf 'selfdef_revocations_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_revocations_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_revocations_textfile_emit_failed gauge\n'
  printf 'selfdef_revocations_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
