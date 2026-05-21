#!/usr/bin/env bash
# selfdef lynis-cron — weekly Lynis audit wrapper.
#
# Invokes `lynis audit system [--quick]`, parses the hardening-
# index + warning/suggestion counts, emits structured JSON tagged
# 'selfdef-lynis' via logger(1). Always exit 0 — Lynis findings
# are operator-pull advisories, not enforcement signals.

set -u

PROFILE="${SELFDEF_LYNIS_PROFILE:-quick}"
LYNIS_BIN="${SELFDEF_LYNIS_BIN:-lynis}"

ARGS=(--cronjob)
if [[ "$PROFILE" == "quick" ]]; then
    ARGS+=(--quick)
fi

tmp_out="$(mktemp)"
tmp_err="$(mktemp)"
"$LYNIS_BIN" audit system "${ARGS[@]}" > "$tmp_out" 2> "$tmp_err"
rc=$?

# Lynis writes a report file at /var/log/lynis-report.dat with
# fields like:
#   hardening_index=72
#   warning[]=...
#   suggestion[]=...
REPORT="${SELFDEF_LYNIS_REPORT:-/var/log/lynis-report.dat}"

if [[ ! -r "$REPORT" ]]; then
    json="{\"tag\":\"selfdef-lynis\",\"severity\":\"high\",\"event\":\"report_missing\",\"rc\":$rc,\"report_path\":\"$REPORT\"}"
    logger -t selfdef-lynis -- "$json"
    rm -f "$tmp_out" "$tmp_err"
    exit 0
fi

hardening_index=$(awk -F= '/^hardening_index=/ {print $2; exit}' "$REPORT" 2>/dev/null || echo "0")
n_warnings=$(grep -c '^warning\[\]'    "$REPORT" 2>/dev/null || echo 0)
n_suggestions=$(grep -c '^suggestion\[\]' "$REPORT" 2>/dev/null || echo 0)

# Severity ladder against hardening_index.
#   ≥ 80  → ok
#   60-79 → warn
#   < 60  → alert
severity="ok"
event="audit_ok"
if [[ -n "$hardening_index" ]] && [[ "$hardening_index" -lt 60 ]]; then
    severity="alert"
    event="hardening_low"
elif [[ -n "$hardening_index" ]] && [[ "$hardening_index" -lt 80 ]]; then
    severity="warn"
    event="hardening_moderate"
fi

# Sample up to 5 warning lines (operator-readable triage).
sample=$(awk -F=  '/^warning\[\]/ {print $2}' "$REPORT" 2>/dev/null | head -5 | tr '\n' '|' | sed 's/"/\\"/g')

json=$(printf '{"tag":"selfdef-lynis","severity":"%s","event":"%s","profile":"%s","lynis_rc":%d,"hardening_index":%s,"warnings":%s,"suggestions":%s,"sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$rc" "$hardening_index" "$n_warnings" "$n_suggestions" "$sample")

logger -t selfdef-lynis -- "$json"

# Always exit 0 — Lynis findings are advisory.
rm -f "$tmp_out" "$tmp_err"
exit 0
