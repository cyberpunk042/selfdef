#!/usr/bin/env bash
# selfdef rkhunter-cron — daily rkhunter scan wrapper.
#
# Invokes rkhunter --check --skip-keypress --report-warnings-only,
# parses the warnings + finding counts, emits structured JSON
# tagged 'selfdef-rkhunter' via logger(1).
#
# rkhunter exit codes:
#   0 = no warnings, no errors
#   1 = warnings encountered  (in --report-warnings-only mode)
#   2 = errors encountered (config/exec problems)
#   non-{0,1,2} = signature DB / file-properties DB outdated /
#                 other runtime issue
#
# Severity ladder:
#   ok    → exit 0 from rkhunter
#   warn  → warnings found (rkhunter rc=1)
#   alert → errors found OR runtime issue (rkhunter rc≥2)

set -u

PROFILE="${SELFDEF_RKHUNTER_PROFILE:-report}"
RKHUNTER_BIN="${SELFDEF_RKHUNTER_BIN:-rkhunter}"

# rkhunter's --skip-keypress disables the interactive "press
# enter to continue" prompts that block the unit on stdin.
# --report-warnings-only collapses the chatty default output to
# just the operator-actionable lines.
tmp_out="$(mktemp)"
tmp_err="$(mktemp)"
"$RKHUNTER_BIN" --check --skip-keypress --report-warnings-only > "$tmp_out" 2> "$tmp_err"
rc=$?

# Count warnings + summarize finding categories from the output.
n_warnings=$(grep -c '^Warning:' "$tmp_out" 2>/dev/null || echo 0)

# Severity classification.
severity="ok"
event="no_findings"
case $rc in
    0) severity="ok";    event="no_findings" ;;
    1) severity="warn";  event="warnings_found" ;;
    2) severity="alert"; event="errors_found" ;;
    *) severity="alert"; event="runtime_issue" ;;
esac

# Sample up to 5 warning lines for the operator-readable summary
# (full output is in the journal via the detail logger below).
sample=$(grep '^Warning:' "$tmp_out" 2>/dev/null | head -5 | tr '\n' '|' | sed 's/"/\\"/g')

json=$(printf '{"tag":"selfdef-rkhunter","severity":"%s","event":"%s","profile":"%s","rkhunter_rc":%d,"warning_count":%s,"sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$rc" "$n_warnings" "$sample")

logger -t selfdef-rkhunter -- "$json"

# Per-line detail tagged separately so the operator can
# `journalctl -t selfdef-rkhunter-detail` to inspect the full
# rkhunter output without grepping the main tag.
head -c 16384 "$tmp_out" | while IFS= read -r line; do
    logger -t selfdef-rkhunter-detail -- "$line"
done

rm -f "$tmp_out" "$tmp_err"

# Profile-driven exit.
if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
