#!/usr/bin/env bash
# selfdef aide-bridge — daily AIDE check wrapper.
#
# Invokes aide --check, parses the diff summary, emits a
# structured JSON event tagged 'selfdef-aide' via logger(1).
# Exit semantics depend on profile:
#   - baseline → always exit 0 (operator-pull only)
#   - enforce  → exit 1 on any diff (systemd marks unit failed)

set -u

PROFILE="${SELFDEF_AIDE_PROFILE:-baseline}"
AIDE_BIN="${SELFDEF_AIDE_BIN:-aide}"
AIDE_CONF="${SELFDEF_AIDE_CONF:-/etc/aide/aide.conf}"

if [[ ! -r "$AIDE_CONF" ]]; then
    json="{\"tag\":\"selfdef-aide\",\"severity\":\"high\",\"event\":\"config_missing\",\"path\":\"$AIDE_CONF\"}"
    logger -t selfdef-aide -- "$json"
    exit 0
fi

# AIDE returns:
#   0 = no differences
#   1-7 = various differences (bitmask: 1=added 2=removed 4=changed)
#   >7 = internal error
tmp_out="$(mktemp)"
tmp_err="$(mktemp)"
"$AIDE_BIN" --config "$AIDE_CONF" --check > "$tmp_out" 2> "$tmp_err"
rc=$?

if [[ $rc -ge 8 ]]; then
    err_head=$(head -c 500 "$tmp_err" | tr '\n' ' ' | sed 's/"/\\"/g')
    json="{\"tag\":\"selfdef-aide\",\"severity\":\"high\",\"event\":\"aide_internal_error\",\"rc\":$rc,\"stderr\":\"$err_head\"}"
    logger -t selfdef-aide -- "$json"
    rm -f "$tmp_out" "$tmp_err"
    exit 0
fi

added=$((rc & 1))
removed=$(( (rc & 2) >> 1 ))
changed=$(( (rc & 4) >> 2 ))

# Parse the summary table that aide emits. Defensive — the output
# format can vary between AIDE versions; missing fields → 0.
n_added=$(awk    -F: '/^[[:space:]]*Added entries:/    {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$tmp_out")
n_removed=$(awk  -F: '/^[[:space:]]*Removed entries:/  {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$tmp_out")
n_changed=$(awk  -F: '/^[[:space:]]*Changed entries:/  {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$tmp_out")
n_added="${n_added:-0}"
n_removed="${n_removed:-0}"
n_changed="${n_changed:-0}"

# Severity ladder.
severity="ok"
event="no_diff"
if [[ $rc -ne 0 ]]; then
    if [[ "$n_removed" -gt 0 || "$n_changed" -gt 0 ]]; then
        severity="alert"   # removals + changes are the high-signal cases
        event="diff_changed_or_removed"
    else
        severity="warn"    # adds only (likely package install / log-rotate artifact)
        event="diff_added_only"
    fi
fi

json=$(printf '{"tag":"selfdef-aide","severity":"%s","event":"%s","profile":"%s","aide_rc":%d,"added":%s,"removed":%s,"changed":%s,"added_bit":%d,"removed_bit":%d,"changed_bit":%d}' \
    "$severity" "$event" "$PROFILE" "$rc" "$n_added" "$n_removed" "$n_changed" "$added" "$removed" "$changed")

logger -t selfdef-aide -- "$json"

# Always log the head of the AIDE output to the journal so the
# operator can inspect via `journalctl -u selfdef-aide-check`.
head -c 8192 "$tmp_out" | while IFS= read -r line; do
    logger -t selfdef-aide-detail -- "$line"
done

rm -f "$tmp_out" "$tmp_err"

# Profile-driven exit.
if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
