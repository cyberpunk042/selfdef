#!/usr/bin/env bash
# selfdef clamav-cron — daily ClamAV scan wrapper.
#
# 1. Refresh signatures via freshclam (best-effort; signature DB
#    updates over network — if offline the scan still runs against
#    last-known DB)
# 2. Invoke clamscan against the profile's path set
# 3. Emit structured JSON tagged 'selfdef-clamav' via logger(1)
# 4. Always exit 0 — findings are operator-pull advisories

set -u

PROFILE="${SELFDEF_CLAMAV_PROFILE:-home}"
CLAMSCAN_BIN="${SELFDEF_CLAMSCAN_BIN:-clamscan}"
FRESHCLAM_BIN="${SELFDEF_FRESHCLAM_BIN:-freshclam}"

# Build the path set for the chosen profile. Skip directories that
# don't exist (clamscan would error otherwise).
declare -a scan_paths
case "$PROFILE" in
    home)
        for p in /home /tmp /var/tmp /srv; do
            [[ -d "$p" ]] && scan_paths+=("$p")
        done
        ;;
    full)
        for p in /home /tmp /var/tmp /srv /opt /usr/local /var/www; do
            [[ -d "$p" ]] && scan_paths+=("$p")
        done
        ;;
    *)
        json="{\"tag\":\"selfdef-clamav\",\"severity\":\"high\",\"event\":\"unknown_profile\",\"profile\":\"$PROFILE\"}"
        logger -t selfdef-clamav -- "$json"
        exit 0
        ;;
esac

if [[ ${#scan_paths[@]} -eq 0 ]]; then
    json="{\"tag\":\"selfdef-clamav\",\"severity\":\"warn\",\"event\":\"no_scan_paths\",\"profile\":\"$PROFILE\"}"
    logger -t selfdef-clamav -- "$json"
    exit 0
fi

# Refresh signatures (best-effort).
fc_rc=0
if command -v "$FRESHCLAM_BIN" >/dev/null 2>&1; then
    "$FRESHCLAM_BIN" --quiet 2>&1 | logger -t selfdef-clamav-detail -- || fc_rc=$?
fi

# Run clamscan.
tmp_out="$(mktemp)"
"$CLAMSCAN_BIN" \
    --recursive \
    --infected \
    --no-summary=no \
    --cross-fs=no \
    --max-filesize=100M \
    --max-scansize=1000M \
    "${scan_paths[@]}" > "$tmp_out" 2>&1
rc=$?

# clamscan exit codes:
#   0 = clean, no virus found
#   1 = virus(es) found
#   2 = error

# Parse the summary block.
infected=$(awk -F': ' '/^Infected files:/  {print $2; exit}' "$tmp_out")
scanned=$(awk  -F': ' '/^Scanned files:/   {print $2; exit}' "$tmp_out")
data_scanned=$(awk -F': ' '/^Data scanned:/ {print $2; exit}' "$tmp_out")
infected="${infected:-0}"
scanned="${scanned:-0}"

# Sample first 5 "FOUND" lines for operator-readable triage.
sample=$(grep ' FOUND$' "$tmp_out" 2>/dev/null | head -5 | tr '\n' '|' | sed 's/"/\\"/g')

# Severity ladder.
severity="ok"
event="no_findings"
case $rc in
    0) ;;  # clean
    1) severity="alert"; event="infected_files" ;;
    2) severity="high";  event="clamscan_error" ;;
    *) severity="high";  event="clamscan_unknown_rc" ;;
esac

json=$(printf '{"tag":"selfdef-clamav","severity":"%s","event":"%s","profile":"%s","clamscan_rc":%d,"infected":%s,"scanned":%s,"freshclam_rc":%d,"sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$rc" "$infected" "$scanned" "$fc_rc" "$sample")

logger -t selfdef-clamav -- "$json"

# Per-line detail for operator triage via journalctl -t
# selfdef-clamav-detail.
head -c 16384 "$tmp_out" | while IFS= read -r line; do
    logger -t selfdef-clamav-detail -- "$line"
done

rm -f "$tmp_out"
# Always exit 0 — clamscan findings are operator-pull advisories
# routed via the notifier-engine on severity=alert.
exit 0
