#!/usr/bin/env bash
# selfdef logfile-integrity-watchdog — detect log tampering
# via monotonic-growth + inode-stability tracking.
#
# Append-only logs only ever GROW (until logrotate rotates
# them, which changes the inode + resets size in a KNOWN way).
# An attacker erasing their tracks truncates or rewrites the
# log in place → the size SHRINKS with the SAME inode. That
# combination (same inode, smaller size) has no benign cause
# and is the indicator-removal signature.
#
# State file: path<TAB>inode<TAB>size per watched log.
#
# Severity:
#   ok    → all logs grew or rotated cleanly (new inode)
#   warn  → a log went missing (deleted)
#   alert → same-inode size shrink (in-place truncation —
#           the tamper signature)

set -u

PROFILE="${SELFDEF_LOGINT_PROFILE:-report}"
STATE="${SELFDEF_LOGINT_STATE:-/var/lib/selfdef/logfile-integrity-state.tsv}"

# Watched logs (only those that exist are tracked).
WATCH=(
    /var/log/wtmp /var/log/btmp /var/log/lastlog
    /var/log/auth.log /var/log/secure
    /var/log/audit/audit.log
    /var/log/journal
    /var/log/syslog /var/log/messages
)

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

for f in "${WATCH[@]}"; do
    [[ -e "$f" ]] || continue
    if [[ -d "$f" ]]; then
        # /var/log/journal is a dir — track aggregate size.
        sz=$(du -sb "$f" 2>/dev/null | awk '{print $1}')
        ino="dir"
    else
        ino=$(stat -c '%i' "$f" 2>/dev/null || echo "?")
        sz=$(stat -c '%s' "$f" 2>/dev/null || echo "0")
    fi
    printf '%s\t%s\t%s\n' "$f" "$ino" "$sz" >> "$current"
done

# First run: write state, no comparison.
if [[ ! -f "$STATE" ]]; then
    mkdir -p "$(dirname "$STATE")"
    cp "$current" "$STATE"
    chmod 0600 "$STATE"
    n=$(wc -l < "$current" | tr -d ' ')
    logger -t selfdef-logfile-integrity -- "$(printf '{"tag":"selfdef-logfile-integrity","severity":"ok","event":"baseline_initial","profile":"%s","tracked":%d}' "$PROFILE" "$n")"
    exit 0
fi

shrinks=0
missing=0
grew=0
rotated=0
sample=()

# Compare each previously-seen log against current.
while IFS=$'\t' read -r path old_ino old_sz; do
    [[ -z "$path" ]] && continue
    line=$(grep -F "$(printf '%s\t' "$path")" "$current" 2>/dev/null | head -1)
    if [[ -z "$line" ]]; then
        missing=$((missing + 1))
        (( ${#sample[@]} < 8 )) && sample+=("MISSING:${path}")
        continue
    fi
    cur_ino=$(echo "$line" | cut -f2)
    cur_sz=$(echo "$line" | cut -f3)
    if [[ "$cur_ino" == "$old_ino" ]]; then
        # Same inode: size must be >= old (append-only).
        if [[ "$cur_sz" =~ ^[0-9]+$ && "$old_sz" =~ ^[0-9]+$ ]] && (( cur_sz < old_sz )); then
            shrinks=$((shrinks + 1))
            (( ${#sample[@]} < 8 )) && sample+=("SHRANK:${path}:${old_sz}->${cur_sz}")
        else
            grew=$((grew + 1))
        fi
    else
        # Inode changed = rotation (or recreation). Benign-ish;
        # logrotate does this. Count it but don't alert.
        rotated=$((rotated + 1))
    fi
done < "$STATE"

severity="ok"; event="logs_intact"
if (( shrinks > 0 )); then
    severity="alert"; event="log_truncation_detected"
elif (( missing > 0 )); then
    severity="warn"; event="log_missing"
fi

# Update state for next run (always — so rotation re-baselines).
cp "$current" "$STATE" 2>/dev/null || true

sample_str=$(IFS='|'; echo "${sample[*]:-}")
json=$(printf '{"tag":"selfdef-logfile-integrity","severity":"%s","event":"%s","profile":"%s","shrinks":%d,"missing":%d,"grew":%d,"rotated":%d,"sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$shrinks" "$missing" "$grew" "$rotated" "$sample_str")
logger -t selfdef-logfile-integrity -- "$json"

for s in "${sample[@]}"; do
    logger -t selfdef-logfile-integrity-detail -- "$s"
done

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
