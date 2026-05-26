#!/usr/bin/env bash
# selfdef timestomp-watchdog — scan system binary + config
# dirs for timestamp-manipulation anomalies.
#
# Three anomaly classes (none has a benign cause on a normal
# system binary):
#   1. FUTURE   — mtime is after "now" (file claims to be from
#                 the future; a careless timestomp overshoot).
#   2. EPOCH    — mtime at/near the Unix epoch (1970-01-01;
#                 `touch -t 197001010000` is the lazy timestomp).
#   3. MTIME>CTIME — mtime is NEWER than ctime by a wide margin.
#                 ctime updates on any metadata change + can't be
#                 set by touch; an attacker who `touch`-es mtime
#                 backwards leaves mtime < ctime (normal after an
#                 edit) — but mtime FAR IN THE FUTURE of ctime, or
#                 a recently-changed ctime with an ancient mtime,
#                 is the timestomp tell.
#
# Severity:
#   ok    → no anomalies
#   warn  → 1..3 anomalies
#   alert → 4+ anomalies OR any in a core bin dir (/bin /sbin
#           /usr/bin /usr/sbin)

set -u

PROFILE="${SELFDEF_TIMESTOMP_PROFILE:-report}"
ROOTS="${SELFDEF_TIMESTOMP_ROOTS:-/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /etc}"

PRUNE_PATHS=(
    "/var/lib/docker/overlay2" "/var/lib/containerd"
    "/var/lib/containers/storage" "/var/lib/snapd/snaps"
    "/proc" "/sys"
)
prune_expr=()
for p in "${PRUNE_PATHS[@]}"; do
    [[ -d "$p" ]] || continue
    prune_expr+=(-path "$p" -prune -o)
done

now=$(date +%s)
# Epoch window: anything before 2001-01-01 (978307200) on a
# system binary is implausible (these distros didn't exist).
epoch_cutoff=978307200
# Future tolerance: 1 day of clock skew is fine.
future_cutoff=$((now + 86400))

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# shellcheck disable=SC2086
for root in $ROOTS; do
    [[ -e "$root" ]] || continue
    find "$root" -xdev "${prune_expr[@]}" -type f -print 2>/dev/null
done | while IFS= read -r f; do
    # mtime + ctime epochs.
    read -r mt ct < <(stat -c '%Y %Z' "$f" 2>/dev/null || echo "0 0")
    [[ "$mt" =~ ^[0-9]+$ ]] || continue
    [[ "$ct" =~ ^[0-9]+$ ]] || continue
    anomaly=""
    if (( mt > future_cutoff )); then
        anomaly="FUTURE"
    elif (( mt < epoch_cutoff )); then
        anomaly="EPOCH"
    elif (( mt > ct + 86400 )); then
        # mtime more than a day AFTER ctime: ctime can't lag
        # mtime on a normal write (ctime >= mtime after a write).
        # mtime > ctime means mtime was set forward by touch.
        anomaly="MTIME_GT_CTIME"
    fi
    [[ -n "$anomaly" ]] && printf '%s\t%s\t%s\n' "$anomaly" "$f" "$mt"
done > "$tmp"

n=$(wc -l < "$tmp" | tr -d ' ')
# Any anomaly in a core bin dir?
core=$(grep -cE $'\t/(bin|sbin|usr/bin|usr/sbin)/' "$tmp" || true)

severity="ok"; event="no_timestamp_anomaly"
if (( core > 0 )) || (( n >= 4 )); then
    severity="alert"; event="timestomp_anomaly"
elif (( n > 0 )); then
    severity="warn"; event="timestamp_anomaly"
fi

sample=$(awk -F'\t' '{print $1":"$2}' "$tmp" | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-timestomp","severity":"%s","event":"%s","profile":"%s","anomalies":%d,"core_bin_anomalies":%d,"sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n" "$core" "$sample")
logger -t selfdef-timestomp -- "$json"

if (( n > 0 )); then
    head -c 32768 "$tmp" | while IFS=$'\t' read -r a f mt; do
        [[ -n "$a" ]] && logger -t selfdef-timestomp-detail -- "${a} ${f} mtime=$(date -d "@${mt}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "$mt")"
    done
fi

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
