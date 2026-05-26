#!/usr/bin/env bash
# selfdef listening-ports-watchdog — daily delta of the
# listening-socket set vs a learned baseline.
#
# First run: write baseline TSV (proto<TAB>local_addr:port) to
#            /var/lib/selfdef/listening-ports-baseline.tsv +
#            emit 'baseline_initial'.
# Subsequent: diff current listen-set against baseline; emit
#            per-class events for added / removed listeners.
#
# Severity:
#   ok    → no delta
#   warn  → 1..2 added listeners
#   alert → 3+ added listeners (mass-backdoor / scan-listener)
#
# A NEW listening port is one of the highest-signal indicators
# of a backdoor, reverse-shell listener, or unauthorized
# service. Removed listeners are operator-cleanup (never alert).

set -u

PROFILE="${SELFDEF_LISTENPORTS_PROFILE:-report}"
BASELINE="${SELFDEF_LISTENPORTS_BASELINE:-/var/lib/selfdef/listening-ports-baseline.tsv}"

# Normalize the listen-set: proto + local addr:port, sorted
# unique. We deliberately ignore the ephemeral peer side and
# the PID (PIDs churn across reboots; the port is the stable
# identity). -H omits the header; -n numeric; -l listening;
# -t tcp -u udp; -p adds process (used in detail only).
current="$(mktemp)"
trap 'rm -f "$current"' EXIT

{
    ss -Hnlt 2>/dev/null | awk '{print "tcp\t" $4}'
    ss -Hnlu 2>/dev/null | awk '{print "udp\t" $4}'
} | sort -u > "$current"

# Detail map: proto addr:port -> process (for the detail log).
detail_map="$(mktemp)"
trap 'rm -f "$current" "$detail_map"' EXIT
{
    ss -Hnltp 2>/dev/null | awk '{print "tcp " $4 " " $NF}'
    ss -Hnlup 2>/dev/null | awk '{print "udp " $4 " " $NF}'
} > "$detail_map" 2>/dev/null || true

cur_count=$(wc -l < "$current" | tr -d ' ')

# First run: baseline.
if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    json=$(printf '{"tag":"selfdef-listening-ports","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")
    logger -t selfdef-listening-ports -- "$json"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))

n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="no_delta"
if (( n_added > 0 )); then
    if (( n_added >= 3 )); then
        severity="alert"; event="mass_new_listeners"
    else
        severity="warn"; event="new_listener"
    fi
fi

added_sample=$(printf '%s' "$added"   | head -8 | tr '\n' '|' | sed 's/\t/ /g')
removed_sample=$(printf '%s' "$removed" | head -8 | tr '\n' '|' | sed 's/\t/ /g')

json=$(printf '{"tag":"selfdef-listening-ports","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$added_sample" "$removed_sample")
logger -t selfdef-listening-ports -- "$json"

# Per-finding detail with the owning process where ss could
# resolve it.
if [[ -n "$added" ]]; then
    printf '%s\n' "$added" | while IFS=$'\t' read -r proto addrport; do
        [[ -z "$proto" ]] && continue
        proc=$(grep -F " ${addrport} " "$detail_map" 2>/dev/null | head -1 | sed 's/.*users:/users:/')
        logger -t selfdef-listening-ports-detail -- "ADDED ${proto} ${addrport} ${proc}"
    done
fi
if [[ -n "$removed" ]]; then
    printf '%s\n' "$removed" | while IFS=$'\t' read -r proto addrport; do
        [[ -z "$proto" ]] && continue
        logger -t selfdef-listening-ports-detail -- "REMOVED ${proto} ${addrport}"
    done
fi

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
