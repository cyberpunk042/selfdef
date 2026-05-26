#!/usr/bin/env bash
# selfdef mta-loopback-detect — verify SMTP listeners bind
# only loopback.
#
# Walks the listening TCP sockets on the SMTP-family ports
# (25 smtp, 465 smtps, 587 submission) and classifies each
# bind address as loopback (127.0.0.0/8, ::1) or exposed
# (0.0.0.0, ::, or a routable address).
#
# Severity:
#   ok    → no SMTP listener OR all SMTP listeners loopback-only
#   warn  → an SMTP port bound to a specific routable address
#           (intentional mail server — operator should confirm)
#   alert → an SMTP port bound to 0.0.0.0 or :: (wildcard —
#           open to the whole network; classic open-relay /
#           spam-cannon exposure)

set -u

PROFILE="${SELFDEF_MTA_PROFILE:-report}"

# Collect listening TCP sockets on SMTP-family ports.
listeners="$(mktemp)"
trap 'rm -f "$listeners"' EXIT
ss -Hnltp 2>/dev/null | awk '{print $4}' | while IFS= read -r addrport; do
    port="${addrport##*:}"
    case "$port" in
        25|465|587) echo "$addrport" ;;
    esac
done > "$listeners"

n_total=$(wc -l < "$listeners" | tr -d ' ')
n_loopback=0
n_exposed=0
n_wildcard=0
exposed_sample=()

while IFS= read -r addrport; do
    [[ -z "$addrport" ]] && continue
    addr="${addrport%:*}"
    case "$addr" in
        127.*|"[::1]"|::1|"127.0.0.1")
            n_loopback=$((n_loopback + 1)) ;;
        "0.0.0.0"|"*"|"[::]"|"::"|"[::ffff:0.0.0.0]")
            n_wildcard=$((n_wildcard + 1))
            (( ${#exposed_sample[@]} < 5 )) && exposed_sample+=("$addrport") ;;
        *)
            n_exposed=$((n_exposed + 1))
            (( ${#exposed_sample[@]} < 5 )) && exposed_sample+=("$addrport") ;;
    esac
done < "$listeners"

severity="ok"; event="no_smtp_or_loopback_only"
if (( n_wildcard > 0 )); then
    severity="alert"; event="smtp_wildcard_bind"
elif (( n_exposed > 0 )); then
    severity="warn"; event="smtp_routable_bind"
fi

sample=$(IFS='|'; echo "${exposed_sample[*]:-}")

json=$(printf '{"tag":"selfdef-mta-loopback","severity":"%s","event":"%s","profile":"%s","smtp_listeners":%d,"loopback":%d,"routable":%d,"wildcard":%d,"exposed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_total" "$n_loopback" "$n_exposed" "$n_wildcard" "$sample")
logger -t selfdef-mta-loopback -- "$json"

for e in "${exposed_sample[@]}"; do
    logger -t selfdef-mta-loopback-detail -- "EXPOSED ${e}"
done

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
