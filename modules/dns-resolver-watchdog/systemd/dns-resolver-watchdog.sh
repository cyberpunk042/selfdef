#!/usr/bin/env bash
# selfdef dns-resolver-watchdog — daily + boot delta of the
# active DNS resolver configuration vs a learned baseline.
#
# Records (each line: class<TAB>value):
#   nameserver:<ip>          — each nameserver in resolv.conf
#   search:<domain>          — each search domain
#   resolved:<ip>            — systemd-resolved upstream (if used)
#   hosts_overrides:<count>  — non-comment /etc/hosts line count
#
# A CHANGED nameserver is the DNS-hijack signature: an attacker
# repoints name resolution to a resolver they control to MITM
# package downloads, TLS (via fake CA + hijacked OCSP), or to
# redirect C2 callbacks.
#
# Severity:
#   ok    → no delta
#   warn  → search-domain or hosts-override change
#   alert → nameserver added/changed (the hijack signature)

set -u

PROFILE="${SELFDEF_DNSRES_PROFILE:-report}"
BASELINE="${SELFDEF_DNSRES_BASELINE:-/var/lib/selfdef/dns-resolver-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

{
    # resolv.conf may be a symlink to systemd-resolved's stub; we
    # read the effective file either way.
    RESOLV="/etc/resolv.conf"
    if [[ -r "$RESOLV" ]]; then
        awk '/^nameserver/ {print "nameserver\t" $2}
             /^search/     {for(i=2;i<=NF;i++) print "search\t" $i}' "$RESOLV"
    fi

    # systemd-resolved actual upstreams (the stub 127.0.0.53 hides
    # the real servers; resolvectl shows them).
    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl dns 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-fA-F:]+:+)+[0-9a-fA-F]+' \
            | sort -u | while IFS= read -r ip; do
                [[ -n "$ip" ]] && printf 'resolved\t%s\n' "$ip"
            done
    fi

    # /etc/hosts override count (a sudden jump = mass-hijack via
    # hosts entries, the poor-man's DNS redirect).
    if [[ -r /etc/hosts ]]; then
        hc=$(grep -cvE '^\s*(#|$)' /etc/hosts 2>/dev/null || echo 0)
        printf 'hosts_overrides\t%s\n' "$hc"
    fi
} | sort -u > "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    json=$(printf '{"tag":"selfdef-dns-resolver","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")
    logger -t selfdef-dns-resolver -- "$json"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))

n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
n_ns_change=$(printf '%s' "$added" | grep -cE '^(nameserver|resolved)' || true)

severity="ok"; event="no_delta"
if (( n_ns_change > 0 )); then
    severity="alert"; event="nameserver_changed"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="resolver_config_changed"
fi

added_sample=$(printf '%s' "$added"   | head -8 | tr '\n' '|' | sed 's/\t/:/g')
removed_sample=$(printf '%s' "$removed" | head -8 | tr '\n' '|' | sed 's/\t/:/g')

json=$(printf '{"tag":"selfdef-dns-resolver","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"nameserver_changes":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$n_ns_change" "$added_sample" "$removed_sample")
logger -t selfdef-dns-resolver -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r c v; do [[ -n "$c" ]] && logger -t selfdef-dns-resolver-detail -- "ADDED ${c} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r c v; do [[ -n "$c" ]] && logger -t selfdef-dns-resolver-detail -- "REMOVED ${c} ${v}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 || n_removed > 0 )); then
    exit 1
fi
exit 0
