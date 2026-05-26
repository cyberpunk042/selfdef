#!/usr/bin/env bash
# selfdef hosts-file-watchdog — boot + daily entry-level delta of
# /etc/hosts vs a learned baseline.
#
# /etc/hosts is consulted BEFORE DNS (per the nsswitch `hosts:`
# order). An attacker who adds or edits an entry can silently
# MITM or blackhole name resolution host-wide:
#
#   echo '185.x.x.x  security.ubuntu.com'      >> /etc/hosts  # MITM updates
#   echo '0.0.0.0    security.debian.org'      >> /etc/hosts  # block patching
#   echo '10.0.0.9   github.com api.github.com' >> /etc/hosts  # redirect supply chain
#
# This is T1565.001 (Stored Data Manipulation) + T1562.001
# (Impair Defenses — blocking update infra). nsswitch-watchdog
# watches the resolver MAP; dns-resolver-watchdog records only
# the /etc/hosts line COUNT; THIS watches the actual ENTRIES, so
# a swap that keeps the count constant still surfaces.
#
# Records (each line: kind<TAB>key<TAB>value):
#   host:<ip>:<hostname>   — one per (ip, hostname) mapping
#
# A hostname matching the sensitive package/security/CA domain
# set is flagged hard — those should resolve via DNS, never be
# pinned in /etc/hosts.
#
# Severity:
#   ok    → no delta
#   warn  → any entry added / removed / changed
#   alert → an entry maps a sensitive package/security/CA domain
#           (regardless of IP — pinning or blackholing it is the
#           hijack signature)

set -u

PROFILE="${SELFDEF_HOSTS_PROFILE:-report}"
BASELINE="${SELFDEF_HOSTS_BASELINE:-/var/lib/selfdef/hosts-file-baseline.tsv}"
HOSTS="${SELFDEF_HOSTS_FILE:-/etc/hosts}"

# Sensitive domains that must resolve via DNS, never be pinned in
# /etc/hosts. A match (any IP) is the hijack/blackhole signature.
# Substring match against each hostname (case-insensitive).
SENSITIVE=(
    ".ubuntu.com" ".debian.org" "security.debian" ".fedoraproject.org"
    ".centos.org" ".rockylinux.org" ".almalinux.org" ".opensuse.org"
    "archive.ubuntu" "security.ubuntu" "deb.debian" "ports.ubuntu"
    ".docker.com" "docker.io" ".github.com" "githubusercontent"
    ".npmjs.org" "registry.npm" ".pypi.org" "pythonhosted"
    ".rubygems.org" "crates.io" ".gradle.org" "maven"
    ".letsencrypt.org" "acme-v02" ".digicert.com" "ocsp." "crl."
    "windowsupdate" ".microsoft.com" ".apple.com" "swscan"
    ".google.com" "dl.google" ".cloudflare.com"
)

if [[ ! -f "$HOSTS" ]]; then
    logger -t selfdef-hosts-file -- '{"tag":"selfdef-hosts-file","severity":"ok","event":"no_hosts_file","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

while IFS= read -r line; do
    line="${line%%#*}"
    # fields: <ip> <host> [host...]. read -ra (NOT `set -- $line`)
    # so a malformed hostname containing a glob char is not expanded
    # against the cwd.
    read -r -a F <<< "$line"
    [[ ${#F[@]} -lt 2 ]] && continue
    ip="${F[0]}"
    for hn in "${F[@]:1}"; do
        hnl="${hn,,}"
        printf 'host\t%s\t%s\n' "$ip" "$hnl" >> "$current"
        for s in "${SENSITIVE[@]}"; do
            if [[ "$hnl" == *"$s"* ]]; then
                suspicious+=("${hnl}@${ip}")
                break
            fi
        done
    done
done < "$HOSTS"

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if (( ${#suspicious[@]} > 0 )); then
    mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)
fi

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp_str=$(IFS='|'; echo "${suspicious[*]:-}")
    sev="ok"; [[ ${#suspicious[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-hosts-file -- "$(printf '{"tag":"selfdef-hosts-file","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="hosts_file_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="hosts_file_sensitive_pin"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="hosts_file_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $2"->"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $2"->"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-hosts-file","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-hosts-file -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k ip hn; do [[ -n "$k" ]] && logger -t selfdef-hosts-file-detail -- "ADDED ${ip} ${hn}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k ip hn; do [[ -n "$k" ]] && logger -t selfdef-hosts-file-detail -- "REMOVED ${ip} ${hn}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
