#!/usr/bin/env bash
# selfdef limits-conf-watchdog — boot + daily delta of the
# pam_limits resource-limit config vs a learned baseline.
#
# /etc/security/limits.conf (+ limits.d/*) set per-login resource
# limits via pam_limits. The security-relevant case: an attacker
# who RE-ENABLES core dumps —
#
#   * hard core unlimited        # revert coredump-suid hardening
#
# — undoes the coredump-suid-restrict protection and re-opens
# memory-secret harvesting (a setuid binary's core dump routinely
# contains credentials/keys it was handling; T1005). Loosening
# nproc / nofile / maxlogins enables fork-bomb / fd-exhaustion /
# multi-session abuse.
#
# Records (each line: kind<TAB>key<TAB>value):
#   limit:<domain>:<type>:<item>:<value>  — each parsed limit
#   file:<path>:<sha12>                   — hash of each conf file
#
# Severity:
#   ok    → no delta
#   warn  → any limit / file added, removed, or changed
#   alert → a NEWLY-ADDED limit that re-enables core dumps (item
#           `core`, value not 0). Pre-existing core values are
#           flagged once at baseline, then not re-alerted.

set -u

PROFILE="${SELFDEF_LIMITS_PROFILE:-report}"
BASELINE="${SELFDEF_LIMITS_BASELINE:-/var/lib/selfdef/limits-conf-baseline.tsv}"
LIMITS="${SELFDEF_LIMITS_FILE:-/etc/security/limits.conf}"
LIMITSD="${SELFDEF_LIMITS_D:-/etc/security/limits.d}"

files=()
[[ -f "$LIMITS" ]] && files+=("$LIMITS")
if [[ -d "$LIMITSD" ]]; then
    for f in "$LIMITSD"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-limits-conf -- '{"tag":"selfdef-limits-conf","severity":"ok","event":"no_limits_conf","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

# A core value that is NOT zero re-enables dumping.
core_enabled_val() { [[ "$1" != "0" ]]; }

declare -a suspicious=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    while IFS= read -r line; do
        line="${line%%#*}"
        # fields: domain type item value. Use read -ra (NOT
        # `set -- $line`) — the `*` domain (the common case) would
        # glob-expand against the cwd under word-splitting.
        read -r -a F <<< "$line"
        [[ ${#F[@]} -lt 4 ]] && continue
        dom="${F[0]}"; typ="${F[1]}"; item="${F[2],,}"; val="${F[3],,}"
        printf 'limit\t%s:%s:%s\t%s\n' "$dom" "$typ" "$item" "$val" >> "$current"
        if [[ "$item" == "core" ]] && core_enabled_val "$val"; then
            suspicious+=("core-reenabled:${dom}:${typ}=${val}")
        fi
    done < "$f"
done

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
    logger -t selfdef-limits-conf -- "$(printf '{"tag":"selfdef-limits-conf","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# A core re-enable is the hardening-revert signature only when
# NEWLY ADDED — a pre-existing legit `core unlimited` lives in the
# baseline and must not re-alert. Scan the ADDED set.
new_core=$(printf '%s' "$added" | awk -F'\t' '$1=="limit" && $2 ~ /:core$/ && $3!="0" {print "core-reenabled:"$2"="$3}')
suspicious=()
[[ -n "$new_core" ]] && mapfile -t suspicious <<< "$new_core"

severity="ok"; event="limits_conf_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="limits_conf_core_reenabled"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="limits_conf_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-limits-conf","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-limits-conf -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-limits-conf-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-limits-conf-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
