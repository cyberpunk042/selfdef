#!/usr/bin/env bash
# selfdef gss-mech-watchdog — boot + daily delta of the GSSAPI
# mechanism config vs a learned baseline + ownership +
# mechanism-path scan.
#
# Every GSSAPI consumer (Kerberized ssh/sshd, NFSv4 sec=krb5,
# OpenLDAP/SASL GSSAPI, sssd, curl --negotiate) loads the mechanism
# shared object named in field 3 of each line in:
#   /etc/gss/mech
#   /etc/gss/mech.d/*.conf
# Line format:  <oid_name> <oid> <mech.so> [options]
# e.g.          gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so
# A planted mech whose .so is a writable/attacker path loads attacker
# code into auth-handling processes (often root) when GSSAPI
# initializes (T1574 hijack execution flow / T1556 modify auth).
# Distinct from ld-preload/ld-so-conf/pkcs11-modules watchdogs.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>          — hash of each mech file
#   own:<path>:<owner:mode>      — owner + mode
#   mech:<path>:<oidname>:<so>   — each mechanism .so
#
# Severity:
#   ok    → no delta
#   warn  → a mechanism / file added / changed / removed
#   alert → a mech file world-writable/non-root, OR a mechanism .so
#           under /tmp /var/tmp /dev/shm /home or relative-with-slash

set -u

PROFILE="${SELFDEF_GSS_PROFILE:-report}"
BASELINE="${SELFDEF_GSS_BASELINE:-/var/lib/selfdef/gss-mech-baseline.tsv}"

# SDD-061 D-6: consume the shared writable-location policy
# (selfdef_is_writable_path) from module-lib instead of a per-module copy.
# Co-shipped by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl
# exports SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a
# real misconfiguration that would leave the watchdog scanning with a
# divergent policy, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-gss-mech -- '{"tag":"selfdef-gss-mech","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-gss-mech -- '{"tag":"selfdef-gss-mech","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
if [[ -n "${SELFDEF_GSS_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_GSS_DIRS}"
else
    DIRS=(/etc/gss/mech.d)
fi
if [[ -n "${SELFDEF_GSS_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_GSS_FILES}"
else
    EXTRA_FILES=(/etc/gss/mech)
fi

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-gss-mech -- '{"tag":"selfdef-gss-mech","severity":"ok","event":"no_gss_mech","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    owner=$(stat -L -c '%U' "$f" 2>/dev/null || echo '?')
    mode=$(stat -L -c '%a' "$f" 2>/dev/null || echo '?')
    printf 'own\t%s\t%s\n' "$f" "${owner}:${mode}" >> "$current"
    base="$(basename "$f")"
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("${base}:world-writable($mode)")
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("${base}:owned-by-$owner")
    fi
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        read -r oidname _oid so _rest <<< "$line"
        [[ -z "$so" ]] && continue
        printf 'mech\t%s\t%s:%s\n' "$f" "$oidname" "$so" >> "$current"
        if selfdef_is_writable_path "$so"; then
            suspicious+=("${base}:mech-writable($oidname=$so)")
        elif [[ "$so" == */* && "$so" != /* ]]; then
            suspicious+=("${base}:mech-relative-path($oidname=$so)")
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
    logger -t selfdef-gss-mech -- "$(printf '{"tag":"selfdef-gss-mech","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="gss_mech_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="gss_mech_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="gss_mech_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-gss-mech","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-gss-mech -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-gss-mech-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-gss-mech-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
