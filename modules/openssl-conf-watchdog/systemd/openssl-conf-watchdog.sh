#!/usr/bin/env bash
# selfdef openssl-conf-watchdog — boot + daily delta of the OpenSSL
# config vs a learned baseline + ownership + engine/provider-module
# scan.
#
# OpenSSL loads code from this config, which is read by EVERY
# OpenSSL-using process (openssl CLI, curl, wget, libcrypto/libssl
# daemons):
#   dynamic_path = /path/engine.so     (ENGINE, OpenSSL 1.x)
#   module       = /path/provider.so   (PROVIDER, OpenSSL 3.x)
#   .include       /path/extra.cnf      (pulls in another config)
# searched in /etc/ssl/openssl.cnf, /etc/pki/tls/openssl.cnf,
# /usr/lib/ssl/openssl.cnf. A planted dynamic_path/module pointing at
# a writable/attacker .so loads attacker code into all of them — a
# near-ubiquitous code-execution foothold (T1574 hijack execution
# flow). Distinct from ld-preload-watchdog, pkcs11-modules-watchdog,
# and gss-mech-watchdog.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each config
#   own:<path>:<owner:mode>  — owner + mode
#   dynpath:<path>:<so>      — ENGINE dynamic_path .so
#   module:<path>:<so>       — PROVIDER module .so
#   include:<path>:<inc>     — .include target
#
# Severity:
#   ok    → no delta
#   warn  → a config / directive added / changed / removed
#   alert → a config world-writable/non-root, OR a dynamic_path/module/
#           .include under /tmp /var/tmp /dev/shm /home or
#           relative-with-slash

set -u

PROFILE="${SELFDEF_OPENSSL_PROFILE:-report}"
BASELINE="${SELFDEF_OPENSSL_BASELINE:-/var/lib/selfdef/openssl-conf-baseline.tsv}"

# SDD-061 D-6: consume the shared writable-location policy
# (selfdef_is_writable_path) from module-lib instead of a per-module copy.
# Co-shipped by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl
# exports SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a
# real misconfiguration that would leave the watchdog scanning with a
# divergent policy, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-openssl-conf -- '{"tag":"selfdef-openssl-conf","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-openssl-conf -- '{"tag":"selfdef-openssl-conf","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
if [[ -n "${SELFDEF_OPENSSL_FILES:-}" ]]; then
    read -r -a RAW_FILES <<< "${SELFDEF_OPENSSL_FILES}"
else
    RAW_FILES=(/etc/ssl/openssl.cnf /etc/pki/tls/openssl.cnf /usr/lib/ssl/openssl.cnf)
fi

flag_path() {
    local p="$1"
    if selfdef_is_writable_path "$p"; then echo "writable"
    elif [[ "$p" == */* && "$p" != /* ]]; then echo "relative"; fi
}

# De-dup by resolved real path (/usr/lib/ssl/openssl.cnf often -> /etc/ssl).
declare -A seen=()
files=()
for f in "${RAW_FILES[@]}"; do
    [[ -f "$f" ]] || continue
    rp=$(readlink -f "$f" 2>/dev/null || echo "$f")
    [[ -n "${seen[$rp]:-}" ]] && continue
    seen[$rp]=1
    files+=("$f")
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-openssl-conf -- '{"tag":"selfdef-openssl-conf","severity":"ok","event":"no_openssl_conf","profile":"'"$PROFILE"'"}'
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
    # dynamic_path = <engine.so>  and  module = <provider.so>
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        key="${line%%=*}"; key="$(printf '%s' "$key" | tr -d '[:space:]')"
        val="${line#*=}"
        val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
        [[ -z "$val" ]] && continue
        case "$key" in
            dynamic_path)
                printf 'dynpath\t%s\t%s\n' "$f" "$val" >> "$current"
                r=$(flag_path "$val"); [[ -n "$r" ]] && suspicious+=("${base}:dynamic_path-${r}($val)")
                ;;
            module)
                printf 'module\t%s\t%s\n' "$f" "$val" >> "$current"
                r=$(flag_path "$val"); [[ -n "$r" ]] && suspicious+=("${base}:module-${r}($val)")
                ;;
        esac
    done < <(grep -iE '^[[:space:]]*(dynamic_path|module)[[:space:]]*=' "$f" 2>/dev/null || true)
    # .include <path>  (or .include = <path>)
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        inc=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*\.include[[:space:]]*=?[[:space:]]*//I')
        inc="${inc#"${inc%%[![:space:]]*}"}"; inc="${inc%"${inc##*[![:space:]]}"}"
        [[ -z "$inc" ]] && continue
        printf 'include\t%s\t%s\n' "$f" "$inc" >> "$current"
        r=$(flag_path "$inc"); [[ -n "$r" ]] && suspicious+=("${base}:include-${r}($inc)")
    done < <(grep -iE '^[[:space:]]*\.include' "$f" 2>/dev/null || true)
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
    logger -t selfdef-openssl-conf -- "$(printf '{"tag":"selfdef-openssl-conf","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="openssl_conf_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="openssl_conf_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="openssl_conf_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-openssl-conf","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-openssl-conf -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-openssl-conf-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-openssl-conf-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
