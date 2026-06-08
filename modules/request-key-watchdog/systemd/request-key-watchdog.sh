#!/usr/bin/env bash
# selfdef request-key-watchdog — boot + daily delta of the kernel
# key-upcall handler config vs a learned baseline.
#
# When the kernel needs a key instantiated (dns_resolver, NFS
# idmap, cifs.spnego, …), it upcalls request-key(8), which consults
# /etc/request-key.conf + /etc/request-key.d/*.conf and runs the
# matching CALLOUT PROGRAM AS ROOT. A rogue callout is root-exec on
# key request — a quiet, obscure persistence vector (T1546):
#
#   #op    type           desc  callout
#   create dns_resolver   *  *  /tmp/.evil %k   # runs as root on upcall
#
# Records (each line: kind<TAB>key<TAB>value):
#   file:<path>:<sha12>     — hash of each request-key config
#   own:<path>:<owner:mode> — owner + mode
#   callout:<type>:<prog>   — callout program (first token) per rule
#
# Severity:
#   ok    → no delta
#   warn  → a rule / file added, removed, or changed
#   alert → a callout program under /tmp /home /dev/shm, world-
#           writable, or bare/relative; or a world-writable/non-root
#           config file

set -u

PROFILE="${SELFDEF_REQKEY_PROFILE:-report}"
BASELINE="${SELFDEF_REQKEY_BASELINE:-/var/lib/selfdef/request-key-baseline.tsv}"
CONF="${SELFDEF_REQKEY_FILE:-/etc/request-key.conf}"
CONFD="${SELFDEF_REQKEY_D:-/etc/request-key.d}"

# SDD-063: consume the shared writable-location policy from module-lib.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-request-key -- '{"tag":"selfdef-request-key","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 4 ]]; then
    logger -t selfdef-request-key -- '{"tag":"selfdef-request-key","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

is_suspicious_prog() {
    local p="$1"
    selfdef_is_writable_dir "$p" && return 0
    case "$p" in
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        "") return 1 ;;
        ./*|../*|*/*) return 0 ;;   # relative path with slash — abnormal
        *) return 1 ;;              # bare name (negate, pipe, …) — request-key
                                    # keywords; not a payload path
    esac
}

files=()
[[ -f "$CONF" ]] && files+=("$CONF")
if [[ -d "$CONFD" ]]; then
    for f in "$CONFD"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-request-key -- '{"tag":"selfdef-request-key","severity":"ok","event":"no_request_key","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    owner=$(stat -c '%U' "$f" 2>/dev/null || echo '?')
    mode=$(stat -c '%a' "$f" 2>/dev/null || echo '?')
    printf 'own\t%s\t%s\n' "$f" "${owner}:${mode}" >> "$current"
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("$(basename "$f"):world-writable($mode)")
    elif [[ "$owner" != "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}" && "$owner" != "?" ]]; then
        suspicious+=("$(basename "$f"):owned-by-$owner")
    fi
    # Rule format: op type description callout-program [args...]
    while IFS= read -r line; do
        line="${line%%#*}"
        read -r -a F <<< "$line"
        # 5 columns: op type description callout-info program [args].
        # The callout PROGRAM is index 4 (index 3 is callout-info, often `*`).
        [[ ${#F[@]} -lt 5 ]] && continue
        rtype="${F[1]}"; prog="${F[4]}"
        printf 'callout\t%s\t%s\n' "$rtype" "$prog" >> "$current"
        is_suspicious_prog "$prog" && suspicious+=("${rtype}:callout=>${prog}")
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
    logger -t selfdef-request-key -- "$(printf '{"tag":"selfdef-request-key","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="request_key_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="request_key_suspicious_callout"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="request_key_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-request-key","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-request-key -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-request-key-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-request-key-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
