#!/usr/bin/env bash
# selfdef xinetd-watchdog — boot + daily delta of the (x)inetd
# super-server service definitions vs a learned baseline.
#
# xinetd/inetd launch the configured server program AS the
# configured user (often root) on each inbound connection to the
# service's port. A rogue or tampered service definition is
# network-triggered root-exec persistence (T1543):
#
#   # /etc/xinetd.d/backdoor
#   service backdoor { type=UNLISTED port=4444 socket_type=stream
#       protocol=tcp wait=no user=root server=/bin/bash disable=no }
#
#   # /etc/inetd.conf
#   4444 stream tcp nowait root /bin/bash bash -i
#
# Watched: /etc/xinetd.d/*  /etc/xinetd.conf  /etc/inetd.conf
#
# Records (each line: kind<TAB>key<TAB>value):
#   file:<path>:<sha12>       — hash of each config file
#   own:<path>:<owner:mode>   — owner + mode
#   xinetd:<svc>:<server>     — an xinetd service's server program
#   inetd:<svc>:<user>:<srv>  — an inetd line's user + server
#
# Severity:
#   ok    → no delta
#   warn  → a service / file added, removed, or changed
#   alert → a server path under /tmp /home /dev/shm or world-
#           writable, OR a world-writable / non-root config file

set -u

PROFILE="${SELFDEF_XINETD_PROFILE:-report}"
BASELINE="${SELFDEF_XINETD_BASELINE:-/var/lib/selfdef/xinetd-baseline.tsv}"
XINETD_D="${SELFDEF_XINETD_D:-/etc/xinetd.d}"
XINETD_CONF="${SELFDEF_XINETD_CONF:-/etc/xinetd.conf}"
INETD_CONF="${SELFDEF_INETD_CONF:-/etc/inetd.conf}"

# SDD-063: consume the shared writable-location policy from module-lib.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-xinetd -- '{"tag":"selfdef-xinetd","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 4 ]]; then
    logger -t selfdef-xinetd -- '{"tag":"selfdef-xinetd","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

is_suspicious_path() {
    local p="$1"
    selfdef_is_writable_dir "$p" && return 0
    case "$p" in
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        *) return 1 ;;  # inetd/xinetd server is normally absolute
    esac
}

files=()
if [[ -d "$XINETD_D" ]]; then
    for f in "$XINETD_D"/*; do [[ -f "$f" ]] && files+=("$f"); done
fi
[[ -f "$XINETD_CONF" ]] && files+=("$XINETD_CONF")
[[ -f "$INETD_CONF" ]] && files+=("$INETD_CONF")

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-xinetd -- '{"tag":"selfdef-xinetd","severity":"ok","event":"no_super_server","profile":"'"$PROFILE"'"}'
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
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("$(basename "$f"):owned-by-$owner")
    fi
    case "$f" in
        "$INETD_CONF")
            # inetd.conf: service socktype proto flags user server args
            while IFS= read -r line; do
                line="${line%%#*}"
                read -r -a F <<< "$line"
                [[ ${#F[@]} -lt 6 ]] && continue
                svc="${F[0]}"; usr="${F[4]}"; srv="${F[5]}"
                printf 'inetd\t%s\t%s:%s\n' "$svc" "$usr" "$srv" >> "$current"
                is_suspicious_path "$srv" && suspicious+=("inetd ${svc}:server=${srv}")
            done < "$f"
            ;;
        *)
            # xinetd: extract the `server = /path` directive value.
            # Anchor on the server token (line start, whitespace, or
            # `{`) so the COMPACT one-line block form is caught too,
            # and pull only the value after THIS directive's `=`.
            while IFS= read -r m; do
                srv=$(printf '%s' "$m" | sed -E 's/.*=[[:space:]]*//')
                [[ -z "$srv" ]] && continue
                printf 'xinetd\t%s\t%s\n' "$(basename "$f")" "$srv" >> "$current"
                is_suspicious_path "$srv" && suspicious+=("$(basename "$f"):server=${srv}")
            done < <(grep -oiE '(^|[[:space:]{])server[[:space:]]*=[[:space:]]*[^[:space:]}]+' "$f" 2>/dev/null)
            ;;
    esac
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
    logger -t selfdef-xinetd -- "$(printf '{"tag":"selfdef-xinetd","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="xinetd_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="xinetd_suspicious_server"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="xinetd_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-xinetd","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-xinetd -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-xinetd-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-xinetd-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
