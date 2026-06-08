#!/usr/bin/env bash
# selfdef inittab-watchdog — boot + daily delta of the SysV init
# config vs a learned baseline + ownership + process scan.
#
# On SysV/upstart init, an /etc/inittab line —
#   id:runlevels:action:process
#   x1:5:respawn:/tmp/.payload      # runs as root at boot, RE-SPAWNS
# — runs the process as root and (with `respawn`) restarts it if it
# exits: self-healing boot persistence (T1037). The exec actions are
# respawn / once / wait / boot / bootwait / sysinit. (ctrlaltdel,
# initdefault, off carry no persistence payload.)
#
# Records (each line: kind<TAB>key<TAB>value):
#   file:<path>:<sha12>            — hash of inittab / upstart conf
#   own:<path>:<owner:mode>        — owner + mode
#   inittab:<id>:<action>:<prog>   — each exec entry's process (1st tok)
#
# Severity:
#   ok    → no delta
#   warn  → an entry / file added, removed, or changed
#   alert → an exec process under /tmp /home /dev/shm, world-writable,
#           or bare/relative; an injection pattern; or a
#           world-writable/non-root inittab

set -u

PROFILE="${SELFDEF_INITTAB_PROFILE:-report}"
BASELINE="${SELFDEF_INITTAB_BASELINE:-/var/lib/selfdef/inittab-baseline.tsv}"
INITTAB="${SELFDEF_INITTAB_FILE:-/etc/inittab}"
UPSTART_D="${SELFDEF_INITTAB_UPSTART:-/etc/init}"

PATTERNS='curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|/dev/tcp/|bash[[:space:]]+-i|base64[[:space:]]+-d|mkfifo'

# SDD-063: consume the shared writable-location policy from module-lib.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-inittab -- '{"tag":"selfdef-inittab","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 4 ]]; then
    logger -t selfdef-inittab -- '{"tag":"selfdef-inittab","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

is_suspicious_prog() {
    local p="$1"
    selfdef_is_writable_dir "$p" && return 0
    case "$p" in
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        ""|@*) return 1 ;;
        ./*|../*|*/*) return 0 ;;
        *) return 0 ;;   # bare program in inittab is abnormal
    esac
}

files=()
[[ -f "$INITTAB" ]] && files+=("$INITTAB")
if [[ -d "$UPSTART_D" ]]; then
    for f in "$UPSTART_D"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-inittab -- '{"tag":"selfdef-inittab","severity":"ok","event":"no_inittab","profile":"'"$PROFILE"'"}'
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
    case "$f" in
        "$INITTAB")
            # id:runlevels:action:process  (4 colon-fields, process may
            # itself contain spaces/args)
            while IFS= read -r line; do
                line="${line%%#*}"
                [[ "$line" == *:*:*:* ]] || continue
                IFS=':' read -r id rl action rest <<< "$line"
                action="${action//[[:space:]]/}"
                case "$action" in
                    respawn|once|wait|boot|bootwait|sysinit|powerwait|powerfail) ;;
                    *) continue ;;   # initdefault/ctrlaltdel/off — no payload
                esac
                proc="$(printf '%s' "$rest" | sed -e 's/^[[:space:]]*//')"
                prog="${proc%% *}"
                [[ -z "$prog" ]] && continue
                printf 'inittab\t%s\t%s:%s\n' "$id" "$action" "$prog" >> "$current"
                is_suspicious_prog "$prog" && suspicious+=("${id}:${action}=>${prog}")
                printf '%s\n' "$proc" | grep -qE "$PATTERNS" && suspicious+=("${id}:payload")
            done < "$f"
            ;;
        *)
            # upstart job: exec / script lines run as root
            while IFS= read -r m; do
                cmd=$(printf '%s' "$m" | sed -E 's/^[[:space:]]*exec[[:space:]]+//')
                prog="${cmd%% *}"
                [[ -z "$prog" ]] && continue
                printf 'inittab\t%s\t%s:%s\n' "$(basename "$f")" "exec" "$prog" >> "$current"
                is_suspicious_prog "$prog" && suspicious+=("$(basename "$f"):exec=>${prog}")
            done < <(grep -E '^[[:space:]]*exec[[:space:]]' "$f" 2>/dev/null)
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
    logger -t selfdef-inittab -- "$(printf '{"tag":"selfdef-inittab","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="inittab_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="inittab_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="inittab_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-inittab","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-inittab -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-inittab-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-inittab-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
