#!/usr/bin/env bash
# selfdef dnf-plugins-watchdog — boot + daily delta of the dnf
# plugin config + post-transaction-actions vs a learned baseline.
#
# The dnf `post-transaction-actions` plugin runs a command AS ROOT
# after a matching package transaction (the RPM-side equivalent of
# apt's DPkg::Post-Invoke). Action files in
# /etc/dnf/plugins/post-transaction-actions.d/*.action use:
#
#   <package-glob>:<transaction-state>:<command>
#   *:in:/tmp/.payload                 # root, on the next dnf install
#
# A rogue .action is root-exec persistence triggered by any
# package change (T1546).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each plugin/action file
#   own:<path>:<owner:mode>  — owner + mode
#   action:<file>:<cmd0>     — each action command (first token)
#
# Severity:
#   ok    → no delta
#   warn  → a file / action added, removed, or changed
#   alert → an action command under /tmp /home /dev/shm, world-
#           writable, or bare/relative; an injection pattern; or a
#           world-writable/non-root file

set -u

PROFILE="${SELFDEF_DNFPLUG_PROFILE:-report}"
BASELINE="${SELFDEF_DNFPLUG_BASELINE:-/var/lib/selfdef/dnf-plugins-baseline.tsv}"
PLUGINS_D="${SELFDEF_DNFPLUG_D:-/etc/dnf/plugins}"
ACTIONS_D="${SELFDEF_DNFPLUG_ACTIONS:-/etc/dnf/plugins/post-transaction-actions.d}"

PATTERNS='curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|/dev/tcp/|bash[[:space:]]+-i|base64[[:space:]]+-d|mkfifo'

# SDD-063: consume the shared writable-location policy from module-lib.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-dnf-plugins -- '{"tag":"selfdef-dnf-plugins","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 4 ]]; then
    logger -t selfdef-dnf-plugins -- '{"tag":"selfdef-dnf-plugins","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

is_suspicious_cmd() {
    local p="$1"
    selfdef_is_writable_dir "$p" && return 0
    case "$p" in
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        "") return 1 ;;
        ./*|../*|*/*) return 0 ;;
        *) return 0 ;;   # bare command in a dnf action is abnormal
    esac
}

files=()
if [[ -d "$PLUGINS_D" ]]; then
    for f in "$PLUGINS_D"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
fi
declare -a action_files=()
if [[ -d "$ACTIONS_D" ]]; then
    for f in "$ACTIONS_D"/*.action; do [[ -f "$f" ]] && action_files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 && ${#action_files[@]} -eq 0 ]]; then
    logger -t selfdef-dnf-plugins -- '{"tag":"selfdef-dnf-plugins","severity":"ok","event":"no_dnf_plugins","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

# Plugin .conf files: hash + ownership (config, no exec).
for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    owner=$(stat -c '%U' "$f" 2>/dev/null || echo '?')
    mode=$(stat -c '%a' "$f" 2>/dev/null || echo '?')
    printf 'own\t%s\t%s\n' "$f" "${owner}:${mode}" >> "$current"
    [[ "$mode" =~ [2367]$ ]] && suspicious+=("$(basename "$f"):world-writable($mode)")
done

# .action files: hash + ownership + the exec command (3rd colon field).
for f in "${action_files[@]}"; do
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
    while IFS= read -r line; do
        line="${line%%#*}"
        [[ "$line" == *:*:* ]] || continue
        cmd="${line#*:}"; cmd="${cmd#*:}"
        cmd="$(printf '%s' "$cmd" | sed -e 's/^[[:space:]]*//')"
        prog="${cmd%% *}"
        [[ -z "$prog" ]] && continue
        printf 'action\t%s\t%s\n' "$(basename "$f")" "$prog" >> "$current"
        is_suspicious_cmd "$prog" && suspicious+=("$(basename "$f"):action=>${prog}")
        printf '%s\n' "$cmd" | grep -qE "$PATTERNS" && suspicious+=("$(basename "$f"):action-payload")
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
    logger -t selfdef-dnf-plugins -- "$(printf '{"tag":"selfdef-dnf-plugins","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="dnf_plugins_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="dnf_plugins_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="dnf_plugins_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-dnf-plugins","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-dnf-plugins -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dnf-plugins-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dnf-plugins-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
