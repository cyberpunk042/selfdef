#!/usr/bin/env bash
# selfdef crypttab-watchdog — boot + daily delta of /etc/crypttab
# vs a learned baseline + ownership + keyscript/keyfile scan.
#
# crypttab format: <target> <source> <keyfile> <options>
# The `keyscript=` option runs a program AS ROOT at early boot to
# obtain the volume key:
#
#   data /dev/sda2 none luks,keyscript=/tmp/.getkey   # root exec at boot
#
# A rogue keyscript is root-exec-at-boot persistence; a keyfile
# under a writable path is key theft / substitution (T1037/T1552).
#
# Records (each line: kind<TAB>target<TAB>value):
#   file:<path>:<sha12>       — hash of crypttab
#   own:<path>:<owner:mode>   — owner + mode
#   crypt:<target>:<src>|<keyfile>|<keyscript>  — each entry
#
# Severity:
#   ok    → no delta
#   warn  → an entry / file added, removed, or changed
#   alert → a keyscript or keyfile under /tmp /home /dev/shm,
#           world-writable, or bare/relative; or a world-writable/
#           non-root crypttab

set -u

PROFILE="${SELFDEF_CRYPTTAB_PROFILE:-report}"
BASELINE="${SELFDEF_CRYPTTAB_BASELINE:-/var/lib/selfdef/crypttab-baseline.tsv}"
CRYPTTAB="${SELFDEF_CRYPTTAB_FILE:-/etc/crypttab}"

is_suspicious_path() {
    local p="$1"
    case "$p" in
        none|""|-) return 1 ;;
        /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) return 0 ;;
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        ./*|../*|*/*) return 0 ;;
        *) return 0 ;;   # bare keyscript path is abnormal
    esac
}

if [[ ! -f "$CRYPTTAB" ]]; then
    logger -t selfdef-crypttab -- '{"tag":"selfdef-crypttab","severity":"ok","event":"no_crypttab","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

h=$(sha256sum "$CRYPTTAB" 2>/dev/null | awk '{print substr($1,1,12)}')
printf 'file\t%s\t%s\n' "$CRYPTTAB" "$h" >> "$current"
owner=$(stat -c '%U' "$CRYPTTAB" 2>/dev/null || echo '?')
mode=$(stat -c '%a' "$CRYPTTAB" 2>/dev/null || echo '?')
printf 'own\t%s\t%s\n' "$CRYPTTAB" "${owner}:${mode}" >> "$current"
if [[ "$mode" =~ [2367]$ ]]; then
    suspicious+=("crypttab:world-writable($mode)")
elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
    suspicious+=("crypttab:owned-by-$owner")
fi

while IFS= read -r line; do
    line="${line%%#*}"
    read -r -a F <<< "$line"
    [[ ${#F[@]} -lt 2 ]] && continue
    target="${F[0]}"; src="${F[1]}"; keyfile="${F[2]:-none}"; opts="${F[3]:-}"
    keyscript=""
    case "$opts" in
        *keyscript=*) keyscript=$(printf '%s' "$opts" | sed -E 's/.*keyscript=//; s/,.*//') ;;
    esac
    printf 'crypt\t%s\t%s|%s|%s\n' "$target" "$src" "$keyfile" "${keyscript:-none}" >> "$current"
    [[ -n "$keyscript" ]] && is_suspicious_path "$keyscript" && suspicious+=("${target}:keyscript=>${keyscript}")
    is_suspicious_path "$keyfile" && suspicious+=("${target}:keyfile=>${keyfile}")
done < "$CRYPTTAB"

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
    logger -t selfdef-crypttab -- "$(printf '{"tag":"selfdef-crypttab","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="crypttab_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="crypttab_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="crypttab_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-crypttab","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-crypttab -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-crypttab-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-crypttab-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
