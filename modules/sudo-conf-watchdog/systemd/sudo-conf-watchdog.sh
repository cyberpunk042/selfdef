#!/usr/bin/env bash
# selfdef sudo-conf-watchdog — boot + daily delta of /etc/sudo.conf
# vs a learned baseline + ownership + Plugin/Path scan.
#
# sudo (SETUID-ROOT) loads its policy and I/O-logging plugins (.so)
# named in /etc/sudo.conf:
#   Plugin <symbol> <path> [args]   — e.g. Plugin sudoers_policy sudoers.so
#   Path plugin_dir <dir>           — where relative Plugin names resolve
# A planted `Plugin policy /tmp/evil.so` — or a `Path plugin_dir`
# pointing at a writable dir so a relative plugin name resolves there
# — loads attacker code into setuid-root sudo on EVERY sudo
# invocation (T1574 hijack execution flow / privilege escalation).
# Distinct from the sudoers watchdogs (rule content in
# /etc/sudoers): this is the sudo plugin-load surface.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>          — hash of /etc/sudo.conf
#   own:<path>:<owner:mode>      — owner + mode
#   plugin:<path>:<name>:<so>    — each Plugin line
#   pathdir:<path>:<name>:<dir>  — each Path line
#
# Severity:
#   ok    → no delta
#   warn  → a directive / file added / changed / removed
#   alert → file world-writable/non-root, OR a Plugin .so / plugin_dir
#           under /tmp /var/tmp /dev/shm /home, OR a relative-with-slash
#           Plugin path

set -u

PROFILE="${SELFDEF_SUDOCONF_PROFILE:-report}"
BASELINE="${SELFDEF_SUDOCONF_BASELINE:-/var/lib/selfdef/sudo-conf-baseline.tsv}"
if [[ -n "${SELFDEF_SUDOCONF_FILES:-}" ]]; then
    read -r -a FILES <<< "${SELFDEF_SUDOCONF_FILES}"
else
    FILES=(/etc/sudo.conf)
fi

is_writable_path() {
    [[ "$1" =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]
}

files=()
for f in "${FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-sudo-conf -- '{"tag":"selfdef-sudo-conf","severity":"ok","event":"no_sudo_conf","profile":"'"$PROFILE"'"}'
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
        read -r kw a b _rest <<< "$line"
        case "$kw" in
            [Pp]lugin)
                # a=symbol name, b=.so path
                [[ -z "$b" ]] && continue
                printf 'plugin\t%s\t%s:%s\n' "$f" "$a" "$b" >> "$current"
                if is_writable_path "$b"; then
                    suspicious+=("${base}:plugin-writable($a=$b)")
                elif [[ "$b" == */* && "$b" != /* ]]; then
                    suspicious+=("${base}:plugin-relative-path($a=$b)")
                fi
                ;;
            [Pp]ath)
                # a=name (e.g. plugin_dir), b=value
                [[ -z "$b" ]] && continue
                printf 'pathdir\t%s\t%s:%s\n' "$f" "$a" "$b" >> "$current"
                if [[ "$a" == "plugin_dir" ]] && is_writable_path "$b"; then
                    suspicious+=("${base}:plugin_dir-writable($b)")
                fi
                ;;
        esac
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
    logger -t selfdef-sudo-conf -- "$(printf '{"tag":"selfdef-sudo-conf","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="sudo_conf_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="sudo_conf_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="sudo_conf_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-sudo-conf","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-sudo-conf -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sudo-conf-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sudo-conf-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
