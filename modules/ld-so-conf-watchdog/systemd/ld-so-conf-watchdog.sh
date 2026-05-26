#!/usr/bin/env bash
# selfdef ld-so-conf-watchdog — boot + daily delta of the
# dynamic-linker search-path configuration vs a learned
# baseline.
#
# /etc/ld.so.conf + /etc/ld.so.conf.d/*.conf list the
# directories ld.so searches for shared libraries. An
# attacker who adds a writable dir (e.g. /tmp, /opt/x) and
# drops a trojaned libc.so.6 / libssl.so there makes the
# linker prefer the malicious lib over the real one for any
# dynamically-linked program — a persistent SO-search-order
# hijack that survives reboot (unlike LD_PRELOAD env vars).
#
# Records (each line: kind<TAB>value):
#   path:<dir>          — each search-path directory listed
#   file:<conf>:<sha12> — hash of each conf file (catches an
#                         edit that doesn't change the dir set
#                         but e.g. reorders / adds include)
#
# A path entry that is WORLD-WRITABLE or under /tmp /home is
# flagged hard (an attacker-controllable library dir on the
# system linker path is game-over).
#
# Severity:
#   ok    → no delta
#   warn  → a conf hash changed / a normal path added
#   alert → a path added that is world-writable or under
#           /tmp /var/tmp /dev/shm /home, OR any path removed

set -u

PROFILE="${SELFDEF_LDSOCONF_PROFILE:-report}"
BASELINE="${SELFDEF_LDSOCONF_BASELINE:-/var/lib/selfdef/ld-so-conf-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

# Resolve the full set of conf files (ld.so.conf usually just
# 'include /etc/ld.so.conf.d/*.conf').
conf_files=()
[[ -f /etc/ld.so.conf ]] && conf_files+=(/etc/ld.so.conf)
if [[ -d /etc/ld.so.conf.d ]]; then
    for f in /etc/ld.so.conf.d/*.conf; do [[ -f "$f" ]] && conf_files+=("$f"); done
fi

declare -a suspicious=()
for f in "${conf_files[@]}"; do
    # file hash
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    # path entries (skip comments + include directives)
    while IFS= read -r line; do
        line="${line%%#*}"; line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        [[ "$line" == include* ]] && continue
        printf 'path\t%s\n' "$line" >> "$current"
        # suspicious if writable/tmp/home
        case "$line" in
            /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) suspicious+=("$line") ;;
            *) [[ -d "$line" && -w "$line" && "$(stat -c '%a' "$line" 2>/dev/null)" =~ [27]$ ]] && suspicious+=("$line") ;;
        esac
    done < "$f"
done

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp_str=$(IFS='|'; echo "${suspicious[*]:-}")
    sev="ok"; [[ ${#suspicious[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-ld-so-conf -- "$(printf '{"tag":"selfdef-ld-so-conf","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
path_removed=$(printf '%s' "$removed" | grep -c '^path' || true)

severity="ok"; event="ld_so_conf_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="ld_so_conf_writable_path"
elif (( path_removed > 0 )); then
    severity="alert"; event="ld_so_conf_path_removed"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="ld_so_conf_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-ld-so-conf","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-ld-so-conf -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k v h; do [[ -n "$k" ]] && logger -t selfdef-ld-so-conf-detail -- "ADDED ${k} ${v} ${h}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k v h; do [[ -n "$k" ]] && logger -t selfdef-ld-so-conf-detail -- "REMOVED ${k} ${v} ${h}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
