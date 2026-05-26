#!/usr/bin/env bash
# selfdef xorg-config-watchdog — boot + daily delta of the X server
# config vs a learned baseline + ownership + ModulePath/Load scan.
#
# On non-rootless setups the X server runs AS ROOT and loads modules
# (.so) from:
#   Section "Files"  -> ModulePath "<dir[,dir...]>"
#   Section "Module" -> Load "<modulename>"
# in /etc/X11/xorg.conf and /etc/X11/xorg.conf.d/*.conf. A planted
# config with a ModulePath under a writable/attacker location loads
# attacker code into the root X server at the next server start
# (T1574 hijack execution flow / T1547). Distinct from
# xsession-watchdog (user-context session scripts) and
# display-manager-hooks-watchdog (DM root login scripts).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>        — hash of each .conf
#   own:<path>:<owner:mode>    — owner + mode
#   modpath:<path>:<dir>       — each ModulePath entry
#   load:<path>:<module>       — each Load entry
#
# Severity:
#   ok    → no delta
#   warn  → a config / directive added / changed / removed
#   alert → a .conf world-writable/non-root, OR a ModulePath under
#           /tmp /var/tmp /dev/shm /home or a relative (non-absolute)
#           ModulePath

set -u

PROFILE="${SELFDEF_XORG_PROFILE:-report}"
BASELINE="${SELFDEF_XORG_BASELINE:-/var/lib/selfdef/xorg-config-baseline.tsv}"
if [[ -n "${SELFDEF_XORG_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_XORG_DIRS}"
else
    DIRS=(/etc/X11/xorg.conf.d)
fi
if [[ -n "${SELFDEF_XORG_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_XORG_FILES}"
else
    EXTRA_FILES=(/etc/X11/xorg.conf)
fi

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-xorg-config -- '{"tag":"selfdef-xorg-config","severity":"ok","event":"no_xorg_config","profile":"'"$PROFILE"'"}'
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
    # ModulePath: directory list the root X server loads .so from.
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        val=$(printf '%s' "$line" | sed -E 's/.*"([^"]*)".*/\1/')
        [[ -z "$val" || "$val" == "$line" ]] && continue
        IFS=',' read -r -a mp <<< "$val"
        for p in "${mp[@]}"; do
            p="${p#"${p%%[![:space:]]*}"}"; p="${p%"${p##*[![:space:]]}"}"
            [[ -z "$p" ]] && continue
            printf 'modpath\t%s\t%s\n' "$f" "$p" >> "$current"
            if [[ "$p" =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]; then
                suspicious+=("${base}:modulepath-writable($p)")
            elif [[ "$p" != /* ]]; then
                suspicious+=("${base}:modulepath-relative($p)")
            fi
        done
    done < <(grep -iE '^[[:space:]]*ModulePath[[:space:]]' "$f" 2>/dev/null || true)
    # Load: named module loaded into the X server.
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        val=$(printf '%s' "$line" | sed -E 's/.*"([^"]*)".*/\1/')
        [[ -z "$val" || "$val" == "$line" ]] && continue
        printf 'load\t%s\t%s\n' "$f" "$val" >> "$current"
        if [[ "$val" =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]; then
            suspicious+=("${base}:load-writable($val)")
        fi
    done < <(grep -iE '^[[:space:]]*Load[[:space:]]' "$f" 2>/dev/null || true)
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
    logger -t selfdef-xorg-config -- "$(printf '{"tag":"selfdef-xorg-config","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="xorg_config_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="xorg_config_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="xorg_config_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-xorg-config","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-xorg-config -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-xorg-config-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-xorg-config-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
