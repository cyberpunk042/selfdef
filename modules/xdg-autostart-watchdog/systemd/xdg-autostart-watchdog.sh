#!/usr/bin/env bash
# selfdef xdg-autostart-watchdog — boot + daily delta of the XDG
# desktop autostart entries vs a learned baseline.
#
# Every .desktop file in an autostart dir with an Exec= line is
# launched by the desktop session on each graphical login. A
# dropped or tampered entry is GUI-login persistence (T1547.013):
#
#   # /etc/xdg/autostart/evil.desktop
#   [Desktop Entry]
#   Type=Application
#   Exec=/tmp/.payload
#   X-GNOME-Autostart-enabled=true
#
# Watched (system + root, attacker-writable):
#   /etc/xdg/autostart/*.desktop
#   /usr/local/share/applications/autostart/*.desktop
#   /root/.config/autostart/*.desktop
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each .desktop
#   own:<path>:<owner:mode>  — owner + mode
#   exec:<file>:<prog>       — the Exec= program (first token)
#
# Severity:
#   ok    → no delta
#   warn  → a .desktop added / changed / removed
#   alert → an Exec target under /tmp /home /dev/shm, world-
#           writable, or a relative-with-slash path; a fetch-pipe-
#           shell payload; or a world-writable/non-root .desktop

set -u

PROFILE="${SELFDEF_XDG_PROFILE:-report}"
BASELINE="${SELFDEF_XDG_BASELINE:-/var/lib/selfdef/xdg-autostart-baseline.tsv}"
if [[ -n "${SELFDEF_XDG_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_XDG_DIRS}"
else
    DIRS=(
        /etc/xdg/autostart
        /usr/local/share/applications/autostart
        /root/.config/autostart
    )
fi

PATTERNS='curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|/dev/tcp/|bash[[:space:]]+-i|base64[[:space:]]+-d|mkfifo|setsid'

is_suspicious_prog() {
    local p="$1"
    case "$p" in
        /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) return 0 ;;
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        ""|%*) return 1 ;;        # empty / a field-code placeholder
        ./*|../*|*/*) return 0 ;; # relative path with a slash — abnormal
        *) return 1 ;;           # bare command (PATH-resolved) — normal
    esac
}

have=0
for d in "${DIRS[@]}"; do [[ -d "$d" ]] && { have=1; break; }; done
if [[ "$have" -eq 0 ]]; then
    logger -t selfdef-xdg-autostart -- '{"tag":"selfdef-xdg-autostart","severity":"ok","event":"no_autostart_dirs","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.desktop; do
        [[ -f "$f" ]] || continue
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
            [[ "$line" =~ ^[[:space:]]*Exec[[:space:]]*= ]] || continue
            cmd="${line#*=}"
            cmd="$(printf '%s' "$cmd" | sed -e 's/^[[:space:]]*//')"
            prog="${cmd%% *}"
            printf 'exec\t%s\t%s\n' "$(basename "$f")" "${prog:-(none)}" >> "$current"
            is_suspicious_prog "$prog" && suspicious+=("$(basename "$f"):Exec=>${prog}")
            printf '%s\n' "$cmd" | grep -qE "$PATTERNS" && suspicious+=("$(basename "$f"):Exec-payload")
        done < "$f"
    done
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
    logger -t selfdef-xdg-autostart -- "$(printf '{"tag":"selfdef-xdg-autostart","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="xdg_autostart_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="xdg_autostart_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="xdg_autostart_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-xdg-autostart","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-xdg-autostart -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-xdg-autostart-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-xdg-autostart-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
