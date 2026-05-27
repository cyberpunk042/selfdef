#!/usr/bin/env bash
# selfdef dbus-service-watchdog — boot + daily delta of the
# admin/local D-Bus system activation services + policy files.
#
# A D-Bus-activated SYSTEM service is described by a .service
# file with an Exec= and a User=; when any client first calls the
# service's bus name, dbus-daemon launches Exec= AS the User=
# (often root). A rogue activation file is therefore root-exec-
# on-demand persistence:
#
#   # /usr/local/share/dbus-1/system-services/evil.service
#   [D-BUS Service]
#   Name=org.evil
#   Exec=/usr/local/sbin/evil
#   User=root
#
# A permissive POLICY (/etc/dbus-1/system.d/*.conf) `<allow
# own="org.privileged"/>` in the default context lets an
# unprivileged process hijack a privileged bus name (T1543/T1548).
#
# Watched (admin/local — attacker-writable):
#   /usr/local/share/dbus-1/system-services/*.service
#   /etc/dbus-1/system-services/*.service
#   /etc/dbus-1/system.d/*.conf
#   /usr/local/share/dbus-1/system.d/*.conf
# NOT /usr/share/dbus-1/* (package-managed).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each .service/.conf
#   own:<path>:<owner:mode>  — owner + mode
#   exec:<svc>:<user>:<cmd0> — activation Exec + User (first token)
#   ownallow:<conf>:<name>   — a policy `<allow own=>` bus name
#
# Severity:
#   ok    → no delta
#   warn  → a file changed or removed
#   alert → a NEW activation .service or a NEW `<allow own=>`
#           policy, OR a file world-writable / non-root, OR an
#           Exec under /tmp /home /dev/shm

set -u

PROFILE="${SELFDEF_DBUS_PROFILE:-report}"
BASELINE="${SELFDEF_DBUS_BASELINE:-/var/lib/selfdef/dbus-service-baseline.tsv}"
if [[ -n "${SELFDEF_DBUS_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_DBUS_DIRS}"
else
    DIRS=(
        /usr/local/share/dbus-1/system-services
        /etc/dbus-1/system-services
        /etc/dbus-1/system.d
        /usr/local/share/dbus-1/system.d
    )
fi

# SDD-063: consume the shared writable-location policy from module-lib.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-dbus-service -- '{"tag":"selfdef-dbus-service","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 4 ]]; then
    logger -t selfdef-dbus-service -- '{"tag":"selfdef-dbus-service","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

is_suspicious_path() {
    local p="$1"
    selfdef_is_writable_dir "$p" && return 0
    case "$p" in
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        *) return 0 ;;
    esac
}

have=0
for d in "${DIRS[@]}"; do [[ -d "$d" ]] && { have=1; break; }; done
if [[ "$have" -eq 0 ]]; then
    logger -t selfdef-dbus-service -- '{"tag":"selfdef-dbus-service","severity":"ok","event":"no_dbus_dirs","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.service "$d"/*.conf; do
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
        case "$f" in
            *.service)
                ex=$(grep -iE '^[[:space:]]*Exec=' "$f" 2>/dev/null | head -1 | sed 's/^[^=]*=//')
                usr=$(grep -iE '^[[:space:]]*User=' "$f" 2>/dev/null | head -1 | sed 's/^[^=]*=//')
                prog="${ex%% *}"
                printf 'exec\t%s\t%s:%s\n' "$(basename "$f")" "${usr:-root}" "${prog:-(none)}" >> "$current"
                [[ -n "$prog" ]] && is_suspicious_path "$prog" && suspicious+=("$(basename "$f"):Exec=>${prog}")
                ;;
            *.conf)
                # policy <allow own="name"/> grants bus-name ownership
                while IFS= read -r nm; do
                    [[ -n "$nm" ]] && printf 'ownallow\t%s\t%s\n' "$(basename "$f")" "$nm" >> "$current"
                done < <(grep -oE '<allow[^>]*own=("|'\'')[^"'\'']+' "$f" 2>/dev/null | sed -E 's/.*own=("|'\'')//' )
                ;;
        esac
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
    logger -t selfdef-dbus-service -- "$(printf '{"tag":"selfdef-dbus-service","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
# A NEW activation service (new .service PATH) or a NEW ownallow
# is high-signal. Compare .service path set; count new ownallow.
base_svc=$(grep '^file' "$BASELINE" 2>/dev/null | cut -f2 | grep '\.service$' | sort -u)
cur_svc=$(grep '^file'  "$current"  2>/dev/null | cut -f2 | grep '\.service$' | sort -u)
new_svc=$(comm -23 <(printf '%s\n' "$cur_svc") <(printf '%s\n' "$base_svc") | grep -c . || true)
new_ownallow=$(printf '%s' "$added" | grep -c '^ownallow' || true)

severity="ok"; event="dbus_service_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="dbus_service_suspicious"
elif (( new_svc > 0 || new_ownallow > 0 )); then
    severity="alert"; event="dbus_service_new"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="dbus_service_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-dbus-service","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-dbus-service -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dbus-service-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dbus-service-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
