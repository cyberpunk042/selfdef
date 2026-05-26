#!/usr/bin/env bash
# selfdef kernel-usermodehelper-watchdog — boot + daily delta of the
# kernel usermode-helper paths vs a learned baseline.
#
# The kernel EXECUTES these paths AS ROOT (kernel context) on
# triggers an unprivileged user can often cause:
#   kernel.modprobe     — run to autoload a module (e.g. creating a
#                         socket of an unloaded protocol family)
#   kernel.hotplug      — legacy hotplug helper (deprecated; modern
#                         systems leave it EMPTY, udev uses netlink)
#   kernel.poweroff_cmd — run on orderly poweroff
# read live from /proc/sys/kernel and set persistently from
# /etc/sysctl.conf + /etc/sysctl.d/*.conf. Setting
# kernel.modprobe=/tmp/x is a classic local privilege escalation:
# trigger an autoload and the kernel runs your program as root
# (T1574 / T1548). Distinct from coredump-pattern-watchdog
# (kernel.core_pattern), modprobe-config-watchdog (modprobe.d), and
# sysctl-hardening-watchdog.
#
# Records (each line: kind<TAB>name<TAB>value):
#   helper:<name>:<value>       — live /proc/sys/kernel value
#   sysctl:<file>:<key>=<value> — a sysctl.d line setting a helper
#
# Severity:
#   ok    → no delta
#   warn  → a helper value / sysctl line added / changed / removed
#   alert → a helper path under /tmp /var/tmp /dev/shm /home,
#           a relative (non-absolute) helper, OR a non-empty
#           kernel.hotplug (deprecated — should be empty)

set -u

PROFILE="${SELFDEF_KUMH_PROFILE:-report}"
BASELINE="${SELFDEF_KUMH_BASELINE:-/var/lib/selfdef/kernel-usermodehelper-baseline.tsv}"

# SDD-061 D-6: consume the shared writable-location policy
# (selfdef_is_writable_path) from module-lib instead of a per-module copy.
# Co-shipped by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl
# exports SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a
# real misconfiguration that would leave the watchdog scanning with a
# divergent policy, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-kernel-usermodehelper -- '{"tag":"selfdef-kernel-usermodehelper","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-kernel-usermodehelper -- '{"tag":"selfdef-kernel-usermodehelper","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
PROC_DIR="${SELFDEF_KUMH_PROC_DIR:-/proc/sys/kernel}"
if [[ -n "${SELFDEF_KUMH_SYSCTL_DIRS:-}" ]]; then
    read -r -a SYSCTL_DIRS <<< "${SELFDEF_KUMH_SYSCTL_DIRS}"
else
    SYSCTL_DIRS=(/etc/sysctl.d /run/sysctl.d /usr/lib/sysctl.d)
fi
if [[ -n "${SELFDEF_KUMH_SYSCTL_FILES:-}" ]]; then
    read -r -a SYSCTL_FILES <<< "${SELFDEF_KUMH_SYSCTL_FILES}"
else
    SYSCTL_FILES=(/etc/sysctl.conf)
fi

HELPERS=(modprobe hotplug poweroff_cmd)

is_writable() { selfdef_is_writable_path "$1"; }

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()
have_any=0

for name in "${HELPERS[@]}"; do
    pf="${PROC_DIR}/${name}"
    [[ -r "$pf" ]] || continue
    have_any=1
    val=$(tr -d '\n' < "$pf" 2>/dev/null)
    printf 'helper\t%s\t%s\n' "$name" "$val" >> "$current"
    if [[ -n "$val" ]]; then
        if is_writable "$val"; then
            suspicious+=("${name}:helper-writable($val)")
        elif [[ "$val" != /* ]]; then
            suspicious+=("${name}:helper-relative($val)")
        fi
    fi
    if [[ "$name" == "hotplug" && -n "$val" ]]; then
        suspicious+=("hotplug:non-empty-deprecated-helper($val)")
    fi
done

# Persistent source: sysctl.d / sysctl.conf lines setting a helper.
scan_sysctl_file() {
    local f="$1" base; base="$(basename "$f")"
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*[#\;] ]] && continue
        key="${line%%=*}"; key="$(printf '%s' "$key" | tr -d '[:space:]' | tr '/' '.')"
        case "$key" in kernel.modprobe|kernel.hotplug|kernel.poweroff_cmd) ;; *) continue ;; esac
        val="${line#*=}"; val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
        printf 'sysctl\t%s\t%s=%s\n' "$f" "$key" "$val" >> "$current"
        if [[ -n "$val" ]]; then
            if is_writable "$val"; then
                suspicious+=("${base}:${key}-writable($val)")
            elif [[ "$val" != /* && "$key" != "kernel.hotplug" ]]; then
                suspicious+=("${base}:${key}-relative($val)")
            fi
            [[ "$key" == "kernel.hotplug" ]] && suspicious+=("${base}:hotplug-set($val)")
        fi
    done < <(grep -iE '^[[:space:]]*kernel[./](modprobe|hotplug|poweroff_cmd)[[:space:]]*=' "$f" 2>/dev/null || true)
}
for d in "${SYSCTL_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && { have_any=1; scan_sysctl_file "$f"; }; done
done
for f in "${SYSCTL_FILES[@]}"; do [[ -f "$f" ]] && { have_any=1; scan_sysctl_file "$f"; }; done

if [[ "$have_any" -eq 0 ]]; then
    logger -t selfdef-kernel-usermodehelper -- '{"tag":"selfdef-kernel-usermodehelper","severity":"ok","event":"no_usermodehelper","profile":"'"$PROFILE"'"}'
    exit 0
fi

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
    logger -t selfdef-kernel-usermodehelper -- "$(printf '{"tag":"selfdef-kernel-usermodehelper","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="usermodehelper_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="usermodehelper_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="usermodehelper_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-kernel-usermodehelper","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-kernel-usermodehelper -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-kernel-usermodehelper-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-kernel-usermodehelper-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
