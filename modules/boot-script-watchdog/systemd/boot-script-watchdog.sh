#!/usr/bin/env bash
# selfdef boot-script-watchdog — boot + daily delta of the
# SysV/rc boot-script surfaces vs a learned baseline.
#
# /etc/rc.local and /etc/init.d/* scripts run AS ROOT at boot —
# even on pure-systemd hosts, via systemd-rc-local-generator
# (rc.local) and systemd-sysv-generator (init.d). They are a
# legacy boot-exec surface that is easy to overlook next to
# native systemd units:
#
#   echo '/tmp/.p &' >> /etc/rc.local                  # T1037.004
#   cp /tmp/evil /etc/init.d/cups-helper; chmod +x ...  # + rc?.d link
#
# Watched:
#   /etc/rc.local  /etc/rc.d/rc.local           (rc.local variants)
#   /etc/init.d/*                               (SysV scripts)
#   /etc/rc{0..6}.d/*  /etc/rcS.d/*             (runlevel symlinks)
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<script>:<sha12>      — hash of rc.local + each init.d script
#   own:<script>:<owner:mode>  — owner + mode (non-root / world-
#                                writable = hijackable)
#   susp:<script>:<pattern>    — a high-risk exec pattern present
#   link:<rcd-link>:<target>   — each runlevel symlink's target
#                                (catches enable/disable + a link to
#                                a rogue script)
#
# Severity:
#   ok    → no delta
#   warn  → a script / symlink added, changed, or removed
#   alert → a script world-writable or non-root-owned, OR
#           containing a suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_BOOTSCRIPT_PROFILE:-report}"
BASELINE="${SELFDEF_BOOTSCRIPT_BASELINE:-/var/lib/selfdef/boot-script-baseline.tsv}"
# Roots (overridable for testing): rc.local files, init.d dir, rc?.d dirs.
RCLOCALS="${SELFDEF_BOOTSCRIPT_RCLOCAL:-/etc/rc.local /etc/rc.d/rc.local}"
INITD="${SELFDEF_BOOTSCRIPT_INITD:-/etc/init.d}"
RCDIRS="${SELFDEF_BOOTSCRIPT_RCDIRS:-/etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rcS.d}"

PATTERNS=(
    'curl[^|;&]*\|[[:space:]]*(ba)?sh' 'wget[^|;&]*\|[[:space:]]*(ba)?sh'
    '/dev/tcp/' '/dev/udp/' 'nc[[:space:]]+.*-e' 'ncat[[:space:]]+.*-e'
    'bash[[:space:]]+-i' 'base64[[:space:]]+-d' 'base64[[:space:]]+--decode'
    'eval[[:space:]]*[`$]' 'python[0-9]*[[:space:]]+-c' 'perl[[:space:]]+-e'
    'mkfifo' 'setsid'
    # a tmp/shm/home path INVOKED as a command (line start or after
    # a separator) — bare execution of a dropped payload. Low FP:
    # legit scripts reference but rarely invoke a tmp path.
    '(^|[;&|][[:space:]]*)/(tmp|var/tmp|dev/shm|home)/'
)

# Does any watched target exist?
have=0
for f in $RCLOCALS; do [[ -f "$f" ]] && { have=1; break; }; done
[[ "$have" -eq 0 && -d "$INITD" ]] && have=1
if [[ "$have" -eq 0 ]]; then
    for d in $RCDIRS; do [[ -d "$d" ]] && { have=1; break; }; done
fi
if [[ "$have" -eq 0 ]]; then
    logger -t selfdef-boot-script -- '{"tag":"selfdef-boot-script","severity":"ok","event":"no_boot_scripts","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

scan_script() {
    local f="$1"
    [[ -f "$f" ]] || return 0
    local h owner mode scan pat
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
    scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
    for pat in "${PATTERNS[@]}"; do
        if printf '%s\n' "$scan" | grep -qE "$pat"; then
            printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
            suspicious+=("$(basename "$f"):$pat")
        fi
    done
}

# rc.local variants
for f in $RCLOCALS; do scan_script "$f"; done
# init.d scripts
if [[ -d "$INITD" ]]; then
    for f in "$INITD"/*; do scan_script "$f"; done
fi
# runlevel symlinks — record their targets (resolve relative to dir)
for d in $RCDIRS; do
    [[ -d "$d" ]] || continue
    for l in "$d"/*; do
        [[ -e "$l" || -L "$l" ]] || continue
        if [[ -L "$l" ]]; then
            tgt=$(readlink "$l" 2>/dev/null || echo '?')
            printf 'link\t%s\t%s\n' "$l" "$tgt" >> "$current"
        fi
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
    logger -t selfdef-boot-script -- "$(printf '{"tag":"selfdef-boot-script","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="boot_script_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="boot_script_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="boot_script_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-boot-script","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-boot-script -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-boot-script-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-boot-script-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
