#!/usr/bin/env bash
# selfdef grub-config-watchdog — boot + daily delta of the GRUB
# config SOURCE vs a learned baseline.
#
# /etc/grub.d/* are generator scripts run AS ROOT by
# grub-mkconfig / update-grub to build grub.cfg. A rogue script
# (or an edit to 40_custom) executes at config-regen and can:
#   - inject a hidden menuentry / chainload a malicious loader
#   - copy a trojaned initrd into /boot
#   - add kernel params to every boot entry
# /etc/default/grub holds GRUB_CMDLINE_LINUX[_DEFAULT]; an
# attacker who adds `init=/bin/sh` (or init=/tmp/x) there hijacks
# PID 1 on the NEXT boot — invisible to kernel-cmdline-watchdog
# (which reads the LIVE /proc/cmdline) until that reboot. This
# watches the SOURCE that defines the next boot. T1542.003 /
# T1037 / T1601 (modify boot config).
#
# Watched:
#   /etc/grub.d/*            (generator scripts)
#   /etc/default/grub        (defaults incl. GRUB_CMDLINE_LINUX)
#   /etc/default/grub.d/*    (drop-ins, if present)
#
# Records (each line: kind<TAB>path/key<TAB>value):
#   file:<path>:<sha12>      — hash of each grub.d script + default
#   own:<script>:<owner:mode>— grub.d script owner+mode
#   susp:<script>:<pattern>  — suspicious exec pattern in a script
#   cmdline:<key>:<value>    — GRUB_CMDLINE_LINUX[_DEFAULT] value
#
# Severity:
#   ok    → no delta
#   warn  → a script / default added, changed, or removed
#   alert → a grub.d script world-writable/non-root/with a
#           suspicious pattern, OR an `init=` (PID-1 hijack) param
#           newly present in GRUB_CMDLINE

set -u

PROFILE="${SELFDEF_GRUB_PROFILE:-report}"
BASELINE="${SELFDEF_GRUB_BASELINE:-/var/lib/selfdef/grub-config-baseline.tsv}"
GRUBD="${SELFDEF_GRUB_D:-/etc/grub.d}"
DEFAULT="${SELFDEF_GRUB_DEFAULT:-/etc/default/grub}"
DEFAULTD="${SELFDEF_GRUB_DEFAULT_D:-/etc/default/grub.d}"

# SDD-061 D-6: consume the shared injection-pattern set + writable-
# location policy from module-lib instead of a per-module copy. Co-shipped
# by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a real
# misconfiguration that would leave the watchdog scanning with a divergent/
# absent set, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-grub-config -- '{"tag":"selfdef-grub-config","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-grub-config -- '{"tag":"selfdef-grub-config","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)
# Module-specific patterns beyond the shared set (preserved verbatim):
PATTERNS+=(
    '(^|[;&|][[:space:]]*)/(tmp|var/tmp|dev/shm)/'
)

have=0
[[ -d "$GRUBD" ]] && have=1
[[ -f "$DEFAULT" ]] && have=1
if [[ "$have" -eq 0 ]]; then
    logger -t selfdef-grub-config -- '{"tag":"selfdef-grub-config","severity":"ok","event":"no_grub_config","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

# grub.d generator scripts
if [[ -d "$GRUBD" ]]; then
    for f in "$GRUBD"/*; do
        [[ -f "$f" ]] || continue
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
        scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$scan" | grep -qE "$pat"; then
                printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
                suspicious+=("$(basename "$f"):$pat")
            fi
        done
    done
fi

# /etc/default/grub (+ drop-ins): hash + extract GRUB_CMDLINE_LINUX
default_files=()
[[ -f "$DEFAULT" ]] && default_files+=("$DEFAULT")
if [[ -d "$DEFAULTD" ]]; then
    for f in "$DEFAULTD"/*; do [[ -f "$f" ]] && default_files+=("$f"); done
fi
for f in "${default_files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    while IFS= read -r line; do
        line="${line%%#*}"
        case "$line" in
            *GRUB_CMDLINE_LINUX*=*)
                key="${line%%=*}"; key="${key//[[:space:]]/}"
                val="${line#*=}"
                val="${val#[\"\']}"; val="${val%[\"\']}"
                printf 'cmdline\t%s\t%s\n' "$key" "$val" >> "$current"
                # init= overrides PID 1 — a boot-time exec hijack.
                if printf '%s' "$val" | grep -qE '(^|[[:space:]])init='; then
                    initval=$(printf '%s' "$val" | grep -oE '(^|[[:space:]])init=[^[:space:]]+' | head -1 | sed 's/.*init=//')
                    suspicious+=("${key}:init=${initval}")
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
    logger -t selfdef-grub-config -- "$(printf '{"tag":"selfdef-grub-config","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="grub_config_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="grub_config_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="grub_config_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-grub-config","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-grub-config -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-grub-config-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-grub-config-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
