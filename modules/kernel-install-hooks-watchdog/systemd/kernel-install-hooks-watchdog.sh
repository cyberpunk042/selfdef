#!/usr/bin/env bash
# selfdef kernel-install-hooks-watchdog — boot + daily delta of the
# kernel-package install-hook dirs vs a learned baseline +
# ownership + suspicious-pattern scan.
#
# dpkg's kernel maintainer scripts and systemd kernel-install run
# every executable in these dirs AS ROOT on each kernel package
# transaction (install / upgrade / remove):
#   /etc/kernel/postinst.d/*        (post-install: update-grub etc.)
#   /etc/kernel/postrm.d/*          (post-remove)
#   /etc/kernel/preinst.d/*         (pre-install)
#   /etc/kernel/prerm.d/*           (pre-remove)
#   /etc/kernel/install.d/*         (systemd kernel-install plugins)
#   /etc/kernel/header_postinst.d/* (header package post-install)
# This is where update-initramfs / update-grub / bootloader regen
# live. An added/tampered hook is root-exec persistence that fires
# on the next kernel update and can plant into the initramfs or
# bootloader (T1542 pre-OS boot / T1546). Distinct from the runtime
# kernel-* modules (cmdline/lockdown/modules/sysrq/yama params) and
# from apt-hooks (apt's own Pre/Post-Invoke).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each hook
#   own:<path>:<owner:mode> — owner + mode
#   susp:<path>:<pattern>   — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a hook added / changed / removed
#   alert → a hook world-writable or non-root-owned, OR containing a
#           suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_KHOOK_PROFILE:-report}"
BASELINE="${SELFDEF_KHOOK_BASELINE:-/var/lib/selfdef/kernel-install-hooks-baseline.tsv}"
if [[ -n "${SELFDEF_KHOOK_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_KHOOK_DIRS}"
else
    DIRS=(
        /etc/kernel/postinst.d
        /etc/kernel/postrm.d
        /etc/kernel/preinst.d
        /etc/kernel/prerm.d
        /etc/kernel/install.d
        /etc/kernel/header_postinst.d
    )
fi

# SDD-061 D-6: consume the shared scan helpers (the single source of
# truth for the injection-pattern set + the writable-location policy)
# instead of a per-module copy. Co-shipped by the .deb at
# /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a
# real misconfiguration that would leave the watchdog scanning with a
# divergent/absent set, so we fail loud with a structured finding
# rather than silently degrade.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-kernel-hooks -- '{"tag":"selfdef-kernel-hooks","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-kernel-hooks -- '{"tag":"selfdef-kernel-hooks","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-kernel-hooks -- '{"tag":"selfdef-kernel-hooks","severity":"ok","event":"no_kernel_hooks","profile":"'"$PROFILE"'"}'
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
    rel="${f#/etc/kernel/}"
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("${rel}:world-writable($mode)")
    elif [[ "$owner" != "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}" && "$owner" != "?" ]]; then
        suspicious+=("${rel}:owned-by-$owner")
    fi
    scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
    for pat in "${PATTERNS[@]}"; do
        if printf '%s\n' "$scan" | grep -qE "$pat"; then
            printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
            suspicious+=("${rel}:$pat")
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
    logger -t selfdef-kernel-hooks -- "$(printf '{"tag":"selfdef-kernel-hooks","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="kernel_hooks_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="kernel_hooks_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="kernel_hooks_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-kernel-hooks","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-kernel-hooks -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-kernel-hooks-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-kernel-hooks-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
