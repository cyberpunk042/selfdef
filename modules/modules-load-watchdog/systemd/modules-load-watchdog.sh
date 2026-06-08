#!/usr/bin/env bash
# selfdef modules-load-watchdog — boot + daily delta of the
# kernel-module auto-load config vs a learned baseline.
#
# systemd-modules-load.service (and the legacy /etc/modules,
# read by the kmod init scripts) force-load the listed kernel
# modules AT BOOT. An attacker who adds a module name here makes
# a malicious out-of-tree module — or a known-vulnerable in-tree
# one used for privesc — load on every boot (T1547.006):
#
#   echo 'evil_lkm' > /etc/modules-load.d/zz.conf
#   echo 'dccp'     >> /etc/modules            # re-enable a CVE-y module
#
# Watched (admin/local/runtime — attacker-writable):
#   /etc/modules-load.d/*.conf  /etc/modules
#   /run/modules-load.d/*.conf  /usr/local/lib/modules-load.d/*.conf
# NOT /usr/lib/modules-load.d (package-managed).
#
# Records (each line: kind<TAB>path/name<TAB>value):
#   file:<path>:<sha12>  — hash of each config file
#   own:<path>:<o:m>     — owner + mode
#   load:<modname>:<src> — each module scheduled to load (src=file)
#
# Severity:
#   ok    → no delta
#   warn  → a module-to-load added/removed, or a file changed
#   alert → a config file world-writable or non-root-owned (an
#           attacker who controls it can force-load any module)

set -u

PROFILE="${SELFDEF_MODLOAD_PROFILE:-report}"
BASELINE="${SELFDEF_MODLOAD_BASELINE:-/var/lib/selfdef/modules-load-baseline.tsv}"
if [[ -n "${SELFDEF_MODLOAD_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_MODLOAD_DIRS}"
else
    DIRS=(
        /etc/modules-load.d /run/modules-load.d
        /usr/local/lib/modules-load.d
    )
fi
ETC_MODULES="${SELFDEF_MODLOAD_ETC_MODULES:-/etc/modules}"

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done
[[ -f "$ETC_MODULES" ]] && files+=("$ETC_MODULES")

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-modules-load -- '{"tag":"selfdef-modules-load","severity":"ok","event":"no_modules_load","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${files[@]}"; do
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
    # Each non-comment line is a module name to load.
    while IFS= read -r line; do
        line="${line%%#*}"
        read -r -a M <<< "$line"
        mod="${M[0]:-}"
        [[ -z "$mod" ]] && continue
        printf 'load\t%s\t%s\n' "$mod" "$(basename "$f")" >> "$current"
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
    logger -t selfdef-modules-load -- "$(printf '{"tag":"selfdef-modules-load","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="modules_load_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="modules_load_writable_config"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="modules_load_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-modules-load","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-modules-load -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-modules-load-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-modules-load-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
