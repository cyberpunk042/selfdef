#!/usr/bin/env bash
# selfdef kernel-module-watchdog — daily + boot delta of the
# loaded-kernel-module set vs a learned baseline.
#
# Baseline = sorted unique module names from /proc/modules.
# A NEW module is high-signal: LKM rootkits load a module to
# hook syscalls / hide processes; an unexpected driver may be
# an attacker-loaded out-of-tree module.
#
# Severity:
#   ok    → no delta
#   warn  → 1..2 added modules
#   alert → 3+ added modules OR an added module that is NOT
#           present under /lib/modules/$(uname -r) (i.e. an
#           out-of-tree / unsigned / injected module — the
#           rootkit signature).

set -u

PROFILE="${SELFDEF_KMOD_PROFILE:-report}"
BASELINE="${SELFDEF_KMOD_BASELINE:-/var/lib/selfdef/kernel-modules-baseline.tsv}"
KREL="$(uname -r 2>/dev/null || echo unknown)"

# Source overrides: operator-test affordance + L2 testability. Defaults
# point at the live kernel surfaces (/proc/modules + /lib/modules/$kver).
# SELFDEF_KMOD_PROCSRC lets a captured snapshot of /proc/modules be
# fed in; SELFDEF_KMOD_MODDIR lets the on-disk-module scan target a
# fixture tree. Live default behavior unchanged.
PROCSRC="${SELFDEF_KMOD_PROCSRC:-/proc/modules}"
MODDIR="${SELFDEF_KMOD_MODDIR:-/lib/modules/${KREL}}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

if [[ -r "$PROCSRC" ]]; then
    awk '{print $1}' "$PROCSRC" | sort -u > "$current"
fi

cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    json=$(printf '{"tag":"selfdef-kernel-modules","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d,"kernel":"%s"}' "$PROFILE" "$cur_count" "$KREL")
    logger -t selfdef-kernel-modules -- "$json"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))

n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# Flag added modules with no matching .ko under /lib/modules
# (out-of-tree / injected — the rootkit signature).
out_of_tree=0
oot_sample=()
if [[ -n "$added" && -d "$MODDIR" ]]; then
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        # modules use _ vs - interchangeably; check both.
        m_dash="${m//_/-}"
        if ! find "$MODDIR" \( -name "${m}.ko" -o -name "${m}.ko.*" -o -name "${m_dash}.ko" -o -name "${m_dash}.ko.*" \) 2>/dev/null | grep -q .; then
            out_of_tree=$((out_of_tree + 1))
            (( ${#oot_sample[@]} < 5 )) && oot_sample+=("$m")
        fi
    done <<< "$added"
fi

severity="ok"; event="no_delta"
if (( out_of_tree > 0 )); then
    severity="alert"; event="out_of_tree_module"
elif (( n_added >= 3 )); then
    severity="alert"; event="mass_new_modules"
elif (( n_added > 0 )); then
    severity="warn"; event="new_module"
fi

added_sample=$(printf '%s' "$added"   | head -10 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | head -10 | tr '\n' '|')
oot_str=$(IFS='|'; echo "${oot_sample[*]:-}")

json=$(printf '{"tag":"selfdef-kernel-modules","severity":"%s","event":"%s","profile":"%s","kernel":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"out_of_tree":%d,"added_sample":"%s","removed_sample":"%s","out_of_tree_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$KREL" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$out_of_tree" \
    "$added_sample" "$removed_sample" "$oot_str")
logger -t selfdef-kernel-modules -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS= read -r m; do [[ -n "$m" ]] && logger -t selfdef-kernel-modules-detail -- "ADDED ${m}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS= read -r m; do [[ -n "$m" ]] && logger -t selfdef-kernel-modules-detail -- "REMOVED ${m}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
