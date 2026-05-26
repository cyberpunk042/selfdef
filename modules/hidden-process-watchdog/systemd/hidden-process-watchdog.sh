#!/usr/bin/env bash
# selfdef hidden-process-watchdog — surface processes hidden
# from the /proc directory listing by a rootkit.
#
# Technique: many userland rootkits (LD_PRELOAD-based, e.g.
# libprocesshider) and some LKM rootkits hide a process by
# filtering readdir(/proc) so `ps` / `ls /proc` don't show
# it — but the process is still ALIVE and its /proc/<pid>
# directory is still directly accessible by exact path.
#
# We enumerate two PID sets:
#   A = readdir(/proc)            — what ps/ls see (filtered)
#   B = direct stat /proc/<pid>   — across the full PID range,
#                                   bypassing readdir filtering
# Any PID in B but not in A is HIDDEN.
#
# Severity:
#   ok    → no hidden PIDs
#   alert → 1+ hidden PIDs (no benign cause for a process to
#           be directly-statable but absent from readdir)

set -u

PROFILE="${SELFDEF_HIDDENPROC_PROFILE:-report}"

# Max PID to probe. Read the kernel's pid_max so we cover the
# whole range without hardcoding.
PID_MAX=32768
if [[ -r /proc/sys/kernel/pid_max ]]; then
    PID_MAX=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 32768)
fi
# Cap the probe to keep the scan bounded on hosts with a huge
# pid_max (e.g. 4194304). Hidden malware uses low/normal PIDs;
# probing the first 200k covers realistic cases cheaply.
PROBE_CAP="${SELFDEF_HIDDENPROC_CAP:-200000}"
(( PID_MAX > PROBE_CAP )) && PID_MAX=$PROBE_CAP

# Set A: PIDs visible via readdir(/proc).
visible="$(mktemp)"
# Set B: PIDs alive via direct stat.
alive="$(mktemp)"
trap 'rm -f "$visible" "$alive"' EXIT

for d in /proc/[0-9]*; do
    p="${d#/proc/}"
    echo "$p"
done | sort -n -u > "$visible"

# Direct-stat probe. /proc/<pid> exists (directly accessible)
# for every live PID even when readdir hides it. We stat the
# directory by exact path.
for ((pid=1; pid<=PID_MAX; pid++)); do
    # Use the shell's test -d which does a direct path stat,
    # not a readdir of /proc.
    [[ -d "/proc/$pid" ]] && echo "$pid"
done | sort -n -u > "$alive"

# Hidden = alive but not visible.
hidden=$(comm -13 "$visible" "$alive")
n_hidden=$(printf '%s' "$hidden" | grep -c . || true)

n_visible=$(wc -l < "$visible" | tr -d ' ')
n_alive=$(wc -l < "$alive" | tr -d ' ')

severity="ok"; event="no_hidden_process"
if (( n_hidden > 0 )); then
    severity="alert"; event="hidden_process_detected"
fi

# For each hidden PID, try to read identifying info via the
# direct path (comm, exe symlink) — a rootkit hiding from
# readdir often still leaves the direct-path readable.
sample=()
if [[ -n "$hidden" ]]; then
    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        comm=$(cat "/proc/$pid/comm" 2>/dev/null | tr -d '\n' || echo "?")
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "?")
        (( ${#sample[@]} < 8 )) && sample+=("${pid}:${comm}:${exe}")
    done <<< "$hidden"
fi
sample_str=$(IFS='|'; echo "${sample[*]:-}")

json=$(printf '{"tag":"selfdef-hidden-process","severity":"%s","event":"%s","profile":"%s","pids_visible":%d,"pids_alive":%d,"hidden":%d,"probe_max":%d,"hidden_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_visible" "$n_alive" "$n_hidden" "$PID_MAX" "$sample_str")
logger -t selfdef-hidden-process -- "$json"

for s in "${sample[@]}"; do
    logger -t selfdef-hidden-process-detail -- "HIDDEN ${s}"
done

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
