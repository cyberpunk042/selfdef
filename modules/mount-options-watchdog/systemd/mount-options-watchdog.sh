#!/usr/bin/env bash
# selfdef mount-options-watchdog — verify security-relevant
# mount points carry the expected hardening flags.
#
# Expected flags per mount (only checked if the mount is a
# SEPARATE filesystem — a flag can't be enforced on a path
# that isn't its own mount, so those are reported as "info"
# not drift):
#   /tmp       nosuid nodev noexec
#   /var/tmp   nosuid nodev noexec
#   /dev/shm   nosuid nodev noexec
#   /home      nosuid nodev
#   /var/log   nosuid nodev noexec
#   /boot      nosuid nodev noexec
#
# Severity:
#   ok    → all separate mounts carry their expected flags
#   warn  → 1..2 missing flags
#   alert → 3+ missing flags (broad remount-weaken event)

set -u

PROFILE="${SELFDEF_MOUNTOPTS_PROFILE:-report}"

# mount : space-separated expected flags
declare -a CHECKS=(
    "/tmp nosuid nodev noexec"
    "/var/tmp nosuid nodev noexec"
    "/dev/shm nosuid nodev noexec"
    "/home nosuid nodev"
    "/var/log nosuid nodev noexec"
    "/boot nosuid nodev noexec"
)

missing=0
not_separate=0
missing_sample=()
sep_sample=()

for entry in "${CHECKS[@]}"; do
    # shellcheck disable=SC2206
    parts=($entry)
    mp="${parts[0]}"
    flags=("${parts[@]:1}")

    # Is this path its own mount? findmnt --target prints the
    # mount that CONTAINS the path; compare its TARGET to mp.
    target=$(findmnt -no TARGET --target "$mp" 2>/dev/null | tail -1)
    if [[ "$target" != "$mp" ]]; then
        not_separate=$((not_separate + 1))
        (( ${#sep_sample[@]} < 6 )) && sep_sample+=("${mp}(on ${target:-?})")
        continue
    fi

    opts=$(findmnt -no OPTIONS --target "$mp" 2>/dev/null | tail -1)
    for f in "${flags[@]}"; do
        if [[ ",$opts," != *",$f,"* ]]; then
            missing=$((missing + 1))
            (( ${#missing_sample[@]} < 8 )) && missing_sample+=("${mp}:${f}")
        fi
    done
done

severity="ok"; event="all_flags_present"
if (( missing > 0 && missing <= 2 )); then
    severity="warn"; event="missing_flags"
elif (( missing > 2 )); then
    severity="alert"; event="broad_missing_flags"
fi

ms=$(IFS='|'; echo "${missing_sample[*]:-}")
ss_=$(IFS='|'; echo "${sep_sample[*]:-}")

json=$(printf '{"tag":"selfdef-mount-options","severity":"%s","event":"%s","profile":"%s","missing_flags":%d,"not_separate_mount":%d,"missing_sample":"%s","not_separate_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$missing" "$not_separate" "$ms" "$ss_")
logger -t selfdef-mount-options -- "$json"

for m in "${missing_sample[@]}"; do
    logger -t selfdef-mount-options-detail -- "MISSING ${m}"
done

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
