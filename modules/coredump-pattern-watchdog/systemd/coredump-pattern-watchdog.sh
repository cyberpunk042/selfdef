#!/usr/bin/env bash
# selfdef coredump-pattern-watchdog — verify kernel.core_pattern
# is not hijacked to a non-allowlisted pipe handler.
#
# When core_pattern begins with '|', the kernel pipes the core
# dump to that program — RUNNING IT AS ROOT — on the next crash
# of ANY process. An attacker sets:
#     echo '|/tmp/.x %p' > /proc/sys/kernel/core_pattern
# then crashes any process (or waits for one) → /tmp/.x runs as
# root. It's a quiet privilege-escalation + persistence trigger.
#
# Legitimate pipe handlers (allowlisted):
#   - /usr/lib/systemd/systemd-coredump  (systemd-coredump)
#   - /usr/share/apport/apport            (Ubuntu apport)
#   - /lib/systemd/systemd-coredump       (alt path)
# A plain (non-pipe) pattern like 'core' or 'core.%p' is fine.
#
# Severity:
#   ok    → plain pattern, or pipe to an allowlisted handler
#   alert → pipe '|' to a NON-allowlisted program (hijack), or a
#           pipe handler that doesn't exist on disk

set -u

PROFILE="${SELFDEF_COREPAT_PROFILE:-report}"

ALLOWLIST=(
    "/usr/lib/systemd/systemd-coredump"
    "/lib/systemd/systemd-coredump"
    "/usr/share/apport/apport"
)

pattern=""
[[ -r /proc/sys/kernel/core_pattern ]] && pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)

severity="ok"; event="core_pattern_safe"; detail=""

if [[ "${pattern:0:1}" == "|" ]]; then
    # Pipe handler: extract the program path (first token after '|').
    prog=$(echo "${pattern:1}" | awk '{print $1}')
    allowed=0
    for a in "${ALLOWLIST[@]}"; do
        [[ "$prog" == "$a" ]] && { allowed=1; break; }
    done
    if (( allowed )); then
        # Confirm the allowlisted handler actually exists (an
        # attacker can't easily fake the path, but verify).
        if [[ -x "$prog" ]]; then
            severity="ok"; event="core_pattern_allowlisted_pipe"; detail="$prog"
        else
            severity="alert"; event="core_pattern_pipe_missing_binary"; detail="$prog (allowlisted path but not executable on disk)"
        fi
    else
        severity="alert"; event="core_pattern_hijacked"; detail="$prog (non-allowlisted pipe handler — runs as root on next crash)"
    fi
else
    # Non-pipe pattern. Safe, but flag a write into a world-
    # writable / tmp dir as suspicious (cores landing in /tmp).
    case "$pattern" in
        /tmp/*|/var/tmp/*|/dev/shm/*)
            severity="warn"; event="core_pattern_tmp_target"; detail="$pattern" ;;
        *)
            severity="ok"; event="core_pattern_safe"; detail="$pattern" ;;
    esac
fi

# escape the detail for JSON
detail_esc=$(printf '%s' "$detail" | sed 's/"/\\"/g')
json=$(printf '{"tag":"selfdef-coredump-pattern","severity":"%s","event":"%s","profile":"%s","core_pattern":"%s","detail":"%s"}' \
    "$severity" "$event" "$PROFILE" "$(printf '%s' "$pattern" | sed 's/"/\\"/g')" "$detail_esc")
logger -t selfdef-coredump-pattern -- "$json"

if [[ "$PROFILE" == "enforce" && "$severity" == "alert" ]]; then
    exit 1
fi
exit 0
