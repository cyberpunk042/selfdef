#!/usr/bin/env bash
# selfdef kernel-cmdline-watchdog — boot + daily delta of the
# kernel command line vs a learned baseline + a weakening-flag
# denylist.
#
# /proc/cmdline is the kernel boot parameters. An attacker with
# GRUB access (physical/console, or who edits grub.cfg + reboots)
# can WEAKEN kernel security:
#   - remove audit=1            → audit subsystem starts disabled
#   - remove lockdown=...       → kernel lockdown off
#   - remove init_on_alloc=1    → no heap zeroing (UAF easier)
#   - add mitigations=off       → all CPU-vuln mitigations off
#   - add nosmep / nosmap       → disable SMEP/SMAP (exploit easier)
#   - add nokaslr               → disable kernel ASLR
#   - add selinux=0 / apparmor=0→ disable MAC
#   - add systemd.confirm_spawn / single / init=/bin/sh → boot subversion
#
# Two signals:
#   1. cmdline CHANGED vs baseline (any drift across boots).
#   2. a known-weakening flag is PRESENT (denylist match),
#      even if it matches the baseline (flag the posture).
#
# Severity:
#   ok    → unchanged + no weakening flag
#   warn  → changed but no weakening flag (operator kernel tuning?)
#   alert → a weakening flag present OR a weakening flag newly added

set -u

PROFILE="${SELFDEF_CMDLINE_PROFILE:-report}"
BASELINE="${SELFDEF_CMDLINE_BASELINE:-/var/lib/selfdef/kernel-cmdline-baseline.txt}"
# SELFDEF_CMDLINE_FILE added 2026-06-06 for L2 weakener-detection
# testability. Live default unchanged.
CMDLINE_FILE="${SELFDEF_CMDLINE_FILE:-/proc/cmdline}"

cmdline=""
[[ -r "$CMDLINE_FILE" ]] && cmdline=$(tr -s ' ' < "$CMDLINE_FILE" | sed 's/^ //; s/ $//')

# Weakening-flag denylist (token or token-prefix match).
WEAKENERS=(
    "mitigations=off" "nosmep" "nosmap" "nokaslr" "noexec=off"
    "selinux=0" "apparmor=0" "init_on_alloc=0" "init_on_free=0"
    "audit=0" "lockdown=none" "single" "init=/bin/sh" "init=/bin/bash"
    "systemd.confirm_spawn" "rd.break"
)
present=()
for w in "${WEAKENERS[@]}"; do
    case " $cmdline " in
        *" $w "*|*" $w") present+=("$w") ;;
    esac
done

# First run: baseline.
if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    printf '%s\n' "$cmdline" > "$BASELINE"
    chmod 0600 "$BASELINE"
    pstr=$(IFS='|'; echo "${present[*]:-}")
    sev="ok"; [[ ${#present[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-kernel-cmdline -- "$(printf '{"tag":"selfdef-kernel-cmdline","severity":"%s","event":"baseline_initial","profile":"%s","weakeners_present":"%s"}' "$sev" "$PROFILE" "$pstr")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

base=$(cat "$BASELINE" 2>/dev/null)
changed=0
[[ "$cmdline" != "$base" ]] && changed=1

# Weakeners that are present now but were NOT in the baseline.
new_weakeners=()
for w in "${present[@]}"; do
    case " $base " in
        *" $w "*|*" $w") : ;;   # was already there
        *) new_weakeners+=("$w") ;;
    esac
done

severity="ok"; event="cmdline_intact"
if (( ${#new_weakeners[@]} > 0 )); then
    severity="alert"; event="weakening_flag_added"
elif (( ${#present[@]} > 0 )); then
    severity="alert"; event="weakening_flag_present"
elif (( changed )); then
    severity="warn"; event="cmdline_changed"
fi

pstr=$(IFS='|'; echo "${present[*]:-}")
nstr=$(IFS='|'; echo "${new_weakeners[*]:-}")

json=$(printf '{"tag":"selfdef-kernel-cmdline","severity":"%s","event":"%s","profile":"%s","changed":%d,"weakeners_present":"%s","weakeners_new":"%s"}' \
    "$severity" "$event" "$PROFILE" "$changed" "$pstr" "$nstr")
logger -t selfdef-kernel-cmdline -- "$json"

if (( changed )); then
    logger -t selfdef-kernel-cmdline-detail -- "WAS  ${base}"
    logger -t selfdef-kernel-cmdline-detail -- "NOW  ${cmdline}"
fi

# Refresh baseline so a confirmed-legit kernel-arg change becomes
# the new trusted cmdline (alert already fired this run).
printf '%s\n' "$cmdline" > "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
