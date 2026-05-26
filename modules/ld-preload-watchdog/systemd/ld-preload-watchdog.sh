#!/usr/bin/env bash
# selfdef ld-preload-watchdog — surface LD_PRELOAD userland-
# rootkit hooks.
#
# Checks three injection surfaces:
#   1. /etc/ld.so.preload — the system-wide preload file.
#      ANY entry is suspicious on most hosts (it's empty/absent
#      by default; legit uses are rare — e.g. some HPC, snoopy).
#   2. Global LD_PRELOAD / LD_LIBRARY_PATH in env files:
#      /etc/environment, /etc/profile, /etc/profile.d/*.sh,
#      /etc/bash.bashrc, root's ~/.bashrc ~/.bash_profile
#      ~/.profile.
#   3. Preload libs residing in world-writable / tmp paths
#      (a preload lib in /tmp or /dev/shm is malware-grade).
#
# Severity:
#   ok    → nothing found
#   warn  → ld.so.preload entry OR global LD_PRELOAD that
#           points to a lib under a trusted path
#   alert → preload lib under /tmp /var/tmp /dev/shm /home OR
#           a non-existent/deleted lib path (classic rootkit)

set -u

PROFILE="${SELFDEF_LDPRELOAD_PROFILE:-report}"

findings=0
alerts=0
sample=()

note() {  # severity_is_alert  text
    local is_alert="$1" text="$2"
    findings=$((findings + 1))
    [[ "$is_alert" == "1" ]] && alerts=$((alerts + 1))
    (( ${#sample[@]} < 10 )) && sample+=("$text")
}

is_suspicious_path() {
    case "$1" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/run/*) return 0 ;;
    esac
    # A path that doesn't exist on disk (deleted-after-load
    # rootkit) is also suspicious.
    [[ -n "$1" && ! -e "$1" ]] && return 0
    return 1
}

# 1. /etc/ld.so.preload
if [[ -s /etc/ld.so.preload ]]; then
    while IFS= read -r lib; do
        lib="$(echo "$lib" | sed 's/#.*//' | tr -d ' ')"
        [[ -z "$lib" ]] && continue
        if is_suspicious_path "$lib"; then
            note 1 "ld.so.preload:${lib}:SUSPICIOUS_PATH"
        else
            note 0 "ld.so.preload:${lib}"
        fi
    done < /etc/ld.so.preload
fi

# 2. Global env files referencing LD_PRELOAD / LD_LIBRARY_PATH.
ENV_FILES=(
    /etc/environment /etc/profile /etc/bash.bashrc
    /root/.bashrc /root/.bash_profile /root/.profile
)
for f in /etc/profile.d/*.sh; do [[ -f "$f" ]] && ENV_FILES+=("$f"); done
for f in "${ENV_FILES[@]}"; do
    [[ -r "$f" ]] || continue
    while IFS= read -r line; do
        # extract the assigned path(s)
        val=$(echo "$line" | sed -E 's/.*LD_PRELOAD=//; s/[";].*//' | tr ':' ' ')
        # read -ra (NOT `for lib in $val`) so a path containing a glob
        # char is not expanded against the cwd.
        read -r -a _libs <<< "$val"
        for lib in "${_libs[@]}"; do
            [[ -z "$lib" || "$lib" == export ]] && continue
            if is_suspicious_path "$lib"; then
                note 1 "${f}:LD_PRELOAD=${lib}:SUSPICIOUS"
            else
                note 0 "${f}:LD_PRELOAD=${lib}"
            fi
        done
    done < <(grep -E '(^|[^A-Z_])LD_PRELOAD=' "$f" 2>/dev/null)
done

severity="ok"; event="no_ld_preload"
if (( alerts > 0 )); then
    severity="alert"; event="suspicious_ld_preload"
elif (( findings > 0 )); then
    severity="warn"; event="ld_preload_present"
fi

sample_str=$(IFS='|'; echo "${sample[*]:-}")

json=$(printf '{"tag":"selfdef-ld-preload","severity":"%s","event":"%s","profile":"%s","findings":%d,"alerts":%d,"sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$findings" "$alerts" "$sample_str")
logger -t selfdef-ld-preload -- "$json"

for s in "${sample[@]}"; do
    logger -t selfdef-ld-preload-detail -- "$s"
done

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
