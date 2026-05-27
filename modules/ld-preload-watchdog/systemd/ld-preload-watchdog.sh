#!/usr/bin/env bash
# selfdef ld-preload-watchdog — surface LD_PRELOAD userland-
# rootkit hooks.
#
# Checks four injection surfaces:
#   1. /etc/ld.so.preload — the system-wide preload file.
#      ANY entry is suspicious on most hosts (it's empty/absent
#      by default; legit uses are rare — e.g. some HPC, snoopy).
#   2. Global LD_PRELOAD / LD_AUDIT in shell env files:
#      /etc/environment, /etc/profile, /etc/profile.d/*.sh,
#      /etc/bash.bashrc, root's ~/.bashrc ~/.bash_profile
#      ~/.profile. (LD_AUDIT is the rtld-audit sibling of
#      LD_PRELOAD — same .so-into-every-program injection.)
#   3. pam_env injection: /etc/security/pam_env.conf
#      (LD_PRELOAD DEFAULT=/...) + /etc/environment.d/*.conf,
#      applied at login by pam_env (distinct syntax/vector).
#   4. Preload libs residing in world-writable / tmp paths
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

# Test/override seams — default to the production paths (no behavior change
# in production; the L2 suite points these at a sandbox).
LDPRELOAD_FILE="${SELFDEF_LDPRELOAD_FILE:-/etc/ld.so.preload}"

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
if [[ -s "$LDPRELOAD_FILE" ]]; then
    while IFS= read -r lib; do
        lib="$(echo "$lib" | sed 's/#.*//' | tr -d ' ')"
        [[ -z "$lib" ]] && continue
        if is_suspicious_path "$lib"; then
            note 1 "ld.so.preload:${lib}:SUSPICIOUS_PATH"
        else
            note 0 "ld.so.preload:${lib}"
        fi
    done < "$LDPRELOAD_FILE"
fi

# 2. Global env files referencing LD_PRELOAD / LD_LIBRARY_PATH.
if [[ -n "${SELFDEF_LDPRELOAD_ENV_FILES:-}" ]]; then
    read -r -a ENV_FILES <<< "${SELFDEF_LDPRELOAD_ENV_FILES}"
else
    ENV_FILES=(
        /etc/environment /etc/profile /etc/bash.bashrc
        /root/.bashrc /root/.bash_profile /root/.profile
    )
    for f in /etc/profile.d/*.sh; do [[ -f "$f" ]] && ENV_FILES+=("$f"); done
fi
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
    # LD_AUDIT — the rtld-audit sibling of LD_PRELOAD; loads a .so as
    # an auditor into every dynamically-linked program (T1574.006).
    while IFS= read -r line; do
        val=$(echo "$line" | sed -E 's/.*LD_AUDIT=//; s/[";].*//' | tr ':' ' ')
        read -r -a _alibs <<< "$val"
        for lib in "${_alibs[@]}"; do
            [[ -z "$lib" || "$lib" == export ]] && continue
            if is_suspicious_path "$lib"; then
                note 1 "${f}:LD_AUDIT=${lib}:SUSPICIOUS"
            else
                note 0 "${f}:LD_AUDIT=${lib}"
            fi
        done
    done < <(grep -E '(^|[^A-Z_])LD_AUDIT=' "$f" 2>/dev/null)
done

# 3. pam_env injection: /etc/security/pam_env.conf uses the syntax
#    `LD_PRELOAD DEFAULT=/path` / `LD_PRELOAD OVERRIDE=/path`, and
#    /etc/environment.d/*.conf uses `LD_PRELOAD=/path`. pam_env
#    applies these at login — a separate vector from the shell-env
#    files above, missed by a plain `LD_PRELOAD=` grep.
if [[ -n "${SELFDEF_LDPRELOAD_PAMENV_FILES:-}" ]]; then
    read -r -a PAMENV_FILES <<< "${SELFDEF_LDPRELOAD_PAMENV_FILES}"
else
    PAMENV_FILES=(/etc/security/pam_env.conf)
    for f in /etc/environment.d/*.conf; do [[ -f "$f" ]] && PAMENV_FILES+=("$f"); done
fi
for f in "${PAMENV_FILES[@]}"; do
    [[ -r "$f" ]] || continue
    while IFS= read -r line; do
        line="${line%%#*}"
        case "$line" in *LD_PRELOAD*|*LD_AUDIT*) ;; *) continue ;; esac
        # Pull the path after DEFAULT=/OVERRIDE=/= (pam_env or env.d).
        val=$(printf '%s' "$line" | sed -E 's/.*(DEFAULT=|OVERRIDE=|=)//; s/[";].*//' | tr ':' ' ')
        read -r -a _plibs <<< "$val"
        for lib in "${_plibs[@]}"; do
            [[ -z "$lib" || "$lib" == LD_PRELOAD || "$lib" == LD_AUDIT ]] && continue
            if is_suspicious_path "$lib"; then
                note 1 "${f}:pam_env:${lib}:SUSPICIOUS"
            else
                note 0 "${f}:pam_env:${lib}"
            fi
        done
    done < <(grep -E 'LD_PRELOAD|LD_AUDIT' "$f" 2>/dev/null)
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
