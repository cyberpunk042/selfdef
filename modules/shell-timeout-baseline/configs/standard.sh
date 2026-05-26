# selfdef shell-timeout-baseline — standard (TMOUT=900).
# Sourced for interactive login shells. readonly so a casual
# `unset TMOUT` in the session fails (operator can still open
# a fresh non-login shell — this is a deterrent + CIS control,
# not a hard jail).
if [ -n "${BASH_VERSION:-}${KSH_VERSION:-}" ]; then
    case "$-" in
        *i*)
            TMOUT=900
            readonly TMOUT
            export TMOUT
            ;;
    esac
fi
