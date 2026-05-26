# selfdef shell-timeout-baseline — strict (TMOUT=300).
if [ -n "${BASH_VERSION:-}${KSH_VERSION:-}" ]; then
    case "$-" in
        *i*)
            TMOUT=300
            readonly TMOUT
            export TMOUT
            ;;
    esac
fi
