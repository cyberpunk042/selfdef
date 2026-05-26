# Module-specific helpers for rsh-telnet-disable.
# shellcheck disable=SC1090,SC2034
SELFDEF_MODULE_LIB_VERSION_REQUIRED=2

if [[ -n "${SELFDEF_MODULE_LIB:-}" && -r "${SELFDEF_MODULE_LIB}" ]]; then
    # shellcheck disable=SC1090
    source "${SELFDEF_MODULE_LIB}"
elif [[ -r "${LIB_DIR}/../../../packaging/lib/module-lib.sh" ]]; then
    # shellcheck disable=SC1091
    source "${LIB_DIR}/../../../packaging/lib/module-lib.sh"
elif [[ -r "/usr/share/selfdef/lib/module-lib.sh" ]]; then
    # shellcheck disable=SC1091
    source "/usr/share/selfdef/lib/module-lib.sh"
else
    echo "ERROR: cannot locate module-lib.sh (set SELFDEF_MODULE_LIB)" >&2
    exit 2
fi

# Legacy cleartext-protocol unit set. Names vary across distros +
# whether inetd/xinetd or systemd-socket-activated. We try all.
LEGACY_UNITS=(
    "telnet.socket"
    "telnetd.service"
    "telnet.service"
    "rsh.socket"
    "rlogin.socket"
    "rexec.socket"
    "rsh.service"
    "rlogin.service"
    "rexec.service"
    "tftp.socket"
    "tftp.service"
    "atftpd.service"
    "finger.socket"
    "finger.service"
)
