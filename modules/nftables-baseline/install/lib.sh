# Module-specific helpers for nftables-baseline.
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

NFT_DROPIN_DIR="/etc/nftables.d"
NFT_DROPIN="${NFT_DROPIN_DIR}/selfdef-baseline.nft"
BACKUP_DIR="/var/lib/selfdef"
BACKUP_FILE="${BACKUP_DIR}/nftables-ruleset.bak"
HEADER_MARKER="# managed-by: selfdef nftables-baseline"

# SSH is ALWAYS in the allow set — the anti-lockout invariant.
# Detect the actual sshd port(s) so a non-22 sshd isn't locked
# out either.
detect_ssh_ports() {
    local ports=""
    if command -v ss >/dev/null 2>&1; then
        ports=$(ss -Hnlt 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' \
                | sort -un | while read -r p; do
                    # heuristic: sshd commonly 22; include any port a
                    # process named sshd listens on.
                    :; done)
    fi
    # Robust: parse sshd_config Port lines + always include 22.
    local cfgports
    cfgports=$(awk 'tolower($1)=="port"{print $2}' /etc/ssh/sshd_config 2>/dev/null | tr '\n' ' ')
    echo "22 ${cfgports}" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -un | tr '\n' ' '
}
