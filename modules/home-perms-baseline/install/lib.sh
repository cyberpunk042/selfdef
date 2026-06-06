# Module-specific helpers for home-perms-baseline.
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

BACKUP_DIR="${SELFDEF_HOMEPERMS_BACKUP_DIR:-/var/lib/selfdef}"
BACKUP_FILE="${BACKUP_DIR}/home-perms.bak"

# Enumerate real human home dirs under /home that belong to a
# login user with uid >= 1000 (skip system accounts, skip
# operator-prefixed names so selfdef never touches them).
# Emits "path\tuid\towner\tmode" per eligible home.
enumerate_homes() {
    local minuid="${SELFDEF_HOME_MINUID:-1000}"
    # Source overrides: operator-test affordance + L2 testability.
    # Default /etc/passwd + /home/ prefix; SELFDEF_HOME_PASSWD lets
    # the L2 suite feed a fixture passwd file; SELFDEF_HOME_PREFIX
    # overrides the home-directory regex prefix (default /home/) so
    # fixtures can place test homes under a tmpdir.
    local passwd="${SELFDEF_HOME_PASSWD:-/etc/passwd}"
    local prefix="${SELFDEF_HOME_PREFIX:-/home/}"
    awk -F: -v min="$minuid" -v p="$prefix" '$3>=min && index($6, p)==1 {print $6 "\t" $3 "\t" $1}' "$passwd" \
    | while IFS=$'\t' read -r dir uid user; do
        [[ -d "$dir" ]] || continue
        # Skip operator-prefixed accounts (selfdef never touches).
        case "$user" in operator|operator-*|selfdef|selfdef-*) continue ;; esac
        local mode
        mode=$(stat -c '%a' "$dir" 2>/dev/null || echo "?")
        printf '%s\t%s\t%s\t%s\n' "$dir" "$uid" "$user" "$mode"
    done
}
