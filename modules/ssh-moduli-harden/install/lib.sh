# Module-specific helpers for ssh-moduli-harden.
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

# SELFDEF_MODULI_FILE + SELFDEF_MODULI_BACKUP_DIR added 2026-06-06
# for L2 testability — live defaults unchanged.
MODULI_FILE="${SELFDEF_MODULI_FILE:-/etc/ssh/moduli}"
BACKUP_DIR="${SELFDEF_MODULI_BACKUP_DIR:-/var/lib/selfdef}"
BACKUP_FILE="${BACKUP_DIR}/ssh-moduli.bak"

# Threshold (minimum modulus bit-size) per profile.
profile_threshold() {
    case "$1" in
        strong)  echo 3072 ;;
        minimum) echo 2048 ;;
        *)       echo 3072 ;;
    esac
}

# /etc/ssh/moduli format: each non-comment line has 5 fields;
# field 5 is the modulus SIZE (bit length - 1 historically;
# modern ssh-keygen writes the actual usable bit size in
# field 5). We compare field 5 against the threshold.
# Count moduli >= threshold without modifying anything.
count_moduli_ge() {
    local file="$1" threshold="$2"
    [[ -r "$file" ]] || { echo 0; return; }
    awk -v t="$threshold" '!/^#/ && NF==5 && $5+0 >= t {n++} END{print n+0}' "$file"
}
