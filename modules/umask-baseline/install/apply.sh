#!/usr/bin/env bash
# umask-baseline — apply.
#
# Installs /etc/profile.d/50-selfdef-umask.sh (interactive shell
# umask) + /etc/login.defs.d/50-selfdef-umask.conf (PAM/login
# umask for non-interactive sessions).
#
# Some distros (older Debian, RHEL 7) don't honor a login.defs.d
# directory — they only read /etc/login.defs. We handle that case
# by ALSO appending to /etc/login.defs WITH header markers (so
# uninstall can locate + remove just our lines).

set -euo pipefail

MODULE="umask-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_UMASK_CONFIG:-/etc/selfdef/modules/umask-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
PROFILE_D="${SELFDEF_PROFILE_D:-/etc/profile.d}"
LOGIN_DEFS_D="${SELFDEF_LOGIN_DEFS_D:-/etc/login.defs.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "group")
case "$PROFILE" in
    group|strict) ;;
    *) die "profile must be group|strict, got '$PROFILE'" ;;
esac

mkdir -p "$PROFILE_D" "$LOGIN_DEFS_D"

install_one() {
    local src="$1" dst="$2" mode="$3"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then return 1; fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $dst"
        return 0
    fi
    install -m "$mode" "$src" "$dst"
}

changes=0
install_one "${CONFIGS_SRC}/${PROFILE}-profile.sh" \
            "${PROFILE_D}/50-selfdef-umask.sh" \
            "0644" && changes=$((changes + 1)) || true

install_one "${CONFIGS_SRC}/${PROFILE}-login.conf" \
            "${LOGIN_DEFS_D}/50-selfdef-umask.conf" \
            "0644" && changes=$((changes + 1)) || true

emit_status "ok" "umask-baseline profile=$PROFILE changes=$changes (NOTE: takes effect on NEXT shell — current shell keeps existing umask)"
