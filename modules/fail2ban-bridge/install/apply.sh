#!/usr/bin/env bash
# fail2ban-bridge — apply.
#
# Installs jail.d drop-in(s) + restarts fail2ban via systemctl.
# Profile-driven: standard ships only 50-selfdef.conf;
# broad ships 50-selfdef.conf + 60-selfdef-recidive.conf.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="fail2ban-bridge"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_FAIL2BAN_CONFIG:-/etc/selfdef/modules/fail2ban-bridge.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
JAIL_D="${SELFDEF_FAIL2BAN_JAIL_D:-/etc/fail2ban/jail.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
case "$PROFILE" in
    standard|broad) ;;
    *) die "profile must be standard|broad, got '$PROFILE'" ;;
esac

mkdir -p "$JAIL_D"

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
# Always install the main drop-in for the chosen profile.
install_one "${CONFIGS_SRC}/${PROFILE}.conf" \
            "${JAIL_D}/50-selfdef.conf" \
            "0644" && changes=$((changes + 1)) || true

# Broad profile: also install recidive jail.
RECIDIVE_DST="${JAIL_D}/60-selfdef-recidive.conf"
if [[ "$PROFILE" == "broad" ]]; then
    install_one "${CONFIGS_SRC}/recidive.conf" \
                "$RECIDIVE_DST" \
                "0644" && changes=$((changes + 1)) || true
else
    # Downgrade: standard profile → remove recidive drop-in if present.
    if [[ -f "$RECIDIVE_DST" ]]; then
        run "remove recidive drop-in (profile downgrade)" -- rm -f "$RECIDIVE_DST"
        changes=$((changes + 1))
    fi
fi

if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    # fail2ban-client reload IS the canonical reload path (graceful);
    # systemctl restart fall-back catches the case where reload
    # fails on a malformed config.
    if command -v fail2ban-client >/dev/null 2>&1; then
        run "fail2ban-client reload" -- fail2ban-client reload || \
            run "systemctl restart fail2ban" -- systemctl restart fail2ban || true
    else
        run "systemctl restart fail2ban" -- systemctl restart fail2ban || true
    fi
fi

emit_status "ok" "fail2ban-bridge profile=$PROFILE changes=$changes"
