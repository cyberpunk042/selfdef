#!/usr/bin/env bash
# aide-bridge — apply.
#
# 1. Drops /etc/aide/aide.conf.d/50-selfdef.conf
# 2. Installs the wrapper script to /usr/local/libexec/selfdef/
#    aide-check.sh
# 3. Installs systemd service + timer to /etc/systemd/system/
# 4. Initializes the AIDE database if missing (aideinit; can take
#    several minutes on a hosts with /opt + /usr/local populated).
# 5. systemctl daemon-reload + enable + start timer.
#
# Drop-in installs the SELFDEF_AIDE_PROFILE env into the service
# unit's [Service] section so the wrapper script reads the right
# profile at every probe.

set -euo pipefail

MODULE="aide-bridge"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AIDE_BRIDGE_CONFIG:-/etc/selfdef/modules/aide-bridge.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
SYSTEMD_SRC="${MODULE_DIR}/systemd"

AIDE_CONFD="${SELFDEF_AIDE_CONFD:-/etc/aide/aide.conf.d}"
AIDE_DROPIN="${AIDE_CONFD}/50-selfdef.conf"
AIDE_DB_DIR="${SELFDEF_AIDE_DB_DIR:-/var/lib/aide}"
AIDE_DB="${AIDE_DB_DIR}/aide.db"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"
[[ -d "$SYSTEMD_SRC" ]] || die "systemd dir missing: $SYSTEMD_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")
case "$PROFILE" in
    baseline|enforce) ;;
    *) die "profile must be baseline|enforce, got '$PROFILE'" ;;
esac

mkdir -p "$AIDE_CONFD" "$AIDE_DB_DIR" "$LIBEXEC_DIR"

install_one() {
    local src="$1" dst="$2" mode="$3"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        return 1
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $dst (mode $mode)"
        return 0
    fi
    install -m "$mode" "$src" "$dst"
}

changes=0
install_one "${CONFIGS_SRC}/aide.conf"                 "$AIDE_DROPIN"                                          "0644" && changes=$((changes + 1)) || true
install_one "${SYSTEMD_SRC}/aide-check.sh"             "${LIBEXEC_DIR}/aide-check.sh"                          "0755" && changes=$((changes + 1)) || true
install_one "${SYSTEMD_SRC}/selfdef-aide-check.service" "${SYSTEMD_DIR}/selfdef-aide-check.service"            "0644" && changes=$((changes + 1)) || true
install_one "${SYSTEMD_SRC}/selfdef-aide-check.timer"  "${SYSTEMD_DIR}/selfdef-aide-check.timer"               "0644" && changes=$((changes + 1)) || true

# Render a drop-in to inject SELFDEF_AIDE_PROFILE into the service
# env. systemd composes /etc/systemd/system/selfdef-aide-check.
# service.d/*.conf with the base unit.
DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-aide-check.service.d"
DROPIN_PROFILE="${DROPIN_DIR_SVC}/50-profile.conf"
mkdir -p "$DROPIN_DIR_SVC"
tmp_dropin="$(mktemp)"
cat > "$tmp_dropin" <<EOF
[Service]
Environment=SELFDEF_AIDE_PROFILE=${PROFILE}
EOF
if [[ -f "$DROPIN_PROFILE" ]] && cmp -s "$tmp_dropin" "$DROPIN_PROFILE"; then
    rm -f "$tmp_dropin"
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DROPIN_PROFILE"
        rm -f "$tmp_dropin"
    else
        install -m 0644 "$tmp_dropin" "$DROPIN_PROFILE"
        rm -f "$tmp_dropin"
    fi
    changes=$((changes + 1))
fi

# Initialize AIDE database if missing.
if [[ ! -f "$AIDE_DB" ]] && [[ "$DRY_RUN" != "1" ]]; then
    log "initializing AIDE database (may take several minutes)..."
    if command -v aideinit >/dev/null 2>&1; then
        run "aideinit" -- aideinit || true
        # aideinit writes aide.db.new — move into place.
        if [[ -f "${AIDE_DB}.new" ]]; then
            mv "${AIDE_DB}.new" "$AIDE_DB"
        fi
    elif command -v aide >/dev/null 2>&1; then
        run "aide --init" -- aide --init || true
        if [[ -f "${AIDE_DB}.new" ]]; then
            mv "${AIDE_DB}.new" "$AIDE_DB"
        fi
    fi
fi

if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]]; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    run "enable + start selfdef-aide-check.timer" -- \
        systemctl enable --now selfdef-aide-check.timer || true
fi

emit_status "ok" "aide-bridge profile=$PROFILE changes=$changes db_exists=$([ -f "$AIDE_DB" ] && echo yes || echo no)"
