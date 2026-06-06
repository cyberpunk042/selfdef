#!/usr/bin/env bash
# dnf-automatic-config — apply.
#
# REPLACES /etc/dnf/automatic.conf (no conf.d). Backs up
# operator's original to .selfdef-backup on first apply.
# Enables --now the dnf-automatic.timer.

set -euo pipefail

MODULE="dnf-automatic-config"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_DNF_AUTO_CONFIG:-/etc/selfdef/modules/dnf-automatic-config.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "security-only")
case "$PROFILE" in
    security-only|security-and-reboot) ;;
    *) die "profile must be security-only|security-and-reboot, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$(dirname "$DNF_AUTO_CONF")"

# Backup operator's original on first apply.
if [[ -f "$DNF_AUTO_CONF" ]] && [[ ! -f "$DNF_AUTO_BACKUP" ]]; then
    if ! head -1 "$DNF_AUTO_CONF" | grep -qF "$DNF_AUTO_MARKER"; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would back up $DNF_AUTO_CONF → $DNF_AUTO_BACKUP"
        else
            install -m 0644 "$DNF_AUTO_CONF" "$DNF_AUTO_BACKUP"
        fi
    fi
fi

# Render with header marker.
tmp_rendered="$(mktemp)"
{
    echo "$DNF_AUTO_MARKER"
    # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
    echo "# profile=$PROFILE"
    cat "$src"
} > "$tmp_rendered"

changes=0
if [[ -f "$DNF_AUTO_CONF" ]] && cmp -s "$tmp_rendered" "$DNF_AUTO_CONF"; then
    rm -f "$tmp_rendered"
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DNF_AUTO_CONF"
        rm -f "$tmp_rendered"
    else
        install -m 0644 "$tmp_rendered" "$DNF_AUTO_CONF"
        rm -f "$tmp_rendered"
    fi
    changes=$((changes + 1))
fi

# Enable + start the timer.
if [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    if systemctl list-unit-files dnf-automatic.timer >/dev/null 2>&1; then
        run "enable + start dnf-automatic.timer" -- \
            systemctl enable --now dnf-automatic.timer || true
    else
        log "NOTICE: dnf-automatic.timer not present — install the dnf-automatic package via `dnf install dnf-automatic` first"
    fi
fi

emit_status "ok" "dnf-automatic-config profile=$PROFILE changes=$changes"
