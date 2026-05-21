#!/usr/bin/env bash
# unattended-upgrades-config — apply.
#
# Installs apt.conf.d drop-ins:
#   50selfdef-unattended-upgrades  — security-only base config
#   60selfdef-unattended-reboot    — reboot override (security-and-reboot only)
#   20selfdef-periodic             — apt.systemd.daily schedule enable
# Then enables apt-daily-upgrade.timer + apt-daily.timer.

set -euo pipefail

MODULE="unattended-upgrades-config"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_UU_CONFIG:-/etc/selfdef/modules/unattended-upgrades-config.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
APT_CONFD="${SELFDEF_APT_CONFD:-/etc/apt/apt.conf.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "security-only")
case "$PROFILE" in
    security-only|security-and-reboot) ;;
    *) die "profile must be security-only|security-and-reboot, got '$PROFILE'" ;;
esac

mkdir -p "$APT_CONFD"

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
# Always install the base + periodic.
install_one "${CONFIGS_SRC}/unattended-upgrades.conf" \
            "${APT_CONFD}/50selfdef-unattended-upgrades" \
            "0644" && changes=$((changes + 1)) || true
install_one "${CONFIGS_SRC}/periodic.conf" \
            "${APT_CONFD}/20selfdef-periodic" \
            "0644" && changes=$((changes + 1)) || true

# Profile-driven reboot override.
REBOOT_DST="${APT_CONFD}/60selfdef-unattended-reboot"
if [[ "$PROFILE" == "security-and-reboot" ]]; then
    install_one "${CONFIGS_SRC}/unattended-upgrades-reboot.conf" \
                "$REBOOT_DST" \
                "0644" && changes=$((changes + 1)) || true
else
    # Downgrade: profile flipped → remove the reboot override file.
    if [[ -f "$REBOOT_DST" ]]; then
        run "remove reboot override (profile downgrade)" -- rm -f "$REBOOT_DST"
        changes=$((changes + 1))
    fi
fi

# Enable the apt-daily-upgrade.timer (drives unattended-upgrade) +
# apt-daily.timer (drives apt-get update).
if [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "enable apt-daily.timer" -- systemctl enable --now apt-daily.timer || true
    run "enable apt-daily-upgrade.timer" -- systemctl enable --now apt-daily-upgrade.timer || true
fi

emit_status "ok" "unattended-upgrades-config profile=$PROFILE changes=$changes"
