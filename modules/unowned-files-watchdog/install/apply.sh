#!/usr/bin/env bash
# unowned-files-watchdog — apply.

set -euo pipefail

MODULE="unowned-files-watchdog"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_UNOWNED_CONFIG:-/etc/selfdef/modules/unowned-files-watchdog.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
SYSTEMD_SRC="${MODULE_DIR}/systemd"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")
case "$PROFILE" in
    report|enforce) ;;
    *) die "profile must be report|enforce, got '$PROFILE'" ;;
esac

mkdir -p "$LIBEXEC_DIR"

install_one() {
    local src="$1" dst="$2" mode="$3"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then return 1; fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $dst (mode $mode)"
        return 0
    fi
    install -m "$mode" "$src" "$dst"
}

changes=0
install_one "${SYSTEMD_SRC}/unowned-files-watchdog.sh"        "${LIBEXEC_DIR}/unowned-files-watchdog.sh"        "0755" && changes=$((changes + 1)) || true
install_one "${SYSTEMD_SRC}/selfdef-unowned-files.service"    "${SYSTEMD_DIR}/selfdef-unowned-files.service"    "0644" && changes=$((changes + 1)) || true
install_one "${SYSTEMD_SRC}/selfdef-unowned-files.timer"      "${SYSTEMD_DIR}/selfdef-unowned-files.timer"      "0644" && changes=$((changes + 1)) || true

# Profile drop-in (Environment=SELFDEF_UNOWNED_PROFILE).
DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-unowned-files.service.d"
DROPIN_PROFILE="${DROPIN_DIR_SVC}/50-profile.conf"
mkdir -p "$DROPIN_DIR_SVC"
tmp_dropin="$(mktemp)"
cat > "$tmp_dropin" <<EOF
[Service]
Environment=SELFDEF_UNOWNED_PROFILE=${PROFILE}
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

if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]]; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    run "enable + start selfdef-unowned-files.timer" -- \
        systemctl enable --now selfdef-unowned-files.timer || true
fi

emit_status "ok" "unowned-files-watchdog profile=$PROFILE changes=$changes"
