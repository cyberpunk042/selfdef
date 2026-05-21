#!/usr/bin/env bash
# journal-tune — apply.
#
# Writes /etc/systemd/journald.conf.d/50-selfdef.conf with the
# chosen profile + restarts systemd-journald via systemctl
# kill --kill-who=main --signal=SIGUSR2 (forces journal rotation)
# then systemctl restart systemd-journald.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="journal-tune"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_JOURNAL_TUNE_CONFIG:-/etc/selfdef/modules/journal-tune.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
DROPIN_DIR="${SELFDEF_JOURNAL_DROPIN_DIR:-/etc/systemd/journald.conf.d}"
DST="${DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
case "$PROFILE" in
    standard|paranoid) ;;
    *) die "profile must be standard|paranoid, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$DROPIN_DIR"

changes=0
if [[ -f "$DST" ]] && cmp -s "$src" "$DST"; then
    :
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DST"
    else
        install -m 0644 "$src" "$DST"
    fi
    changes=$((changes + 1))
fi

if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl restart systemd-journald" -- systemctl restart systemd-journald || true
fi

emit_status "ok" "journal-tune profile=$PROFILE changes=$changes"
