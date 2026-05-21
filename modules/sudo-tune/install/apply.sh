#!/usr/bin/env bash
# sudo-tune — apply.
#
# Installs /etc/sudoers.d/50-selfdef-tune via the canonical
# visudo -cf validation pattern. A syntactically-bad sudoers
# file LOCKS THE OPERATOR OUT of sudo — visudo -cf is the
# refuse-to-brick guard.
#
# Also creates the iolog dir + (paranoid profile only) the
# lecture file.

set -euo pipefail

MODULE="sudo-tune"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_SUDO_TUNE_CONFIG:-/etc/selfdef/modules/sudo-tune.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
SUDOERS_D="${SELFDEF_SUDOERS_D:-/etc/sudoers.d}"
DST="${SUDOERS_D}/50-selfdef-tune"
IOLOG_DIR="${SELFDEF_SUDO_IOLOG_DIR:-/var/log/sudo-io}"
LECTURE_FILE="${SELFDEF_SUDO_LECTURE:-/etc/selfdef/sudo-lecture.txt}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit-trail")
case "$PROFILE" in
    audit-trail|paranoid) ;;
    *) die "profile must be audit-trail|paranoid, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$IOLOG_DIR"
chmod 0700 "$IOLOG_DIR"
chown root:root "$IOLOG_DIR"

# Lecture file (paranoid only — audit-trail uses sudo's built-in
# default lecture text).
if [[ "$PROFILE" == "paranoid" ]]; then
    mkdir -p "$(dirname "$LECTURE_FILE")"
    if [[ "$DRY_RUN" != "1" ]]; then
        install -m 0644 "${CONFIGS_SRC}/lecture.txt" "$LECTURE_FILE"
    fi
fi

# REFUSE-TO-BRICK: validate the new file with visudo -cf BEFORE
# installing. If visudo rejects it, we keep the operator's
# previous (functional) /etc/sudoers.d intact.
tmp_validate="$(mktemp)"
cp "$src" "$tmp_validate"
if ! visudo -cf "$tmp_validate" >/dev/null 2>&1; then
    rm -f "$tmp_validate"
    die "visudo -cf REJECTED the rendered profile — refusing to install (would lock the operator out)"
fi
rm -f "$tmp_validate"

changes=0
if [[ -f "$DST" ]] && cmp -s "$src" "$DST"; then
    :
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DST (mode 0440)"
    else
        install -m 0440 "$src" "$DST"
    fi
    changes=$((changes + 1))
fi

emit_status "ok" "sudo-tune profile=$PROFILE changes=$changes iolog_dir=$IOLOG_DIR"
