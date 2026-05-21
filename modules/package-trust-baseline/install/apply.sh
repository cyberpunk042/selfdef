#!/usr/bin/env bash
# package-trust-baseline — apply.
#
# Installs /etc/apt/apt.conf.d/50-selfdef-secure with the chosen
# profile. Validates the result with `apt-config dump` after
# write so a syntactically-bad file rolls back via the backup
# pattern.

set -euo pipefail

MODULE="package-trust-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_PKG_TRUST_CONFIG:-/etc/selfdef/modules/package-trust-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
APT_CONFD="${SELFDEF_APT_CONFD:-/etc/apt/apt.conf.d}"
DST="${APT_CONFD}/50-selfdef-secure"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
case "$PROFILE" in
    standard|strict) ;;
    *) die "profile must be standard|strict, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$APT_CONFD"

# Backup current state IF it exists.
backup=""
if [[ -f "$DST" ]]; then
    backup="${DST}.selfdef-rollback.$$"
    cp "$DST" "$backup"
fi

changes=0
if [[ -f "$DST" ]] && cmp -s "$src" "$DST"; then
    :
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DST"
        changes=1
    else
        install -m 0644 "$src" "$DST"
        # Validate by running apt-config dump — a syntactically-bad
        # file makes apt-config exit non-zero. Rollback on failure.
        if ! apt-config dump >/dev/null 2>&1; then
            log "apt-config dump REJECTED the new file; rolling back"
            if [[ -n "$backup" ]] && [[ -f "$backup" ]]; then
                mv "$backup" "$DST"
            else
                rm -f "$DST"
            fi
            die "apt-config dump validation failed — refused to commit"
        fi
        changes=1
    fi
fi

[[ -n "$backup" ]] && [[ -f "$backup" ]] && rm -f "$backup"

emit_status "ok" "package-trust-baseline profile=$PROFILE changes=$changes"
