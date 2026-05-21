#!/usr/bin/env bash
# auditd-immutable — apply.
#
# Installs /etc/audit/rules.d/99-selfdef-immutable.rules and
# runs `augenrules --load` to apply. The 99- prefix ensures
# this rule is consulted AFTER every other rule file (audit-
# rules ships 50-selfdef-base.rules + 50-selfdef-paranoid.rules).
#
# enforce profile triggers `-e 2` which locks the rules; from
# then until reboot, all auditctl modifications are refused.

set -euo pipefail

MODULE="auditd-immutable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AUDITD_IMMUTABLE_CONFIG:-/etc/selfdef/modules/auditd-immutable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
RULES_D="${SELFDEF_AUDIT_RULES_D:-/etc/audit/rules.d}"
DST="${RULES_D}/99-selfdef-immutable.rules"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"
[[ -d "$RULES_D" ]] || die "audit rules.d missing: $RULES_D (install auditd package + apply audit-rules module first)"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")
case "$PROFILE" in
    audit|enforce) ;;
    *) die "profile must be audit|enforce, got '$PROFILE'" ;;
esac

# REFUSE-TO-BRICK: enforce profile requires acknowledge_immutable.
if [[ "$PROFILE" == "enforce" ]]; then
    ACK=$(toml_get acknowledge_immutable "$CONFIG_FILE" || echo "false")
    if [[ "$ACK" != "true" ]]; then
        die "enforce profile sets -e 2 which locks audit rules until reboot; set acknowledge_immutable = true in $CONFIG_FILE after baseline-tuning of audit-rules is complete + confirming no operator workflow needs runtime auditctl modification"
    fi
fi

src="${CONFIGS_SRC}/${PROFILE}.rules"
[[ -r "$src" ]] || die "profile source missing: $src"

changes=0
if [[ -f "$DST" ]] && cmp -s "$src" "$DST"; then
    :
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DST"
    else
        install -m 0640 "$src" "$DST"
    fi
    changes=$((changes + 1))
fi

# Reload audit rules via augenrules + auditd restart.
if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]]; then
    if command -v augenrules >/dev/null 2>&1; then
        run "augenrules --load" -- augenrules --load || true
    fi
    # Note: if -e 2 was previously set by an EARLIER rule load,
    # augenrules --load BELOW IT will FAIL silently for new rules.
    # That's the point — only reboot can unlock. Operator
    # encountering this should reboot.
fi

# Detect live state.
if command -v auditctl >/dev/null 2>&1; then
    live_e=$(auditctl -s 2>/dev/null | awk -F': *' '/^enabled/ {print $2; exit}' || echo "?")
    log "live audit enabled=$live_e (0=off, 1=on-mutable, 2=immutable)"
fi

emit_status "ok" "auditd-immutable profile=$PROFILE changes=$changes"
