#!/usr/bin/env bash
# audit-rules — apply.
#
# Writes selfdef rule files to /etc/audit/rules.d/ + runs
# `augenrules --load` to atomic-swap the live rule set.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware. Only touches files
# prefixed `50-selfdef-*` so operator-authored rules in the
# same dir are preserved.

set -euo pipefail

MODULE="audit-rules"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AUDIT_RULES_CONFIG:-/etc/selfdef/modules/audit-rules.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
RULES_SRC="${SELFDEF_AUDIT_RULES_SRC:-${MODULE_DIR}/rules}"
RULES_DIR="${SELFDEF_AUDIT_RULES_DIR:-/etc/audit/rules.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$RULES_SRC" ]] || die "rule source dir missing: $RULES_SRC"
[[ -d "$RULES_DIR" ]] || die "audit rules dir missing: $RULES_DIR (install auditd package first)"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "base")
case "$PROFILE" in
    base|paranoid) ;;
    *) die "profile must be base|paranoid, got '$PROFILE'" ;;
esac

# Determine rule files to install.
RULE_FILES=()
case "$PROFILE" in
    base)
        RULE_FILES=("base.rules")
        ;;
    paranoid)
        # paranoid is base + paranoid (both files load; augenrules
        # concatenates by filename sort, both start with 50-selfdef-).
        RULE_FILES=("base.rules" "paranoid.rules")
        ;;
esac

installed=0
changes=0

for rf in "${RULE_FILES[@]}"; do
    src="${RULES_SRC}/${rf}"
    dst="${RULES_DIR}/50-selfdef-${rf}"
    [[ -r "$src" ]] || die "rule source missing: $src"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        : # no change
    else
        run "install ${rf}" -- install -m 0640 "$src" "$dst"
        changes=$((changes + 1))
    fi
    installed=$((installed + 1))
done

# Remove rule files that DON'T belong to the current profile.
# (Switching from paranoid → base must delete the paranoid file.)
for stale in "${RULES_DIR}"/50-selfdef-*.rules; do
    [[ -e "$stale" ]] || continue   # glob nomatch
    fname=$(basename "$stale")
    keep=false
    for rf in "${RULE_FILES[@]}"; do
        if [[ "$fname" == "50-selfdef-${rf}" ]]; then
            keep=true
            break
        fi
    done
    if ! $keep; then
        run "remove stale rule file $fname" -- rm -f "$stale"
        changes=$((changes + 1))
    fi
done

# Reload audit rules if we made any change.
if [[ "$changes" -gt 0 ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would run augenrules --load"
    else
        if command -v augenrules >/dev/null; then
            run "augenrules --load" -- augenrules --load
        else
            # Fallback: auditctl -R reloads one file at a time.
            for rf in "${RULE_FILES[@]}"; do
                run "auditctl -R 50-selfdef-${rf}" -- auditctl -R "${RULES_DIR}/50-selfdef-${rf}"
            done
        fi
    fi
fi

emit_status "ok" "audit-rules profile=$PROFILE installed=$installed changes=$changes"
