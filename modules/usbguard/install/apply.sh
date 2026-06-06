#!/usr/bin/env bash
# usbguard — apply.
#
# Renders /etc/usbguard/rules.conf from the chosen profile.
# In `strict` mode, REQUIRES /etc/selfdef/usbguard/operator-
# baseline.rules to exist + be non-empty; refuses to install
# otherwise (refuse-to-brick safeguard — strict + empty
# baseline = locked-out keyboard).
#
# Also drops a 50-selfdef.conf into the daemon's drop-in dir
# pinning auditing on. Restarts usbguard.service.
#
# Idempotent: re-running with the same input writes byte-identical
# rules.conf. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="usbguard"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_USBGUARD_CONFIG:-/etc/selfdef/modules/usbguard.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
RULES_SRC="${SELFDEF_USBGUARD_RULES:-${MODULE_DIR}/rules}"
RULES_DST="${SELFDEF_USBGUARD_RULES_FILE:-/etc/usbguard/rules.conf}"
DAEMON_DROPIN_DIR="${SELFDEF_USBGUARD_DROPIN_DIR:-/etc/usbguard/usbguard-daemon.conf.d}"
DAEMON_DROPIN="${DAEMON_DROPIN_DIR}/50-selfdef.conf"
OPERATOR_DIR="${SELFDEF_USBGUARD_OPERATOR_DIR:-/etc/selfdef/usbguard}"
BASELINE_FILE="${SELFDEF_USBGUARD_BASELINE:-${OPERATOR_DIR}/operator-baseline.rules}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$RULES_SRC" ]] || die "rule source dir missing: $RULES_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "permissive")
case "$PROFILE" in
    permissive|strict) ;;
    *) die "profile must be permissive|strict, got '$PROFILE'" ;;
esac

mkdir -p "$OPERATOR_DIR"

# refuse-to-brick guard for strict mode.
if [[ "$PROFILE" == "strict" ]]; then
    if [[ ! -s "$BASELINE_FILE" ]]; then
        die "strict profile requires non-empty baseline at $BASELINE_FILE — \
generate one with 'usbguard generate-policy > $BASELINE_FILE' while \
profile=permissive is active, then re-apply"
    fi
fi

# Render the rules.conf.
tmp_rules="$(mktemp)"
{
    # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
    echo "# === selfdef usbguard rules.conf (profile=$PROFILE) ==="
    if [[ "$PROFILE" == "strict" ]]; then
        echo "# --- operator baseline (from $BASELINE_FILE) ---"
        cat "$BASELINE_FILE"
        echo "# --- tail (selfdef strict.conf) ---"
        cat "${RULES_SRC}/strict.conf"
    else
        cat "${RULES_SRC}/permissive.conf"
    fi
} > "$tmp_rules"

# Splice into rules.conf only if the content changed.
mkdir -p "$(dirname "$RULES_DST")"
if [[ -f "$RULES_DST" ]] && cmp -s "$tmp_rules" "$RULES_DST"; then
    rm -f "$tmp_rules"
    rules_changed=0
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would update $RULES_DST"
        rm -f "$tmp_rules"
    else
        install -m 0600 "$tmp_rules" "$RULES_DST"
        rm -f "$tmp_rules"
    fi
    rules_changed=1
fi

# Daemon drop-in.
tmp_dropin="$(mktemp)"
cat > "$tmp_dropin" <<EOF
# selfdef-managed daemon drop-in — audit-mode + restore-controller.
# Operator: do not edit; rendered by /etc/selfdef/modules/usbguard.toml + module apply.
AuditBackend=LinuxAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
EOF

mkdir -p "$DAEMON_DROPIN_DIR"
if [[ -f "$DAEMON_DROPIN" ]] && cmp -s "$tmp_dropin" "$DAEMON_DROPIN"; then
    rm -f "$tmp_dropin"
    dropin_changed=0
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would update $DAEMON_DROPIN"
        rm -f "$tmp_dropin"
    else
        install -m 0644 "$tmp_dropin" "$DAEMON_DROPIN"
        rm -f "$tmp_dropin"
    fi
    dropin_changed=1
fi

# Restart the daemon if anything changed.
if [[ "$rules_changed" == "1" || "$dropin_changed" == "1" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would systemctl restart usbguard.service"
    elif command -v systemctl >/dev/null; then
        run "restart usbguard.service" -- systemctl restart usbguard.service || true
    fi
fi

emit_status "ok" "usbguard profile=$PROFILE rules_changed=$rules_changed dropin_changed=$dropin_changed"
