#!/usr/bin/env bash
# selinux-baseline — apply.

set -euo pipefail

MODULE="selinux-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_SELINUX_CONFIG:-/etc/selfdef/modules/selinux-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")
case "$PROFILE" in
    audit|permissive|enforcing) ;;
    *) die "profile must be audit|permissive|enforcing, got '$PROFILE'" ;;
esac

LIVE=$(selinux_live_mode)
CFG=$(selinux_config_mode)
DENIALS=$(selinux_recent_denials)

# SELinux not present (e.g. Debian/Ubuntu host) → no-op. The
# conflicts=["apparmor-baseline"] manifest field steers
# operators to the right module per distro.
if [[ "$LIVE" == "unavailable" ]]; then
    log "SELinux not available on this host (getenforce missing) — use apparmor-baseline on Debian/Ubuntu"
    emit_status "ok" "selinux-baseline no-op (SELinux unavailable)"
    exit 0
fi

# audit profile: report only.
if [[ "$PROFILE" == "audit" ]]; then
    log "SELinux live=$LIVE config=$CFG recent_denials=$DENIALS"
    emit_status "ok" "selinux-baseline audit: live=$LIVE config=$CFG denials=$DENIALS"
    exit 0
fi

if [[ "$PROFILE" == "permissive" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would set SELINUX=permissive + setenforce 0"
        emit_status "ok" "selinux-baseline DRY_RUN profile=permissive"
        exit 0
    fi
    # Persist + live (setenforce 0 is always safe — never bricks).
    if [[ -w "$SELINUX_CONFIG" || -w "$(dirname "$SELINUX_CONFIG")" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=permissive/' "$SELINUX_CONFIG" 2>/dev/null || true
    fi
    if [[ "$LIVE" == "Enforcing" ]]; then
        setenforce 0 2>/dev/null && log "setenforce 0 (live permissive)" || log "WARN: setenforce 0 failed"
    fi
    emit_status "ok" "selinux-baseline profile=permissive (config persisted; live=$(selinux_live_mode))"
    exit 0
fi

# enforcing profile.
if [[ "$PROFILE" == "enforcing" ]]; then
    # Refuse-to-brick: disabled→enforcing needs a full filesystem
    # autorelabel + reboot. Doing it blind can leave the host
    # unbootable if labels are wrong. Require acknowledge_relabel.
    if [[ "$LIVE" == "Disabled" || "$CFG" == "disabled" ]]; then
        ack=$(toml_get acknowledge_relabel "$CONFIG_FILE" 2>/dev/null || echo "false")
        if [[ "$ack" != "true" ]]; then
            die "SELinux is currently disabled. disabled→enforcing requires a full filesystem autorelabel + reboot, which can leave the host unbootable if mislabeled. Add 'acknowledge_relabel = true' to $CONFIG_FILE to proceed (we will set SELINUX=enforcing + schedule /.autorelabel; YOU must reboot)."
        fi
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would set SELINUX=enforcing + touch /.autorelabel (reboot required)"
            emit_status "ok" "selinux-baseline DRY_RUN profile=enforcing (relabel path)"
            exit 0
        fi
        sed -i 's/^SELINUX=.*/SELINUX=enforcing/' "$SELINUX_CONFIG" 2>/dev/null || true
        touch "$SELFDEF_AUTORELABEL_FILE" 2>/dev/null || true
        log "set SELINUX=enforcing + scheduled /.autorelabel — OPERATOR MUST REBOOT to relabel + enter enforcing"
        emit_status "ok" "selinux-baseline profile=enforcing (relabel scheduled; reboot required)"
        exit 0
    fi

    # Already permissive or enforcing → safe to go live.
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would set SELINUX=enforcing + setenforce 1"
        emit_status "ok" "selinux-baseline DRY_RUN profile=enforcing"
        exit 0
    fi
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' "$SELINUX_CONFIG" 2>/dev/null || true
    setenforce 1 2>/dev/null && log "setenforce 1 (live enforcing)" || log "WARN: setenforce 1 failed"
    emit_status "ok" "selinux-baseline profile=enforcing (config persisted; live=$(selinux_live_mode); recent_denials=$DENIALS)"
    exit 0
fi
