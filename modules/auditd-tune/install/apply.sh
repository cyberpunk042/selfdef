#!/usr/bin/env bash
# auditd-tune — apply.
#
# REPLACES /etc/audit/auditd.conf (auditd doesn't honor conf.d).
# On first apply, backs up the operator's original to
# auditd.conf.selfdef-backup. The replacement carries a header
# marker so uninstall can refuse to remove operator-edited
# replacements.
#
# Also bumps kernel.audit_backlog_limit via `auditctl -b` and
# restarts auditd.service to apply the new auditd.conf.

set -euo pipefail

MODULE="auditd-tune"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AUDITD_TUNE_CONFIG:-/etc/selfdef/modules/auditd-tune.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
case "$PROFILE" in
    standard|high-volume) ;;
    *) die "profile must be standard|high-volume, got '$PROFILE'" ;;
esac

BACKLOG_LIMIT=$(toml_get backlog_limit "$CONFIG_FILE" || echo "8192")
BACKLOG_LIMIT="${SELFDEF_AUDITD_BACKLOG_LIMIT:-$BACKLOG_LIMIT}"

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

# Render the replacement with the header marker prepended so
# uninstall can verify ownership.
tmp_rendered="$(mktemp)"
{
    echo "$AUDITD_MARKER"
    # NOTE: no `rendered=$(date)` — including timestamp defeats
    # the cmp -s idempotency check (per dns-shield + proc-hidepid
    # fix lineage, 2026-06-06).
    echo "# profile=$PROFILE"
    cat "$src"
} > "$tmp_rendered"

# Backup the operator's auditd.conf on first apply.
if [[ -f "$AUDITD_CONF" ]] && [[ ! -f "$AUDITD_BACKUP" ]]; then
    if ! head -1 "$AUDITD_CONF" | grep -qF "$AUDITD_MARKER"; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would back up operator auditd.conf to $AUDITD_BACKUP"
        else
            install -m 0640 "$AUDITD_CONF" "$AUDITD_BACKUP"
            log "backed up operator auditd.conf → $AUDITD_BACKUP"
        fi
    fi
fi

# Replace the file if content differs.
changes=0
if [[ -f "$AUDITD_CONF" ]] && cmp -s "$tmp_rendered" "$AUDITD_CONF"; then
    rm -f "$tmp_rendered"
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $AUDITD_CONF"
        rm -f "$tmp_rendered"
    else
        install -m 0640 "$tmp_rendered" "$AUDITD_CONF"
        rm -f "$tmp_rendered"
    fi
    changes=$((changes + 1))
fi

# Apply kernel backlog limit + restart auditd.
if [[ "$DRY_RUN" != "1" ]] && command -v auditctl >/dev/null; then
    run "auditctl -b $BACKLOG_LIMIT" -- auditctl -b "$BACKLOG_LIMIT" || true
fi
if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    # auditd's restart is special — `service auditd restart` on
    # Debian/Ubuntu, `systemctl restart auditd` on others. The
    # OS-installed package's unit file may also REFUSE restart
    # (RefuseManualStop=yes); fall back to `kill -HUP $(pidof auditd)`
    # for that case.
    if ! run "systemctl restart auditd" -- systemctl restart auditd 2>/dev/null; then
        log "systemctl restart auditd failed; falling back to SIGHUP"
        run "kill -HUP auditd" -- pkill -HUP -x auditd || true
    fi
fi

emit_status "ok" "auditd-tune profile=$PROFILE backlog=$BACKLOG_LIMIT changes=$changes"
