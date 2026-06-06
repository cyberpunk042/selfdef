#!/usr/bin/env bash
# motd-doctrine — apply.
#
# REPLACES /etc/issue, /etc/issue.net, /etc/motd (header marker
# at top of each rendered file for uninstall ownership check).
# On first apply backs up operator's originals to .selfdef-backup.
# verbose profile additionally installs the dynamic
# /etc/update-motd.d/50-selfdef-presence script.

set -euo pipefail

MODULE="motd-doctrine"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_MOTD_CONFIG:-/etc/selfdef/modules/motd-doctrine.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
TEMPLATES_SRC="${MODULE_DIR}/templates"
UPDATE_MOTD_DIR="${SELFDEF_UPDATE_MOTD_DIR:-/etc/update-motd.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$TEMPLATES_SRC" ]] || die "templates dir missing: $TEMPLATES_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "minimal")
case "$PROFILE" in
    minimal|verbose) ;;
    *) die "profile must be minimal|verbose, got '$PROFILE'" ;;
esac

backup_and_install() {
    local src="$1" dst="$2" template_basename="$3"
    local backup="${dst}.selfdef-backup"

    # Backup operator's original on first apply (if not already a
    # selfdef-managed file).
    if [[ -f "$dst" ]] && [[ ! -f "$backup" ]]; then
        if ! head -1 "$dst" | grep -qF "$ISSUE_MARKER"; then
            if [[ "$DRY_RUN" == "1" ]]; then
                log "DRY_RUN: would back up $dst → $backup"
            else
                install -m 0644 "$dst" "$backup"
                log "backed up $dst → $backup"
            fi
        fi
    fi

    # Render with header marker prepended.
    local tmp_rendered
    tmp_rendered="$(mktemp)"
    {
        echo "$ISSUE_MARKER"
        # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
        echo "# template=$template_basename profile=$PROFILE"
        cat "$src"
    } > "$tmp_rendered"

    if [[ -f "$dst" ]] && cmp -s "$tmp_rendered" "$dst"; then
        rm -f "$tmp_rendered"
        return 1
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $dst"
        rm -f "$tmp_rendered"
        return 0
    fi
    install -m 0644 "$tmp_rendered" "$dst"
    rm -f "$tmp_rendered"
    return 0
}

# Destination paths overridable via env-vars (operator-test
# affordance + L2 testability). Live defaults unchanged.
ISSUE_DST="${SELFDEF_MOTD_ISSUE:-/etc/issue}"
ISSUE_NET_DST="${SELFDEF_MOTD_ISSUE_NET:-/etc/issue.net}"
MOTD_DST="${SELFDEF_MOTD_MOTD:-/etc/motd}"

changes=0
backup_and_install "${TEMPLATES_SRC}/issue.txt"     "${ISSUE_DST}"     "issue.txt"     && changes=$((changes + 1)) || true
backup_and_install "${TEMPLATES_SRC}/issue.net.txt" "${ISSUE_NET_DST}" "issue.net.txt" && changes=$((changes + 1)) || true
backup_and_install "${TEMPLATES_SRC}/motd.txt"      "${MOTD_DST}"      "motd.txt"      && changes=$((changes + 1)) || true

# Verbose profile: install the dynamic motd hook.
DYN_HOOK="${UPDATE_MOTD_DIR}/50-selfdef-presence"
if [[ "$PROFILE" == "verbose" ]]; then
    mkdir -p "$UPDATE_MOTD_DIR"
    if [[ -f "$DYN_HOOK" ]] && cmp -s "${TEMPLATES_SRC}/50-selfdef-presence" "$DYN_HOOK"; then
        :
    else
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would install $DYN_HOOK"
        else
            install -m 0755 "${TEMPLATES_SRC}/50-selfdef-presence" "$DYN_HOOK"
        fi
        changes=$((changes + 1))
    fi
else
    # Profile downgrade: remove the verbose hook if present.
    if [[ -f "$DYN_HOOK" ]]; then
        run "remove $DYN_HOOK (profile downgrade)" -- rm -f "$DYN_HOOK"
        changes=$((changes + 1))
    fi
fi

emit_status "ok" "motd-doctrine profile=$PROFILE changes=$changes"
