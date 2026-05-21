#!/usr/bin/env bash
# cron-baseline — apply.
#
# Writes /etc/cron.allow + /etc/at.allow with the operator-chosen
# user set + empty /etc/cron.deny + /etc/at.deny (the .allow file
# takes precedence when both exist; explicit empty .deny avoids
# distro-specific surprises).
#
# Per cron(8): if /etc/cron.allow exists, only users listed there
# can use crontab. If not, /etc/cron.deny controls. Setting BOTH
# defensively eliminates the ambiguity.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="cron-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_CRON_BASELINE_CONFIG:-/etc/selfdef/modules/cron-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
CRON_ALLOW="${SELFDEF_CRON_ALLOW:-/etc/cron.allow}"
AT_ALLOW="${SELFDEF_AT_ALLOW:-/etc/at.allow}"
CRON_DENY="${SELFDEF_CRON_DENY:-/etc/cron.deny}"
AT_DENY="${SELFDEF_AT_DENY:-/etc/at.deny}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "root-only")
case "$PROFILE" in
    root-only|operator-list) ;;
    *) die "profile must be root-only|operator-list, got '$PROFILE'" ;;
esac

# Build the allow-list.
declare -a allow_users=("root")
if [[ "$PROFILE" == "operator-list" ]]; then
    operator_users=$(toml_get operator_users "$CONFIG_FILE" || echo "")
    IFS=',' read -ra extra_users <<< "$operator_users"
    for u in "${extra_users[@]}"; do
        u_trimmed="$(echo "$u" | tr -d ' \t')"
        [[ -z "$u_trimmed" ]] && continue
        # Verify user exists.
        if id "$u_trimmed" >/dev/null 2>&1; then
            allow_users+=("$u_trimmed")
        else
            log "WARN: configured operator user '$u_trimmed' does not exist — skipping"
        fi
    done
fi

# Backup operator's originals on first apply.
for f in "$CRON_ALLOW" "$AT_ALLOW" "$CRON_DENY" "$AT_DENY"; do
    backup="${f}.selfdef-backup"
    if [[ -f "$f" ]] && [[ ! -f "$backup" ]] && [[ "$DRY_RUN" != "1" ]]; then
        install -m 0644 "$f" "$backup"
    fi
done

install_lines() {
    local dst="$1"
    shift
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "$@" > "$tmp"
    if [[ -f "$dst" ]] && cmp -s "$tmp" "$dst"; then
        rm -f "$tmp"
        return 1
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $dst with users: $*"
        rm -f "$tmp"
        return 0
    fi
    install -m 0640 "$tmp" "$dst"
    chown root:crontab "$dst" 2>/dev/null || chown root:root "$dst"
    rm -f "$tmp"
}

install_empty() {
    local dst="$1"
    if [[ -f "$dst" ]] && [[ ! -s "$dst" ]]; then
        return 1
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install empty $dst"
        return 0
    fi
    install -m 0640 /dev/null "$dst"
}

changes=0
install_lines "$CRON_ALLOW" "${allow_users[@]}" && changes=$((changes + 1)) || true
install_lines "$AT_ALLOW"   "${allow_users[@]}" && changes=$((changes + 1)) || true
install_empty "$CRON_DENY" && changes=$((changes + 1)) || true
install_empty "$AT_DENY" && changes=$((changes + 1)) || true

emit_status "ok" "cron-baseline profile=$PROFILE allow_users=${#allow_users[@]} changes=$changes"
