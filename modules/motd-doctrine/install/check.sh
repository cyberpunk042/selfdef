#!/usr/bin/env bash
# motd-doctrine — check. Read-only.

set -euo pipefail

MODULE="motd-doctrine"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_MOTD_CONFIG:-/etc/selfdef/modules/motd-doctrine.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
UPDATE_MOTD_DIR="${SELFDEF_UPDATE_MOTD_DIR:-/etc/update-motd.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "minimal")

drift=0
for f in /etc/issue /etc/issue.net /etc/motd; do
    if [[ ! -f "$f" ]]; then
        emit_status "drift" "$f missing"
        drift=$((drift + 1))
    elif ! head -1 "$f" | grep -qF "$ISSUE_MARKER"; then
        emit_status "drift" "$f present but not selfdef-managed (no header marker)"
        drift=$((drift + 1))
    fi
done

if [[ "$PROFILE" == "verbose" ]]; then
    if [[ ! -x "${UPDATE_MOTD_DIR}/50-selfdef-presence" ]]; then
        emit_status "drift" "50-selfdef-presence missing or not executable"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "motd-doctrine profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "motd-doctrine profile=$PROFILE no drift"
