#!/usr/bin/env bash
# sudo-tune — uninstall.
#
# Removes the selfdef sudoers.d drop-in. PRESERVES /var/log/sudo-io/
# (operator-collected forensic data; manual rm to reclaim) and
# /var/log/sudo.log (audit history).
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="sudo-tune"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SUDOERS_D="${SELFDEF_SUDOERS_D:-/etc/sudoers.d}"
DST="${SUDOERS_D}/50-selfdef-tune"
LECTURE_FILE="${SELFDEF_SUDO_LECTURE:-/etc/selfdef/sudo-lecture.txt}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
for f in "$DST" "$LECTURE_FILE"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

# Final validate — operator's REMAINING sudoers tree must still
# parse. Refuse-to-brick guard for the uninstall side too.
if command -v visudo >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    if ! visudo -c >/dev/null 2>&1; then
        log "WARNING: visudo -c reports sudoers tree DOES NOT parse cleanly after uninstall — operator should inspect /etc/sudoers + sibling files"
    fi
fi

emit_status "ok" "sudo-tune removed=$removed (NOTE: /var/log/sudo-io/ + /var/log/sudo.log preserved)"
