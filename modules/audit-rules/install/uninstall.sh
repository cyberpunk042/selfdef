#!/usr/bin/env bash
# audit-rules — uninstall.
#
# Removes every /etc/audit/rules.d/50-selfdef-*.rules file this
# module owns. Leaves /etc/audit/rules.d/ itself + any operator-
# authored files alone. Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="audit-rules"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
RULES_DIR="${SELFDEF_AUDIT_RULES_DIR:-/etc/audit/rules.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
for f in "${RULES_DIR}"/50-selfdef-*.rules; do
    [[ -e "$f" ]] || continue   # glob nomatch when none present
    run "remove $(basename "$f")" -- rm -f "$f"
    removed=$((removed + 1))
done

# Reload audit rules so the live ruleset reflects what's on disk.
if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v augenrules >/dev/null; then
    run "augenrules --load" -- augenrules --load
fi

emit_status "ok" "audit-rules removed=$removed"
