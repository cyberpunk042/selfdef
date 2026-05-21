#!/usr/bin/env bash
# service-account-lock — apply.
#
# Walks /etc/passwd. For every account with UID < 1000 AND
# UID not in reserved_uids list AND shell is interactive:
#   - audit: LOG the finding
#   - enforce: record original shell + chsh to nologin + passwd -l

set -euo pipefail

MODULE="service-account-lock"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_SVC_ACCOUNT_CONFIG:-/etc/selfdef/modules/service-account-lock.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")
case "$PROFILE" in
    audit|enforce) ;;
    *) die "profile must be audit|enforce, got '$PROFILE'" ;;
esac

reserved_uids=$(toml_get reserved_uids "$CONFIG_FILE" || echo "0,1,2,3")
# Build a quick-lookup set.
declare -A RESERVED
for uid in $(echo "$reserved_uids" | tr ',' ' '); do
    uid="${uid// /}"
    [[ -n "$uid" ]] && RESERVED["$uid"]=1
done

# Ensure log dir exists.
mkdir -p "$(dirname "$ORIGINAL_LOG")"
# Initialize the original-log header on enforce.
if [[ "$PROFILE" == "enforce" ]] && [[ ! -f "$ORIGINAL_LOG" ]] && [[ "$DRY_RUN" != "1" ]]; then
    cat > "$ORIGINAL_LOG" <<'EOF'
# selfdef service-account-lock — original-shell record.
# One line per locked account: <username> <original_shell>
# Used by uninstall.sh to restore.
EOF
fi

audited=0
locked=0
while IFS=: read -r username _ uid _ _ _ shell; do
    [[ -z "$username" ]] && continue
    [[ "$uid" -ge 1000 ]] && continue           # operator-interactive account
    [[ -n "${RESERVED[$uid]:-}" ]] && continue   # reserved
    if ! is_interactive_shell "$shell"; then
        continue                                  # already nologin/false
    fi

    audited=$((audited + 1))
    log "FOUND: $username (uid=$uid) shell=$shell"

    if [[ "$PROFILE" == "enforce" ]]; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would chsh $username → $NOLOGIN_SHELL + passwd -l"
            continue
        fi
        # Record original (only first time — preserve operator's
        # baseline through repeat applies).
        if ! grep -qE "^${username} " "$ORIGINAL_LOG" 2>/dev/null; then
            echo "$username $shell" >> "$ORIGINAL_LOG"
        fi
        if chsh -s "$NOLOGIN_SHELL" "$username" >/dev/null 2>&1; then
            log "chsh $username → $NOLOGIN_SHELL"
            locked=$((locked + 1))
        else
            log "WARN: chsh $username failed (PAM restriction?)"
        fi
        passwd -l "$username" >/dev/null 2>&1 || true
    fi
done < /etc/passwd

emit_status "ok" "service-account-lock profile=$PROFILE audited=$audited locked=$locked"
