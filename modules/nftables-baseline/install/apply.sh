#!/usr/bin/env bash
# nftables-baseline — apply.
#
# Renders a default-deny inet ruleset to /etc/nftables.d/
# selfdef-baseline.nft, validates it with `nft -c -f` (parse
# check), confirms the SSH-allow anti-lockout invariant, backs
# up the current ruleset, then loads it.

set -euo pipefail

MODULE="nftables-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_NFT_CONFIG:-/etc/selfdef/modules/nftables-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")
case "$PROFILE" in
    baseline|web|locked) ;;
    *) die "profile must be baseline|web|locked, got '$PROFILE'" ;;
esac

command -v nft >/dev/null 2>&1 || die "nft (nftables) unavailable"

ALLOW_TCP=$(toml_get allow_tcp "$CONFIG_FILE" 2>/dev/null || echo "")
ALLOW_UDP=$(toml_get allow_udp "$CONFIG_FILE" 2>/dev/null || echo "")
SSH_PORTS=$(detect_ssh_ports)

# Build the SSH + extra TCP allow set (SSH always included).
tcp_set="$(echo "$SSH_PORTS $(echo "$ALLOW_TCP" | tr ',' ' ')" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -un | paste -sd, -)"
[[ -z "$tcp_set" ]] && tcp_set="22"
udp_set="$(echo "$ALLOW_UDP" | tr ',' '\n' | grep -E '^[0-9]+$' | sort -un | paste -sd, -)"

# locked profile: egress default-drop requires acknowledge.
egress_policy="accept"
if [[ "$PROFILE" == "locked" ]]; then
    ack=$(toml_get acknowledge_egress "$CONFIG_FILE" 2>/dev/null || echo "false")
    if [[ "$ack" != "true" ]]; then
        die "locked profile sets OUTPUT default-drop (only established + DNS/NTP/HTTPS egress). This can break package managers + monitoring. Add 'acknowledge_egress = true' to $CONFIG_FILE to proceed."
    fi
    egress_policy="drop"
fi

# Render the ruleset.
render_ruleset() {
    cat <<EOF
${HEADER_MARKER}
# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=${PROFILE}
# SSH allow ports: ${tcp_set} (SSH always included — anti-lockout)
table inet selfdef_filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        tcp dport { ${tcp_set} } accept
EOF
    [[ -n "$udp_set" ]] && echo "        udp dport { ${udp_set} } accept"
    cat <<EOF
        counter comment "selfdef-dropped-input"
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy ${egress_policy};
        ct state established,related accept
        oifname "lo" accept
EOF
    if [[ "$egress_policy" == "drop" ]]; then
        cat <<EOF
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        udp dport { 53, 123 } accept
        tcp dport { 53, 443 } accept
        counter comment "selfdef-dropped-output"
EOF
    fi
    echo "    }"
    echo "}"
}

mkdir -p "$NFT_DROPIN_DIR"
tmp="$(mktemp "${NFT_DROPIN}.XXXXXX")"
render_ruleset > "$tmp"

# Parse-check the ruleset BEFORE doing anything live.
if ! nft -c -f "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    die "rendered ruleset failed 'nft -c' parse check — refusing to apply (anti-brick)"
fi

# Anti-lockout invariant: the rendered ruleset MUST contain an
# accept for an SSH port. (Belt-and-suspenders — we built it
# that way, but verify before going live.)
if ! grep -qE "tcp dport \{ .*22.* \} accept|tcp dport \{ .*${SSH_PORTS%% *}.* \} accept" "$tmp"; then
    rm -f "$tmp"
    die "rendered ruleset lacks an SSH accept — refusing to apply (anti-lockout)"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: validated ruleset (profile=$PROFILE tcp_allow=$tcp_set egress=$egress_policy); would back up + load"
    rm -f "$tmp"
    emit_status "ok" "nftables-baseline DRY_RUN profile=$PROFILE"
    exit 0
fi

# Backup the current live ruleset once.
mkdir -p "$BACKUP_DIR"
if [[ ! -f "$BACKUP_FILE" ]]; then
    nft list ruleset > "$BACKUP_FILE" 2>/dev/null || true
    chmod 0600 "$BACKUP_FILE"
    log "backed up current ruleset → $BACKUP_FILE"
fi

chmod 0644 "$tmp"
mv -f "$tmp" "$NFT_DROPIN"
log "wrote $NFT_DROPIN"

# Load it live. We delete our own table first (idempotent
# re-apply) then load.
nft delete table inet selfdef_filter 2>/dev/null || true
if nft -f "$NFT_DROPIN" 2>/dev/null; then
    log "loaded selfdef_filter ruleset (profile=$PROFILE)"
else
    log "WARN: nft -f load failed; ruleset file written but not live (run 'nft -f $NFT_DROPIN' manually)"
fi

emit_status "ok" "nftables-baseline profile=$PROFILE ssh_ports='${SSH_PORTS}' tcp_allow=$tcp_set egress=$egress_policy"
