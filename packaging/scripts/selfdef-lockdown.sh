#!/usr/bin/env bash
# selfdef-lockdown.sh — example egress lockdown via nftables.
#
# This is an EXAMPLE. Read it before installing. Tune the lifeline allowlist
# (`SELFDEF_LIFELINES`) to your environment — at minimum: your ntfy server's
# IP, your WireGuard server's IP, and possibly DNS resolvers needed to reach
# them.
#
# Install as /usr/local/sbin/selfdef-lockdown.sh (mode 0750, root:selfdef).
# Add `selfdef ALL=(ALL) NOPASSWD: /usr/local/sbin/selfdef-lockdown.sh` to
# /etc/sudoers.d/selfdef if you want the daemon to invoke it without root.
# Better: run the daemon with `CAP_NET_ADMIN` via a systemd drop-in.

set -euo pipefail

ACTION="${1:-help}"

# Comma-separated list of IPs/CIDRs the host is still allowed to talk to.
# Override via env or by editing this script.
SELFDEF_LIFELINES="${SELFDEF_LIFELINES:-127.0.0.0/8,::1/128}"

TABLE="inet selfdef_panic"

cmd_activate() {
    nft list table inet selfdef_panic >/dev/null 2>&1 && nft delete table inet selfdef_panic || true

    nft add table inet selfdef_panic
    nft 'add chain inet selfdef_panic output { type filter hook output priority 0 ; policy drop ; }'
    # TRADE-OFF (read before relying on this for a compromise response): accepting
    # `established,related` keeps EXISTING connections alive — including an active
    # C2 / exfil channel the attacker already opened. It only blocks NEW egress.
    # It is kept by default so the lockdown doesn't also sever YOUR management /
    # SSH session. For a true panic that must CUT active connections, set
    # SELFDEF_LOCKDOWN_CUT_ESTABLISHED=1 (and make sure your lifeline rule below
    # covers the IP you manage the host from, or you will lock yourself out).
    if [ "${SELFDEF_LOCKDOWN_CUT_ESTABLISHED:-0}" != "1" ]; then
        nft 'add rule inet selfdef_panic output ct state established,related accept'
    fi
    nft 'add rule inet selfdef_panic output oifname "lo" accept'
    # WireGuard interface allowed — operator-defined; uncomment if applicable.
    # nft 'add rule inet selfdef_panic output oifname "wg0" accept'

    IFS=',' read -ra LIFELINES <<< "$SELFDEF_LIFELINES"
    for ip in "${LIFELINES[@]}"; do
        if [[ "$ip" == *:* ]]; then
            nft "add rule inet selfdef_panic output ip6 daddr $ip accept"
        else
            nft "add rule inet selfdef_panic output ip daddr $ip accept"
        fi
    done

    logger -t selfdef-lockdown "egress lockdown active; lifelines=$SELFDEF_LIFELINES"
    echo "lockdown active"
}

cmd_deactivate() {
    nft delete table inet selfdef_panic 2>/dev/null && \
        logger -t selfdef-lockdown "egress lockdown lifted"
    echo "lockdown lifted"
}

cmd_status() {
    if nft list table inet selfdef_panic >/dev/null 2>&1; then
        echo "active"
        nft list table inet selfdef_panic
    else
        echo "inactive"
    fi
}

case "$ACTION" in
    activate) cmd_activate ;;
    deactivate) cmd_deactivate ;;
    status) cmd_status ;;
    *)
        echo "usage: $0 {activate|deactivate|status}" >&2
        exit 2
        ;;
esac
