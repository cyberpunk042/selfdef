#!/usr/bin/env bash
# vpn-bridge — keygen helper. NOT auto-run by `selfdefctl modules apply`.
# Operator invokes this manually once per host.
#
# Generates a WireGuard private/public key pair into /etc/wireguard/
# with 0600 perms on the private key. Refuses to overwrite an existing
# keypair (manual operator action required to rotate).
#
# Usage:  sudo /usr/share/selfdef/modules/vpn-bridge/install/keygen.sh [iface]

set -euo pipefail

IFACE="${1:-wg0}"
DIR="${SELFDEF_VPN_BRIDGE_WG_DIR:-/etc/wireguard}"
PRIV="${DIR}/${IFACE}.privkey"
PUB="${DIR}/${IFACE}.pubkey"

if ! command -v wg >/dev/null; then
    echo "wg(8) missing — install wireguard-tools first" >&2
    exit 1
fi

if [[ -f "$PRIV" || -f "$PUB" ]]; then
    echo "Refusing to overwrite existing keypair:" >&2
    echo "  $PRIV"  >&2
    echo "  $PUB"   >&2
    echo "Move or delete them first if you want to rotate." >&2
    exit 1
fi

mkdir -p "$DIR"
umask 077
wg genkey | tee "$PRIV" | wg pubkey > "$PUB"
chmod 0600 "$PRIV"
chmod 0644 "$PUB"

echo "Generated:"
echo "  private key: $PRIV (0600)"
echo "  public key:  $PUB  (0644)"
echo
echo "Public key (share this with your peers):"
cat "$PUB"
