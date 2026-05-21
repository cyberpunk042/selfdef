#!/usr/bin/env bash
# selfdef wol-disable wrapper.
#
# Walks every ethernet NIC. For each:
#   - audit profile: log current WoL state
#   - enforce profile: ethtool -s <iface> wol d

set -u

PROFILE="${SELFDEF_WOL_PROFILE:-enforce}"

# Walk only real wired NICs (skip loopback, virtual, wireless,
# bridge, docker bridges).
mapfile -t nics < <(
    ls -1 /sys/class/net 2>/dev/null | while read -r iface; do
        [[ "$iface" == "lo" ]] && continue
        # Skip wireless (no WoL via ethtool typically; WoWLAN is
        # separate).
        [[ -d "/sys/class/net/$iface/wireless" ]] && continue
        # Skip bridges + dummy + docker + vlan + tun/tap.
        case "$iface" in
            br*|veth*|docker*|virbr*|vnet*|tun*|tap*|dummy*|cni*|flannel*) continue ;;
        esac
        # Verify ethtool can query it (real PHY).
        ethtool "$iface" >/dev/null 2>&1 && echo "$iface"
    done
)

count_total=0
count_disabled=0
count_enabled=0
for iface in "${nics[@]}"; do
    count_total=$((count_total + 1))
    # Current WoL state.
    wol_state=$(ethtool "$iface" 2>/dev/null | awk -F': ' '/Wake-on/ {print $2; exit}')
    wol_state="${wol_state:-?}"

    if [[ "$PROFILE" == "audit" ]]; then
        logger -t selfdef-wol-disable -- "{\"iface\":\"$iface\",\"wol_state\":\"$wol_state\",\"action\":\"audit-only\"}"
        continue
    fi

    # enforce profile.
    if [[ "$wol_state" == "d" ]]; then
        count_disabled=$((count_disabled + 1))
        # Already disabled; no-op (avoid logging noise).
        continue
    fi

    # Try to disable.
    if ethtool -s "$iface" wol d >/dev/null 2>&1; then
        logger -t selfdef-wol-disable -- "{\"iface\":\"$iface\",\"wol_state_before\":\"$wol_state\",\"action\":\"disabled\"}"
        count_disabled=$((count_disabled + 1))
    else
        # Some virtualized NICs / containers don't support WoL at
        # all (the call returns -EOPNOTSUPP). Not a failure.
        logger -t selfdef-wol-disable -- "{\"iface\":\"$iface\",\"wol_state\":\"$wol_state\",\"action\":\"unsupported\"}"
        count_enabled=$((count_enabled + 1))
    fi
done

logger -t selfdef-wol-disable -- "{\"summary\":\"complete\",\"profile\":\"$PROFILE\",\"total\":$count_total,\"disabled\":$count_disabled,\"enabled_or_unsupported\":$count_enabled}"
exit 0
