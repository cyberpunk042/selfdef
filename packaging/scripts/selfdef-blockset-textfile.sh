#!/bin/bash
# selfdef-blockset-textfile — emit Prometheus node_exporter
# textfile gauges for the kernel-side selfdef-blocks nftables
# table state (SDD-065 §5).
#
# Surfaces real IPS-host operator visibility for the SDD-065
# IP-block action layer:
#   - is the selfdef-blocks table present in the kernel?
#   - how many addresses are currently in v4 / v6 sets?
#   - what's the oldest-remaining TTL (when does the next
#     auto-release happen)?
#
# Pairs with nftables observer (14th sibling) at the kernel-
# packet-filter axis: nftables observer surfaces the full
# operator firewall; this one surfaces selfdef's own action layer.
#
# Runs every 60s via the companion timer. 19th sibling observer.
#
# Honest-offline: when nft is uninstalled OR the selfdef-blocks
# table is absent (selfdefd hasn't bootstrapped yet) emit zero
# with selfdef_blockset_present=0 sentinel.
#
# Caps: requires CAP_NET_ADMIN to invoke `nft list set`. The
# companion service unit grants AmbientCapabilities=CAP_NET_ADMIN
# — same documented exception as 14th sibling.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_BLOCKSET_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-blockset.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_blockset_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_blockset_textfile_emit_failed gauge\n'
    printf 'selfdef_blockset_textfile_emit_failed 1\n'
    printf '# HELP selfdef_blockset_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_blockset_last_run_unix gauge\n'
    printf 'selfdef_blockset_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

blockset_present=0
blockset_v4_count=0
blockset_v6_count=0
blockset_oldest_expiry_unix=0

if command -v nft >/dev/null 2>&1; then
  # Is the selfdef-blocks table present?
  if nft -a list table inet selfdef-blocks >/dev/null 2>&1; then
    blockset_present=1
    # Count v4 elements — `nft list set` outputs `elements = { ... }`.
    if v4_set="$(nft list set inet selfdef-blocks v4 2>/dev/null)"; then
      blockset_v4_count="$(printf '%s\n' "$v4_set" \
        | grep -oE 'expires [0-9]+s' | wc -l || true)"
      # If elements use no timeout, fall back to comma count.
      if [ "$blockset_v4_count" -eq 0 ]; then
        blockset_v4_count="$(printf '%s\n' "$v4_set" \
          | tr -d '\n' \
          | grep -oE 'elements = \{[^}]*\}' \
          | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
          | wc -l || true)"
      fi
    fi
    if v6_set="$(nft list set inet selfdef-blocks v6 2>/dev/null)"; then
      blockset_v6_count="$(printf '%s\n' "$v6_set" \
        | grep -oE 'expires [0-9]+s' | wc -l || true)"
    fi
    # Compute oldest-remaining expiry across both sets — the
    # operator sees "next auto-release happens at unix T".
    smallest_expiry=0
    for set in v4 v6; do
      if cur="$(nft list set inet selfdef-blocks "$set" 2>/dev/null)"; then
        # Parse `expires Ns` tokens, find min, add to now.
        while read -r secs; do
          [ -z "$secs" ] && continue
          if [ "$smallest_expiry" -eq 0 ] || [ "$secs" -lt "$smallest_expiry" ]; then
            smallest_expiry="$secs"
          fi
        done < <(printf '%s\n' "$cur" | grep -oE 'expires [0-9]+s' | awk '{print $2}' | tr -d 's')
      fi
    done
    if [ "$smallest_expiry" -gt 0 ]; then
      blockset_oldest_expiry_unix=$(( $(date +%s) + smallest_expiry ))
    fi
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_blockset_present 1 if the inet selfdef-blocks nft table exists (selfdefd bootstrapped).\n'
  printf '# TYPE selfdef_blockset_present gauge\n'
  printf 'selfdef_blockset_present %d\n' "$blockset_present"

  printf '# HELP selfdef_blockset_v4_count Current IPv4 entries in the SDD-065 blockset.\n'
  printf '# TYPE selfdef_blockset_v4_count gauge\n'
  printf 'selfdef_blockset_v4_count %d\n' "$blockset_v4_count"

  printf '# HELP selfdef_blockset_v6_count Current IPv6 entries in the SDD-065 blockset.\n'
  printf '# TYPE selfdef_blockset_v6_count gauge\n'
  printf 'selfdef_blockset_v6_count %d\n' "$blockset_v6_count"

  printf '# HELP selfdef_blockset_total_count Sum of v4 + v6 entries (operator-readable rollup).\n'
  printf '# TYPE selfdef_blockset_total_count gauge\n'
  printf 'selfdef_blockset_total_count %d\n' "$(( blockset_v4_count + blockset_v6_count ))"

  printf '# HELP selfdef_blockset_oldest_expiry_unix Unix timestamp of the soonest auto-release (0 if no timed entries).\n'
  printf '# TYPE selfdef_blockset_oldest_expiry_unix gauge\n'
  printf 'selfdef_blockset_oldest_expiry_unix %d\n' "$blockset_oldest_expiry_unix"

  printf '# HELP selfdef_blockset_last_run_unix Wall-clock seconds of last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_blockset_last_run_unix gauge\n'
  printf 'selfdef_blockset_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_blockset_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_blockset_textfile_emit_failed gauge\n'
  printf 'selfdef_blockset_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
