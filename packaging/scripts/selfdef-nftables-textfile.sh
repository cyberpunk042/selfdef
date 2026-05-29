#!/bin/bash
# selfdef-nftables-textfile — emit Prometheus node_exporter
# textfile gauges for kernel packet-filter (nftables) + conntrack
# state.
#
# Surfaces real IPS-host operator visibility: tracks nftables
# chain/rule counts + conntrack-table fill-rate. Pairs with
# fail2ban (13th sibling): fail2ban acts in-process to ban IPs;
# nftables is the actual kernel packet-filter enforcing those bans.
# Together: complete IPS perimeter view.
#
# Why this is page-worthy:
# - nftables ruleset drift (rule count drops to 0) = firewall
#   silently disabled
# - conntrack table near 90%+ full = new connections DROP at
#   kernel level (DoS-equivalent)
#
# Runs every 60s via the companion timer. 14th sibling observer.
#
# Caps: nft list ruleset requires CAP_NET_ADMIN. The service unit
# grants AmbientCapabilities=CAP_NET_ADMIN — documented exception
# to the 12-clause hardening pattern.
#
# Honest-offline: when nft is uninstalled, emit nftables_present=0
# but still emit conntrack metrics (always readable from /proc).
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_NFTABLES_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-nftables.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_nftables_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_nftables_textfile_emit_failed gauge\n'
    printf 'selfdef_nftables_textfile_emit_failed 1\n'
    printf '# HELP selfdef_nftables_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_nftables_last_run_unix gauge\n'
    printf 'selfdef_nftables_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Conntrack metrics — always readable from /proc regardless of nft.
conntrack_count=0
conntrack_max=0
conntrack_used_percent=0
if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
  conntrack_count="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
fi
if [ -r /proc/sys/net/netfilter/nf_conntrack_max ]; then
  conntrack_max="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)"
fi
if [ "$conntrack_max" -gt 0 ]; then
  conntrack_used_percent=$(( (conntrack_count * 100) / conntrack_max ))
fi

# nftables presence + ruleset counts.
nftables_present=0
chains_total=0
rules_total=0
tables_total=0
if command -v nft >/dev/null 2>&1; then
  nftables_present=1
  # nft list ruleset; fall back to 0 on parse error.
  if ruleset="$(nft -a list ruleset 2>/dev/null)"; then
    # Count tables (top-level "table ... {").
    tables_total="$(printf '%s\n' "$ruleset" | grep -cE '^table ' || true)"
    # Count chains ("chain ... {").
    chains_total="$(printf '%s\n' "$ruleset" | grep -cE '^[[:space:]]+chain ' || true)"
    # Rules are lines inside chains, tagged with "# handle N" by nft -a.
    rules_total="$(printf '%s\n' "$ruleset" | grep -cE '# handle [0-9]+$' || true)"
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_nftables_present 1 if nft binary is installed.\n'
  printf '# TYPE selfdef_nftables_present gauge\n'
  printf 'selfdef_nftables_present %d\n' "$nftables_present"

  printf '# HELP selfdef_nftables_tables_total Count of nftables tables in active ruleset.\n'
  printf '# TYPE selfdef_nftables_tables_total gauge\n'
  printf 'selfdef_nftables_tables_total %d\n' "$tables_total"

  printf '# HELP selfdef_nftables_chains_total Count of nftables chains in active ruleset.\n'
  printf '# TYPE selfdef_nftables_chains_total gauge\n'
  printf 'selfdef_nftables_chains_total %d\n' "$chains_total"

  printf '# HELP selfdef_nftables_rules_total Count of nftables rules in active ruleset.\n'
  printf '# TYPE selfdef_nftables_rules_total gauge\n'
  printf 'selfdef_nftables_rules_total %d\n' "$rules_total"

  printf '# HELP selfdef_conntrack_count Current conntrack table size.\n'
  printf '# TYPE selfdef_conntrack_count gauge\n'
  printf 'selfdef_conntrack_count %d\n' "$conntrack_count"

  printf '# HELP selfdef_conntrack_max Maximum conntrack table size.\n'
  printf '# TYPE selfdef_conntrack_max gauge\n'
  printf 'selfdef_conntrack_max %d\n' "$conntrack_max"

  printf '# HELP selfdef_conntrack_used_percent Conntrack table fill percentage (0-100).\n'
  printf '# TYPE selfdef_conntrack_used_percent gauge\n'
  printf 'selfdef_conntrack_used_percent %d\n' "$conntrack_used_percent"

  printf '# HELP selfdef_nftables_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
  printf '# TYPE selfdef_nftables_last_run_unix gauge\n'
  printf 'selfdef_nftables_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_nftables_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_nftables_textfile_emit_failed gauge\n'
  printf 'selfdef_nftables_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
