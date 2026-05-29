#!/bin/bash
# selfdef-package-state-textfile — emit Prometheus node_exporter
# textfile gauges for apt/dpkg package-state hygiene.
#
# Surfaces real IPS-host operator visibility: tracks pending
# security updates, days-since-last-apt-update, and overall package
# count. Pairs with sshd-config (16th sibling) at the
# security-baseline axis: sshd-config tracks hardening posture;
# this tracks whether the host has applied known fixes.
#
# Why this is page-worthy:
# - pending security updates > 0 = known-vulnerable packages installed
# - apt-update stale (> 7d) = operator visibility into CVE space
#   has lapsed; new CVEs are unknown
# - dpkg-broken packages = supply-chain interrupt
#
# Runs every 60s via the companion timer. 17th sibling observer.
#
# Honest-offline: when apt/dpkg aren't installed (e.g., rpm-based
# host) emit zero with package_manager_apt=0 sentinel.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_PACKAGE_STATE_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-package-state.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_package_state_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_package_state_textfile_emit_failed gauge\n'
    printf 'selfdef_package_state_textfile_emit_failed 1\n'
    printf '# HELP selfdef_package_state_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_package_state_last_run_unix gauge\n'
    printf 'selfdef_package_state_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Honest-offline if apt/dpkg not installed.
package_manager_apt=0
dpkg_packages_total=0
apt_pending_total=0
apt_pending_security=0
apt_last_update_unix=0
apt_update_age_days=0
dpkg_broken_packages=0

if command -v dpkg-query >/dev/null 2>&1; then
  package_manager_apt=1
  # Installed package count.
  dpkg_packages_total="$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | wc -l)"
  # Broken packages — anything in iU (unpacked) or iF (half-configured) state.
  dpkg_broken_packages="$(dpkg-query -W -f='${db:Status-Abbrev}\n' 2>/dev/null \
    | grep -cvE '^(ii|rc|un|hn) ' || true)"
fi

# apt-list pending updates (requires apt; doesn't fetch from net).
if command -v apt-get >/dev/null 2>&1; then
  if pending_output="$(apt-get -s upgrade 2>/dev/null)"; then
    apt_pending_total="$(printf '%s\n' "$pending_output" \
      | grep -cE '^Inst ' || true)"
    apt_pending_security="$(printf '%s\n' "$pending_output" \
      | grep -cE '^Inst .*-security' || true)"
  fi
fi

# apt-update freshness — mtime of /var/lib/apt/lists/.
if [ -d /var/lib/apt/lists ]; then
  # Pick the most recently-touched file inside lists/.
  if newest="$(find /var/lib/apt/lists -maxdepth 1 -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1)"; then
    if [ -n "$newest" ]; then
      apt_last_update_unix="${newest%.*}"
      now="$(date +%s)"
      apt_update_age_days=$(( (now - apt_last_update_unix) / 86400 ))
    fi
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_package_manager_apt 1 if apt/dpkg-query are installed.\n'
  printf '# TYPE selfdef_package_manager_apt gauge\n'
  printf 'selfdef_package_manager_apt %d\n' "$package_manager_apt"

  printf '# HELP selfdef_dpkg_packages_total Count of installed binary packages.\n'
  printf '# TYPE selfdef_dpkg_packages_total gauge\n'
  printf 'selfdef_dpkg_packages_total %d\n' "$dpkg_packages_total"

  printf '# HELP selfdef_dpkg_broken_packages Count of packages in non-clean state (iU/iF/etc).\n'
  printf '# TYPE selfdef_dpkg_broken_packages gauge\n'
  printf 'selfdef_dpkg_broken_packages %d\n' "$dpkg_broken_packages"

  printf '# HELP selfdef_apt_pending_total Total upgradeable packages (simulated apt upgrade).\n'
  printf '# TYPE selfdef_apt_pending_total gauge\n'
  printf 'selfdef_apt_pending_total %d\n' "$apt_pending_total"

  printf '# HELP selfdef_apt_pending_security Pending packages from -security repos (CVE patches).\n'
  printf '# TYPE selfdef_apt_pending_security gauge\n'
  printf 'selfdef_apt_pending_security %d\n' "$apt_pending_security"

  printf '# HELP selfdef_apt_last_update_unix Unix timestamp of most recent apt update.\n'
  printf '# TYPE selfdef_apt_last_update_unix gauge\n'
  printf 'selfdef_apt_last_update_unix %d\n' "$apt_last_update_unix"

  printf '# HELP selfdef_apt_update_age_days Days since last apt update (CVE-visibility freshness).\n'
  printf '# TYPE selfdef_apt_update_age_days gauge\n'
  printf 'selfdef_apt_update_age_days %d\n' "$apt_update_age_days"

  printf '# HELP selfdef_package_state_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
  printf '# TYPE selfdef_package_state_last_run_unix gauge\n'
  printf 'selfdef_package_state_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_package_state_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_package_state_textfile_emit_failed gauge\n'
  printf 'selfdef_package_state_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
