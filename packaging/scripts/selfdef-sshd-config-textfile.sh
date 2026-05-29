#!/bin/bash
# selfdef-sshd-config-textfile — emit Prometheus node_exporter
# textfile gauges for SSH server config hardening state.
#
# Surfaces real IPS-host operator visibility: tracks the canonical
# safety toggles in /etc/ssh/sshd_config (PermitRootLogin,
# PasswordAuthentication, etc.) and a content-hash of the active
# config. Pairs with auth-events (11th sibling) at the attack-
# surface axis: auth-events tracks login attempts; this tracks
# whether the SSH server is HARDENED against those attempts.
#
# Why this is page-worthy:
# - PermitRootLogin=yes drift = remote root attack-surface opens
# - PasswordAuthentication=yes drift = brute-force vector returns
# - config hash drift = unauthorized sshd_config modification
#
# Runs every 60s via the companion timer. 16th sibling observer.
#
# Honest-offline: when /etc/ssh/sshd_config is missing or
# unreadable, emit sshd_config_present=0.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_SSHD_CONFIG_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-sshd-config.prom}"
SSHD_CONFIG="${SELFDEF_SSHD_CONFIG_PATH:-/etc/ssh/sshd_config}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_sshd_config_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_sshd_config_textfile_emit_failed gauge\n'
    printf 'selfdef_sshd_config_textfile_emit_failed 1\n'
    printf '# HELP selfdef_sshd_config_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_sshd_config_last_run_unix gauge\n'
    printf 'selfdef_sshd_config_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Honest-offline if sshd_config absent.
config_present=0
config_hash=0
permit_root_login=0      # 0=safe (no/prohibit-password); 1=hazard (yes)
password_authentication=0 # 0=safe (no); 1=hazard (yes)
permit_empty_passwords=0  # 0=safe (no); 1=hazard (yes)
challenge_response=0      # 0=safe (no); 1=hazard (yes)
x11_forwarding=0          # 0=safe (no); 1=permissive (yes)
use_pam=1                 # 1=safe (yes); 0=hazard (no)
protocol_v2_only=1        # 1=safe (Protocol 2 only); 0=hazard (1 enabled)

if [ -r "$SSHD_CONFIG" ]; then
  config_present=1
  # SHA-256 content hash, expressed as a numeric short for gauge —
  # we emit the first 16 hex chars as decimal so Grafana can
  # display drift. (Full hash is in the help text.)
  full_hash="$(sha256sum "$SSHD_CONFIG" 2>/dev/null | awk '{print $1}')"
  # Take first 8 hex chars (32 bits) — fits in float64 without
  # precision loss.
  short_hex="${full_hash:0:8}"
  config_hash=$(( 16#$short_hex ))

  # Parse safety toggles. We look at uncommented config lines
  # (not Match-block scoped overrides — those are a more
  # advanced parse).
  raw_value() {
    local key="$1"
    grep -iE "^[[:space:]]*${key}[[:space:]]+" "$SSHD_CONFIG" 2>/dev/null \
      | tail -1 | awk '{print tolower($2)}'
  }

  v="$(raw_value PermitRootLogin)"
  if [ "$v" = "yes" ]; then permit_root_login=1; fi

  v="$(raw_value PasswordAuthentication)"
  if [ "$v" = "yes" ]; then password_authentication=1; fi

  v="$(raw_value PermitEmptyPasswords)"
  if [ "$v" = "yes" ]; then permit_empty_passwords=1; fi

  v="$(raw_value ChallengeResponseAuthentication)"
  if [ "$v" = "yes" ]; then challenge_response=1; fi

  v="$(raw_value X11Forwarding)"
  if [ "$v" = "yes" ]; then x11_forwarding=1; fi

  v="$(raw_value UsePAM)"
  if [ "$v" = "no" ]; then use_pam=0; fi

  v="$(raw_value Protocol)"
  if [ -n "$v" ] && [ "$v" != "2" ]; then protocol_v2_only=0; fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_sshd_config_present 1 if sshd_config exists and is readable.\n'
  printf '# TYPE selfdef_sshd_config_present gauge\n'
  printf 'selfdef_sshd_config_present %d\n' "$config_present"

  if [ "$config_present" -eq 1 ]; then
    printf '# HELP selfdef_sshd_config_hash First 32 bits of SHA-256(sshd_config) — drift detection.\n'
    printf '# TYPE selfdef_sshd_config_hash gauge\n'
    printf 'selfdef_sshd_config_hash %d\n' "$config_hash"
  fi

  printf '# HELP selfdef_sshd_permit_root_login 1 if PermitRootLogin yes (HAZARD).\n'
  printf '# TYPE selfdef_sshd_permit_root_login gauge\n'
  printf 'selfdef_sshd_permit_root_login %d\n' "$permit_root_login"

  printf '# HELP selfdef_sshd_password_authentication 1 if PasswordAuthentication yes (brute-force vector).\n'
  printf '# TYPE selfdef_sshd_password_authentication gauge\n'
  printf 'selfdef_sshd_password_authentication %d\n' "$password_authentication"

  printf '# HELP selfdef_sshd_permit_empty_passwords 1 if PermitEmptyPasswords yes (HAZARD).\n'
  printf '# TYPE selfdef_sshd_permit_empty_passwords gauge\n'
  printf 'selfdef_sshd_permit_empty_passwords %d\n' "$permit_empty_passwords"

  printf '# HELP selfdef_sshd_challenge_response 1 if ChallengeResponseAuthentication yes.\n'
  printf '# TYPE selfdef_sshd_challenge_response gauge\n'
  printf 'selfdef_sshd_challenge_response %d\n' "$challenge_response"

  printf '# HELP selfdef_sshd_x11_forwarding 1 if X11Forwarding yes (permissive).\n'
  printf '# TYPE selfdef_sshd_x11_forwarding gauge\n'
  printf 'selfdef_sshd_x11_forwarding %d\n' "$x11_forwarding"

  printf '# HELP selfdef_sshd_use_pam 1 if UsePAM yes (safe default).\n'
  printf '# TYPE selfdef_sshd_use_pam gauge\n'
  printf 'selfdef_sshd_use_pam %d\n' "$use_pam"

  printf '# HELP selfdef_sshd_protocol_v2_only 1 if Protocol 2 only (safe).\n'
  printf '# TYPE selfdef_sshd_protocol_v2_only gauge\n'
  printf 'selfdef_sshd_protocol_v2_only %d\n' "$protocol_v2_only"

  printf '# HELP selfdef_sshd_config_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
  printf '# TYPE selfdef_sshd_config_last_run_unix gauge\n'
  printf 'selfdef_sshd_config_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_sshd_config_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_sshd_config_textfile_emit_failed gauge\n'
  printf 'selfdef_sshd_config_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
