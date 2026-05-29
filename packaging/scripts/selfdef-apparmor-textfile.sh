#!/bin/bash
# selfdef-apparmor-textfile — emit Prometheus node_exporter textfile
# gauges for the selfdefd AppArmor profile-enforcement state.
#
# Surfaces real IPS-host operator visibility: profile loaded?,
# enforce vs complain mode?, total system profile count, kernel
# AppArmor support present?
#
# Runs every 60s via the companion selfdef-apparmor-textfile.timer.
# Sister to the 5 existing observer wrappers (cli-mirror + m060 +
# four-watchdog + modules-catalog + daemon-process) — same atomic
# tempfile + rename pattern, same honest-offline discipline.
#
# AppArmor profile-enforcement state is a load-bearing IPS surface:
# selfdefd runs under packaging/apparmor/usr.bin.selfdefd; an
# operator silently switching the profile to complain mode (or
# unloading it) weakens the IPS spine without firing any other
# alarm. This observer detects that drift.
#
# Honest-offline: when AppArmor isn't supported by the kernel OR
# /sys/kernel/security/apparmor/ is inaccessible, emit a sentinel
# gauge — never silently emit zeroed gauges that would mask an
# unenforced daemon as "healthy".
#
# Environment:
#   SELFDEF_APPARMOR_TEXTFILE_PATH (default
#     /var/lib/node_exporter/textfile_collector/selfdef-apparmor.prom)
#   SELFDEF_APPARMOR_PROFILE_NAME (default /usr/bin/selfdefd)
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_APPARMOR_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-apparmor.prom}"
PROFILE_NAME="${SELFDEF_APPARMOR_PROFILE_NAME:-/usr/bin/selfdefd}"

emit_failure_sentinel() {
  # Atomic write of the failure sentinel. Same convention as the
  # four-watchdog + modules + daemon-process wrappers.
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_apparmor_textfile_emit_failed Wrapper exited unhealthy (kernel AppArmor absent, /sys inaccessible, profile probe failed).\n'
    printf '# TYPE selfdef_apparmor_textfile_emit_failed gauge\n'
    printf 'selfdef_apparmor_textfile_emit_failed 1\n'
    printf '# HELP selfdef_apparmor_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_apparmor_last_run_unix gauge\n'
    printf 'selfdef_apparmor_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

PROFILES_FILE="/sys/kernel/security/apparmor/profiles"

# Honest-offline: kernel AppArmor unavailable.
if ! [ -r "$PROFILES_FILE" ]; then
  emit_failure_sentinel
  exit 2
fi

# Total AppArmor profiles loaded system-wide.
total_profiles="$(wc -l < "$PROFILES_FILE" 2>/dev/null || echo 0)"

# Selfdef profile state. The /sys/kernel/security/apparmor/profiles
# format is `<name> (<mode>)` per line — e.g. `/usr/bin/selfdefd (enforce)`.
selfdef_line="$(grep -F "$PROFILE_NAME " "$PROFILES_FILE" 2>/dev/null || true)"

if [ -z "$selfdef_line" ]; then
  # Profile not loaded — distinct from sentinel (kernel is fine,
  # but our profile isn't installed). Emit gauges with explicit
  # values so the operator sees the drift.
  selfdef_loaded=0
  selfdef_enforce=0
  selfdef_complain=0
  selfdef_mode="absent"
else
  selfdef_loaded=1
  # Extract mode from `(enforce)` / `(complain)` / `(kill)` /
  # `(unconfined)` suffix.
  selfdef_mode="$(echo "$selfdef_line" | sed -n 's/.*(\([^)]*\)).*/\1/p')"
  case "$selfdef_mode" in
    enforce)  selfdef_enforce=1; selfdef_complain=0 ;;
    complain) selfdef_enforce=0; selfdef_complain=1 ;;
    *)        selfdef_enforce=0; selfdef_complain=0 ;;
  esac
fi

# Build textfile in temp + atomic rename.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_apparmor_profile_loaded 1 if the selfdefd AppArmor profile is loaded in the kernel; 0 otherwise.\n'
  printf '# TYPE selfdef_apparmor_profile_loaded gauge\n'
  printf 'selfdef_apparmor_profile_loaded{profile="%s"} %d\n' "$PROFILE_NAME" "$selfdef_loaded"

  printf '# HELP selfdef_apparmor_profile_enforce 1 if the profile is in enforce mode (the secure default); 0 otherwise.\n'
  printf '# TYPE selfdef_apparmor_profile_enforce gauge\n'
  printf 'selfdef_apparmor_profile_enforce{profile="%s"} %d\n' "$PROFILE_NAME" "$selfdef_enforce"

  printf '# HELP selfdef_apparmor_profile_complain 1 if the profile is in complain mode (logs violations but does not enforce); 0 otherwise.\n'
  printf '# TYPE selfdef_apparmor_profile_complain gauge\n'
  printf 'selfdef_apparmor_profile_complain{profile="%s"} %d\n' "$PROFILE_NAME" "$selfdef_complain"

  printf '# HELP selfdef_apparmor_profiles_loaded_total Count of all AppArmor profiles loaded in the kernel.\n'
  printf '# TYPE selfdef_apparmor_profiles_loaded_total gauge\n'
  printf 'selfdef_apparmor_profiles_loaded_total %d\n' "$total_profiles"

  printf '# HELP selfdef_apparmor_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_apparmor_last_run_unix gauge\n'
  printf 'selfdef_apparmor_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_apparmor_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_apparmor_textfile_emit_failed gauge\n'
  printf 'selfdef_apparmor_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR

# Honest-offline doctrine — exit 0 even when the profile is absent
# (the textfile carries that information). Exit 2 only on kernel-
# level unavailability (handled by the trap above).
exit 0
