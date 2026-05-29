#!/bin/bash
# selfdef-modules-textfile — emit Prometheus node_exporter textfile
# gauges for the selfdef module catalog state.
#
# Calls `selfdefctl modules list --json`, parses the structured
# response, and atomically writes a node_exporter textfile with
# per-module presence + category + phase rollup gauges + a
# total-count gauge + an observer-freshness gauge.
#
# Runs every 60s via the companion selfdef-modules-textfile.timer.
# Pairs with the existing selfdef-cli-mirror-doctor +
# selfdef-m060-doctor + selfdef-four-watchdog-doctor textfile
# observers — same atomic tempfile + rename pattern, same
# node_exporter textfile_collector consumption shape, same
# honest-offline sentinel discipline.
#
# Selfdef ships 188+ module catalog entries under /usr/share/selfdef/
# modules/ (see backlog/SHIPPED.md MS001 + MS006 + MS017 + MS046+
# rows). This observer surfaces THAT inventory to Prometheus so
# operators can build dashboards / alerts on per-category drift
# (e.g., a hardening module dropping below the expected count).
#
# Honest-offline: when selfdefd is unreachable OR `selfdefctl
# modules list --json` fails, the wrapper emits a sentinel gauge
# `selfdef_modules_textfile_emit_failed=1` matching the
# four-watchdog convention so monitoring can distinguish "no data"
# from "no modules installed" — never silently produces zeroed
# gauges that would mask a wedged daemon as a healthy host with
# zero modules.
#
# Environment:
#   SELFDEF_MODULES_TEXTFILE_PATH (default
#     /var/lib/node_exporter/textfile_collector/selfdef-modules.prom)
#   SELFDEF_MODULES_DIR (optional override; default reads from
#     selfdefctl's resolved dir)
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_MODULES_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-modules.prom}"

emit_failure_sentinel() {
  # Atomic write of the failure sentinel so node_exporter sees a
  # consistent file. Mirrors the four-watchdog wrapper convention.
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_modules_textfile_emit_failed Wrapper exited unhealthy (selfdefctl failure, daemon unreachable, or no JSON).\n'
    printf '# TYPE selfdef_modules_textfile_emit_failed gauge\n'
    printf 'selfdef_modules_textfile_emit_failed 1\n'
    printf '# HELP selfdef_modules_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_modules_last_run_unix gauge\n'
    printf 'selfdef_modules_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — selfdefctl + jq on PATH.
if ! command -v selfdefctl >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

# Honor an optional --dir override via SELFDEF_MODULES_DIR.
list_args=("modules" "list" "--json")
if [ -n "${SELFDEF_MODULES_DIR:-}" ]; then
  list_args+=("--dir" "${SELFDEF_MODULES_DIR}")
fi

json="$(selfdefctl "${list_args[@]}" 2>/dev/null)" || {
  emit_failure_sentinel
  exit 2
}

# Validate envelope shape: must be a JSON array of objects each
# carrying at least the `name` field. Refuse to emit zeroed gauges
# from a malformed response — same honest-offline discipline as the
# four-watchdog wrapper.
if ! echo "$json" | jq -e 'type == "array"' >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

total="$(echo "$json" | jq -r 'length')"
# Per-category roll-up — count modules per `category` field with
# sane fallback when the field is absent. Same shape for `phase`.
categories_json="$(echo "$json" | jq -r '
  group_by(.category // "uncategorized")
  | map({key: (.[0].category // "uncategorized"), count: length})
  | from_entries
')"
phases_json="$(echo "$json" | jq -r '
  group_by(.phase // "main")
  | map({key: (.[0].phase // "main"), count: length})
  | from_entries
')"

# Build textfile in temp + atomic rename.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_modules_total Total selfdef modules present in the catalog directory.\n'
  printf '# TYPE selfdef_modules_total gauge\n'
  printf 'selfdef_modules_total %s\n' "$total"

  printf '# HELP selfdef_modules_by_category Selfdef modules per category (hardening / observability / etc).\n'
  printf '# TYPE selfdef_modules_by_category gauge\n'
  echo "$categories_json" | jq -r 'to_entries[] | "\(.key)\t\(.value)"' \
    | sort \
    | while IFS=$'\t' read -r cat count; do
        printf 'selfdef_modules_by_category{category="%s"} %s\n' "$cat" "$count"
      done

  printf '# HELP selfdef_modules_by_phase Selfdef modules per install phase (pre / main / post).\n'
  printf '# TYPE selfdef_modules_by_phase gauge\n'
  echo "$phases_json" | jq -r 'to_entries[] | "\(.key)\t\(.value)"' \
    | sort \
    | while IFS=$'\t' read -r phase count; do
        printf 'selfdef_modules_by_phase{phase="%s"} %s\n' "$phase" "$count"
      done

  printf '# HELP selfdef_modules_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_modules_last_run_unix gauge\n'
  printf 'selfdef_modules_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_modules_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_modules_textfile_emit_failed gauge\n'
  printf 'selfdef_modules_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

# Clear the ERR trap on successful emit.
trap - ERR
exit 0
