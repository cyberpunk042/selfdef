# Shared helpers used by apply/check/uninstall. Sourced, not executed.
# Caller must have set:
#   MODULE        — "integrity-sentinel"
#   DRY_RUN       — 0 | 1
#   CONFIG_FILE   — path to the rendered host config (selfdef sets this
#                   via SELFDEF_INTEGRITY_SENTINEL_CONFIG)

# shellcheck disable=SC2034  # used by sourcing scripts

log() { echo "[integrity-sentinel] $*" >&2; }

emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}

die() { emit_status "failed" "$*"; exit 1; }

run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@"
    fi
}

# Minimal TOML reader: only `key = "value"` / `key = N`. The
# paths-as-an-array problem is handled by the separate paths_file
# (one absolute path per line) rather than by parsing TOML arrays.
toml_get() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"; line="${line## }"; line="${line%% #*}"
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "$line"
}

# Expand the paths_file into a sorted, deduplicated list of absolute
# paths. Globs (`*`, `**`) are expanded with globstar+nullglob so a
# missing match contributes nothing rather than the literal pattern.
# Blank lines and `#`-comments are skipped.
#
# Stdin: paths_file contents
# Stdout: NUL-separated absolute paths (sorted, deduped)
expand_paths() {
    local paths_file="$1"
    [[ -r "$paths_file" ]] || die "paths_file not readable: $paths_file"

    # Run the expansion in a subshell so globstar/nullglob don't leak.
    (
        shopt -s globstar nullglob
        while IFS= read -r raw; do
            # Trim trailing CR, leading/trailing spaces.
            local line="${raw%$'\r'}"
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" || "$line" == \#* ]] && continue

            # Refuse anything not anchored at `/` — we don't want
            # apply.sh's CWD changing what gets baselined.
            if [[ "$line" != /* ]]; then
                echo "[integrity-sentinel] refusing non-absolute path: $line" >&2
                exit 2
            fi

            # `eval` is necessary to expand globs inside a variable
            # without re-tokenising on spaces. The line was checked
            # above for shell-meta we don't want; we still quote.
            # shellcheck disable=SC2086
            for match in $line; do
                # nullglob means: if the glob had no match, $line is
                # left empty after expansion — `for` body simply
                # doesn't execute. If the glob matched literally
                # (no metachars), `for` executes once with the
                # literal path, which may or may not exist (we check
                # next).
                if [[ -e "$match" ]]; then
                    # Only baseline regular files. Skip dirs, symlinks
                    # to dirs, sockets, etc.
                    if [[ -f "$match" ]]; then
                        printf '%s\0' "$match"
                    fi
                fi
            done
        done < "$paths_file"
    ) | LC_ALL=C sort -zu
}

# Compute sha256sum-formatted baseline for the NUL-separated paths on
# stdin. Output goes to stdout in `<sha256>  <path>\n` form, sorted
# by path.
compute_baseline() {
    # xargs -0 sha256sum gets us the exact format we want. We sort by
    # path afterwards for stable diffs.
    xargs -0 -r sha256sum 2>/dev/null | LC_ALL=C sort -k 2
}

# Optional: append a Detection Finding (OCSF class 2004) to the
# `eventstream` JSONL the daemon tails so the existing notifier
# chain (ntfy / Signal) fires. Gated on `event_stream_path` being
# set in the host config — if it's absent or empty, this is a no-op
# so deployments without a daemon side stay quiet.
#
# DRY-RUN: when `SELFDEF_DRY_RUN=1`, the helper logs what it would
# do and returns without writing — the rest of the run remains
# side-effect-free.
#
# Caller args:
#   $1 — profile     ("strict" | "warn-only")
#   $2 — summary     (human-readable message attached to the event)
#
# Requires the sourcing script to have already set CONFIG_FILE.
emit_drift_event() {
    local profile="$1" summary="$2"
    local stream_path
    stream_path=$(toml_get event_stream_path "$CONFIG_FILE" || echo "")
    [[ -z "$stream_path" ]] && return 0

    # Severity defaults: strict drift is High (operator action expected),
    # warn-only drift is Low (informational alert). Operators can
    # override per-profile via event_severity_* keys.
    local severity
    if [[ "$profile" == "strict" ]]; then
        severity=$(toml_get event_severity_strict "$CONFIG_FILE" || echo "high")
    else
        severity=$(toml_get event_severity_warn "$CONFIG_FILE" || echo "low")
    fi

    local ctl="${SELFDEF_CTL_BIN:-selfdefctl}"
    if ! command -v "$ctl" >/dev/null 2>&1; then
        log "selfdefctl not on PATH; skipping eventstream emission"
        return 0
    fi

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log "DRY-RUN: would emit drift event (severity=$severity) to $stream_path"
        return 0
    fi

    # Best-effort. We never want a notifier hiccup to fail the
    # selfdef-apply / selfdef-check pipeline — drift detection is the
    # source of truth in the structured-status JSON line.
    if ! "$ctl" --config /dev/null events emit \
            --class-uid 2004 \
            --activity-id 1 \
            --severity "$severity" \
            --source "selfdef.integrity-sentinel" \
            --message "$summary" \
            --out "$stream_path" 2>/dev/null; then
        log "warning: selfdefctl events emit failed (path=$stream_path)"
    fi
}
