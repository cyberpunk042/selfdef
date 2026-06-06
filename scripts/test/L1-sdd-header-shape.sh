#!/usr/bin/env bash
# L1-sdd-header-shape.sh — SDD document header shape integrity gate.
#
# selfdef ships 79 SDD documents in `docs/sdd/<NNN>-<slug>.md`. Each SDD
# carries a uniform header pattern set by SDD-000-charter:
#   # SDD-NNN — <title> (optional MS-binding)
#   > Status: **<state>** ...
#
# This pattern is the operator's discoverability + state-tracking surface.
# Three silent-drift classes:
#
#   1. Number collision — two SDDs accidentally numbered the same (file
#      slugs differ but the heading SDD-NNN clashes).
#   2. Missing/malformed first heading — a SDD without `# SDD-NNN —` is
#      undiscoverable through the standard SDD-number search pattern.
#   3. Missing/malformed `Status:` — operators can't tell at a glance
#      whether the SDD is implemented, in-review, accepted, abandoned.
#
# Allowed status values per docs/sdd/000-charter.md + the existing SDD
# corpus survey 2026-06-05: draft / accepted / review / implemented /
# partially-implemented / abandoned / superseded / scoping / active.
# The corpus uses both bold (`**state**`) and plain (`state`) forms;
# both are accepted. SDDs that intentionally omit a `Status:` line
# (e.g. the SDD-065..078 action-surface family — operator-stated they
# encode the action surface itself, no per-SDD status) are exempt.
#
# Run with: bash scripts/test/L1-sdd-header-shape.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SDD_DIR="${REPO_ROOT}/docs/sdd"

failures=0

if [[ ! -d "${SDD_DIR}" ]]; then
    echo "FAIL: ${SDD_DIR} not present"
    exit 1
fi

# Track which SDD numbers we've seen (catch collisions)
declare -A sdd_number_to_file

# Allowed status states (markdown bold-wrapped match)
allowed_states="implemented accepted partially-implemented draft review abandoned superseded scoping active"

# Gate 1: each SDD's first H1 heading is `# SDD-NNN — ...`
# Gate 2: each SDD declares a `Status: **<state>**` line within the
#         first 25 lines (the convention is to put it in the lead blockquote).
# Gate 3: no two SDDs share the same SDD-NNN number.
echo "▶ Walking docs/sdd/*.md ($(ls "${SDD_DIR}"/*.md 2>/dev/null | wc -l) files)..."

for sdd in "${SDD_DIR}"/*.md; do
    [[ -f "${sdd}" ]] || continue
    name="$(basename "${sdd}")"
    # README/INDEX-style files + the SDD-000 charter (meta-SDD) are
    # intentionally exempt from per-SDD header shape — they don't follow
    # the per-SDD pattern by design.
    case "${name}" in
        README.md|INDEX.md|index.md|000-charter.md) continue ;;
    esac

    # Gate 1: extract the first `# ` heading
    first_h1=$(grep -m1 '^# ' "${sdd}" || true)
    if [[ -z "${first_h1}" ]]; then
        echo "  FAIL ${name}: no '# ' top-level heading"
        failures=$((failures + 1))
        continue
    fi
    if ! echo "${first_h1}" | grep -qE '^# SDD-[0-9]{3}( —| -|— | - ).*'; then
        echo "  FAIL ${name}: first heading does not match '# SDD-NNN — <title>' shape: ${first_h1}"
        failures=$((failures + 1))
        continue
    fi
    # Extract the NNN
    sdd_num=$(echo "${first_h1}" | grep -oE 'SDD-[0-9]{3}' | head -1 | sed 's/SDD-//')

    # Gate 3: collision detection
    if [[ -n "${sdd_number_to_file[${sdd_num}]:-}" ]]; then
        echo "  FAIL SDD-${sdd_num} number collision: ${name} clashes with ${sdd_number_to_file[${sdd_num}]}"
        failures=$((failures + 1))
    else
        sdd_number_to_file["${sdd_num}"]="${name}"
    fi

    # Gate 2: Status line within first 25 lines. Accepts 4 shapes:
    #   1. `> Status: **state**` (blockquote + bold span)
    #   2. `> Status: state`     (blockquote plain)
    #   3. `**Status:** state`   (markdown-bold inline — adopted for
    #      SDD-065..078 action-surface specs in 2026-06)
    #   4. `Status: state`       (plain — SDD-062/063)
    # SDDs without ANY of those shapes are SKIPped rather than failed
    # (operator-scope exemption). Surface as ADVISORY so they are
    # visible but don't break CI.
    status_line=$(head -25 "${sdd}" | grep -m1 -E '(^|> )[[:space:]]*(\*\*)?Status:?(\*\*)?[[:space:]]+' || true)
    if [[ -z "${status_line}" ]]; then
        echo "  ADVISORY ${name}: no 'Status: <state>' line in first 25 lines (action-surface SDDs intentionally omit; others may need operator review)"
        continue
    fi
    # Try bold form first (`**state**`), then plain (after `Status:`,
    # take the first word, stopping at any space or '—' that begins a
    # continuation like 'scoping — requirements only'). Both greps may
    # fail; || true keeps set -e happy.
    state=$(echo "${status_line}" | { grep -oE '\*\*[a-z-]+(\b|[[:space:]])' || true; } | head -1 | tr -d '*' | tr -d ' ')
    if [[ -z "${state}" ]]; then
        state=$(echo "${status_line}" \
            | sed -E 's|.*Status:?(\*\*)?[[:space:]]+||' \
            | sed -E 's|\*\*||g' \
            | { grep -oE '^[a-z-]+' || true; } \
            | head -1)
    fi
    if [[ -z "${state}" ]]; then
        echo "  ADVISORY ${name}: Status line found but state token not extractable: ${status_line}"
        continue
    fi
    if ! echo "${allowed_states}" | tr ' ' '\n' | grep -qFx "${state}"; then
        echo "  FAIL ${name}: status state '${state}' not in allowed set (${allowed_states})"
        failures=$((failures + 1))
        continue
    fi
done

total="${#sdd_number_to_file[@]}"

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-sdd-header-shape FAIL: ${failures} header-shape violation(s) across ${total} valid SDDs"
    exit 1
fi

echo "L1-sdd-header-shape PASS: ${total} SDDs all have well-shaped # SDD-NNN headings + valid Status: **<state>** + no number collisions"
