#!/usr/bin/env bash
# L1-backlog-index-coherence.sh — backlog/INDEX.md ↔ filesystem coherence
# gate for the selfdef milestone catalog.
#
# backlog/INDEX.md is the auto-generated factual index that surfaces the
# full milestone catalog at a glance (per its own preamble:
# "Surfaces the existing requirement catalog at a glance — no invention").
# The contract is bidirectional: every row in INDEX.md must reference a
# real milestone file, AND every file under backlog/milestones/MS*.md
# must have an INDEX.md row. Silent drift in either direction breaks
# operator discoverability:
#
#   1. INDEX → file missing — operator clicks a row, hits 404 / dead link
#   2. file → no INDEX row — operator following the catalog can't find
#      the milestone via the canonical entry point
#   3. R-row count mismatch — INDEX promises N R-rows but the milestone
#      file ships M; operators planning capacity get wrong numbers
#
# This gate enforces all three with text-shape assertions (no parsing
# library, no markdown engine — pure grep + comm).
#
# Run with: bash scripts/test/L1-backlog-index-coherence.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INDEX="${REPO_ROOT}/backlog/INDEX.md"
MILESTONES_DIR="${REPO_ROOT}/backlog/milestones"

failures=0

if [[ ! -f "${INDEX}" ]]; then
    echo "FAIL: ${INDEX} not present (the milestone-catalog entry point is gone)"
    exit 1
fi
if [[ ! -d "${MILESTONES_DIR}" ]]; then
    echo "FAIL: ${MILESTONES_DIR} not present (no milestone files to gate)"
    exit 1
fi

# --- Extract the two sets we'll compare ---
# From INDEX.md: every `milestones/MS<NNN>-<slug>.md` linked path (no dups)
index_paths=$(grep -oE 'milestones/MS[0-9]{3}-[a-z0-9-]+\.md' "${INDEX}" | sort -u)

# From filesystem: every MS*.md file under backlog/milestones
fs_paths=$(cd "${REPO_ROOT}/backlog" && ls milestones/MS[0-9][0-9][0-9]-*.md 2>/dev/null | sort -u)

# --- Gate 1: every INDEX path resolves to a real file ---
echo "▶ Gate 1: every backlog/INDEX.md row references a real milestone file"
while IFS= read -r p; do
    [[ -z "${p}" ]] && continue
    if [[ -f "${REPO_ROOT}/backlog/${p}" ]]; then
        echo "  PASS ${p} resolves"
    else
        echo "  FAIL ${p} referenced in INDEX.md but file does not exist"
        failures=$((failures + 1))
    fi
done <<< "${index_paths}"

# --- Gate 2: every milestone file has an INDEX.md row ---
echo "▶ Gate 2: every backlog/milestones/MS*.md file has an INDEX.md row"
while IFS= read -r p; do
    [[ -z "${p}" ]] && continue
    if echo "${index_paths}" | grep -qFx "${p}"; then
        echo "  PASS ${p} has INDEX row"
    else
        echo "  FAIL ${p} exists on disk but has NO row in INDEX.md (operator can't discover via catalog entry-point)"
        failures=$((failures + 1))
    fi
done <<< "${fs_paths}"

# --- Gate 3: R-row count consistency ---
# INDEX.md row shape: "| [MS<NNN>-<slug>](milestones/MS<NNN>-<slug>.md) | <N> | <title>"
# Milestone file R-row count: lines matching "^| R[0-9]+ |"
echo "▶ Gate 3: INDEX.md R-row count matches each milestone file's actual R-row count"
while IFS= read -r p; do
    [[ -z "${p}" ]] && continue
    milestone_file="${REPO_ROOT}/backlog/${p}"
    [[ -f "${milestone_file}" ]] || continue
    # Extract the slug stem (e.g. MS001-selfdef-daemon-core) to grep the
    # exact INDEX row that links to this file.
    stem=$(basename "${p}" .md)
    # Take the row that contains this stem in the [link](...) form.
    index_row=$(grep -F "[${stem}](milestones/${stem}.md)" "${INDEX}" | head -1 || true)
    if [[ -z "${index_row}" ]]; then
        echo "  SKIP ${stem}: row not found in expected shape (caught by Gate 2 if real, otherwise format drift)"
        continue
    fi
    # Pull the middle column (the R-row count promise) — right-aligned per
    # the INDEX preamble's `|---:|` column-spec.
    promised=$(echo "${index_row}" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$3); print $3}')
    actual=$(grep -cE '^\| R[0-9]+ \|' "${milestone_file}")
    if [[ "${promised}" == "${actual}" ]]; then
        echo "  PASS ${stem}: INDEX promises ${promised}, file has ${actual}"
    else
        echo "  FAIL ${stem}: INDEX promises ${promised} R-rows, file actually has ${actual}"
        failures=$((failures + 1))
    fi
done <<< "${fs_paths}"

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-backlog-index-coherence FAIL: ${failures} catalog drift(s)"
    exit 1
fi

total=$(echo "${fs_paths}" | wc -l)
echo "L1-backlog-index-coherence PASS: ${total} milestones — INDEX.md ↔ filesystem ↔ R-row counts all coherent"
