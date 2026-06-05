#!/usr/bin/env bash
# L1-info-hub-doc-references.sh — selfdef docs cross-repo deep-link
# integrity against the devops-solutions-information-hub.
#
# Selfdef operator docs cite info-hub paths via GitHub blob URLs
# (e.g. the MS048 failure-modes runbook cites the Peace Machine + Core
# Law doctrine page at
# `cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
# doctrine/peace-machine-and-core-law.md`). Drift on either repo's main
# breaks the operator's deep-link.
#
# This gate walks every `cyberpunk042/devops-solutions-information-hub/
# blob/main/<path>` reference in selfdef's `docs/` tree and verifies
# the path exists in the adjacent info-hub repo.
#
# SKIPs cleanly when info-hub not adjacent. Currently surfaces
# selfdef↔info-hub paths as ADVISORY (not FAIL) — the doctrine page
# `wiki/spine/doctrine/peace-machine-and-core-law.md` is operator-
# supervised authoring per SDD-031 line 147; it lives on the info-hub
# `claude/recover-projects-b0oT6` branch via PR #17 awaiting operator
# decision. Failing CI on a known-pending merge would be unilateral
# scope-overstep; surfacing as ADVISORY puts the finding on the operator's
# review surface without breaking CI.
#
# Run with: bash scripts/test/L1-info-hub-doc-references.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCS_ROOT="${REPO_ROOT}/docs"
INFO_HUB_DEFAULT="${REPO_ROOT}/../devops-solutions-information-hub"
INFO_HUB="${SELFDEF_INFO_HUB_REPO:-${INFO_HUB_DEFAULT}}"

if [[ ! -d "${INFO_HUB}" ]]; then
    echo "SKIP: info-hub repo not adjacent at ${INFO_HUB} — set SELFDEF_INFO_HUB_REPO to override."
    exit 0
fi

# Extract every (path-after-blob-main) reference under selfdef's docs/
# (anchors stripped — we check file existence, not heading resolution).
declare -a refs
while IFS= read -r url; do
    [[ -z "${url}" ]] && continue
    # Strip the leading "cyberpunk042/devops-solutions-information-hub/
    # blob/<branch>/" prefix; strip trailing #anchor and ).
    path=$(echo "${url}" | sed -E 's|^cyberpunk042/devops-solutions-information-hub/blob/[a-z0-9_-]+/||; s|#.*$||; s|\).*$||')
    refs+=("${path}")
done < <(grep -rohE 'cyberpunk042/devops-solutions-information-hub/blob/[a-z][a-z0-9_-]*/[^[:space:])\#"]+' "${DOCS_ROOT}" 2>/dev/null | sort -u)

if [[ "${#refs[@]}" -eq 0 ]]; then
    echo "L1-info-hub-doc-references PASS: no info-hub cross-repo refs found under ${DOCS_ROOT}"
    exit 0
fi

advisories=0
hard_failures=0

# Path-specific advisory list — known-pending merges that should NOT
# break CI but should surface on every commit so the operator sees the
# stale reference each run.
# Format: <path>|<reason>
ADVISORY_PATHS=(
    "wiki/spine/doctrine/peace-machine-and-core-law.md|operator-supervised authoring per SDD-031 line 147; on info-hub PR #17 (branch claude/recover-projects-b0oT6) awaiting operator decision"
)

is_advisory_path() {
    local p="$1"
    for row in "${ADVISORY_PATHS[@]}"; do
        IFS='|' read -r adv_path _ <<< "${row}"
        if [[ "${p}" == "${adv_path}" ]]; then
            return 0
        fi
    done
    return 1
}

advisory_reason() {
    local p="$1"
    for row in "${ADVISORY_PATHS[@]}"; do
        IFS='|' read -r adv_path reason <<< "${row}"
        if [[ "${p}" == "${adv_path}" ]]; then
            echo "${reason}"
            return
        fi
    done
}

echo "▶ Walking selfdef docs for info-hub cross-repo refs (${#refs[@]} distinct paths)..."
for p in "${refs[@]}"; do
    if [[ -f "${INFO_HUB}/${p}" ]]; then
        echo "  PASS ${p}"
    elif is_advisory_path "${p}"; then
        echo "  ADVISORY ${p}: $(advisory_reason "${p}")"
        advisories=$((advisories + 1))
    else
        echo "  FAIL ${p}: not present in adjacent info-hub repo (broken cross-repo deep-link)"
        hard_failures=$((hard_failures + 1))
    fi
done

if [[ "${hard_failures}" -gt 0 ]]; then
    echo "L1-info-hub-doc-references FAIL: ${hard_failures} broken cross-repo deep-link(s) (${advisories} advisories)"
    exit 1
fi

if [[ "${advisories}" -gt 0 ]]; then
    echo "L1-info-hub-doc-references PASS: ${#refs[@]} refs (${advisories} ADVISORY — operator-pending; see annotations above)"
else
    echo "L1-info-hub-doc-references PASS: ${#refs[@]} cross-repo refs all resolve"
fi
