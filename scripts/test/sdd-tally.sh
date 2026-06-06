#!/usr/bin/env bash
# scripts/test/sdd-tally.sh — MS013 charter-tracking drift detector.
#
# Prints per-status counts across docs/sdd/*.md headers. Useful when
# operators want to verify the SDD ledger reflects what's actually
# shipping in production (per the operator standing directive 'You
# cannot mark something done if it hasn't reached Prod').
#
# Exit 0 always — informational only; this is NOT a coherence gate.
# Source: MS013 SDD-charter doctrine + the per-session SDD authoring
# work documented in CHANGELOG.md.
set -uo pipefail

SDD_DIR="${SDD_DIR:-docs/sdd}"
if [[ ! -d "${SDD_DIR}" ]]; then
    echo "sdd-tally: ${SDD_DIR} not found" >&2
    exit 2
fi

# Extract every status header (any of 3 shapes) into a single word,
# then count by status.
declare -A counts=()
total=0
while IFS= read -r f; do
    # Pull the canonical status word. SDDs use four header shapes:
    #   1. `> Status: **implemented**`     (blockquote + bold span)
    #   2. `> Status: implemented`         (blockquote plain)
    #   3. `**Status:** draft / arch spec` (markdown-bold inline —
    #      adopted for SDD-065..078 action-surface specs in 2026-06)
    #   4. `Status: accepted`              (plain — SDD-062..063)
    # Also tolerate qualifier suffixes ("scoping — requirements
    # only"). Capture the first sequence of lowercase / `<` / `-`
    # after the leading prefix.
    status_word="$(grep -m1 -oE '^(> Status: |\*\*Status:\*\* |Status: )\*{0,2}[a-z<-]+' "${f}" \
        | sed -E 's/^(> Status: |\*\*Status:\*\* |Status: )\*{0,2}([a-z<-]+).*/\2/' \
        || true)"
    if [[ -z "${status_word}" ]]; then
        # 4th fallback: SDDs without a Status header but with an
        # "## Implementation status" section + all-checked
        # checkboxes (SDD-061..063 family) are implementation-
        # complete. Count them as `implemented` when the file
        # contains "## Implementation status" AND has at least one
        # checked checkbox (`- [x]`) AND has NO unchecked
        # checkboxes (`- [ ]`).
        if grep -qE '^## Implementation status' "${f}" \
            && grep -qE '^- \[x\]' "${f}" \
            && ! grep -qE '^- \[ \]' "${f}"; then
            status_word="implemented"
        fi
    fi
    status_word="${status_word:-unknown}"
    counts[${status_word}]=$((${counts[${status_word}]:-0} + 1))
    total=$((total + 1))
done < <(find "${SDD_DIR}" -maxdepth 1 -name '[0-9][0-9][0-9]-*.md' | sort)

echo "MS013 SDD ledger — status tally for ${SDD_DIR}/"
echo "──────────────────────────────────────────────────────"
# Canonical order: implemented (top) → accepted → review → scoping → draft → other
# `accepted` is the SDD-062 "rule shipped experimental" tier — past
# scoping but pre-fully-implemented.
for status in implemented accepted review scoping draft living "<draft" unknown; do
    n="${counts[${status}]:-0}"
    if [[ "${n}" -gt 0 ]]; then
        printf "  %-14s %d\n" "${status}" "${n}"
    fi
done
echo "──────────────────────────────────────────────────────"
echo "  total          ${total}"
