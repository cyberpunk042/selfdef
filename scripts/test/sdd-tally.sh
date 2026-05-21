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

# Extract every "> Status: **<word>**" header line into a single
# space-delimited word per SDD, then count by status.
declare -A counts=()
total=0
while IFS= read -r f; do
    # Pull the canonical status word. Some SDDs use bold span
    # (`> Status: **implemented**`); some don't (`> Status:
    # implemented`); some carry a qualifier ("scoping —
    # requirements only, design deferred"). We capture the first
    # sequence of lowercase / `<` / `-` after the leading prefix.
    status_word="$(grep -m1 -oE '^> Status: \*{0,2}[a-z<-]+' "${f}" \
        | sed -E 's/^> Status: \*{0,2}([a-z<-]+).*/\1/' \
        || true)"
    status_word="${status_word:-unknown}"
    counts[${status_word}]=$((${counts[${status_word}]:-0} + 1))
    total=$((total + 1))
done < <(find "${SDD_DIR}" -maxdepth 1 -name '[0-9][0-9][0-9]-*.md' | sort)

echo "MS013 SDD ledger — status tally for ${SDD_DIR}/"
echo "──────────────────────────────────────────────────────"
# Canonical order: implemented (top) → review → scoping → draft → other
for status in implemented review scoping draft living "<draft" unknown; do
    n="${counts[${status}]:-0}"
    if [[ "${n}" -gt 0 ]]; then
        printf "  %-14s %d\n" "${status}" "${n}"
    fi
done
echo "──────────────────────────────────────────────────────"
echo "  total          ${total}"
