#!/usr/bin/env bash
# L1-cross-repo-alert-runbook-binding.sh — cross-repo coherence gate.
#
# The MS048 operator runbook at
#   docs/operator/ms048-scheduler-failure-modes.md
# carries a §1 index mapping every cockpit-fired alert (sovereign-os side)
# to the runbook section that documents the remediation. Two cross-repo
# contracts live in this seam:
#
#   1. Every alert NAME in the runbook §1 must exist as `- alert: <name>`
#      in cyberpunk042/sovereign-os/config/prometheus/alerts/
#      selfdef-scheduler.rules.yml. A silent rename or removal sovereign-os-
#      side breaks every operator following the runbook (the cd_link from
#      the cockpit alert won't resolve to a section).
#
#   2. Every cd_link label in the runbook §1 must exist as `cd_link: <slug>`
#      in the alert file. This is the actual label the cockpit's alert card
#      uses to deep-link into the runbook section; a silent label change
#      sovereign-os-side breaks the deep link silently.
#
#   3. Every alert NAME in the alert file must have a runbook §1 row
#      pointing somewhere. Adding a new alert without a runbook row leaves
#      operators stranded when it fires.
#
# This gate symmetrically enforces all three. Skips with a notice when the
# sovereign-os repo is not adjacent (development environments without both
# repos cloned), so the gate is non-blocking in that case but lights up in
# CI on the standard layout where both repos sit side by side.
#
# Run with: bash scripts/test/L1-cross-repo-alert-runbook-binding.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="${REPO_ROOT}/docs/operator/ms048-scheduler-failure-modes.md"
SOV_REPO_DEFAULT="${REPO_ROOT}/../sovereign-os"
SOV_REPO="${SOVEREIGN_OS_REPO:-${SOV_REPO_DEFAULT}}"
ALERTS="${SOV_REPO}/config/prometheus/alerts/selfdef-scheduler.rules.yml"

if [[ ! -f "${RUNBOOK}" ]]; then
    echo "FAIL: runbook not present at ${RUNBOOK}"
    exit 1
fi

if [[ ! -f "${ALERTS}" ]]; then
    echo "SKIP: sovereign-os alerts file not present at ${ALERTS} — set SOVEREIGN_OS_REPO env var to point at the sister repo."
    exit 0
fi

failures=0

# Extract alert names FROM the runbook §1 index (rows like
# "| `SelfdefSchedulerXxx` | `cd-link-slug` | [§N ...] |")
runbook_alerts=$(grep -oE '`Selfdef[A-Za-z]+`' "${RUNBOOK}" | tr -d '`' | sort -u)
# Each row shape: "| `Name` | `cd-link-slug` | [§N ...] |" — extract the
# second backtick-bounded token per row.
runbook_cd_links=$(grep -E '^\| `Selfdef' "${RUNBOOK}" | awk -F'`' '{print $4}' | sort -u)

# Extract alert names + cd_link labels FROM the alerts file
alerts_names=$(grep -E '^[[:space:]]*- alert:[[:space:]]+Selfdef' "${ALERTS}" | awk '{print $NF}' | sort -u)
alerts_cd_links=$(grep -E '^[[:space:]]*cd_link:[[:space:]]+[a-z-]+' "${ALERTS}" | awk '{print $NF}' | sort -u)

# Gate 1: every runbook alert exists in the alerts file
echo "▶ Gate 1: runbook alerts must exist sovereign-os-side"
while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    if echo "${alerts_names}" | grep -qFx "${name}"; then
        echo "  PASS ${name} present in sovereign-os alerts"
    else
        echo "  FAIL ${name} referenced in runbook §1 but NOT present in ${ALERTS}"
        failures=$((failures + 1))
    fi
done <<< "${runbook_alerts}"

# Gate 2: every runbook cd_link exists in the alerts file
echo "▶ Gate 2: runbook cd_link labels must exist sovereign-os-side"
while IFS= read -r link; do
    [[ -z "${link}" ]] && continue
    if echo "${alerts_cd_links}" | grep -qFx "${link}"; then
        echo "  PASS cd_link '${link}' present in sovereign-os alerts"
    else
        echo "  FAIL cd_link '${link}' referenced in runbook §1 but NOT present as cd_link in ${ALERTS}"
        failures=$((failures + 1))
    fi
done <<< "${runbook_cd_links}"

# Gate 3: every sovereign-os alert has a runbook row
echo "▶ Gate 3: every sovereign-os alert must be documented in runbook"
while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    if echo "${runbook_alerts}" | grep -qFx "${name}"; then
        echo "  PASS ${name} documented in runbook §1"
    else
        echo "  FAIL ${name} alert exists sovereign-os-side but NO runbook row points to it (operators stranded when it fires)"
        failures=$((failures + 1))
    fi
done <<< "${alerts_names}"

# Gate 4: in-document anchor integrity — every (#anchor) in runbook §1
# resolves to a real `## N. Section Heading` further down in the same file.
# A silent rename of a section heading without a §1 anchor update breaks the
# deep-link with no detection until incident time.
echo "▶ Gate 4: runbook §1 anchors must resolve to real section headings"

# Extract anchors used in §1 (form: (#some-anchor-text))
anchors=$(grep -E '^\| `Selfdef' "${RUNBOOK}" | grep -oE '\(#[0-9a-z-]+\)' | tr -d '()' | tr -d '#' | sort -u)

# Markdown anchor-slug rule: lowercase, drop punctuation, then spaces→dash.
# Per GitHub-flavored markdown, punctuation removal happens BEFORE the
# space→dash transform, so `## 6. Blackwell + host pressure` becomes
# `6-blackwell--host-pressure` (the `+` is dropped to nothing, leaving two
# adjacent spaces, both becoming dashes). DO NOT tr-s collapse — that
# would mismatch what the renderer produces.
heading_slugs=$(grep -E '^## ' "${RUNBOOK}" \
    | sed 's/^## //' \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's|[^a-z0-9 -]+||g' \
    | tr ' ' '-' \
    | sort -u)

while IFS= read -r anchor; do
    [[ -z "${anchor}" ]] && continue
    if echo "${heading_slugs}" | grep -qFx "${anchor}"; then
        echo "  PASS anchor #${anchor} resolves to a real section heading"
    else
        echo "  FAIL anchor #${anchor} referenced in runbook §1 but NO matching `## N. ...` heading found"
        failures=$((failures + 1))
    fi
done <<< "${anchors}"

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-cross-repo-alert-runbook-binding FAIL: ${failures} binding violation(s)"
    exit 1
fi

echo "L1-cross-repo-alert-runbook-binding PASS: runbook ↔ sovereign-os alerts symmetric + in-doc anchors resolve"
