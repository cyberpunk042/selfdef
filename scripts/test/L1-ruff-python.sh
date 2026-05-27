#!/usr/bin/env bash
# L1-ruff-python.sh — ruff lint gate over selfdef's Python surface
#
# selfdef's Python is small but critical: scripts/guardian/guardian-core (the
# MS044 IPS response daemon) + scripts/ux-harness/selfdef-ux-harness (the
# MS045 coherence harness) + the tests/. A ruff finding (undefined name,
# unused import, redefinition, …) can be a real defect in the daemon. CI lints
# Python; this mirrors it in the local coherence harness so it lands before a
# push, not in CI.
#
# Source: extends the MS045/SDD-030 coherence harness (parallels
# L1-shellcheck-scan.sh for bash).
set -euo pipefail

if ! command -v ruff >/dev/null 2>&1; then
    echo "L1-ruff-python SKIP: ruff not installed (CI installs it; local convenience only)"
    exit 0
fi

# The two no-extension python3 entrypoints + every .py (excluding caches/target).
targets=(scripts/guardian/guardian-core scripts/ux-harness/selfdef-ux-harness)
mapfile -t pys < <(find . -name '*.py' -not -path '*/__pycache__/*' -not -path './target/*' 2>/dev/null | sort)
targets+=("${pys[@]}")

if ! ruff check "${targets[@]}"; then
    echo "L1-ruff-python FAIL: ruff findings above." >&2
    exit 1
fi

echo "L1-ruff-python PASS: ${#targets[@]} Python files, 0 ruff findings"
exit 0
