#!/usr/bin/env bash
# L1-test-helper-dedup-coherence.sh — CLI test-helper dedup gate (F-2026-060)
#
# F-2026-060: the CLI module integration tests (crates/selfdef-cli/tests/
# module_*.rs) once duplicated ~9 copies of the same helper primitives
# (workspace_root / write_file / last_stdout_line / snapshot_tree / ...).
# They were consolidated into crates/selfdef-cli/tests/common/mod.rs and
# every module_*.rs migrated to `mod common; use common::{...}`. This gate
# LOCKS that closure so the duplication can't silently creep back when a
# new module test is added by copy-paste:
#
#   1. Every crates/selfdef-cli/tests/module_*.rs declares `mod common;`
#      (so it consumes the shared helpers).
#   2. No module_*.rs RE-DEFINES a heavy common helper body. The thin
#      per-file `fn module_dir() -> PathBuf { common::module_dir("<slug>") }`
#      wrapper is allowed (idiomatic slug-pin), but a local
#      `fn workspace_root` / `fn write_file` / etc. is forbidden — that's
#      the duplication F-2026-060 closed.
#
# Run: bash scripts/test/L1-test-helper-dedup-coherence.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_ROOT}" || { echo "cd ${REPO_ROOT} failed" >&2; exit 2; }

TESTS_DIR="crates/selfdef-cli/tests"
COMMON="${TESTS_DIR}/common/mod.rs"

# Heavy helpers that MUST live only in common/mod.rs (not the thin
# zero-arg module_dir slug wrapper, which is allowed per-file).
HEAVY_HELPERS=(workspace_root write_file last_stdout_line snapshot_tree
               assert_tree_unchanged write_executable prepended_path)

if [[ ! -f "${COMMON}" ]]; then
    echo "L1-test-helper-dedup FAIL: shared helper module ${COMMON} missing" >&2
    exit 1
fi

failures=0
count=0

shopt -s nullglob
for f in "${TESTS_DIR}"/module_*.rs; do
    count=$((count + 1))
    base="$(basename "${f}")"
    if ! grep -qE '^mod common;' "${f}"; then
        echo "  FAIL ${base}: does not declare 'mod common;' — must consume the shared test helpers (F-2026-060)"
        failures=$((failures + 1))
    fi
    for h in "${HEAVY_HELPERS[@]}"; do
        if grep -qE "fn ${h}\b" "${f}"; then
            echo "  FAIL ${base}: re-defines heavy helper 'fn ${h}' — use common::${h} (F-2026-060 duplication)"
            failures=$((failures + 1))
        fi
    done
done
shopt -u nullglob

if [[ "${count}" -eq 0 ]]; then
    echo "L1-test-helper-dedup FAIL: no module_*.rs test files found (parser/path drift)" >&2
    exit 1
fi

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-test-helper-dedup FAIL: ${failures} duplication violation(s)"
    exit 1
fi

echo "L1-test-helper-dedup PASS: ${count} module_*.rs tests all consume common/mod.rs; no heavy-helper duplication (F-2026-060 closed)"
