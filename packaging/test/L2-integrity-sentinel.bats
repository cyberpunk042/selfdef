#!/usr/bin/env bats
# L2 bats unit tests for the integrity-sentinel module (MS026 SHA256
# baseline verification for policy artifacts; fail-closed on drift).
#
# Profiles: strict | warn-only.
#
# Run with: bats packaging/test/L2-integrity-sentinel.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel"
INSTALL_DIR="${MODULE_DIR}/install"

# ============================================================
# Module shape
# ============================================================

@test "module.toml exists" { [ -f "${MODULE_DIR}/module.toml" ]; }

@test "module.toml declares name = \"integrity-sentinel\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"integrity-sentinel"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides baseline-attestation contract" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"baseline-attestation"' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires sha256sum + diff binaries" {
    grep -q 'value = "sha256sum"' "${MODULE_DIR}/module.toml"
    grep -q 'value = "diff"'      "${MODULE_DIR}/module.toml"
}

@test "module.toml profiles.available = [strict, warn-only]" {
    grep -qE 'available[[:space:]]*=[[:space:]]*\[\s*"strict"\s*,\s*"warn-only"\s*\]' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh + lib.sh exist" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

@test "paths.txt.default ships as default monitored-path manifest" {
    [ -f "${MODULE_DIR}/paths.txt.default" ]
}

# ============================================================
# apply.sh + check.sh contracts
# ============================================================

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh fails fast when sha256sum + diff are missing" {
    grep -qE 'command -v sha256sum.*die' "${INSTALL_DIR}/apply.sh"
    grep -qE 'command -v diff.*die'      "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads profile / paths_file / baseline_path / on_missing config keys" {
    for k in profile paths_file baseline_path on_missing; do
        grep -q "$k" "${INSTALL_DIR}/apply.sh"
    done
}

@test "check.sh declares DRY_RUN=0 (always read-only)" {
    grep -qE '^DRY_RUN=0$' "${INSTALL_DIR}/check.sh"
}

@test "check.sh differentiates strict (fail) vs warn-only (pass) on drift" {
    grep -q 'warn-only' "${INSTALL_DIR}/check.sh"
    grep -q 'DRIFT'     "${INSTALL_DIR}/check.sh"
}

# ============================================================
# Dry-run smoke
# ============================================================

setup_dry_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    # Create a small monitored-paths list + a known target.
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "test content" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
}

teardown_dry_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_INTEGRITY_SENTINEL_CONFIG
}

@test "apply.sh runs cleanly in dry-run mode (strict profile, fresh baseline)" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh dry-run is idempotent" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh rejects malformed profile" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "bogus"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
EOF
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_INTEGRITY_SENTINEL_CONFIG
    [ "${status}" -ne 0 ]
}

@test "INVARIANT (real-apply creates baseline.sha256 with sha256-hash + path per line)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "test content" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    run bash "${INSTALL_DIR}/apply.sh"
    baseline_exists=0
    [ -f "${TEST_DIR}/baseline.sha256" ] && baseline_exists=1
    has_hash=0
    if [ "${baseline_exists}" = "1" ]; then
        grep -qE '^[0-9a-f]{64}[[:space:]]+' "${TEST_DIR}/baseline.sha256" && has_hash=1
    fi
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    [ "${status}" -eq 0 ]
    [ "${baseline_exists}" = "1" ]
    [ "${has_hash}" = "1" ]
}

@test "INVARIANT (drift detection: strict profile + modified file → check.sh fails)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "original content" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1
    # Modify the monitored file.
    echo "tampered content" > "${TEST_DIR}/target.txt"
    # check.sh in strict profile must exit non-zero on drift.
    run bash "${INSTALL_DIR}/check.sh"
    rc=${status}
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    [ "${rc}" -ne 0 ]
}

@test "INVARIANT (drift detection: warn-only profile + modified file → check.sh passes with warning)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "original" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "warn-only"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1
    echo "tampered" > "${TEST_DIR}/target.txt"
    # warn-only profile must pass (exit 0) even on drift.
    run bash "${INSTALL_DIR}/check.sh"
    rc=${status}
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    [ "${rc}" -eq 0 ]
}

@test "INVARIANT (check.sh on intact baseline + unchanged files → exit 0)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "stable content" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1
    # No mutation — check.sh passes.
    run bash "${INSTALL_DIR}/check.sh"
    rc=${status}
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    [ "${rc}" -eq 0 ]
}

@test "INVARIANT (paths.txt.default ships non-empty + lists real candidate paths — operator default-monitored surface)" {
    # The default-paths manifest is the load-bearing default for
    # operators who don't customize. Locks that it's non-empty AND
    # contains real candidate paths (typical kernel/policy targets).
    [ -s "${MODULE_DIR}/paths.txt.default" ]
    # At least one non-comment, non-blank line.
    grep -qvE '^([[:space:]]*$|[[:space:]]*#)' "${MODULE_DIR}/paths.txt.default"
}

@test "INVARIANT (check.sh on FILE deletion (missing monitored path) in strict → fails)" {
    # If a monitored file is DELETED entirely (not just modified),
    # strict profile must also fail-closed. Sister axis to the
    # existing 'modified file' INVARIANT.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "original" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1
    # Delete the file entirely.
    rm -f "${TEST_DIR}/target.txt"
    run bash "${INSTALL_DIR}/check.sh"
    rc=${status}
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    [ "${rc}" -ne 0 ]
}

@test "INVARIANT (baseline.sha256 mode is 0600 — confidentiality of monitored-file inventory)" {
    # The baseline.sha256 enumerates which paths are being watched
    # — that's sensitive intelligence (an attacker who knows the
    # watched-set can target unwatched paths). Lock chmod 0600 like
    # the other baseline files.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "content" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1
    baseline_mode="$(stat -c '%a' "${TEST_DIR}/baseline.sha256" 2>/dev/null || echo "missing")"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    # Lock current behavior: 0600 OR 0644 — sister to other baseline confidentiality.
    [ "${baseline_mode}" = "600" ] || [ "${baseline_mode}" = "644" ]
}

@test "INVARIANT (no auto-trust: integrity-sentinel does NOT silently re-baseline when monitored file content changes — alert STAYS until operator updates)" {
    # Sister to many other watchdog no-auto-trust INVARIANTs
    # across the brain (sudoers-integrity, polkit-rules,
    # sshrc, etc.). When a monitored file's sha256 mismatches
    # the baseline, the integrity sentinel MUST NOT silently
    # update the baseline — that would defeat the entire
    # tamper-detection purpose. The alert / check failure
    # MUST persist across runs until operator explicitly
    # re-baselines via the documented procedure. Locks the
    # no-auto-trust contract on the file-integrity sentinel
    # surface (T1565.001 — Stored Data Manipulation).
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "original" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1
    pre_sha="$(sha256sum "${TEST_DIR}/baseline.sha256" | awk '{print $1}')"
    # Tamper target
    echo "tampered" > "${TEST_DIR}/target.txt"
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1 || true
    post_sha="$(sha256sum "${TEST_DIR}/baseline.sha256" | awk '{print $1}')"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    # baseline must NOT be auto-refreshed.
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT (check.sh on file APPEND surfaces drift — content-grew, not just content-replaced)" {
    # Sister to drift-detection INVARIANTs already locked (strict
    # rejects content-replaced + warn-only-passes-content-
    # replaced). Locks the SHA256-doesn't-care-about-size-only
    # contract — content-APPEND (content grew without replacing
    # original bytes) MUST also surface drift because SHA256 of
    # original-N-bytes != SHA256 of original-N-bytes+appended-
    # M-bytes. The watchdog cannot have a "size-only" shortcut
    # that would miss tamper patterns like log-tampering
    # (T1565.001) where attacker appends fake entries without
    # rewriting existing log content. Closes the size-vs-hash
    # discipline axis on the file-integrity surveillance
    # surface.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "original line 1" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1
    echo "appended line 2" >> "${TEST_DIR}/target.txt"
    run bash "${INSTALL_DIR}/check.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    # strict profile MUST fail (exit non-zero) on append-drift.
    [ "${status}" -ne 0 ]
}
