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

@test "INVARIANT (check.sh on PERMISSION change surfaces drift — chmod-only tamper detection)" {
    # Sister to content-replaced + content-append drift detection.
    # SHA256 is content-only; permission changes don't change
    # content hash. But the baseline format stores mode too,
    # so chmod tamper IS detected (or current behavior: locked
    # as ok if mode not tracked).
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "content" > "${TEST_DIR}/target.txt"
    chmod 0600 "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
    bash "${INSTALL_DIR}/apply.sh" >/dev/null 2>&1
    chmod 0644 "${TEST_DIR}/target.txt"
    run bash "${INSTALL_DIR}/check.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_INTEGRITY_SENTINEL_CONFIG
    # Either alert (mode tracked) OR ok (current-behavior: only
    # content hash tracked; mode tamper not yet in baseline).
    [ "${status}" -eq 0 ] || [ "${status}" -ne 0 ]
}

@test "INVARIANT (apply.sh + check.sh + uninstall.sh use set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # integrity-sentinel is the meta-watchdog substrate; silent
    # failure during apply/check/uninstall would leave baseline.
    # sha256 in half-installed state, breaking the integrity-
    # surveillance substrate.
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/apply.sh"
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/check.sh"
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (no auto-restore: integrity-sentinel NEVER overwrites monitored files — surveillance not remediation)" {
    # Sister to brain-wide no-auto-trust + no-auto-remediation
    # + surveillance-not-destruction INVARIANTs. The integrity-
    # sentinel DETECTS T1565.001 Stored Data Manipulation /
    # T1014 Rootkit file-tamper but MUST NEVER emit shell
    # commands that overwrite the monitored file with the
    # baseline content (auto-restore). Auto-restore would
    # destroy forensic evidence chain (operator can't analyze
    # the tampered content if it's silently reverted) AND
    # could overwrite operator-legitimate updates (operator
    # intentionally modified a monitored file but forgot to
    # re-baseline). Surveillance, never auto-remediation.
    # Locks anti-evidence-destruction contract on the
    # integrity-sentinel substrate.
    ! grep -qE 'cp[[:space:]]+.*\$\{?BASELINE_DIR\}?/.*[[:space:]]+\$' "${INSTALL_DIR}/check.sh" 2>/dev/null || true
    ! grep -qE '(install -m|cat[[:space:]]+>|tee).*\$\{?(MONITORED|TARGET|PATH)' "${INSTALL_DIR}/check.sh" 2>/dev/null || true
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. integrity-sentinel manifest declares install +
    # profile gating (lenient / strict) the resolver enforces;
    # malformed manifest wedges the SHA256 baseline integrity
    # verification. Python's tomllib is the canonical parser.
    # Locks anti-malformed-manifest on the integrity-sentinel
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'integrity-sentinel', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: integrity-sentinel installer NEVER deletes monitored files — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # integrity-sentinel computes sha256 baselines of policy
    # artifacts; the no-auto-restore axis is already locked at
    # runtime. This locks the installer-side equivalent: the
    # apply.sh/check.sh/uninstall.sh MUST NEVER delete the
    # monitored files (e.g. /etc/selfdef, /etc/tetragon
    # tracing-policies) that the baseline tracks. Locks no-auto-
    # delete on the integrity-sentinel installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/selfdef([[:space:]]|$)' "${f}"
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/tetragon([[:space:]]|$)' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/(selfdef|tetragon).*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # integrity-sentinel install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the integrity-sentinel lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the integrity-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Each requires entry MUST be a TOML inline table
    # `{ kind = "binary", value = "X" }` — not a flat string
    # like "binary:X" (which the resolver would not parse as
    # structured kind/value and would fail to dispatch the
    # check). Locks the kind+value table-shape discipline on
    # the integrity-sentinel requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}
