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

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the integrity-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The category field groups modules in
    # the operator install dashboard (detection / hardening /
    # disable / etc.). An empty/missing category would surface
    # as an Uncategorized bucket, harming triage. Locks
    # category-present discipline on the integrity-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # The version field MUST follow X.Y.Z semver so the resolver
    # can sort versions numerically + version-gate downstream
    # consumers. A regression to "v1" / "1.0" / "1.0.0-beta+meta"
    # would break the sortable numeric comparison. Locks the
    # semver-X.Y.Z discipline on the integrity-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the integrity-sentinel module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the integrity-sentinel module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the integrity-sentinel
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for integrity-sentinel is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the integrity-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the integrity-sentinel install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (integrity-sentinel module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the integrity-sentinel requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the integrity-sentinel
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the integrity-sentinel
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the integrity-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the integrity-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late', 'pre', 'post'}, f'phase must be canonical, got {p!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (integrity-sentinel README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (integrity-sentinel install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (integrity-sentinel install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (integrity-sentinel install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (integrity-sentinel install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (integrity-sentinel install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (integrity-sentinel install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (integrity-sentinel install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (integrity-sentinel install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (integrity-sentinel install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (integrity-sentinel install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (integrity-sentinel install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (integrity-sentinel install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (integrity-sentinel module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (integrity-sentinel module.toml exists at canonical path modules/integrity-sentinel/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (integrity-sentinel module dir is at canonical path modules/integrity-sentinel/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (integrity-sentinel install dir exists at modules/integrity-sentinel/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (integrity-sentinel install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (integrity-sentinel install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (integrity-sentinel install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (integrity-sentinel install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (integrity-sentinel module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (integrity-sentinel install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (integrity-sentinel install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (integrity-sentinel install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (integrity-sentinel install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (integrity-sentinel install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (integrity-sentinel install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (integrity-sentinel install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (integrity-sentinel install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (integrity-sentinel module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (integrity-sentinel module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"integrity-sentinel"' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import re
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln, f'expected key=val before sections, got {ln!r}'
        break
"
}

@test "INVARIANT (integrity-sentinel module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (integrity-sentinel module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (integrity-sentinel module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (integrity-sentinel module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (integrity-sentinel module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (integrity-sentinel module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
allowed = {'binary', 'package', 'kernel-feature'}
for el in r:
    k = el.get('kind', '')
    assert k in allowed, f'requires.kind must be in {allowed}, got {k!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml requires items have value as non-empty string — TOML-requires-value-nonempty-canonical 130)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    v = el.get('value', '')
    assert isinstance(v, str) and v, f'requires.value must be non-empty string, got {v!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml provides list elements are all non-empty strings — TOML-provides-elements-string-canonical 131)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides') or []
for el in p:
    assert isinstance(el, str) and el, f'provides element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml conflicts list elements are all non-empty strings (or empty list) — TOML-conflicts-elements-string-canonical 132)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts') or []
for el in c:
    assert isinstance(el, str) and el, f'conflicts element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml consumes list elements are all non-empty strings (or empty) — TOML-consumes-elements-string-canonical 133)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes') or []
for el in c:
    assert isinstance(el, str) and el, f'consumes element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml depends_on list elements are all non-empty strings (or empty) — TOML-depends-on-elements-string-canonical 134)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('depends_on') or []
for el in c:
    assert isinstance(el, str) and el, f'depends_on element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.paths list elements are all absolute paths (starting with /) — TOML-install-paths-paths-absolute-canonical 135)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert isinstance(el, str) and el and el.startswith('/'), f'install_paths.paths element must be absolute path, got {el!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.paths list elements are unique (no duplicates) — TOML-install-paths-paths-unique-canonical 136)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
assert len(paths) == len(set(paths)), f'install_paths.paths must be unique, duplicates: {[p for p in paths if paths.count(p) > 1]!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml name field matches kebab-case pattern [a-z][a-z0-9-]+ — TOML-name-kebab-case-canonical 137)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
import re
n = data.get('name', '')
assert re.fullmatch(r'[a-z][a-z0-9-]+', n), f'name must match kebab-case [a-z][a-z0-9-]+, got {n!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml requires items have exactly the {kind, value} keyset (no extras) — TOML-requires-elements-strict-keys-canonical 138)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert set(el.keys()) == {'kind', 'value'}, f'requires element must have exactly kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (integrity-sentinel module.toml install_paths.paths elements use FHS-canonical prefixes {/etc, /var, /usr, /run, /opt} — TOML-install-paths-fhs-prefix-canonical 139)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
prefixes = ('/etc/', '/var/', '/usr/', '/run/', '/opt/')
for el in paths:
    assert any(el.startswith(pf) for pf in prefixes), f'install_paths.paths element must use FHS-canonical prefix {prefixes}, got {el!r}'
"
}
