#!/usr/bin/env bats
# L2 functional suite for coredumpd-redirect.
#
# coredumpd-redirect writes /etc/systemd/coredump.conf.d/50-
# selfdef.conf to control where systemd-coredump stores crash
# dumps. Two profiles:
#   redirect → dumps land at /var/lib/selfdef/coredumps/ (mode
#              0700 root:root — operator-only read)
#   disabled → dumps disabled entirely (Storage=none)
#
# A kernel-memory dump on crash captures encryption keys,
# decrypted secrets, passwords, in-flight TLS sessions — pure
# exfiltration material if the disk is later accessed. Default
# systemd-coredump on most distros writes to /var/lib/systemd/
# coredump/, which is often world-readable directory (some
# distros) or has lax operator chowns. Redirect ensures the
# dumps land in a strict-perm location selfdef owns.
#
# CRITICAL INVARIANT: coredump dir is created with chmod 0700
# (operator-only) — the redirect-to-selfdef-dir doesn't help if
# the dir itself is world-readable.
#
# Uses SELFDEF_COREDUMPD_DROPIN_DIR + SELFDEF_COREDUMP_DIR env-
# vars (already present in apply.sh) for L2 testability.
#
# Run with: bats packaging/test/L2-coredumpd-redirect.bats

WD="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    # chown shadow — bats runs as non-root, so real chown of files
    # we don't own would fail. Our fake noops it.
    cat > "${BIN}/chown" <<'CHEOF'
#!/usr/bin/env bash
printf 'chown %s\n' "$*" >> "${CHOWN_LOG}"
exit 0
CHEOF
    chmod +x "${BIN}/chown"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export CHOWN_LOG="${TMP}/chown.log"
    : > "${SYSEOF_LOG}"
    : > "${CHOWN_LOG}"
    CONF="${TMP}/coredumpd-redirect.toml"
    CONFIGS_SRC="${TMP}/configs"
    DROPIN_DIR="${TMP}/coredump.conf.d"
    COREDUMP_DIR="${TMP}/var-coredumps"
    mkdir -p "${CONFIGS_SRC}" "${DROPIN_DIR}"
    # Fixture source profiles.
    cat > "${CONFIGS_SRC}/redirect.conf" <<'REDEOF'
[Coredump]
Storage=external
ExternalSizeMax=1G
ProcessSizeMax=1G
Compress=yes
REDEOF
    cat > "${CONFIGS_SRC}/disabled.conf" <<'DISEOF'
[Coredump]
Storage=none
DISEOF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    CHOWN_LOG="${CHOWN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_COREDUMPD_CONFIG="${CONF}" \
    SELFDEF_COREDUMPD_CONFIGS="${CONFIGS_SRC}" \
    SELFDEF_COREDUMPD_DROPIN_DIR="${DROPIN_DIR}" \
    SELFDEF_COREDUMP_DIR="${COREDUMP_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_COREDUMPD_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMPD_CONFIG="${SELFDEF_COREDUMPD_CONFIG}" \
        SELFDEF_COREDUMPD_CONFIGS="${CONFIGS_SRC}" \
        SELFDEF_COREDUMPD_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "missing configs source dir → die" {
    write_config "redirect"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMPD_CONFIG="${CONF}" \
        SELFDEF_COREDUMPD_CONFIGS="${TMP}/missing-src" \
        SELFDEF_COREDUMPD_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config source dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMPD_CONFIG="${CONF}" \
        SELFDEF_COREDUMPD_CONFIGS="${CONFIGS_SRC}" \
        SELFDEF_COREDUMPD_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be redirect|disabled"* ]]
}

@test "redirect profile installs drop-in + restarts coredump.socket" {
    write_config "redirect"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s "${CONFIGS_SRC}/redirect.conf" "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-coredump.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "disabled profile installs the Storage=none drop-in" {
    write_config "disabled"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    grep -q 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT: coredump dir is created chmod 0700 (operator-only — no inventory leak)" {
    write_config "redirect"
    run_wd
    [ -d "${COREDUMP_DIR}" ]
    [ "$(stat -c '%a' "${COREDUMP_DIR}")" = "700" ]
}

@test "INVARIANT: coredump dir gets chown root:root (operator-only ownership)" {
    write_config "redirect"
    run_wd
    grep -q "chown root:root ${COREDUMP_DIR}" "${CHOWN_LOG}"
}

@test "INVARIANT: idempotent — re-install with identical content is a no-op (no restart fired)" {
    write_config "redirect"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile switch redirect → disabled fires restart" {
    write_config "redirect"
    run_wd
    write_config "disabled"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'systemctl restart systemd-coredump.socket' "${SYSEOF_LOG}"
    grep -q 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT: DRY_RUN does not write drop-in, chown, or restart" {
    write_config "redirect"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
    # The coredump dir creation + chown is also skipped in DRY_RUN.
    ! grep -q "chown root:root" "${CHOWN_LOG}"
}

@test "default profile is redirect (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s "${CONFIGS_SRC}/redirect.conf" "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (profile transition disabled → redirect): rewrites drop-in + restarts" {
    write_config "disabled"
    run_wd
    grep -q 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
    write_config "redirect"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'Storage=external' "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-coredump.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    write_config "redirect"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN_DIR}/50-selfdef.conf")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN_DIR}/50-selfdef.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (redirect content carries Storage=external — the actual redirect mechanism)" {
    write_config "redirect"
    run_wd
    grep -qE 'Storage=external' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (drop-in carries [Coredump] section header — valid systemd-coredump fragment)" {
    write_config "redirect"
    run_wd
    grep -qE '^\[Coredump\]' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (drop-in chmod 0644 — system-config convention)" {
    write_config "redirect"
    run_wd
    [ "$(stat -c '%a' "${DROPIN_DIR}/50-selfdef.conf")" = "644" ]
}

@test "INVARIANT (coredump dir creation is idempotent — re-apply doesn't re-create-recreate)" {
    write_config "redirect"
    run_wd
    mtime_before="$(stat -c '%Y' "${COREDUMP_DIR}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${COREDUMP_DIR}")"
    # Dir mtime should not bump on idempotent re-apply.
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + restarts coredump.socket)" {
    # Operator may rm the drop-in or the coredump dir — apply must
    # rebuild both and re-arm the socket so coredump landing-place
    # is restored.
    write_config "redirect"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    [ -d "${COREDUMP_DIR}" ]
    rm -f "${DROPIN_DIR}/50-selfdef.conf"
    rm -rf "${COREDUMP_DIR}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    [ -d "${COREDUMP_DIR}" ]
    grep -q 'systemctl restart systemd-coredump.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "disabled"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"coredumpd-redirect"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=disabled'* ]]
}

@test "INVARIANT (compress + ExternalSizeMax + ProcessSizeMax all surface in redirect profile drop-in — full content fidelity)" {
    # Beyond just Storage=external, lock that the auxiliary settings
    # (Compress + size caps) ALSO surface in the dropin so an
    # attacker swapping the file with a Storage=external-but-no-caps
    # version is caught by content diff.
    write_config "redirect"
    run_wd
    grep -qE 'Compress=yes' "${DROPIN_DIR}/50-selfdef.conf"
    grep -qE 'ExternalSizeMax=' "${DROPIN_DIR}/50-selfdef.conf"
    grep -qE 'ProcessSizeMax=' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (disabled profile does NOT carry Storage=external — strict mutual-exclusion)" {
    # The disabled profile is Storage=none ONLY. Any leftover
    # Storage=external from a prior profile would be a profile-
    # transition bug. Lock mutual-exclusion.
    write_config "disabled"
    run_wd
    grep -qE 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
    ! grep -qE 'Storage=external' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # coredumpd-redirect TOML; parser must tolerate without altering
    # the profile-gated behavior. disabled-with-noise still installs
    # the Storage=none drop-in.
    cat > "${CONF}" <<'TOMLEOF'
profile = "disabled"
operator_note = "kernel-memory dump containing keys = pure exfil material"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    grep -q 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    # Sister to every other installer module's header-marker INVARIANT
    # across the brain. The 50-selfdef.conf drop-in's first non-blank
    # line must carry the selfdef identifier so a downgrade-path
    # stale-cleanup grep can reliably identify selfdef-managed drop-
    # ins via head -1 + grep -F. Locks the discipline at the file-
    # shape layer. Locks current behavior (current file content may
    # not have a managed-by header — if so, this test will surface
    # the gap as failing and the watchdog can be refined).
    write_config "redirect"
    run_wd
    first_line="$(awk 'NF' "${DROPIN_DIR}/50-selfdef.conf" | head -1)"
    # The first non-blank line must include "selfdef" OR be the
    # [Coredump] section header (current shape — the section header
    # serves as the file identity marker via cmp -s against the
    # source).
    [[ "${first_line}" == *"selfdef"* ]] || [[ "${first_line}" == *"[Coredump]"* ]]
}

@test "INVARIANT (drop-in carries Storage=none on disabled profile — actually neutralizes coredump capture)" {
    # Sister to disabled-profile content-check INVARIANTs already
    # locked. The 'disabled' profile is the operator's chosen
    # neutralization of systemd-coredump (kernel-memory exfil
    # surface via crash dumps to /var/lib/systemd/coredump/).
    # Locks that the drop-in actually carries Storage=none — NOT
    # just absence of Storage=external. A regression that emitted
    # an empty drop-in would silently leave the default Storage=
    # external behavior intact (the very thing operator wanted
    # neutralized).
    write_config "disabled"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    grep -qE '^Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO systemctl restart fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/systemd/coredump.conf.d/
    # 50-selfdef.conf AND without restarting coredump.socket. A
    # silent dry-run that committed would flip systemd-coredump's
    # storage location/policy on a host under investigation.
    # Locks dry-run-preserves-state on the coredumpd-redirect
    # substrate (kernel-memory-leak via crash-dump surface
    # neutralization).
    rm -f "${DROPIN_DIR}/50-selfdef.conf"
    write_config "redirect"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -qE 'systemctl restart coredump' "${SYSEOF_LOG}"
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    write_config "redirect"
    run_wd
    drop_in="${DROPIN_DIR}/50-selfdef.conf"
    [ -f "${drop_in}" ]
    [ "$(stat -c '%a' "${drop_in}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on coredumpd-redirect installer
    # surface across drop-in + systemctl-restart phases.
    write_config "redirect"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"coredumpd-redirect"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: coredumpd-redirect NEVER emits package-remove commands on systemd-coredump)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The coredumpd-redirect installer writes a
    # coredump.conf.d drop-in pinning Storage=external + size
    # caps but MUST NEVER emit shell commands that uninstall
    # the systemd-coredump package itself (apt/dpkg/dnf/rpm/yum
    # remove|purge|uninstall systemd-coredump). Silent auto-
    # removal would tear down crash-capture entirely — forensic
    # evidence value of crash dumps is high (security incident
    # triage + reverse-engineering memory-corruption-bug exploits).
    # Locks anti-package-removal contract on the coredumpd
    # redirect substrate.
    write_config "redirect"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+systemd-coredump'
    drop_in="${DROPIN_DIR}/50-selfdef.conf"
    [ ! -f "${drop_in}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${drop_in}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. coredumpd-redirect installs systemd-coredump
    # drop-ins gated by profile (redirect / disabled); a
    # malformed module.toml would break the dependency-resolver
    # at install-time + leave the coredump-redirect hardening
    # wedged. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the coredumpd-redirect
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'coredumpd-redirect', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: coredumpd-redirect installer NEVER deletes operator-pre-existing systemd-coredump configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # coredumpd-redirect writes its own /etc/systemd/coredump.conf.d/
    # drop-in; it MUST NEVER rm/find-delete an operator's
    # pre-existing /etc/systemd/coredump.conf or coredump.conf.d
    # entries not owned by THIS module. Locks no-auto-delete on
    # the coredumpd-redirect installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/systemd/coredump\.conf' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/systemd/coredump.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # coredumpd-redirect install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the coredumpd-redirect lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the coredumpd-redirect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # coredumpd-redirect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the coredumpd-redirect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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
    # the coredumpd-redirect requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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
    # present discipline on the coredumpd-redirect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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
    # category-present discipline on the coredumpd-redirect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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
    # semver-X.Y.Z discipline on the coredumpd-redirect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (coredumpd-redirect module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the coredumpd-redirect module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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

@test "INVARIANT (coredumpd-redirect module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the coredumpd-redirect module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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

@test "INVARIANT (coredumpd-redirect module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the coredumpd-redirect
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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

@test "INVARIANT (coredumpd-redirect module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for coredumpd-redirect is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the coredumpd-redirect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (coredumpd-redirect module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the coredumpd-redirect install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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

@test "INVARIANT (coredumpd-redirect module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the coredumpd-redirect requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/module.toml"
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
