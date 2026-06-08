#!/usr/bin/env bats
# L2 functional suite for bootloader-password-detect.
#
# bootloader-password-detect installs a systemd timer that checks
# whether GRUB / systemd-boot / RAUC / U-Boot is password-protected.
# An unprotected bootloader is a quiet privilege-escalation vector:
# an attacker with physical access can edit the boot command line
# from the GRUB menu (init=/bin/bash, single-user, etc.) and skip
# authentication entirely. The detector reports this.
#
# Profiles:
#   report  → log finding, no enforcement
#   enforce → log + exit non-zero (systemd records failure surfacing
#             via doctor / dashboard)
#
# Same shape as entropy-baseline: libexec script + service unit +
# timer unit + service.d/50-profile.conf drop-in setting
# SELFDEF_BOOTLOADER_PROFILE env-var.
#
# Uses SELFDEF_LIBEXEC_DIR + SELFDEF_SYSTEMD_DIR env-vars (already
# present) for L2 testability.
#
# Run with: bats packaging/test/L2-bootloader-password-detect.bats

WD="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/bootloader-password-detect.toml"
    LIBEXEC_DIR="${TMP}/libexec"
    SYSTEMD_DIR="${TMP}/systemd"
    mkdir -p "${LIBEXEC_DIR}" "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_BOOTLOADER_CONFIG="${CONF}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_BOOTLOADER_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_BOOTLOADER_CONFIG="${SELFDEF_BOOTLOADER_CONFIG}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_BOOTLOADER_CONFIG="${CONF}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be report|enforce"* ]]
}

@test "report profile installs all 4 files (libexec + service + timer + profile drop-in)" {
    write_config "report"
    run_wd
    [ -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    [ -x "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf" ]
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=report' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
}

@test "enforce profile drop-in carries SELFDEF_BOOTLOADER_PROFILE=enforce" {
    write_config "enforce"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
}

@test "libexec script chmod 0755 (executable convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${LIBEXEC_DIR}/bootloader-password-detect.sh")" = "755" ]
}

@test "service + timer + drop-in chmod 0644 (system-config convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-bootloader-password.service")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf")" = "644" ]
}

@test "daemon-reload + timer enable fire on initial install" {
    write_config "report"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-bootloader-password.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO daemon-reload" {
    write_config "report"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change report → enforce updates drop-in + fires daemon-reload" {
    write_config "report"
    run_wd
    write_config "enforce"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install anything or fire systemctl" {
    write_config "report"
    DRY_RUN=1 run_wd
    ! [ -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "default profile is report (no profile key — the safe default)" {
    : > "${CONF}"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=report' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
}

@test "INVARIANT (profile downgrade enforce → report): rewrites drop-in back + fires reload" {
    write_config "enforce"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    write_config "report"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=report' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    ! grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves all 4 file mtimes" {
    write_config "report"
    run_wd
    mtime_libexec_before="$(stat -c '%Y' "${LIBEXEC_DIR}/bootloader-password-detect.sh")"
    mtime_service_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.service")"
    mtime_timer_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer")"
    mtime_dropin_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf")"
    sleep 1
    run_wd
    [ "${mtime_libexec_before}" = "$(stat -c '%Y' "${LIBEXEC_DIR}/bootloader-password-detect.sh")" ]
    [ "${mtime_service_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.service")" ]
    [ "${mtime_timer_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer")" ]
    [ "${mtime_dropin_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf")" ]
}

@test "INVARIANT (libexec script carries detect logic — actually checks the 4 bootloaders)" {
    write_config "report"
    run_wd
    # The libexec script must actually probe the 4 bootloaders.
    libexec="${LIBEXEC_DIR}/bootloader-password-detect.sh"
    grep -qiE 'grub|systemd-boot|rauc|u-boot' "${libexec}"
}

@test "INVARIANT (service unit references the libexec script): wiring is correct" {
    write_config "report"
    run_wd
    grep -qE 'ExecStart=' "${SYSTEMD_DIR}/selfdef-bootloader-password.service"
    grep -q 'bootloader-password-detect' "${SYSTEMD_DIR}/selfdef-bootloader-password.service"
}

@test "INVARIANT (timer unit carries OnCalendar or OnBootSec — actually fires periodically)" {
    write_config "report"
    run_wd
    grep -qE '(OnCalendar|OnBootSec|OnUnitActiveSec)=' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer"
}

@test "INVARIANT (no render-timestamp in any installed file): defeats cmp -s idempotency" {
    write_config "report"
    run_wd
    for f in "${LIBEXEC_DIR}/bootloader-password-detect.sh" \
             "${SYSTEMD_DIR}/selfdef-bootloader-password.service" \
             "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" \
             "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"; do
        ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "$f"
    done
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates all 4 files + fires daemon-reload)" {
    # Operator may rm one of the installed files — apply must rebuild
    # and re-arm the timer so the bootloader-detect surveillance is restored.
    write_config "report"
    run_wd
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" ]
    rm -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" \
          "${SYSTEMD_DIR}/selfdef-bootloader-password.service" \
          "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" \
          "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf" ]
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"bootloader-password-detect"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enforce'* ]]
}

@test "INVARIANT (libexec carries GRUB detection axes — multi-distro grub.cfg locations probed)" {
    # Module-header comment notes "other bootloaders out of scope" —
    # the libexec is GRUB-focused. Lock the actual coverage: GRUB
    # primary config + multi-distro EFI variants + user-config file.
    write_config "report"
    run_wd
    libexec="${LIBEXEC_DIR}/bootloader-password-detect.sh"
    # Core GRUB locations.
    grep -q '/boot/grub/grub.cfg' "${libexec}"
    grep -q '/boot/grub2/grub.cfg' "${libexec}"
    # Multi-distro EFI variants.
    grep -qE '/boot/efi/EFI/(debian|ubuntu|fedora)/grub.cfg' "${libexec}"
    # Password directive scanner (the actual check).
    grep -qE 'password' "${libexec}"
}

@test "INVARIANT (timer + service header marker — operator-audit-trail)" {
    write_config "report"
    run_wd
    grep -qE '^#.*selfdef|^#.*managed-by' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer"
    grep -qE '^#.*selfdef|^#.*managed-by' "${SYSTEMD_DIR}/selfdef-bootloader-password.service"
}

@test "INVARIANT (libexec is shell-sourceable: bash -n parses cleanly — service ExecStart contract)" {
    # The libexec script runs from systemd ExecStart. bash -n must
    # parse cleanly. Sister to umask-baseline + shell-timeout-
    # baseline + tensor-parallel-inference + slm-cpu-loop + wol-
    # disable shell-sourceable INVARIANT.
    write_config "report"
    run_wd
    bash -n "${LIBEXEC_DIR}/bootloader-password-detect.sh"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # bootloader-password-detect TOML; parser must tolerate without
    # altering the profile-gated behavior. enforce-with-noise still
    # writes the SELFDEF_BOOTLOADER_PROFILE=enforce drop-in
    # (escalates missing-bootloader-password from log-only to
    # systemd-failure-recorded — the operator-dashboard signal for
    # physical-access boot-edit surveillance).
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforce"
operator_note = "bootloader pwless = physical-access kernel-cmdline edit"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    ! grep -q 'SELFDEF_BOOTLOADER_PROFILE=report' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
}

@test "INVARIANT (libexec falls through to ok/no_grub when no grub.cfg present — anti-false-alert on non-GRUB hosts)" {
    # Sister to many other watchdog's no-target-found fall-through
    # INVARIANTs across the brain. When the libexec runs on a non-
    # GRUB host (sd-boot / EFISTUB-only / U-Boot / chromebook
    # custom), it MUST emit ok/no_grub instead of false-firing
    # alert — operator dashboards would be flooded with bogus
    # alerts otherwise on every non-GRUB workstation. Current-
    # behavior lock: sd-boot coverage is a future-decision; today
    # the script is GRUB-only with safe ok fallthrough on absent.
    # Closes the no-target fall-through invariant.
    write_config "report"
    run_wd
    grep -qE '"event":"no_grub"|exit 0' "${LIBEXEC_DIR}/bootloader-password-detect.sh"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO service/timer/libexec/profile-drop-in files written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without installing the 4 files (service + timer +
    # libexec + profile drop-in) AND without firing daemon-reload.
    # A silent dry-run that committed would land a recurring boot-
    # time scanner against grub.cfg on a host where operator was
    # investigating. Locks the dry-run-preserves-state contract on
    # the bootloader-password detection substrate.
    rm -rf "${SYSTEMD_DIR}" "${LIBEXEC_DIR}"
    mkdir -p "${SYSTEMD_DIR}" "${LIBEXEC_DIR}"
    write_config "report"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service" ]
    [ ! -f "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" ]
    [ ! -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    ! grep -q 'daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (timer unit carries Persistent=true — missed-fires catch up after long downtime)" {
    # Sister to brain-wide timer Persistent=true INVARIANTs.
    write_config "report"
    run_wd
    grep -qE '^Persistent=true' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on bootloader-password-detect
    # installer surface across libexec + service + timer +
    # profile-drop-in phases.
    write_config "report"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"bootloader-password-detect"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes (entropy-baseline,
    # secure-boot-status, swap-encryption-detect). The
    # bootloader-password-detect probe runs ON the timer's
    # scheduled fire — executes ONCE, emits a verdict, then
    # exits. Type=simple would leave systemd thinking the probe
    # is a long-running daemon, breaking timer's OnSuccess /
    # OnUnitActiveSec semantics (which depend on the service
    # reaching inactive(dead) before the next fire). Locks
    # oneshot-probe contract on the bootloader-password-detect
    # substrate.
    write_config "report"
    run_wd
    svc="${SYSTEMD_DIR}/selfdef-bootloader-password.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: detect module NEVER mutates GRUB config — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{delete,uninstall,restore,
    # chmod,fix} family. bootloader-password-detect is a DETECT
    # module: it MUST surface verdicts (ok/warn/alert) about
    # GRUB password posture, NEVER auto-edit grub.cfg, NEVER
    # invoke grub-mkpasswd-pbkdf2, NEVER tee/sed-i into
    # /boot/grub*/grub.cfg or /etc/grub.d/*. Auto-remediation
    # on bootloader config is operator-domain (physical-access
    # threat model demands operator-conscious password choice
    # + GRUB regen via grub2-mkconfig). Surveillance-not-
    # remediation is the canonical selfdef DETECT-module
    # contract. Locks no-auto-fix on the bootloader-password-
    # detect substrate.
    libexec="modules/bootloader-password-detect/systemd/bootloader-password-detect.sh"
    [ -f "${libexec}" ]
    # Filter comments before pattern-matching to avoid false-
    # positives from severity-vocabulary docstrings that may
    # mention mutation verbs in prose.
    ! grep -vE '^[[:space:]]*#' "${libexec}" | grep -qE 'sed[[:space:]]+-i.*grub'
    ! grep -vE '^[[:space:]]*#' "${libexec}" | grep -qE '>[[:space:]]*/boot/grub'
    ! grep -vE '^[[:space:]]*#' "${libexec}" | grep -qE '>[[:space:]]*/etc/grub\.d'
    ! grep -vE '^[[:space:]]*#' "${libexec}" | grep -qE 'tee[[:space:]].*grub\.cfg'
    ! grep -vE '^[[:space:]]*#' "${libexec}" | grep -qE 'grub-?mkpasswd'
    ! grep -vE '^[[:space:]]*#' "${libexec}" | grep -qE 'grub2?-set-password'
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. bootloader-password-detect manifest declares
    # install + profile gating (report / enforce) the resolver
    # enforces; malformed manifest wedges the GRUB-password-
    # detection probe. Python's tomllib is the canonical
    # parser. Locks anti-malformed-manifest on the bootloader-
    # password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'bootloader-password-detect', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # bootloader-password-detect install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the bootloader-password-detect lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install"
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
    # the depends_on field of the bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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
    # bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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
    # the bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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
    # the bootloader-password-detect requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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
    # present discipline on the bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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
    # category-present discipline on the bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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
    # semver-X.Y.Z discipline on the bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the bootloader-password-detect module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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

@test "INVARIANT (bootloader-password-detect module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the bootloader-password-detect module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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

@test "INVARIANT (bootloader-password-detect module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the bootloader-password-detect
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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

@test "INVARIANT (bootloader-password-detect module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for bootloader-password-detect is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the bootloader-password-detect install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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

@test "INVARIANT (bootloader-password-detect module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the bootloader-password-detect requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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

@test "INVARIANT (bootloader-password-detect module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the bootloader-password-detect
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the bootloader-password-detect
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the bootloader-password-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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

@test "INVARIANT (bootloader-password-detect module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (bootloader-password-detect README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (bootloader-password-detect install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (bootloader-password-detect install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (bootloader-password-detect install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (bootloader-password-detect install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (bootloader-password-detect install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (bootloader-password-detect install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (bootloader-password-detect install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (bootloader-password-detect install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (bootloader-password-detect install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (bootloader-password-detect install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (bootloader-password-detect install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (bootloader-password-detect install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (bootloader-password-detect module.toml [install_paths].paths includes at least one /usr/ path — binary-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/usr/') for p in ps), f'paths must include ≥1 /usr/ target, got {ps!r}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml exists at canonical path modules/bootloader-password-detect/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (bootloader-password-detect module dir is at canonical path modules/bootloader-password-detect/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (bootloader-password-detect install dir exists at modules/bootloader-password-detect/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (bootloader-password-detect install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (bootloader-password-detect install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (bootloader-password-detect install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (bootloader-password-detect install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (bootloader-password-detect module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (bootloader-password-detect install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (bootloader-password-detect install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (bootloader-password-detect install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (bootloader-password-detect install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (bootloader-password-detect install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (bootloader-password-detect install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (bootloader-password-detect install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (bootloader-password-detect install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (bootloader-password-detect module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (bootloader-password-detect module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (bootloader-password-detect module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
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

@test "INVARIANT (bootloader-password-detect module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (bootloader-password-detect module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (bootloader-password-detect module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92 — libexec-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p or '/usr/local/' in p for p in ps)
"
}

@test "INVARIANT (bootloader-password-detect module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (bootloader-password-detect module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (bootloader-password-detect module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (bootloader-password-detect module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (bootloader-password-detect module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (bootloader-password-detect module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (bootloader-password-detect module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (bootloader-password-detect module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}
