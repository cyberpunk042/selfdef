#!/usr/bin/env bats
# L2 functional + capture-regression suite for pam-config-watchdog.
#
# pam-config-watchdog inventories the PAM-stack configuration two ways:
#
#   1. /etc/pam.d/* RULE LINES (the auth stack — normalized to
#      "type control module"). A new "auth sufficient pam_evil.so" rule
#      that accepts a magic password is the classic PAM backdoor.
#   2. The on-disk pam_*.so MODULE set + sha256-12 hashes. A replaced
#      pam_unix.so (patched to log passwords or accept a backdoor) is
#      surfaced via hash drift.
#
# Severity:
#   ok    → no delta (baseline match)
#   warn  → line / module REMOVED (post-hoc reduction)
#   alert → line / module ADDED OR hash CHANGED (an attacker would do
#           one of these; the unidirectional escalation is by design)
#
# What this suite locks:
#   - INVENTORY-CAPTURE regression (existing) — `printf` records must
#     reach `$current` not stdout (the 2026-05-27 root-cause bug)
#   - Both inventory passes (pamline + pammod) emit the right kind tag
#   - Baseline confidentiality (chmod 0600 — PAM module hashes are
#     sensitive: enumerated for forensics)
#   - Delta detection: line ADD → alert / pam_config_changed
#   - Delta detection: line REMOVE → warn / pam_config_removed
#   - Hash drift detection: pam_*.so file content change → alert /
#     pam_config_changed (surfacing as an ADDED entry because the
#     hash-12 string differs)
#   - ENFORCE profile: added-rules return exit-1 (failure surface for
#     systemd unit alerting); removals return exit-0 (post-hoc
#     reduction is informational only)
#   - REPORT profile: any delta returns exit-0 (log-only)
#
# Adds SELFDEF_PAMCFG_PAM_DIR + SELFDEF_PAMCFG_LIB_DIRS env-var
# overrides (added 2026-06-06) for L2 delta-testability. Live defaults
# unchanged.
#
# Run with: bats packaging/test/L2-pam-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd/pam-config-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/pam-baseline.tsv"
    PAM_DIR="${TMP}/pam.d"
    LIB_DIR="${TMP}/lib-security"
    mkdir -p "${PAM_DIR}" "${LIB_DIR}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_PAMCFG_PROFILE="${PROFILE:-report}" \
    SELFDEF_PAMCFG_BASELINE="${BASELINE}" \
    SELFDEF_PAMCFG_PAM_DIR="${PAM_DIR}" \
    SELFDEF_PAMCFG_LIB_DIRS="${LIB_DIR}" \
    bash "${WD}"
}

run_wd_rc() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_PAMCFG_PROFILE="${PROFILE:-report}" \
    SELFDEF_PAMCFG_BASELINE="${BASELINE}" \
    SELFDEF_PAMCFG_PAM_DIR="${PAM_DIR}" \
    SELFDEF_PAMCFG_LIB_DIRS="${LIB_DIR}" \
    bash "${WD}" >/dev/null 2>&1
    echo $?
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Helper: write a synthetic PAM stack + pam_*.so set.
write_pam_inventory() {
    cat > "${PAM_DIR}/common-auth" <<'EOF'
auth required pam_unix.so try_first_pass nullok
auth required pam_deny.so
EOF
    cat > "${PAM_DIR}/common-password" <<'EOF'
password required pam_unix.so obscure sha512
password required pam_pwquality.so retry=3
EOF
    # Synthetic pam_*.so files for hash sampling.
    echo 'fake-pam-unix-binary-v1' > "${LIB_DIR}/pam_unix.so"
    echo 'fake-pam-deny-binary-v1' > "${LIB_DIR}/pam_deny.so"
    echo 'fake-pam-pwquality-binary-v1' > "${LIB_DIR}/pam_pwquality.so"
}

@test "first run captures the PAM inventory into the baseline (non-empty)" {
    write_pam_inventory
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                          # NON-EMPTY = the bug-fix regression lock
    # Pam-line records surface.
    grep -qP '^pamline\t' "${BASELINE}"
    # Pam-module records surface.
    grep -qP '^pammod\t' "${BASELINE}"
}

@test "baseline records BOTH inventory passes (pamline + pammod kind tags)" {
    write_pam_inventory
    run_wd
    # Specific pam-line content surfaces in normalized form.
    grep -qP '^pamline\tcommon-auth\tauth required pam_unix\.so$' "${BASELINE}"
    grep -qP '^pamline\tcommon-password\tpassword required pam_pwquality\.so$' "${BASELINE}"
    # Specific pam-module surfaces with 12-char hash.
    grep -qP '^pammod\t.*pam_unix\.so\t[0-9a-f]{12}$' "${BASELINE}"
    grep -qP '^pammod\t.*pam_deny\.so\t[0-9a-f]{12}$' "${BASELINE}"
}

@test "baseline is chmod 0600 (confidentiality — pam module hash + auth-stack inventory is sensitive)" {
    write_pam_inventory
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "unchanged PAM stack on second run → ok / no_delta" {
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — ADDED pam rule line → alert / pam_config_changed (the classic PAM backdoor case)" {
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker appends a magic-password rule.
    echo 'auth sufficient pam_evil.so backdoor=1' >> "${PAM_DIR}/common-auth"
    # Companion fake pam_evil.so dropped in the lib dir.
    echo 'fake-pam-evil-binary' > "${LIB_DIR}/pam_evil.so"
    run_wd
    cap | grep -q '"event":"pam_config_changed"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'pamline:common-auth:auth sufficient pam_evil.so'
}

@test "DELTA detect — REMOVED pam rule line → warn / pam_config_removed" {
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker removes a hardening rule.
    sed -i '/pam_pwquality\.so/d' "${PAM_DIR}/common-password"
    rm -f "${LIB_DIR}/pam_pwquality.so"
    run_wd
    cap | grep -q '"event":"pam_config_removed"'
    cap | grep -q '"severity":"warn"'
}

@test "DELTA detect — pam_*.so HASH CHANGE → alert / pam_config_changed (attacker-patched module)" {
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker overwrites pam_unix.so with a patched version that
    # logs passwords or accepts a backdoor — the hash changes.
    echo 'attacker-patched-pam-unix-v2' > "${LIB_DIR}/pam_unix.so"
    run_wd
    cap | grep -q '"event":"pam_config_changed"'
    cap | grep -q '"severity":"alert"'
    # The change surfaces as one ADDED entry (the new hash) + one
    # REMOVED entry (the old hash).
    cap | grep -q '"added":1'
    cap | grep -q '"removed":1'
}

@test "ENFORCE profile: ADDED rule → exit-1 (failure surface for systemd unit alerting)" {
    write_pam_inventory
    PROFILE=report run_wd                                  # baseline init
    echo 'auth sufficient pam_evil.so' >> "${PAM_DIR}/common-auth"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "1" ]
}

@test "ENFORCE profile: REMOVED-only delta → exit-0 (post-hoc reduction is informational)" {
    write_pam_inventory
    PROFILE=report run_wd
    sed -i '/pam_deny\.so/d' "${PAM_DIR}/common-auth"
    rm -f "${LIB_DIR}/pam_deny.so"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "REPORT profile: ADDED rule → exit-0 (log-only — journald is the surface)" {
    write_pam_inventory
    PROFILE=report run_wd
    echo 'auth sufficient pam_evil.so' >> "${PAM_DIR}/common-auth"
    rc="$(PROFILE=report run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "INVARIANT (no auto-trust): pam-config-watchdog does NOT refresh the baseline on delta — every subsequent run re-reports the delta until operator updates the baseline" {
    # CONTRAST with group-integrity-watchdog (which DOES auto-refresh
    # to mark legit changes trusted). For PAM, every change is a
    # security event that must remain visible until operator review,
    # so the watchdog must KEEP reporting the delta on every run.
    write_pam_inventory
    PROFILE=report run_wd
    echo 'auth sufficient pam_evil.so' >> "${PAM_DIR}/common-auth"
    PROFILE=report run_wd                                  # first delta run
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=report run_wd                                  # delta STAYS reported
    cap | grep -q '"event":"pam_config_changed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pam_unix.so HASH changes specifically — the pam_unix.so signature on hash drift)" {
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'attacker-pwned-pam-unix' > "${LIB_DIR}/pam_unix.so"
    run_wd
    cap | grep -q 'pam_unix'   # specific module name surfaces in JSON
}

@test "INVARIANT (rule-add to common-password — symmetric to common-auth axis)" {
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'password sufficient pam_attacker.so backdoor=1' >> "${PAM_DIR}/common-password"
    echo 'fake' > "${LIB_DIR}/pam_attacker.so"
    run_wd
    cap | grep -q '"event":"pam_config_changed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (NEW pam.d file (e.g. attacker creates /etc/pam.d/distinctive-backdoor) → alert)" {
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${PAM_DIR}/distinctive-backdoor" <<'EOF'
auth sufficient pam_distinctive_backdoor.so
EOF
    echo 'fake' > "${LIB_DIR}/pam_distinctive_backdoor.so"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'distinctive-backdoor'
}

@test "INVARIANT (compound delta: hash drift + rule add simultaneously → alert with both event signatures)" {
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Hash drift AND rule add together.
    echo 'attacker-pwned-pam-unix' > "${LIB_DIR}/pam_unix.so"
    echo 'auth sufficient pam_evil.so' >> "${PAM_DIR}/common-auth"
    echo 'fake' > "${LIB_DIR}/pam_evil.so"
    run_wd
    cap | grep -q '"event":"pam_config_changed"'
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    write_pam_inventory
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-pam-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (commented PAM line NOT in inventory: # prefix filtered from pamline records)" {
    # /etc/pam.d/* files use # as comment marker. Operator notes
    # about hypothetical rules must NOT surface as real auth-stack
    # entries.
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a commented evil rule.
    echo '# auth sufficient pam_evil.so backdoor=1 — future plan, not yet active' >> "${PAM_DIR}/common-auth"
    run_wd
    # Severity must NOT be alert (no real rule added).
    ! cap | grep -q '"severity":"alert"'
    ! cap | grep -q '"event":"pam_config_changed"'
}

@test "INVARIANT (multi-file scan: changes across multiple pam.d files all surface)" {
    # Attacker plants backdoor rules in multiple files at once.
    # All must surface in single scan.
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant backdoor in two files.
    echo 'auth sufficient pam_evil_a.so' >> "${PAM_DIR}/common-auth"
    echo 'password sufficient pam_evil_b.so' >> "${PAM_DIR}/common-password"
    echo 'fake' > "${LIB_DIR}/pam_evil_a.so"
    echo 'fake' > "${LIB_DIR}/pam_evil_b.so"
    run_wd
    cap | grep -q '"event":"pam_config_changed"'
    cap | grep -q '"severity":"alert"'
    # Both module names should surface for forensics.
    cap | grep -qE 'pam_evil_a|pam_evil_b'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_PAMCFG_PROFILE)" {
    write_pam_inventory
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (added_sample includes pamline:file:rule format for forensics)" {
    # The sample shape: pamline:<file>:<rule>. Operator can grep
    # by file or by rule to investigate the specific change.
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'auth sufficient pam_distinctive_backdoor.so' >> "${PAM_DIR}/common-auth"
    echo 'fake' > "${LIB_DIR}/pam_distinctive_backdoor.so"
    run_wd
    cap | grep -q 'pamline:common-auth'
    cap | grep -q 'pam_distinctive_backdoor'
}

@test "INVARIANT (multi-lib-dir scan: pam_*.so in second lib dir ALSO scanned — both /lib/security + /lib64/security)" {
    # Real distros may have PAM modules in /lib/security OR
    # /lib64/security OR /usr/lib/x86_64-linux-gnu/security
    # (Debian multiarch). All must be enumerated. Sister to other
    # multi-dir scan INVARIANTs across the brain.
    LIB_DIR2="${TMP}/lib64-security"; mkdir -p "${LIB_DIR2}"
    write_pam_inventory
    PATH="${BIN}:${PATH}" \
    SELFDEF_PAMCFG_PROFILE="report" \
    SELFDEF_PAMCFG_BASELINE="${BASELINE}" \
    SELFDEF_PAMCFG_PAM_DIR="${PAM_DIR}" \
    SELFDEF_PAMCFG_LIB_DIRS="${LIB_DIR} ${LIB_DIR2}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant a backdoor pam in the SECOND lib dir.
    echo 'fake-backdoor-multiarch' > "${LIB_DIR2}/pam_multiarch_attacker.so"
    PATH="${BIN}:${PATH}" \
    SELFDEF_PAMCFG_PROFILE="report" \
    SELFDEF_PAMCFG_BASELINE="${BASELINE}" \
    SELFDEF_PAMCFG_PAM_DIR="${PAM_DIR}" \
    SELFDEF_PAMCFG_LIB_DIRS="${LIB_DIR} ${LIB_DIR2}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'pam_multiarch_attacker'
}

@test "INVARIANT (PAM stack-syntax normalization: trailing whitespace/comments stripped before baseline diff — operator-touch tolerance)" {
    # Operator may add/remove trailing whitespace or end-of-line
    # comments without semantic change. The watchdog should
    # normalize these out before diffing.
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add trailing whitespace to existing rule lines.
    sed -i 's|pam_unix.so try_first_pass nullok|pam_unix.so try_first_pass nullok    |' "${PAM_DIR}/common-auth"
    run_wd
    # Severity should be ok or warn (formatting noise), NOT alert.
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sample names the offending pam.d file in JSON — operator triage routing)" {
    # When a rule-add fires, sample MUST surface the offending pam.d
    # file path so operator dashboard routes triage to the right
    # path. Sister contract: polkit-rules/nfs-exports/rhosts/
    # sysusers sample-naming pattern.
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${PAM_DIR}/99-very-distinctive-attacker-pam-stack" <<'EOF'
auth sufficient pam_evil.so
EOF
    echo 'fake' > "${LIB_DIR}/pam_evil.so"
    run_wd
    cap | grep -q 'very-distinctive-attacker'
}

@test "INVARIANT (rogue pam_*.so under /home — user-writable hijack on PAM auth-stack dlopen surface)" {
    # Sister to many other watchdog's /home user-writable
    # INVARIANT across the brain (krb5-plugins, gss-mech,
    # openssl, nm-vpn). /home is the user-writable surface — an
    # attacker with regular user account can drop a malicious
    # PAM module .so into their home and have it dlopen()'d by
    # every PAM-using service (sshd, sudo, su, login, screen
    # lock). Locks axis-symmetry on /home for the PAM module
    # surface (T1556 — Modify Authentication Process via PAM
    # module hijack; pam_*.so runs AS the consuming process
    # which means AS ROOT for system-auth services).
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${PAM_DIR}/99-evil-home-mod" <<'EOF'
auth sufficient /home/user/.evil-pam.so
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (rogue pam_*.so under /var/tmp — writable-root axis-symmetric expansion on PAM auth-stack dlopen surface)" {
    # Sister to /home rogue PAM module INVARIANT already locked.
    # /var/tmp is writable by ALL users (sticky-bit doesn't gate
    # dlopen) AND persists across reboots (unlike /tmp /dev/shm
    # tmpfs on most distros) — attackers prefer it for boot-
    # survival persistence. Locks axis-symmetric writable-root
    # coverage on the T1556 PAM module hijack surface symmetric
    # to /home.
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${PAM_DIR}/99-evil-vartmp-mod" <<'EOF'
auth sufficient /var/tmp/.evil-pam.so
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (rogue pam_*.so under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion on PAM auth-stack dlopen surface)" {
    # Sister to /home + /var/tmp rogue PAM module INVARIANTs
    # already locked. /dev/shm is the canonical tmpfs in-RAM
    # writable-root that survives no on-disk forensic trace —
    # attackers stage payloads there because (a) RAM, (b)
    # preserves across most security tools that don't scan
    # tmpfs. PAM dlopen MUST recognize /dev/shm pam_*.so paths —
    # locks axis-symmetric tmpfs writable-root coverage on
    # T1556 Modify Authentication Process via PAM module hijack
    # — PAM module runs IN-PROCESS AS the consuming process
    # (login/sshd/sudo/su) with full credential access.
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${PAM_DIR}/99-evil-shm-mod" <<'EOF'
auth sufficient /dev/shm/.evil-pam.so
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (relative-with-slash rogue pam_*.so 'sub/dir/p.so' → alert: PWD-at-exec attacker primitive on PAM auth-stack)" {
    # Sister to /home + /var/tmp + /dev/shm + /tmp rogue PAM
    # module writable-root INVARIANTs. Relative-with-slash path
    # is the PWD-at-exec attacker primitive: pam_unix resolves
    # 'sub/dir/p.so' relative to the PWD of the consuming process
    # (login/sshd/sudo/su) — attacker who pivots into a writable
    # CWD can stage their malicious .so for the next login. T1556
    # Modify Authentication Process.
    write_pam_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${PAM_DIR}/99-evil-relative" <<'EOF'
auth sufficient sub/dir/evil-pam.so
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on pam-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The pam-config-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1556 Modify Authentication Process via
    # PAM module hijack alert. Locks parser contract on the
    # /etc/pam.d detection surface.
    write_pam_inventory
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    cat > "${PAM_DIR}/99-evil" <<'EOF'
auth sufficient /tmp/.evil.so
EOF
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # pam-config-watchdog runs ON the timer's scheduled fire —
    # scans /etc/pam.d for rogue pam_*.so paths in writable
    # roots, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the pam-config-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd/selfdef-pam-config.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. pam-config-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # pam-config-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # pam-config-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'pam-config-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: pam-config-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. pam-config-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the pam-config-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (pam-config-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the pam-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pam-config-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # pam-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pam-config-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # pam-config-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pam-config-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the pam-config-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pam-config-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # pam-config-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pam-config-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the pam-config-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pam-config-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the pam-config-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # pam-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the pam-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the pam-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the pam-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the pam-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the pam-config-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the pam-config-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # pam-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # pam-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the pam-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (pam-config-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the pam-config-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}
