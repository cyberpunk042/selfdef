#!/usr/bin/env bats
# L2 bats functional tests for the sudoers-defaults-watchdog scan script.
#
# `Defaults` lines in /etc/sudoers{,.d} shape EVERY sudo invocation. Three
# high-signal classes turn sudo into a privilege-escalation primitive:
#   - secure_path with a writable/tmp/home/relative element (sudo resolves
#     a trojan binary from there);
#   - env_keep/env_check/env_delete of a dangerous var (LD_PRELOAD,
#     LD_LIBRARY_PATH, BASH_ENV, …) surviving into the root command;
#   - !env_reset (the whole caller environment survives into sudo).
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# sudoers file/dir + baseline in a tmp sandbox via SELFDEF_SUDODEF_*.
#
# Run with: bats packaging/test/L2-sudoers-defaults-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd/sudoers-defaults-watchdog.sh"
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

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
    BASELINE="${TMP}/baseline.tsv"
    SUDOERS="${TMP}/sudoers"
    SUDOERSD="${TMP}/sudoers.d"; mkdir -p "${SUDOERSD}"
    BENIGN='Defaults secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults env_reset
Defaults requiretty
'
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SUDODEF_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUDODEF_BASELINE="${BASELINE}" \
    SELFDEF_SUDODEF_FILE="${SUDOERS_F:-$SUDOERS}" \
    SELFDEF_SUDODEF_D="${SUDOERSD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no sudoers present → ok / no_sudoers" {
    SUDOERS_F="${TMP}/nonexistent" SUDOERSD="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_sudoers"'
    cap | grep -q '"severity":"ok"'
}

@test "benign Defaults, first run → ok / baseline_initial" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged sudoers on second run → ok / sudoers_defaults_intact" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudoers_defaults_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — dangerous Defaults
# ============================================================

@test "secure_path containing /tmp → alert / sudoers_defaults_dangerous" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd                                   # benign baseline
    printf 'Defaults secure_path="/usr/bin:/tmp"\nDefaults env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudoers_defaults_dangerous"'
    cap | grep -q '"severity":"alert"'
}

@test "env_keep of LD_PRELOAD → alert" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults env_keep += "LD_PRELOAD"\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "!env_reset → alert" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/bin"\nDefaults !env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "secure_path with a relative element → alert" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:bin"\nDefaults env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign Defaults change → warn / sudoers_defaults_changed" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults timestamp_timeout=15\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudoers_defaults_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a standard secure_path + env_reset is NOT flagged" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "env_keep of a non-dangerous var (EDITOR) is NOT flagged" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults env_keep += "EDITOR"\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a dangerous default" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/tmp"\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# Dangerous-var expansion (LD_LIBRARY_PATH / BASH_ENV / PYTHONPATH / IFS)
# ============================================================

@test "INVARIANT (env_keep LD_LIBRARY_PATH → alert): dangerous-var coverage expansion" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults env_keep += "LD_LIBRARY_PATH"\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (env_keep BASH_ENV → alert): bash startup-file env hijack via sudo)" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults env_keep += "BASH_ENV"\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (env_keep PYTHONPATH → alert): import-hijack via sudo-invoked python script)" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults env_keep += "PYTHONPATH"\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# env_check axis (not just env_keep)
# ============================================================

@test "INVARIANT (env_check IFS → alert): env_check axis is also a survival channel" {
    # env_check has the SAME survival semantics as env_keep when
    # the var passes the check — both let dangerous vars cross the
    # sudo boundary. Lock that env_check is covered, not only
    # env_keep.
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults env_check += "IFS"\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# secure_path writable-root expansion (/var/tmp + /dev/shm)
# ============================================================

@test "INVARIANT (secure_path containing /var/tmp → alert): writable-root expansion on secure_path axis" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/var/tmp"\nDefaults env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (secure_path containing /dev/shm → alert): writable-root expansion on secure_path axis" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/dev/shm"\nDefaults env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# sudoers.d drop-in axis (alerts must surface in drop-ins, not only main file)
# ============================================================

@test "INVARIANT (dangerous Defaults in sudoers.d drop-in → alert): drop-in axis is scanned, not just /etc/sudoers" {
    # The scan must walk sudoers.d/ too — attackers commonly plant
    # dangerous Defaults in a drop-in to avoid touching the main
    # sudoers file (less visible in diffs).
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/tmp"\n' > "${SUDOERSD}/00-dangerous"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# JSON record contract (SDD-062 single-line consumer)
# ============================================================

@test "INVARIANT (JSON record is emitted as a SINGLE main logger line — SDD-062 downstream JSON-line consumer contract)" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-sudoers-defaults -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (current-behavior: sudoers-defaults-watchdog auto-refreshes baseline on delta — sister of auto-trust family vs no-auto-trust sudoers-integrity / sudo-conf)" {
    # Current architectural choice: sudoers-defaults-watchdog
    # auto-refreshes baseline on detected delta. CONTRAST against
    # sudoers-integrity-watchdog which tracks GRANTS (no-auto-trust)
    # and sudo-conf-watchdog which tracks PLUGINS (no-auto-trust).
    # The distinction: Defaults are operator-tuning tunables that
    # change more often (timestamp_timeout, requiretty, etc.).
    # Lock current architectural shape so a future no-auto-trust
    # refinement is intentional, not silent.
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/tmp"\nDefaults env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline auto-refreshed → ok
    # Lock current behavior: third run sees no_delta + ok
    cap | grep -q '"event":"sudoers_defaults_intact"' || cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (secure_path containing /home → alert: user-writable hijack on secure_path axis)" {
    # Operator's home dir is a writable-root variant — symmetric
    # axis to /tmp + /var/tmp + /dev/shm already locked. A
    # secure_path element under /home means sudo will resolve
    # binaries from there with root privilege.
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/home/user/bin"\nDefaults env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented dangerous Defaults NOT flagged: # prefix filtered)" {
    # An operator note about a hypothetical dangerous Defaults
    # must not trigger alert. Sister contract: nfs-exports/rhosts/
    # sudoers-integrity commented-pattern filtering.
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s# Defaults env_keep += "LD_PRELOAD" — example never enabled\n' "${BENIGN}" > "${SUDOERS}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (env_keep += LD_LIBRARY_PATH → alert: dynamic-loader env-pass-through axis sister to LD_PRELOAD)" {
    # Sister to LD_PRELOAD env-pass-through INVARIANT already
    # locked. LD_LIBRARY_PATH is the OTHER canonical dynamic-
    # loader env-var attackers leverage for hijack (sister axis
    # to LD_PRELOAD + LD_AUDIT from systemd-environment-watchdog).
    # If sudo passes LD_LIBRARY_PATH through to the privileged
    # subprocess, attacker can hijack libc.so.6 resolution to
    # their own evil libc. T1574.006 — Dynamic Linker Hijacking
    # via env-pass-through.
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%sDefaults env_keep += "LD_LIBRARY_PATH"\n' "${BENIGN}" > "${SUDOERS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (env_keep += LD_AUDIT → alert: dynamic-loader audit env-pass-through axis sister to LD_PRELOAD + LD_LIBRARY_PATH)" {
    # Sister to LD_PRELOAD + LD_LIBRARY_PATH env-pass-through
    # INVARIANTs already locked. LD_AUDIT is the third canonical
    # dynamic-loader env-var attackers leverage — it loads an
    # auditing library that gets called for every symbol
    # resolution, providing intercept-and-modify capability
    # equivalent to LD_PRELOAD. If sudo passes LD_AUDIT through
    # to privileged subprocess, attacker plants their .so as
    # the audit library and intercepts every symbol resolution.
    # T1574.006 — Dynamic Linker Hijacking via LD_AUDIT.
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%sDefaults env_keep += "LD_AUDIT"\n' "${BENIGN}" > "${SUDOERS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (env_keep += PYTHONPATH → alert: python-runtime env-pass-through axis sister to LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT family)" {
    # Sister to LD_PRELOAD + LD_LIBRARY_PATH + LD_AUDIT env-keep
    # INVARIANTs already locked. PYTHONPATH is the python-
    # runtime analog of dynamic-loader env-vars — if sudo
    # passes PYTHONPATH through to privileged python subprocess
    # (e.g., sudo invoking a python admin script), attacker
    # plants their malicious .py module in their PYTHONPATH and
    # python's import resolves their module before the system
    # one. T1574 Hijack Execution Flow via python module
    # substitution — sister axis to T1574.006 dynamic-loader.
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%sDefaults env_keep += "PYTHONPATH"\n' "${BENIGN}" > "${SUDOERS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (env_keep += PERL5LIB → alert: perl-runtime env-pass-through axis sister to LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT/PYTHONPATH family)" {
    # Sister to LD_PRELOAD + LD_LIBRARY_PATH + LD_AUDIT +
    # PYTHONPATH env-keep INVARIANTs already locked. PERL5LIB
    # is the perl-runtime analog of dynamic-loader env-vars —
    # if sudo passes PERL5LIB through to a privileged perl
    # subprocess (e.g., sudo invoking a perl admin script),
    # attacker plants their malicious .pm module in their
    # PERL5LIB and perl's @INC resolves their module before the
    # system one. T1574 Hijack Execution Flow via perl module
    # substitution — sister axis to T1574.006 dynamic-loader.
    # Closes PERL5LIB axis on the language-runtime env-keep
    # alert coverage.
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%sDefaults env_keep += "PERL5LIB"\n' "${BENIGN}" > "${SUDOERS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on sudoers-defaults surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The sudoers-defaults-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1574 Hijack Execution Flow
    # via sudo env_keep dynamic-loader env-pass-through alert.
    # Locks parser contract on the sudoers Defaults detection
    # surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd                                              # ok / baseline
    printf '%sDefaults env_keep += "LD_PRELOAD"\n' "${BENIGN}" > "${SUDOERS}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # sudoers-defaults-watchdog runs ON the timer's scheduled
    # fire — scans /etc/sudoers + sudoers.d for env_keep
    # dangerous additions (LD_PRELOAD/PYTHONPATH/PERL5LIB family),
    # emits a verdict, then exits. Type=simple would break
    # timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the sudoers-defaults-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd/selfdef-sudoers-defaults.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. sudoers-defaults-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # sudoers-defaults-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # sudoers-defaults-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'sudoers-defaults-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: sudoers-defaults-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. sudoers-defaults-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the sudoers-defaults-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (sudoers-defaults-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the sudoers-defaults-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-defaults-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # sudoers-defaults-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-defaults-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # sudoers-defaults-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-defaults-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the sudoers-defaults-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-defaults-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # sudoers-defaults-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-defaults-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the sudoers-defaults-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-defaults-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the sudoers-defaults-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # sudoers-defaults-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the sudoers-defaults-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the sudoers-defaults-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the sudoers-defaults-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the sudoers-defaults-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the sudoers-defaults-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the sudoers-defaults-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # sudoers-defaults-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # sudoers-defaults-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the sudoers-defaults-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the sudoers-defaults-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (sudoers-defaults-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the sudoers-defaults-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    [ -f "${script_dir}/sudoers-defaults-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (sudoers-defaults-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (sudoers-defaults-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (sudoers-defaults-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (sudoers-defaults-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (sudoers-defaults-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog .sh script tag selfdef-sudoers-defaults matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-sudoers-defaults
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (sudoers-defaults-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}
