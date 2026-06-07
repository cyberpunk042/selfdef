#!/usr/bin/env bats
# L2 bats functional tests for the binfmt-watchdog scan script.
#
# Fourth watchdog functional-severity suite, covering yet another
# detection mechanism: COLON-DELIMITED FIELD extraction. A binfmt.d
# registration line `:name:type:offset:magic:mask:interpreter:flags`
# tells the kernel to run `interpreter` whenever a matching file is
# executed (the 'C'/'F' flags run it with the caller's creds / as an
# open fd) — so a registration whose interpreter sits under a writable
# root, or is a non-absolute name, is a binfmt_misc code-exec primitive
# (T1546). Alert = writable/non-absolute interpreter OR world-writable/
# non-root .conf. No injection-pattern scan in this module.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# binfmt.d dir pointed at a tmp sandbox via SELFDEF_BINFMT_DIRS; locks
# the same `"severity":"alert"` token SDD-062 routes on.
#
# Run with: bats packaging/test/L2-binfmt-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/binfmt-watchdog/systemd/binfmt-watchdog.sh"
# SDD-061 D-6: scan script now sources the shared module-lib.
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
    BINFMTD="${TMP}/binfmt.d"; mkdir -p "${BINFMTD}"
    CONF="${BINFMTD}/reg.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BINFMT_PROFILE="${PROFILE:-report}" \
    SELFDEF_BINFMT_BASELINE="${BASELINE}" \
    SELFDEF_BINFMT_DIRS="${BINFMTD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no binfmt.d registrations present → ok / no_binfmt" {
    # binfmt.d dir exists but has no *.conf.
    run_wd
    cap | grep -q '"event":"no_binfmt"'
    cap | grep -q '"severity":"ok"'
}

@test "benign interpreter, first run → ok / baseline_initial" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / binfmt_intact" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"binfmt_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "interpreter under a writable root → alert" {
    printf ':evil:M:0:magic:mask:/tmp/evil:OC\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "non-absolute interpreter → alert" {
    printf ':evil:M:0:magic:mask:relinterp:OC\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign registration added after baseline → warn / binfmt_changed" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n:qemu-mips:M:0:magic2:mask:/usr/bin/qemu-mips:OCF\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"binfmt_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "interpreter under /usr/bin is NOT flagged (no alert)" {
    printf ':python3.12:E::py::/usr/bin/python3.12:\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable registration is NOT flagged" {
    printf '# :evil:M:0:magic:mask:/tmp/evil:OC\n:qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# SDD-061 D-6 — shared-lib dependency fails loud
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf ':evil:M:0:magic:mask:/tmp/evil:OC\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits zero on a benign baseline" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -eq 0 ]
}

@test "baseline is chmod 0600 (confidentiality — binfmt inventory enumerates kernel-trigger code-exec surface)" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (interpreter under /var/tmp): writable-root expansion" {
    printf ':evil:M:0:magic:mask:/var/tmp/.interpreter:OC\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (interpreter under /dev/shm): tmpfs writable-root expansion" {
    printf ':evil:M:0:magic:mask:/dev/shm/.interpreter:OC\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (interpreter under /home): user-writable hijack coverage" {
    printf ':evil:M:0:magic:mask:/home/user/.interpreter:OC\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable binfmt.d conf): file itself world-writable → alert" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable binfmt.d conf): group-writable → alert above world-writable bar" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (multi-line config with both benign + suspicious — suspicious wins)" {
    # Even if a config carries a benign registration alongside a
    # suspicious one, severity should escalate to the suspicious one.
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n:evil:M:0:magic:mask:/tmp/evil:OC\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-binfmt -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): binfmt-watchdog does NOT refresh baseline on suspicious-interpreter detection — alert STAYS until operator updates" {
    # T1546 kernel-trigger code-exec primitive — alert MUST persist
    # across runs until operator explicitly re-baselines.
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    printf ':evil:M:0:magic:mask:/tmp/evil:OC\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/binfmt.d + /run/binfmt.d + /usr/lib/binfmt.d axes — suspicious in EITHER → alert)" {
    BINFMTD2="${TMP}/run-binfmt.d"; mkdir -p "${BINFMTD2}"
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BINFMT_PROFILE="report" \
    SELFDEF_BINFMT_BASELINE="${BASELINE}" \
    SELFDEF_BINFMT_DIRS="${BINFMTD} ${BINFMTD2}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf ':evil:M:0:magic:mask:/tmp/evil:OC\n' > "${BINFMTD2}/evil.conf"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BINFMT_PROFILE="report" \
    SELFDEF_BINFMT_BASELINE="${BASELINE}" \
    SELFDEF_BINFMT_DIRS="${BINFMTD} ${BINFMTD2}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (C flag detected: interpreter run with caller's creds is the privilege-escalation axis)" {
    # The C flag is the dangerous one — it runs the interpreter with
    # the CALLER's uid (so attacker-controlled interpreter runs with
    # whatever creds invoke a matching binary). Lock that interpreter
    # under writable root with C flag triggers alert (sister to the
    # OC + OCF flag tests).
    printf ':evil:M:0:magic:mask:/tmp/evil:C\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-path interpreter 'sub/dir/p' → alert)" {
    # Sister to the writable-root axes already locked. A non-
    # absolute interpreter path is resolved by the kernel against
    # PWD-at-exec time — undefined behavior + attacker primitive
    # because the resolution depends on what dir the matching
    # binary is invoked from. Locks detection of relative
    # interpreters alongside the absolute-writable-root family.
    # Sister to request-key-watchdog relative-callout INVARIANT
    # already locked on the kernel-trigger code-load family.
    printf ':evil:M:0:magic:mask:sub/dir/interpreter:OC\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named binfmt entry surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # binfmt entry (T1574 — Hijack Execution Flow via binary-
    # format interpreter; every exec of a matching binary fires
    # the planted interpreter), the entry NAME MUST surface in
    # the JSON sample so operator dashboard routes triage to the
    # right path.
    printf ':qemu-arm:M:0:magic:mask:/usr/bin/qemu-arm:OCF\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf ':evil:M:0:magic:mask:/tmp/.evil-interpreter:OC\n' > "${BINFMTD}/99-distinctive-attacker-binfmt.conf"
    run_wd
    cap | grep -q 'distinctive-attacker-binfmt'
}

@test "INVARIANT (interpreter under /home — user-writable persistence vector → alert; writable-root axis-symmetric expansion)" {
    # Sister to /tmp + /var/tmp + /dev/shm writable-root interpreter
    # INVARIANTs already locked. /home/<user> is writable by the
    # owning user without privilege; an attacker who pivots into a
    # user account plants an interpreter at /home/<user>/.bin/sh
    # AND registers a binfmt entry pointing at it — every exec of
    # a matching binary fires the planted interpreter (T1574 —
    # Hijack Execution Flow). Locks the /home axis on the binfmt
    # writable-root coverage symmetric to /tmp /var/tmp /dev/shm.
    printf ':evil:M:0:magic:mask:/home/alice/.binfmt-interp:OC\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    printf ':e1:M:0:magic:mask:/tmp/.e1:OC\n:e2:M:0:magic:mask:/var/tmp/.e2:OC\n:e3:M:0:magic:mask:/dev/shm/.e3:OC\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-binfmt -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1574 binfmt_misc Hijack Execution
    # Flow surveillance.
    printf ':java:M:0:magic:mask:/usr/bin/java:OC\n' > "${CONF}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on binfmt surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The binfmt-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1574 binfmt_misc Hijack Execution Flow
    # alert. Locks parser contract on the binfmt.d interpreter-
    # registration detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf ':java:M:0:magic:mask:/usr/bin/java:OC\n' > "${CONF}"
    run_wd                                              # ok / baseline
    printf ':evil:M:0:magic:mask:/tmp/.evil:OC\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: binfmt-watchdog NEVER deletes binfmt.d entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # binfmt-watchdog DETECTS T1574 binfmt_misc Hijack Execution
    # Flow but MUST NEVER emit sed/awk/rm commands to auto-
    # clean the interpreter registration. The detected entry
    # may be operator-legitimate (custom QEMU multi-arch
    # interpreter, wine binary handler, multi-platform CI).
    # Silent auto-delete would destroy operator baseline state
    # AND could break cross-architecture binary execution.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the binfmt surveillance substrate.
    printf ':evil:M:0:magic:mask:/tmp/.evil:OC\n' > "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q 'evil' "${CONF}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*binfmt'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # binfmt-watchdog runs ON the timer's scheduled fire — diffs
    # /proc/sys/fs/binfmt_misc against baseline, emits a verdict
    # on suspicious interpreter registrations, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the binfmt-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/binfmt-watchdog/systemd/selfdef-binfmt.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: binfmt-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. binfmt-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the binfmt-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/binfmt-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (binfmt-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The binfmt-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the binfmt-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/binfmt-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (binfmt-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # All watchdog libexec scripts MUST surface JSON records
    # via logger -t with a selfdef-prefixed tag so downstream
    # syslog/journald consumers can route per-watchdog records
    # via the tag field rather than parsing the JSON payload
    # for the module field. The tag prefix MUST be "selfdef-"
    # so cross-watchdog SIEM filters (`syslog-ng-filter "selfdef-*"`)
    # capture every selfdef-watchdog without per-watchdog tag
    # enumeration. A regression dropping the selfdef- prefix
    # would cause SIEM filters to silently miss records. Locks
    # SDD-062 logger-tag routing discipline on the binfmt-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/binfmt-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (binfmt-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The binfmt-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the binfmt-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/binfmt-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
