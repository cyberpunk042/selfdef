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
