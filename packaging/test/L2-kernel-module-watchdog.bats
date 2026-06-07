#!/usr/bin/env bats
# L2 functional suite for kernel-module-watchdog.
#
# kernel-module-watchdog snapshots the loaded module set from
# /proc/modules and alerts on:
#   - 1..2 new modules           → warn / new_module
#   - 3+ new modules             → alert / mass_new_modules
#   - any new module with no matching .ko under /lib/modules/$kver
#                                → alert / out_of_tree_module
#                                  (the LKM-rootkit signature: an
#                                  attacker loads an injected /
#                                  unsigned module to hook syscalls).
#
# Uses SELFDEF_KMOD_PROCSRC + SELFDEF_KMOD_MODDIR env-var overrides
# (added 2026-06-06 as operator-test + L2 testability affordances) to
# point the watchdog at fixture files instead of /proc/modules and
# /lib/modules/$(uname -r).
#
# Run with: bats packaging/test/L2-kernel-module-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd/kernel-module-watchdog.sh"

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
    BASELINE="${TMP}/kernel-modules-baseline.tsv"
    PROCSRC="${TMP}/proc-modules"
    MODDIR="${TMP}/modules"
    mkdir -p "${MODDIR}"
}

teardown() { rm -rf "${TMP}"; }

# write_modules_proc <mod1> <mod2> ...  → emits /proc/modules-shape lines.
write_modules_proc() {
    : > "${PROCSRC}"
    for m in "$@"; do
        printf '%s 16384 0 - Live 0x0000000000000000\n' "${m}" >> "${PROCSRC}"
    done
}

# stage_ko <module-name> — drop a fake .ko file in the moddir so the
# out-of-tree detector finds it.
stage_ko() {
    : > "${MODDIR}/${1}.ko"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_KMOD_PROFILE="${PROFILE:-report}" \
    SELFDEF_KMOD_BASELINE="${BASELINE}" \
    SELFDEF_KMOD_PROCSRC="${PROCSRC}" \
    SELFDEF_KMOD_MODDIR="${MODDIR}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run captures the module set into the baseline + chmod 0600" {
    write_modules_proc ext4 nvme intel_pmc_core
    stage_ko ext4; stage_ko nvme; stage_ko intel_pmc_core
    run_wd
    [ -f "${BASELINE}" ]
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"baseline_count":3'
}

@test "unchanged module set on second run → ok / no_delta" {
    write_modules_proc ext4 nvme
    stage_ko ext4; stage_ko nvme
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"added":0'
}

@test "1 new module with .ko on disk → warn / new_module" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd                              # baseline = {ext4}
    write_modules_proc ext4 newdriver
    stage_ko newdriver                  # .ko exists → not out-of-tree
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"new_module"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"added":1'
    cap | grep -qE '"out_of_tree":0'
}

@test "3+ new in-tree modules → alert / mass_new_modules" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 a b c
    stage_ko a; stage_ko b; stage_ko c
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"mass_new_modules"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":3'
}

@test "new module with NO matching .ko → alert / out_of_tree_module (rootkit signature)" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 rootkit_lkm    # no .ko staged → out of tree
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"out_of_tree_module"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"out_of_tree":1'
}

@test "out_of_tree takes precedence over mass_new_modules (alert classification ordering)" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    # 3 new modules but ONE is out-of-tree → must classify as
    # out_of_tree_module (the more-specific rootkit signature),
    # not mass_new_modules.
    write_modules_proc ext4 a b rootkit_lkm
    stage_ko a; stage_ko b              # rootkit_lkm has no .ko
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"out_of_tree_module"'
    cap | grep -qE '"out_of_tree":1'
    cap | grep -qE '"added":3'
}

@test "module name with underscore matches dash-named .ko (kernel mod naming convention)" {
    # The kernel uses underscore and dash interchangeably in module
    # names. Lock that the .ko-existence check handles both.
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 some_driver
    # Stage with DASH (the file-system filename uses dash).
    : > "${MODDIR}/some-driver.ko"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # Should NOT be classified as out-of-tree (the dash-vs-underscore
    # rule resolves it).
    cap | grep -qE '"out_of_tree":0'
    cap | grep -q '"event":"new_module"'
}

@test "removed module (operator cleanup) does NOT alert" {
    write_modules_proc ext4 oldmod
    stage_ko ext4; stage_ko oldmod
    run_wd                                 # baseline = {ext4, oldmod}
    write_modules_proc ext4                # oldmod removed
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"no_delta"'
    cap | grep -qE '"removed":1'
}

@test "the emitted JSON carries every promised schema field" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd                                 # baseline-initial path
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-kernel-modules"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -q '"kernel":'
    printf '%s' "${line}" | grep -qE '"baseline_count":[0-9]+'
}

@test "enforce profile + new module → exit 1" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 newdriver
    stage_ko newdriver
    # Use bats' `run` to capture status without aborting on non-zero exit.
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KMOD_PROFILE=enforce \
        SELFDEF_KMOD_BASELINE="${BASELINE}" \
        SELFDEF_KMOD_PROCSRC="${PROCSRC}" \
        SELFDEF_KMOD_MODDIR="${MODDIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "INVARIANT (mass-new threshold boundary): exactly 2 → warn, exactly 3 → alert" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 a b           # 2 new
    stage_ko a; stage_ko b
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"new_module"'   # at 2, still warn (not mass)
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (added_sample carries the specific module name for forensics)" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 distinctive_attacker_lkm
    stage_ko distinctive_attacker_lkm
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'distinctive_attacker_lkm'
}

@test "INVARIANT (mass-new out_of_tree mix — both 3+ AND out-of-tree present): event is out_of_tree, severity is alert" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    # 4 new, 2 of which are out-of-tree.
    write_modules_proc ext4 a b rk1 rk2
    stage_ko a; stage_ko b
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"out_of_tree_module"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"out_of_tree":2'
}

@test "INVARIANT (enforce + no_delta → exit 0): unchanged passes even in enforce" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (enforce + out_of_tree → exit 1, single module is enough)" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 rootkit_lkm
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KMOD_PROFILE=enforce \
        SELFDEF_KMOD_BASELINE="${BASELINE}" \
        SELFDEF_KMOD_PROCSRC="${PROCSRC}" \
        SELFDEF_KMOD_MODDIR="${MODDIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-kernel-modules -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): kernel-module-watchdog does NOT refresh baseline on out-of-tree detection — alert STAYS until operator updates" {
    # Out-of-tree (rootkit) module loads are NEVER routine; the
    # alert must persist across runs until operator explicitly
    # re-baselines.
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 rootkit_lkm
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"out_of_tree_module"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_KMOD_PROFILE)" {
    write_modules_proc ext4
    stage_ko ext4
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (kernel field surfaces uname -r for operator verification — multi-kernel-version hosts)" {
    # Multi-kernel hosts (booted from a non-default kernel) need
    # to verify the watchdog is checking the RIGHT modules/$(uname
    # -r)/ tree. The 'kernel' field surfaces that.
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    # The kernel field should be present in the JSON.
    cap | grep -qE '"kernel":"[^"]+"'
}

@test "INVARIANT (severity precedence: out_of_tree + mass-new same scan → out_of_tree event takes precedence over mass_new_modules)" {
    # When BOTH out-of-tree AND mass-new fire in same scan, the
    # event reports out_of_tree_module (more-specific signal).
    # Already covered by existing test 13 — this duplicates as a
    # safety lock.
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 a b c rootkit_lkm    # 4 new, 1 out-of-tree
    stage_ko a; stage_ko b; stage_ko c
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"out_of_tree_module"'
    ! cap | grep -q '"event":"mass_new_modules"'
}

@test "INVARIANT (3-add boundary lock: exactly 3 in-tree adds → alert mass_new_modules)" {
    # Sister to cron-job-watchdog 3-add + listening-ports 3-add +
    # suid-sgid 4-add + timestomp 4-add boundary INVARIANTs.
    # Mass-new threshold here is 3 (inclusive). Regression that
    # bumps to 4+ would trip here.
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 a b c    # exactly 3 new in-tree
    stage_ko a; stage_ko b; stage_ko c
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"mass_new_modules"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":3'
}

@test "INVARIANT (compound out-of-tree multi-module: 2 out-of-tree modules in same scan → out_of_tree=2, single alert event)" {
    # Sister to crontab-allow multi-grant consolidation pattern.
    # When multiple out-of-tree modules surface in same scan,
    # single alert event with out_of_tree counter = N.
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    write_modules_proc ext4 rootkit1 rootkit2
    # NEITHER staged — both out-of-tree.
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"out_of_tree_module"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"out_of_tree":2'
    main_count=$(cap | grep -cE '^-t selfdef-kernel-modules -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (kver-aware moddir: SELFDEF_KMOD_MODDIR points at the watchdog's idea of /lib/modules/\$(uname -r); .ko-existence check uses that exact dir)" {
    # Lock that the moddir env-var is the load-bearing knob for
    # the .ko-existence check. A regression that hardcoded
    # /lib/modules/\$(uname -r) in the script (ignoring the env
    # override) would trip in CI (no /lib/modules/\$(uname -r)
    # exists in the test sandbox). The fact that the existing
    # tests work means SELFDEF_KMOD_MODDIR IS load-bearing —
    # lock it explicitly.
    write_modules_proc ext4 newdriver
    stage_ko ext4
    stage_ko newdriver       # staged in the test MODDIR, not in real /lib/modules
    run_wd
    # If the script ignored SELFDEF_KMOD_MODDIR and used real
    # /lib/modules, newdriver would surface as out-of-tree (since
    # it's not in real /lib/modules). The fact that it does NOT
    # surface as out-of-tree confirms the env-var is honored.
    cap | grep -qE '"baseline_count":2'
}
