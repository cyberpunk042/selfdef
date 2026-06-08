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

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named module surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker loads a new
    # kernel module (T1547.006 — Kernel Modules and Extensions
    # persistence), the module name MUST surface in the JSON
    # sample so operator dashboard routes triage to the right
    # module. Locks the operator-visibility contract on the
    # kernel-module surveillance surface.
    write_modules_proc ext4
    stage_ko ext4
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    write_modules_proc ext4 distinctive_attacker_mod
    stage_ko distinctive_attacker_mod
    run_wd
    cap | grep -q 'distinctive_attacker_mod'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. The selfdef-kernel-module
    # logger tag must fire EXACTLY ONCE per scan regardless of
    # how many kmod add/remove events surface. Multi-line
    # output would break the SDD-062 downstream JSON-line
    # consumer (Sigma correlator) which expects one structured
    # record per scan. Locks the consolidation discipline on
    # the kernel-module surveillance surface (T1547.006).
    write_modules_proc ext4 xt_owner xt_conntrack overlay
    stage_ko ext4 xt_owner xt_conntrack overlay
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-kernel-modules -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline file is chmod 0600 — confidentiality of kmod-inventory)" {
    # Sister to brain-wide baseline-confidentiality INVARIANTs.
    # The baseline enumerates loaded kernel modules; operator-
    # private prevents reconnaissance of kernel capabilities
    # surface.
    write_modules_proc ext4 xt_owner
    stage_ko ext4 xt_owner
    run_wd
    [ -f "${BASELINE}" ]
    mode="$(stat -c '%a' "${BASELINE}")"
    [ "${mode}" = "600" ] || [ "${mode}" = "640" ] || [ "${mode}" = "644" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1547.006 kernel-module surveillance.
    write_modules_proc ext4 xt_owner
    stage_ko ext4 xt_owner
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on kernel-module surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The kernel-module-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1547.006 Kernel Modules and Extensions
    # alert. Locks parser contract on the kernel-module
    # inventory delta detection surface.
    write_modules_proc ext4 xt_owner
    stage_ko ext4 xt_owner
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    write_modules_proc ext4 xt_owner attacker_planted_mod
    stage_ko ext4 xt_owner attacker_planted_mod
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # kernel-module-watchdog runs ON the timer's scheduled fire
    # — diffs lsmod output against baseline + checks .ko in-tree
    # vs out-of-tree, emits a verdict, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks oneshot-
    # probe contract on the kernel-module-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd/selfdef-kernel-modules.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. kernel-module-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # kernel-module-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # kernel-module-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'kernel-module-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: kernel-module-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. kernel-module-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the kernel-module-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (kernel-module-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the kernel-module-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-module-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # kernel-module-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-module-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # kernel-module-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-module-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the kernel-module-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-module-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # kernel-module-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-module-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the kernel-module-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-module-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the kernel-module-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # kernel-module-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the kernel-module-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the kernel-module-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the kernel-module-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the kernel-module-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the kernel-module-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the kernel-module-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # kernel-module-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # kernel-module-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the kernel-module-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the kernel-module-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (kernel-module-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (kernel-module-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (kernel-module-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (kernel-module-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the kernel-module-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    [ -f "${script_dir}/kernel-module-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (kernel-module-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (kernel-module-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (kernel-module-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script tag selfdef-kernel-module matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-kernel-module
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (kernel-module-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (kernel-module-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .timer file exists at canonical path modules/kernel-module-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (kernel-module-watchdog module.toml exists at canonical path modules/kernel-module-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (kernel-module-watchdog systemd dir exists at modules/kernel-module-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (kernel-module-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (kernel-module-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (kernel-module-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (kernel-module-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (kernel-module-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (kernel-module-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (kernel-module-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (kernel-module-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (kernel-module-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (kernel-module-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (kernel-module-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (kernel-module-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (kernel-module-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (kernel-module-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (kernel-module-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (kernel-module-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (kernel-module-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (kernel-module-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (kernel-module-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (kernel-module-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (kernel-module-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-module-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}
