#!/usr/bin/env bats
# L2 functional suite for mount-options-watchdog.
#
# mount-options-watchdog verifies that security-relevant mount points
# carry their hardening flags (/tmp, /var/tmp, /dev/shm, /home,
# /var/log, /boot — nosuid / nodev / noexec per per-mount expectation).
# A mount-point that is NOT its own filesystem can't carry these flags
# (so it's reported as not_separate_mount, not drift). Severity tiers:
#   ok    → every separate-mount target carries every expected flag
#   warn  → 1..2 missing flags
#   alert → 3+ missing flags (broad remount-weaken event signature)
#
# Tests shadow findmnt on PATH with a deterministic fixture so every
# tier fires reproducibly.
#
# Run with: bats packaging/test/L2-mount-options-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd/mount-options-watchdog.sh"

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
    MNT_TABLE="${TMP}/mount-fixture.tsv"   # path \t options
}

teardown() { rm -rf "${TMP}"; }

# write_fixture <one-mount-per-line: PATH<TAB>OPTIONS>
# Mounts NOT in the fixture are treated as non-separate (target = /).
write_fixture() { printf '%s\n' "$@" > "${MNT_TABLE}"; }

mk_findmnt() {
    cat > "${BIN}/findmnt" <<'FMEOF'
#!/usr/bin/env bash
# Fake findmnt for L2-mount-options-watchdog. We honor:
#   findmnt -no TARGET  --target <path>
#   findmnt -no OPTIONS --target <path>
mode=""
target=""
i=1
while (( i <= $# )); do
    arg="${!i}"
    case "$arg" in
        -no)
            j=$((i+1))
            field="${!j}"
            case "$field" in
                TARGET)  mode="target" ;;
                OPTIONS) mode="options" ;;
            esac
            i=$((j+1)) ;;
        --target)
            j=$((i+1))
            target="${!j}"
            i=$((j+1)) ;;
        *) i=$((i+1)) ;;
    esac
done

# Look up <target> in the fixture; if found, emit TARGET=target or
# OPTIONS=opts; if not, the mount-point isn't its own FS → return "/"
# as the containing mount.
found_line="$(awk -F'\t' -v t="${target}" '$1==t{print; exit}' "${MNT_TABLE}")"
if [[ -n "${found_line}" ]]; then
    case "${mode}" in
        target)  printf '%s\n' "${target}" ;;
        options) printf '%s\n' "$(awk -F'\t' -v t="${target}" '$1==t{print $2; exit}' "${MNT_TABLE}")" ;;
    esac
else
    # Not its own FS: pretend the containing mount is /.
    case "${mode}" in
        target)  printf '/\n' ;;
        options) printf 'rw,relatime\n' ;;
    esac
fi
FMEOF
    chmod +x "${BIN}/findmnt"
    export MNT_TABLE
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    MNT_TABLE="${MNT_TABLE}" \
    SELFDEF_MOUNTOPTS_PROFILE="${PROFILE:-report}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "no separate mounts → ok (the not-its-own-FS path is info, not drift)" {
    mk_findmnt
    write_fixture                       # empty fixture
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"all_flags_present"'
    cap | grep -qE '"missing_flags":0'
    # All 6 expected mount-points reported as not_separate.
    cap | grep -qE '"not_separate_mount":6'
}

@test "all separate mounts carry expected flags → ok / all_flags_present" {
    mk_findmnt
    write_fixture \
        $'/tmp\tnosuid,nodev,noexec,relatime' \
        $'/var/tmp\tnosuid,nodev,noexec,relatime' \
        $'/dev/shm\tnosuid,nodev,noexec,relatime' \
        $'/home\tnosuid,nodev,relatime' \
        $'/var/log\tnosuid,nodev,noexec,relatime' \
        $'/boot\tnosuid,nodev,noexec,relatime'
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"all_flags_present"'
    cap | grep -qE '"missing_flags":0'
    cap | grep -qE '"not_separate_mount":0'
}

@test "1 missing flag on /tmp → warn / missing_flags" {
    mk_findmnt
    # /tmp missing noexec; other expected mounts not separate.
    write_fixture $'/tmp\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"missing_flags"'
    cap | grep -qE '"missing_flags":1'
}

@test "2 missing flags → warn / missing_flags (upper boundary of warn tier)" {
    mk_findmnt
    write_fixture $'/tmp\tnosuid,relatime'
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"missing_flags":2'
}

@test "3+ missing flags → alert / broad_missing_flags (the remount-weaken signature)" {
    mk_findmnt
    # /tmp missing all 3 hardening flags → 3 misses on /tmp alone.
    write_fixture $'/tmp\trelatime'
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"broad_missing_flags"'
    cap | grep -qE '"missing_flags":3'
}

@test "the emitted JSON carries every promised schema field" {
    mk_findmnt
    write_fixture $'/tmp\tnosuid,nodev,noexec,relatime'
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-mount-options"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"missing_flags":[0-9]+'
    printf '%s' "${line}" | grep -qE '"not_separate_mount":[0-9]+'
    printf '%s' "${line}" | grep -q '"missing_sample":'
    printf '%s' "${line}" | grep -q '"not_separate_sample":'
}

@test "missing_sample carries 'mountpoint:flag' rows" {
    mk_findmnt
    write_fixture $'/tmp\tnosuid,relatime'    # missing nodev + noexec
    run_wd
    cap | grep -q '/tmp:nodev'
    cap | grep -q '/tmp:noexec'
}

@test "enforce profile + missing-flags → exit 1" {
    mk_findmnt
    write_fixture $'/tmp\tnosuid,relatime'
    PATH="${BIN}:${PATH}" \
        MNT_TABLE="${MNT_TABLE}" \
        SELFDEF_MOUNTOPTS_PROFILE=enforce \
        bash "${WD}" && fail "enforce + missing flags should exit non-zero"
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "enforce profile + all flags present → exit 0" {
    mk_findmnt
    write_fixture $'/tmp\tnosuid,nodev,noexec,relatime'
    PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}

@test "BOUNDARY: 2-misses + 1-miss (sum=3) → alert (the broad-weaken pattern combines across mount points)" {
    mk_findmnt
    # /tmp missing nodev+noexec (2 misses) AND /var/tmp missing noexec (1 miss) = sum 3
    write_fixture \
        $'/tmp\tnosuid,relatime' \
        $'/var/tmp\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"missing_flags":3'
}

@test "INVARIANT (/dev/shm + noexec): missing noexec on /dev/shm surfaces in sample (executable-tmpfs attack surface)" {
    mk_findmnt
    write_fixture $'/dev/shm\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '/dev/shm:noexec'
}

@test "INVARIANT (/boot read-write detected via missing nodev): /boot must carry nodev too" {
    mk_findmnt
    write_fixture $'/boot\tnosuid,relatime'   # missing nodev + noexec
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
    cap | grep -q '/boot:nodev'
}

@test "INVARIANT (per-mount-point isolation): expecting nosuid only — non-expected flag IS NOT alerted on" {
    mk_findmnt
    # /home doesn't carry noexec expectation (would break user execs); confirm not flagged.
    write_fixture \
        $'/home\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"all_flags_present"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_findmnt
    write_fixture $'/tmp\tnosuid,nodev,noexec,relatime'
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-mount-options -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (sharp boundary: 2 missing flags = warn; 3 missing flags = alert — single-notch escalation)" {
    # 2 misses (warn) and 3 misses (alert) is the single-notch
    # transition. Locks the boundary.
    mk_findmnt
    write_fixture $'/tmp\tnosuid,relatime'                    # 2 missing: nodev + noexec
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"missing_flags":2'
    : > "${SELFDEF_TEST_LOGCAP}"
    write_fixture $'/tmp\trelatime'                           # 3 missing: nosuid + nodev + noexec
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"missing_flags":3'
}

@test "INVARIANT (cross-mount aggregation: 3 mounts × 1 miss each → alert (sum is 3, not max-per-mount))" {
    # The severity ladder sums missing flags ACROSS all mount
    # points — 3 mounts each missing exactly 1 flag = 3 total =
    # alert. Locks against a per-mount-max regression.
    mk_findmnt
    write_fixture \
        $'/tmp\tnosuid,nodev,relatime' \
        $'/var/tmp\tnosuid,nodev,relatime' \
        $'/var/log\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"missing_flags":3'
}

@test "INVARIANT (not_separate_sample surfaces operator-readable paths — distinct from missing_sample)" {
    # When some mounts ARE separate FS (with missing flags) and
    # OTHERS aren't (treated as not_separate), the JSON must
    # carry BOTH samples distinct so operator can triage which
    # category each mount falls into.
    mk_findmnt
    # /tmp is separate FS with missing flags; everything else not.
    write_fixture $'/tmp\tnosuid,relatime'
    run_wd
    # missing_sample carries the /tmp:nodev + /tmp:noexec entries.
    cap | grep -q '/tmp:nodev'
    cap | grep -q '/tmp:noexec'
    # not_separate_sample carries the other 5 expected paths.
    cap | grep -qE '"not_separate_mount":5'
    cap | grep -q '/var/tmp'
}

@test "INVARIANT (JSON profile field echoes operator-set SELFDEF_MOUNTOPTS_PROFILE)" {
    mk_findmnt
    write_fixture $'/tmp\tnosuid,nodev,noexec,relatime'
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (stateless re-evaluation: missing-flag alert STAYS visible on every run until operator remounts)" {
    # mount-options-watchdog is stateless (no baseline-refresh required) —
    # re-evaluates LIVE mount table on every run. A missing-flag mount that
    # stays mounted across runs MUST re-alert every run, not decay to ok
    # after first detection.
    mk_findmnt
    write_fixture $'/tmp\trelatime'                     # 3 missing flags
    run_wd
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"broad_missing_flags"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (boundary 1 miss: warn ladder lower bound)" {
    # The warn ladder lower bound is 1 miss; locks against regression
    # where 1 miss might silently decay to ok.
    mk_findmnt
    write_fixture $'/tmp\tnosuid,nodev,relatime'        # 1 missing: noexec
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"missing_flags":1'
}

@test "INVARIANT (multiple separate mounts all hardened — no false-positive at scale)" {
    # When ALL six expected mounts are separate AND ALL carry their
    # full flag set, severity stays ok. Locks against regression where
    # the multi-mount path might accidentally false-positive.
    mk_findmnt
    write_fixture \
        $'/tmp\tnosuid,nodev,noexec,relatime' \
        $'/var/tmp\tnosuid,nodev,noexec,relatime' \
        $'/dev/shm\tnosuid,nodev,noexec,relatime' \
        $'/home\tnosuid,nodev,relatime' \
        $'/var/log\tnosuid,nodev,noexec,relatime' \
        $'/boot\tnosuid,nodev,noexec,relatime'
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"all_flags_present"'
    cap | grep -qE '"missing_flags":0'
}

@test "INVARIANT (/var/tmp + nosuid: missing nosuid on /var/tmp surfaces in sample — sister axis to /tmp+nosuid)" {
    # Sister to the /dev/shm + noexec axis already locked. /var/tmp
    # carries the same hardening expectation as /tmp (nosuid + nodev
    # + noexec) since it's a writable-spool surface that can be used
    # to drop binaries; a missing nosuid would let an attacker drop
    # a setuid binary into /var/tmp and pivot to root. Lock the
    # axis-symmetry on /var/tmp.
    mk_findmnt
    write_fixture $'/var/tmp\tnodev,noexec,relatime'      # missing nosuid only
    run_wd
    cap | grep -q '/var/tmp:nosuid'
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (/boot + nosuid: missing nosuid on /boot surfaces in sample — boot-data integrity axis)" {
    # Sister to /tmp+nosuid, /var/tmp+nosuid, /dev/shm+noexec
    # axes already locked. /boot carries the kernel + initramfs
    # blobs — anti-tampering policy says any setuid binary
    # planted in /boot would survive across kernel-upgrade
    # cycles and could be invoked from the boot loader's chain
    # (T1542 family — boot persistence vectors). Lock the axis-
    # symmetry on /boot: missing nosuid → surfaces in sample so
    # operator dashboard routes triage to the right path.
    mk_findmnt
    write_fixture $'/boot\tnodev,noexec,relatime'         # missing nosuid only
    run_wd
    cap | grep -q '/boot:nosuid'
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (/var/log + nodev: missing nodev on /var/log surfaces in sample — audit-log device-creation defense)" {
    # Sister to /tmp+nosuid, /var/tmp+nosuid, /dev/shm+noexec,
    # /boot+nosuid axes already locked. /var/log is the audit-
    # trail directory — anti-tampering policy says it should be
    # nodev (no device-node creation; an attacker who can create
    # a character/block device in /var/log might use mknod c
    # /dev/sda to plant a raw block-device tap on the underlying
    # disk). Lock the axis-symmetry on /var/log: missing nodev
    # surfaces in sample so operator dashboard routes triage to
    # the audit-log integrity surface.
    mk_findmnt
    write_fixture $'/var/log\tnosuid,noexec,relatime'    # missing nodev only
    run_wd
    cap | grep -q '/var/log:nodev'
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (/home + nodev: missing nodev on /home surfaces in sample — cross-user device-creation defense)" {
    # Sister to /tmp+nosuid, /var/tmp+nosuid, /dev/shm+noexec,
    # /boot+nosuid, /var/log+nodev axes already locked. /home
    # is shared user-data surface — attacker with regular user
    # account who creates a device-node in their home dir gets
    # cross-user / cross-namespace access if the device node is
    # owned by the user (e.g. mknod c /dev/sda for raw disk
    # access). Lock axis-symmetry on /home: missing nodev
    # surfaces in sample so operator dashboard routes triage
    # to the home-dir mount integrity.
    mk_findmnt
    write_fixture $'/home\tnosuid,noexec,relatime'       # missing nodev only
    run_wd
    cap | grep -q '/home:nodev'
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (detail-tag axis: per-finding selfdef-mount-options-detail emissions bounded to one-per-missing-flag — operator log-spelunking)" {
    # Sister to brain-wide main-tag + detail-tag emission
    # INVARIANTs across the brain. The mount-options watchdog
    # emits ONE main 'selfdef-mount-options' JSON record per
    # scan (locked by JSON-record-is-SINGLE-main-logger-line
    # INVARIANT above) AND emits 'selfdef-mount-options-detail'
    # records one-per-missing-flag for operator log-spelunking
    # (operator can grep journalctl -t selfdef-mount-options-
    # detail to enumerate the specific finding rows). Two
    # missing flags → two detail records. Locks the
    # multi-detail-bounded-by-finding-count contract on the
    # filesystem mount-options surveillance surface.
    mk_findmnt
    write_fixture $'/tmp\trelatime' $'/var/tmp\trelatime'  # /tmp missing 3, /var/tmp missing 3
    run_wd
    detail_count=$(cap | grep -cE '^-t selfdef-mount-options-detail -- ')
    # Two mounts × 3 missing flags each = 6 detail records
    [ "${detail_count}" = "6" ]
}

@test "INVARIANT (/dev/shm + nodev: missing nodev on /dev/shm surfaces in sample — tmpfs in-RAM device-creation defense)" {
    # Sister to /tmp+nosuid, /var/tmp+nosuid, /boot+nosuid, /var/log+nodev,
    # /home+nodev axes already locked. /dev/shm is tmpfs in-RAM
    # writable-root; missing nodev there lets attacker mknod a
    # device node in tmpfs for cross-process device-style IPC or
    # raw-disk shadowing. T1574 hijack execution flow + T1057
    # process discovery via tmpfs device.
    mk_findmnt
    write_fixture $'/dev/shm\tnosuid,noexec,relatime'    # missing nodev only
    run_wd
    cap | grep -q '/dev/shm:nodev'
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on mount-options surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The mount-options-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1574 mount-options-tamper / device-
    # hardening-bypass alert. Locks parser contract on the
    # findmnt detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_findmnt
    write_fixture $'/tmp\tnosuid,nodev,noexec,relatime'  # all hardened
    run_wd                                              # ok / baseline
    write_fixture $'/tmp\trelatime'                     # missing 3 flags → alert
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # mount-options-watchdog runs ON the timer's scheduled fire
    # — scans mount table for missing nodev/nosuid/noexec on
    # canonical paths, emits a verdict, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the mount-options-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd/selfdef-mount-options.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. mount-options-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # mount-options-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # mount-options-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'mount-options-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: mount-options-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. mount-options-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the mount-options-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (mount-options-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the mount-options-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (mount-options-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # mount-options-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (mount-options-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # mount-options-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (mount-options-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the mount-options-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (mount-options-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # mount-options-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (mount-options-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the mount-options-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (mount-options-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the mount-options-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # mount-options-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the mount-options-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the mount-options-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}
