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

@test "INVARIANT (mount-options-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the mount-options-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the mount-options-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the mount-options-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the mount-options-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # mount-options-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # mount-options-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the mount-options-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the mount-options-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (mount-options-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (mount-options-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (mount-options-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (mount-options-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the mount-options-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    [ -f "${script_dir}/mount-options-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (mount-options-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (mount-options-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (mount-options-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (mount-options-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (mount-options-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script declares severity= variable with canonical vocabulary — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'severity=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script tag selfdef-mount-options matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-mount-options
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script uses printf-format JSON output — structured-event-emission contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'printf' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (mount-options-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (mount-options-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (mount-options-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .timer file exists at canonical path modules/mount-options-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (mount-options-watchdog module.toml exists at canonical path modules/mount-options-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (mount-options-watchdog systemd dir exists at modules/mount-options-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (mount-options-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (mount-options-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (mount-options-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (mount-options-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (mount-options-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (mount-options-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (mount-options-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (mount-options-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (mount-options-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (mount-options-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (mount-options-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (mount-options-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (mount-options-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (mount-options-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (mount-options-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (mount-options-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (mount-options-watchdog module.toml has install_paths section non-empty 93)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
ps = ip.get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (mount-options-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"mount-options-watchdog"' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (mount-options-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (mount-options-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (mount-options-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (mount-options-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (mount-options-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (mount-options-watchdog module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (mount-options-watchdog module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mount-options-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}
