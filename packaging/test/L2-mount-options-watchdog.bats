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
