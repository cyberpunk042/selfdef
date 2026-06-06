#!/usr/bin/env bats
# L2 functional suite for nfs-mount-watchdog.
#
# A network filesystem is content the local host does NOT control.
# If mounted WITHOUT nosuid, a setuid-root binary placed on the
# export (by whoever runs the server, OR a MITM on an unencrypted
# link) is honored by the client — any local user runs it and
# gets root. nodev likewise blocks device-node tricks.
#
# Severity tiers:
#   ok    → no network mounts, or all carry nosuid+nodev
#   warn  → a network mount missing nodev (but has nosuid)
#   alert → a network mount missing nosuid (THE root vector)
#
# Tests shadow findmnt on PATH with a deterministic mount-table
# so every tier (including the multi-mount mixed-flag case) fires
# reproducibly.
#
# Run with: bats packaging/test/L2-nfs-mount-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd/nfs-mount-watchdog.sh"

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
    MNT_TABLE="${TMP}/mounts.tsv"   # fstype<TAB>target<TAB>opts
}

teardown() { rm -rf "${TMP}"; }

mk_findmnt() {
    cat > "${BIN}/findmnt" <<'FMEOF'
#!/usr/bin/env bash
# Fake findmnt for L2-nfs-mount-watchdog. We honor:
#   findmnt -rno TARGET,OPTIONS -t <fstype>
# and emit the lines from $MNT_TABLE whose fstype field matches.
fstype=""
i=1
while (( i <= $# )); do
    case "${!i}" in
        -t) j=$((i+1)); fstype="${!j}"; i=$((j+1)) ;;
        *)  i=$((i+1)) ;;
    esac
done
awk -F'\t' -v f="${fstype}" '$1==f{print $2 " " $3}' "${MNT_TABLE}"
FMEOF
    chmod +x "${BIN}/findmnt"
}

# write_mounts <fstype tab target tab options> ...
write_mounts() {
    : > "${MNT_TABLE}"
    for row in "$@"; do
        printf '%s\n' "${row}" >> "${MNT_TABLE}"
    done
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    MNT_TABLE="${MNT_TABLE}" \
    SELFDEF_NFSMOUNT_PROFILE="${PROFILE:-report}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "no network mounts → ok / no_network_mounts" {
    mk_findmnt
    write_mounts             # empty table
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"no_network_mounts"'
    cap | grep -qE '"network_mounts":0'
}

@test "NFS mount with nosuid+nodev → ok / network_mounts_hardened" {
    mk_findmnt
    write_mounts $'nfs4\t/mnt/share\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"network_mounts_hardened"'
    cap | grep -qE '"network_mounts":1'
    cap | grep -qE '"missing_nosuid":0'
    cap | grep -qE '"missing_nodev":0'
}

@test "NFS mount missing nodev only → warn / network_mount_missing_nodev" {
    mk_findmnt
    write_mounts $'nfs4\t/mnt/share\tnosuid,relatime'    # no nodev
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"network_mount_missing_nodev"'
    cap | grep -qE '"missing_nodev":1'
    cap | grep -qE '"missing_nosuid":0'
}

@test "NFS mount missing nosuid → alert / network_mount_missing_nosuid (THE root vector)" {
    mk_findmnt
    write_mounts $'nfs4\t/mnt/share\tnodev,relatime'     # no nosuid
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"network_mount_missing_nosuid"'
    cap | grep -qE '"missing_nosuid":1'
}

@test "missing nosuid takes precedence over missing nodev (alert wins)" {
    mk_findmnt
    write_mounts \
        $'nfs4\t/mnt/share1\tnosuid,relatime' \
        $'nfs4\t/mnt/share2\tnodev,relatime'     # has nodev, NO nosuid
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"network_mount_missing_nosuid"'
}

@test "CIFS mount missing nosuid → alert (the same root vector via SMB)" {
    mk_findmnt
    write_mounts $'cifs\t/mnt/winshare\tnodev,relatime'
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"network_mount_missing_nosuid"'
}

@test "fuse.sshfs mount missing nosuid → alert (the SSHFS surface)" {
    mk_findmnt
    write_mounts $'fuse.sshfs\t/mnt/remote\tnodev,relatime'
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "multiple hardened mounts across fstypes → ok" {
    mk_findmnt
    write_mounts \
        $'nfs4\t/mnt/share\tnosuid,nodev,relatime' \
        $'cifs\t/mnt/winshare\tnosuid,nodev,relatime' \
        $'fuse.sshfs\t/mnt/remote\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"network_mounts":3'
}

@test "the emitted JSON carries every promised schema field" {
    mk_findmnt
    write_mounts $'nfs4\t/mnt/share\tnodev,relatime'
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-nfs-mount"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"network_mounts":[0-9]+'
    printf '%s' "${line}" | grep -qE '"missing_nosuid":[0-9]+'
    printf '%s' "${line}" | grep -qE '"missing_nodev":[0-9]+'
    printf '%s' "${line}" | grep -q '"nosuid_sample":'
    printf '%s' "${line}" | grep -q '"nodev_sample":'
}

@test "enforce profile + missing-nosuid → exit 1" {
    mk_findmnt
    write_mounts $'nfs4\t/mnt/share\tnodev,relatime'
    PATH="${BIN}:${PATH}" \
        MNT_TABLE="${MNT_TABLE}" \
        SELFDEF_NFSMOUNT_PROFILE=enforce \
        bash "${WD}" && fail "enforce + missing nosuid should exit non-zero"
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile + no network mounts → exit 0" {
    mk_findmnt
    write_mounts
    PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (nfs vs nfs4 — both fstypes covered)" {
    mk_findmnt
    write_mounts $'nfs\t/mnt/legacy\tnodev,relatime'   # NFSv3
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"network_mount_missing_nosuid"'
}

@test "INVARIANT (cifs missing-nodev only → warn, not alert): same warn-tier semantic as NFS" {
    mk_findmnt
    write_mounts $'cifs\t/mnt/winshare\tnosuid,relatime'   # no nodev
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"network_mount_missing_nodev"'
}

@test "INVARIANT (fuse.sshfs missing-nodev only → warn): SSHFS warn-tier coverage" {
    mk_findmnt
    write_mounts $'fuse.sshfs\t/mnt/remote\tnosuid,relatime'
    run_wd
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (nosuid_sample carries the mountpoint:fstype for forensics)" {
    mk_findmnt
    write_mounts $'nfs4\t/mnt/distinctive-share\tnodev,relatime'
    run_wd
    cap | grep -q '/mnt/distinctive-share'
}

@test "INVARIANT (5+ network mounts all-hardened → ok scales): bound check" {
    mk_findmnt
    write_mounts \
        $'nfs4\t/mnt/s1\tnosuid,nodev,relatime' \
        $'nfs4\t/mnt/s2\tnosuid,nodev,relatime' \
        $'nfs4\t/mnt/s3\tnosuid,nodev,relatime' \
        $'cifs\t/mnt/w1\tnosuid,nodev,relatime' \
        $'fuse.sshfs\t/mnt/r1\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"network_mounts":5'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_findmnt
    write_mounts $'nfs4\t/mnt/share\tnosuid,nodev,relatime'
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-nfs-mount -- ')
    [ "${main_count}" = "1" ]
}
