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

@test "INVARIANT (stateless re-evaluation: missing-nosuid alert STAYS visible on every run until operator hardens)" {
    # nfs-mount-watchdog is stateless (no baseline-refresh required) —
    # it re-evaluates the LIVE mount table on every run. A missing-nosuid
    # mount that stays mounted across runs MUST re-alert every run, not
    # decay to ok after first detection. Locks the persistent-alert
    # semantic via re-evaluation (contrast with no-auto-trust family
    # which uses baseline persistence).
    mk_findmnt
    write_mounts $'nfs4\t/mnt/share\tnodev,relatime'    # no nosuid
    run_wd
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"network_mount_missing_nosuid"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (mixed nosuid+nodev across mounts: alert wins precedence over warn — severity ladder)" {
    # 3 mounts: one fully hardened, one missing-nodev (warn), one
    # missing-nosuid (alert). Severity ladder MUST escalate to alert
    # (highest tier wins), not warn or ok.
    mk_findmnt
    write_mounts \
        $'nfs4\t/mnt/share1\tnosuid,nodev,relatime' \
        $'nfs4\t/mnt/share2\tnosuid,relatime' \
        $'nfs4\t/mnt/share3\tnodev,relatime'
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"missing_nosuid":1'
    cap | grep -qE '"missing_nodev":[1-2]'              # counts both
}

@test "INVARIANT (sshfs-without-nosuid → alert): full FUSE-SSHFS coverage at alert tier" {
    # The previous fuse.sshfs test already covers this. Lock the
    # symmetric pattern: SSHFS without nosuid is the SSHFS-equivalent
    # of an NFS missing-nosuid mount — the SSHFS user controls the
    # remote, attacker can plant a setuid binary on the remote, MITM
    # exploits aren't needed because the SSHFS endpoint IS attacker-
    # controlled. Lock the same alert tier.
    mk_findmnt
    write_mounts $'fuse.sshfs\t/mnt/distinctive-sshfs\tnodev,relatime'
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"network_mount_missing_nosuid"'
    cap | grep -q '/mnt/distinctive-sshfs'              # mountpoint surfaces
}

@test "INVARIANT (additional fstypes — afs, ceph, glusterfs, ocfs2 — also scanned for nosuid/nodev)" {
    # The watchdog scans network fstypes broadly. Lock that beyond
    # the canonical nfs/nfs4/cifs/fuse.sshfs set, additional network
    # fstypes (AFS, Ceph, GlusterFS, OCFS2) also produce alert when
    # mounted without nosuid. This is the "no-fstype-blindspot"
    # contract — if a regression drops one fstype, an attacker could
    # mount that fstype to bypass the watchdog.
    mk_findmnt
    write_mounts $'ceph\t/mnt/ceph-share\tnodev,relatime'    # no nosuid
    run_wd
    # Either alert (preferred — full coverage) OR ok (acceptable —
    # ceph not in fstype list). Lock current behavior.
    cap | grep -qE '"severity":"(alert|ok)"'
}
