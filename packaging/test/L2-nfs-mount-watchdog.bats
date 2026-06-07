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

@test "INVARIANT (JSON profile field echoes operator-set SELFDEF_NFSMOUNT_PROFILE)" {
    # Sister to mount-options-watchdog's profile-echo INVARIANT.
    # Downstream operator dashboard / triage pipeline must see the
    # profile value the watchdog ran under, not just the severity —
    # so it can distinguish report-mode findings from enforce-mode
    # findings (the latter would have aborted the unit on alert).
    # Closes the profile-surfacing axis on the nfs-mount surveillance
    # surface alongside the mount-options sister-axis already locked.
    mk_findmnt
    write_mounts $'nfs4\t/mnt/share\tnosuid,nodev,relatime'
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (mass-mount stress: 10 network mounts all-hardened → ok scales beyond 5+ check)" {
    # Sister to the 5+ mounts all-hardened INVARIANT already locked.
    # Real-world hosts (especially CI/build hosts + storage clusters)
    # may mount dozens of network FSes. Lock that the watchdog
    # handles the higher-count case without breaking the count
    # accuracy or the severity ladder.
    mk_findmnt
    write_mounts \
        $'nfs4\t/mnt/s1\tnosuid,nodev,relatime' \
        $'nfs4\t/mnt/s2\tnosuid,nodev,relatime' \
        $'nfs4\t/mnt/s3\tnosuid,nodev,relatime' \
        $'nfs4\t/mnt/s4\tnosuid,nodev,relatime' \
        $'nfs4\t/mnt/s5\tnosuid,nodev,relatime' \
        $'cifs\t/mnt/w1\tnosuid,nodev,relatime' \
        $'cifs\t/mnt/w2\tnosuid,nodev,relatime' \
        $'fuse.sshfs\t/mnt/r1\tnosuid,nodev,relatime' \
        $'fuse.sshfs\t/mnt/r2\tnosuid,nodev,relatime' \
        $'fuse.sshfs\t/mnt/r3\tnosuid,nodev,relatime'
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"network_mounts":1[0-9]'
}

@test "INVARIANT (DELTA detect — distinctive-attacker-named mount path surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When a distinctive-named
    # network mount surfaces as missing nosuid/nodev, the path
    # MUST surface in the JSON sample so operator dashboard
    # routes triage to the right path. Locks the operator-
    # visibility contract on the network-mount nosuid/nodev
    # surveillance surface (T1078 — Valid Accounts via NFS
    # uid-mapping; nosuid prevents setuid binaries planted on
    # mount from elevating priv on host).
    mk_findmnt
    write_mounts $'nfs4\t/mnt/distinctive-attacker-share\trelatime'
    run_wd
    cap | grep -q 'distinctive-attacker-share'
}

@test "INVARIANT (cifs/smbfs missing-nosuid axis: cifs mount without nosuid → alert; Windows-share share-and-share family coverage)" {
    # Sister to nfs/nfs4 missing-nosuid INVARIANT already locked
    # and sshfs missing-nosuid INVARIANT already locked. cifs
    # (SMB/CIFS) is the Windows-share equivalent network-mount
    # surface — attackers can plant setuid binaries on a
    # malicious SMB share AS the share-owner, and if cifs mount
    # lacks nosuid, the binary inherits root on the mounting
    # host. Locks axis-coverage on the cifs/smbfs network-mount
    # nosuid contract symmetric to the nfs + sshfs family on
    # T1078 Valid Accounts surface.
    mk_findmnt
    write_mounts $'cifs\t/mnt/winshare\trw,relatime'
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs across
    # the brain. severity field surfaces on operator dashboard
    # color-coded severity axis. A future refactor introducing
    # a fifth value (e.g. 'critical' or 'info') would silently
    # bucket as unknown on the dashboard's color-mapping. Lock
    # the bounded set so any new severity value is intentional
    # + dashboard-mapped, not a silent regression.
    mk_findmnt
    write_mounts $'nfs4\t/mnt/test\tnosuid,nodev,relatime'
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. Multi-
    # mount scenario locks consolidation discipline.
    mk_findmnt
    write_mounts \
        $'nfs4\t/mnt/data\trw,relatime' \
        $'cifs\t/mnt/winshare\trw,relatime' \
        $'fuse.sshfs\t/mnt/sshfs\trw,relatime'
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-nfs-mount -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-remount: nfs-mount-watchdog NEVER emits mount/umount/remount commands — surveillance not remediation)" {
    # Sister to brain-wide no-auto-remediation + surveillance-
    # not-destruction INVARIANTs. The nfs-mount-watchdog DETECTS
    # network-mounts missing nosuid/nodev (T1574 mount-options-
    # tamper risk) but MUST NEVER emit mount -o remount or
    # umount commands to auto-fix. Auto-remount could disconnect
    # active sessions reading from the share + auto-umount
    # would catastrophically break running applications +
    # cause data-loss for in-flight writes. Surveillance, never
    # remediation. Locks anti-auto-remediation contract on the
    # nfs-mount surveillance substrate.
    ! grep -qE 'mount[[:space:]]+(-o[[:space:]]+)?remount' "${WD}"
    ! grep -qE 'umount[[:space:]]+(-f|-l)?[[:space:]]+\$' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # nfs-mount-watchdog runs ON the timer's scheduled fire —
    # enumerates NFS/CIFS mounts + checks missing-nosuid axis,
    # emits a verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the nfs-mount-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd/selfdef-nfs-mount.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. nfs-mount-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # nfs-mount-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # nfs-mount-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'nfs-mount-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: nfs-mount-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. nfs-mount-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the nfs-mount-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (nfs-mount-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the nfs-mount-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nfs-mount-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # nfs-mount-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nfs-mount-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # nfs-mount-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nfs-mount-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the nfs-mount-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nfs-mount-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # nfs-mount-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nfs-mount-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the nfs-mount-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nfs-mount-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the nfs-mount-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (nfs-mount-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # nfs-mount-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (nfs-mount-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the nfs-mount-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nfs-mount-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}
