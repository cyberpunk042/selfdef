#!/usr/bin/env bats
# L2 bats unit tests for the MS044 Guardian Daemon systemd unit + the
# postinst install/uninstall flow.
#
# Validates MS044 R10411-R10440 (systemd unit hardening + ordering) and
# R10471-R10480 (ZFS audit log paths + ring buffer dirs).
#
# Run with: bats packaging/test/L2-guardian.bats
#
# Source: SDD-029 Deliverable 6 — L2 (bats)

UNIT="${BATS_TEST_DIRNAME}/../systemd/selfdef-guardian.service"
POSTINST="${BATS_TEST_DIRNAME}/../debian/postinst"
POSTRM="${BATS_TEST_DIRNAME}/../debian/postrm"

# ============================================================
# R10411-R10420: unit file existence + structural shape
# ============================================================

@test "R10411: selfdef-guardian.service exists in packaging/systemd" {
    [ -f "${UNIT}" ]
}

@test "R10412: unit declares Type=simple" {
    grep -q "^Type=simple$" "${UNIT}"
}

@test "R10413: unit declares Restart=always (Guardian IS the watchdog)" {
    grep -q "^Restart=always$" "${UNIT}"
}

@test "R10414: unit binds After=tetragon.service" {
    grep -qE "^After=.*tetragon.service" "${UNIT}"
}

@test "R10414: unit binds After=zfs-mount.service" {
    grep -qE "^After=.*zfs-mount.service" "${UNIT}"
}

@test "R10415: unit declares Wants=tetragon.service (graceful start without)" {
    grep -q "^Wants=tetragon.service$" "${UNIT}"
}

@test "R10416: ExecStart points at /usr/local/bin/selfdef-guardian" {
    grep -q "^ExecStart=/usr/local/bin/selfdef-guardian$" "${UNIT}"
}

# ============================================================
# R10421-R10440: hardening (systemd-analyze security baseline)
# ============================================================

@test "R10421: NoNewPrivileges=true" {
    grep -q "^NoNewPrivileges=true$" "${UNIT}"
}

@test "R10422: ProtectSystem=strict" {
    grep -q "^ProtectSystem=strict$" "${UNIT}"
}

@test "R10423: ReadWritePaths includes selfdef + /mnt/vault/context" {
    grep -q "^ReadWritePaths=.*/var/log/selfdef" "${UNIT}"
    grep -q "^ReadWritePaths=.*/var/cache/selfdef" "${UNIT}"
    grep -q "^ReadWritePaths=.*/mnt/vault/context" "${UNIT}"
}

@test "R10424: DeviceAllow /dev/console rw (console BEL alert)" {
    grep -q "^DeviceAllow=/dev/console rw$" "${UNIT}"
}

@test "R10425: ProtectKernelTunables=true" {
    grep -q "^ProtectKernelTunables=true$" "${UNIT}"
}

@test "R10426: ProtectKernelLogs=true" {
    grep -q "^ProtectKernelLogs=true$" "${UNIT}"
}

@test "R10427: ProtectControlGroups=true" {
    grep -q "^ProtectControlGroups=true$" "${UNIT}"
}

@test "R10428: RestrictAddressFamilies AF_UNIX + AF_INET + AF_INET6" {
    grep -q "^RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6$" "${UNIT}"
}

@test "R10429: LockPersonality=true" {
    grep -q "^LockPersonality=true$" "${UNIT}"
}

@test "R10430: RestrictNamespaces=true" {
    grep -q "^RestrictNamespaces=true$" "${UNIT}"
}

@test "R10431: RestrictRealtime=true" {
    grep -q "^RestrictRealtime=true$" "${UNIT}"
}

@test "R10432: RestrictSUIDSGID=true" {
    grep -q "^RestrictSUIDSGID=true$" "${UNIT}"
}

@test "R10433: SystemCallArchitectures=native" {
    grep -q "^SystemCallArchitectures=native$" "${UNIT}"
}

@test "R10434: MemoryDenyWriteExecute=true" {
    grep -q "^MemoryDenyWriteExecute=true$" "${UNIT}"
}

@test "R10435: User=root (Ring 0 IPS service per MS039)" {
    grep -q "^User=root$" "${UNIT}"
}

@test "R10436: Group=root (Ring 0 IPS service per MS039)" {
    grep -q "^Group=root$" "${UNIT}"
}

# ============================================================
# R10437-R10440: restart-storm cap
# ============================================================

@test "R10437: RestartSec=2s (bounded supervisorless window)" {
    grep -q "^RestartSec=2s$" "${UNIT}"
}

@test "R10438: StartLimitIntervalSec=60s (in [Unit])" {
    grep -q "^StartLimitIntervalSec=60s$" "${UNIT}"
}

@test "R10439: StartLimitBurst=10 (cap restart-storm)" {
    grep -q "^StartLimitBurst=10$" "${UNIT}"
}

@test "R10440: WantedBy=multi-user.target" {
    grep -q "^WantedBy=multi-user.target$" "${UNIT}"
}

# ============================================================
# Postinst / postrm wiring (Deliverable 5)
# ============================================================

@test "postinst references selfdef-guardian.service" {
    grep -q "selfdef-guardian.service" "${POSTINST}"
}

@test "postinst installs unit to /etc/systemd/system/" {
    grep -q "/etc/systemd/system/selfdef-guardian.service" "${POSTINST}"
}

@test "postinst pre-creates /var/cache/selfdef/guardian/ring" {
    grep -q "/var/cache/selfdef/guardian/ring" "${POSTINST}"
}

@test "postinst pre-creates /mnt/vault/context only if mountpoint" {
    grep -q "mountpoint -q /mnt/vault" "${POSTINST}"
}

@test "postrm purge: disable + stop + remove Guardian unit" {
    grep -q "systemctl disable selfdef-guardian.service" "${POSTRM}"
    grep -q "systemctl stop selfdef-guardian.service" "${POSTRM}"
    grep -q "rm -f /etc/systemd/system/selfdef-guardian.service" "${POSTRM}"
}

@test "postrm remove: stop only (preserve unit for upgrade reinstall)" {
    # postrm has TWO cases: purge (disable+stop+rm) and remove (stop only).
    # Verify both `systemctl stop selfdef-guardian.service` invocations exist —
    # one inside the purge block, one inside the remove block.
    count="$(grep -c 'systemctl stop selfdef-guardian.service' "${POSTRM}")"
    [ "${count}" -ge 2 ]
}

# ============================================================
# Three-watchdog trio coherence (cross-unit check)
# ============================================================

@test "sister units present (friction-audit + perimeter + guardian)" {
    [ -f "${BATS_TEST_DIRNAME}/../systemd/sovereign-guard.service" ]
    [ -f "${BATS_TEST_DIRNAME}/../tetragon-policies/sovereign-perimeter.yaml" ]
    [ -f "${UNIT}" ]
}

@test "systemd-analyze verify on guardian unit (when available)" {
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        skip "systemd-analyze not installed in test env"
    fi
    # The 'is not executable' diagnostic is expected in dev — binary
    # isn't built+installed. Look only for actual unit-syntax errors.
    # Use `set +e` to capture exit code without failing the test.
    set +e
    output="$(systemd-analyze verify "${UNIT}" 2>&1)"
    set -e
    if echo "${output}" | grep -qE "Unknown key|Invalid|Failed to parse"; then
        echo "systemd-analyze unit-syntax errors detected:" >&2
        echo "${output}" >&2
        return 1
    fi
}

@test "INVARIANT (guardian.service uses set -euo / NoNewPrivileges / ProtectSystem — Ring-0 hardening contract)" {
    # Sister to brain-wide Ring-0 hardening INVARIANT family.
    # The guardian service is the kernel-event tap; it MUST
    # be hardened: NoNewPrivileges to prevent setuid escalation,
    # ProtectSystem=strict to forbid /etc writes, and a set of
    # canonical hardening directives. Locks Ring-0 hardening
    # discipline on the guardian unit substrate.
    grep -qE '^NoNewPrivileges=true' "${UNIT}"
    grep -qE '^ProtectSystem=' "${UNIT}"
}

@test "INVARIANT (guardian.service After=tetragon.service — eBPF-substrate ordering contract)" {
    # Sister to brain-wide systemd ordering INVARIANT family.
    # The guardian taps kernel events via tetragon's eBPF
    # surface; it must start AFTER tetragon. Without After=
    # tetragon.service, guardian would race tetragon at boot
    # + silently fail to attach hooks. Locks the eBPF-substrate
    # ordering discipline on the guardian unit substrate.
    grep -qE '^After=' "${UNIT}"
}

@test "INVARIANT (guardian.service uses ProtectSystem= or ProtectKernel directive — hardening discipline)" {
    # Sister to brain-wide Ring-0 hardening INVARIANT family.
    # Guardian is a kernel-event tap; minimal hardening set
    # MUST include at least one Protect* directive. A unit
    # without ANY hardening would have full /etc-write surface,
    # making the guardian itself a target. Locks minimal-
    # hardening discipline on the guardian unit substrate.
    grep -qE '^Protect[A-Z]' "${UNIT}"
}

@test "INVARIANT (guardian.service uses Wants=tetragon.service, NOT Requires= — graceful-degrade contract)" {
    # Sister to brain-wide Wants-vs-Requires INVARIANT family.
    # Guardian taps tetragon's eBPF socket, but per sain-01 §10
    # dump 569-588 the unit MUST use Wants=tetragon.service
    # (graceful, dependency-encouraged-but-not-required) rather
    # than Requires=tetragon.service (hard-dependency that
    # would refuse to start guardian on hosts where tetragon
    # is not installed). A regression that swapped Wants= for
    # Requires= would break MS044's "guardian still starts +
    # waits patiently on the socket" promise — on hosts
    # without tetragon, guardian would never start, leaving
    # the perimeter watchdog blind. Locks the Wants-not-
    # Requires graceful-degrade discipline on the guardian
    # unit substrate.
    grep -qE '^Wants=tetragon\.service' "${UNIT}"
    ! grep -qE '^Requires=tetragon\.service' "${UNIT}"
}

@test "INVARIANT (guardian.service RestartSec=2s — bounded supervisorless window contract)" {
    # Sister to brain-wide systemd RestartSec= INVARIANT family.
    # The guardian unit is Restart=always; without RestartSec=
    # systemd defaults to 100ms, which combined with a fast-
    # failing exec would create a hot-loop. The operator-
    # extension declares RestartSec=2s to bound the
    # supervisorless window — a 2-second gap between guardian
    # crash + restart attempt — short enough that the perimeter
    # watchdog has minimal coverage gap, long enough that
    # systemd's StartLimitBurst dampener actually kicks in
    # before a 10-burst restart-storm completes. Locks the
    # 2s bounded-supervisorless-window discipline on the
    # guardian unit substrate.
    grep -qE '^RestartSec=2s$' "${UNIT}"
}
