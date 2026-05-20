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
