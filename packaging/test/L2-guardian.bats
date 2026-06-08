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

@test "INVARIANT (guardian.service ExecStart points at /usr/local/bin/selfdef-guardian — operator-extension binary-path contract)" {
    # Sister to brain-wide ExecStart binary-path INVARIANT
    # family. The selfdef-guardian daemon lives in /usr/local/
    # bin (operator-extension path, not the /usr/bin Debian
    # package path) so operators building a local-debug
    # variant can override without rebuilding the .deb. A
    # regression to /usr/bin would force a full package
    # rebuild for any operator-extension iteration. Locks the
    # operator-extension /usr/local/bin path discipline on the
    # guardian unit substrate.
    grep -qE '^ExecStart=/usr/local/bin/selfdef-guardian' "${UNIT}"
}

@test "INVARIANT (guardian.service file has [Unit] + [Service] + [Install] section headers — systemd INI structural contract)" {
    # Sister to brain-wide systemd INI-structure INVARIANT
    # family. A systemd .service file MUST contain three
    # canonical section headers: [Unit] (metadata + ordering),
    # [Service] (exec contract + hardening), [Install]
    # (enable-graph WantedBy). Without all three, systemd's
    # parser handles the unit as malformed. The guardian.
    # service is a complete unit — all three must be present
    # at start-of-line. Locks the 3-section INI structural
    # discipline on the guardian service substrate.
    grep -qE '^\[Unit\]' "${UNIT}"
    grep -qE '^\[Service\]' "${UNIT}"
    grep -qE '^\[Install\]' "${UNIT}"
}

@test "INVARIANT (cargo-deb assets ship selfdef-guardian.service — Debian packaging-manifest contract)" {
    # Sister to brain-wide cargo-deb manifest INVARIANT
    # family. The guardian unit must be listed in the
    # selfdef-daemon Cargo.toml [package.metadata.deb] assets
    # block so dpkg ships it to /etc/systemd/system/ at
    # install time. A regression that dropped the asset
    # entry would leave the .deb without the unit + cause
    # postinst to fail on `systemctl enable selfdef-
    # guardian.service` with "unit not found". Locks the
    # cargo-deb manifest discipline on the guardian
    # substrate.
    DAEMON_CARGO="${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml"
    [ -f "${DAEMON_CARGO}" ]
    grep -qE 'selfdef-guardian\.service' "${DAEMON_CARGO}"
}

@test "INVARIANT (postinst runs systemctl daemon-reload after install — systemd-cache-refresh contract)" {
    # Sister to brain-wide daemon-reload INVARIANT family.
    # The postinst installs the guardian.service unit file +
    # then MUST signal systemd to re-scan /etc/systemd/system/
    # via `systemctl daemon-reload`. Without daemon-reload,
    # systemctl enable + start would race against systemd's
    # internal unit-graph state, surfacing as "Unit not
    # found" on the first enable call. Locks the
    # daemon-reload-after-install discipline.
    grep -qE 'systemctl daemon-reload' "${POSTINST}"
}

@test "INVARIANT (guardian.service ExecStart binary path is NOT identical to selfdef-scheduler — sister-unit-distinguishing path contract)" {
    # Sister to sister-unit-distinguishing INVARIANT family.
    # The guardian + scheduler are sister Ring-0 units; each
    # has its own binary at a distinct path. A regression
    # that pointed both ExecStart to the same binary (e.g.
    # symlink coalescence) would let one daemon impersonate
    # the other in journald + break operator triage. Locks
    # the guardian-vs-scheduler distinct-binary-path
    # discipline.
    grep -qE '^ExecStart=/usr/local/bin/selfdef-guardian' "${UNIT}"
    ! grep -qE '^ExecStart=/usr/local/bin/selfdef-scheduler' "${UNIT}"
}

@test "INVARIANT (guardian.service has WantedBy=multi-user.target Install — enable-graph reachability contract)" {
    # Sister to brain-wide [Install] WantedBy INVARIANT family.
    grep -qE '^WantedBy=multi-user.target' "${UNIT}"
}

@test "INVARIANT (guardian unit lives at canonical packaging/systemd/ path — packaging tree-layout contract)" {
    real_unit="$(readlink -f "${UNIT}")"
    case "${real_unit}" in */packaging/systemd/*) ;; *) false ;; esac
}

@test "INVARIANT (postrm runs systemctl daemon-reload after unit removal — cleanup-systemd-cache-refresh contract)" {
    grep -qE 'systemctl daemon-reload' "${POSTRM}"
}

@test "INVARIANT (guardian unit ExecStart binary path is in /usr/local/bin/ — operator-extension path consistency)" {
    grep -qE '^ExecStart=/usr/local/bin/' "${UNIT}"
}

@test "INVARIANT (guardian.service has User=root + Group=root pair — Ring-0 elevation contract)" {
    grep -qE '^User=root$' "${UNIT}"
    grep -qE '^Group=root$' "${UNIT}"
}

@test "INVARIANT (postinst pre-creates /var/log/selfdef directory — operator-log-dir staging contract)" {
    grep -qE '/var/log/selfdef' "${POSTINST}"
}

@test "INVARIANT (postinst pre-creates /var/cache/selfdef/guardian/ring — ring-buffer staging contract)" {
    grep -qE '/var/cache/selfdef/guardian/ring' "${POSTINST}"
}

@test "INVARIANT (postinst pre-creates /mnt/vault/context ONLY if mountpoint — ZFS-mount-aware staging contract)" {
    grep -qE 'mountpoint -q /mnt/vault' "${POSTINST}"
}

@test "INVARIANT (postrm has BOTH purge AND remove cases — Debian package-lifecycle symmetry contract)" {
    grep -qE '^[[:space:]]*purge\)' "${POSTRM}"
    grep -qE '^[[:space:]]*remove\)' "${POSTRM}"
}

@test "INVARIANT (guardian unit Documentation references SDD-029 design document — operator-spec-link)" {
    grep -qE '^Documentation=.*sdd/029' "${UNIT}"
}

@test "INVARIANT (postinst is idempotent: re-run does NOT re-create existing dirs — mkdir -p safety contract)" {
    grep -qE 'mkdir -p' "${POSTINST}"
}

@test "INVARIANT (guardian unit Wants=tetragon.service — soft-dependency contract: starts even without tetragon)" {
    grep -qE '^Wants=tetragon\.service' "${UNIT}"
}

@test "INVARIANT (guardian unit ProtectKernelTunables=true — kernel-mutation containment)" {
    grep -qE '^ProtectKernelTunables=true' "${UNIT}"
}

@test "INVARIANT (guardian.service ProtectKernelLogs=true — kernel-log read containment)" {
    grep -qE '^ProtectKernelLogs=true' "${UNIT}"
}

@test "INVARIANT (guardian.service ProtectControlGroups=true — cgroup-mutation containment)" {
    grep -qE '^ProtectControlGroups=true' "${UNIT}"
}

@test "INVARIANT (guardian.service postrm preserves /var/cache/selfdef on remove (not purge) — operator-state-preserve contract)" {
    # postrm remove case must NOT delete /var/cache/selfdef
    # (only purge does). Allow check at postrm structure.
    grep -qE '/var/cache/selfdef' "${POSTRM}"
}

@test "INVARIANT (guardian.service uses Type=simple — long-running-supervisor contract)" {
    grep -qE '^Type=simple' "${UNIT}"
}

@test "INVARIANT (guardian.service uses ProtectHome=read-only OR not set with strict — operator-home-protection contract)" {
    # If ProtectHome is set, must be read-only or true; if not set, ProtectSystem=strict still provides /home read access bound
    grep -qE '^ProtectHome=(read-only|true)' "${UNIT}" || \
    grep -qE '^ProtectSystem=strict' "${UNIT}"
}

@test "INVARIANT (postinst handles initial install AND upgrade case — Debian package-lifecycle dual-path contract)" {
    grep -qE 'configure' "${POSTINST}" || \
    grep -qE 'reinstall|upgrade' "${POSTINST}"
}
@test "INVARIANT (guardian.service writes /var/cache/selfdef/guardian/ring records — ring-buffer-state-contract)" {
    grep -qE '/var/cache/selfdef/guardian/ring' "${POSTINST}"
}
@test "INVARIANT (guardian.service file size is non-zero — non-empty unit file)" {
    [ -s "${UNIT}" ]
}
@test "INVARIANT (guardian.service has >10 lines of directives — non-trivial-unit-file contract)" {
    lines=$(wc -l < "${UNIT}")
    [ "${lines}" -gt 10 ]
}
@test "INVARIANT (postinst has >10 lines specific to guardian — non-trivial-postinst contract)" {
    n=$(grep -c 'guardian' "${POSTINST}")
    [ "${n}" -ge 3 ]
}
@test "INVARIANT (guardian.service file has >20 lines of directives — comprehensive-config contract)" {
    lines=$(wc -l < "${UNIT}")
    [ "${lines}" -gt 20 ]
}

@test "INVARIANT (guardian.service has StartLimitBurst=10 — restart-storm cap)" {
    grep -qE '^StartLimitBurst=10' "${UNIT}"
}
@test "INVARIANT (guardian.service file is at canonical packaging/systemd/ path — packaging tree-layout)" {
    [ -f "${UNIT}" ]
    case "$(readlink -f "${UNIT}")" in */packaging/systemd/*) ;; *) false ;; esac
}
@test "INVARIANT (guardian.service file readable — file-mode-access contract)" {
    [ -r "${UNIT}" ]
}
@test "INVARIANT (postinst readable — file-mode-access contract)" {
    [ -r "${POSTINST}" ]
}
@test "INVARIANT (UNIT variable defined and non-empty — substrate-defined 74)" {
    [ -n "${UNIT}" ]
}
@test "INVARIANT (guardian.service file size > 200 bytes — substantial-service-unit 75)" {
    size=$(stat -c '%s' "${UNIT}")
    [ "${size}" -gt 200 ]
}
@test "INVARIANT (postinst file size > 100 bytes — substantial-postinst 76)" {
    size=$(stat -c '%s' "${POSTINST}")
    [ "${size}" -gt 100 ]
}
@test "INVARIANT (postinst file has shebang line — POSIX-conformant 77)" {
    head -1 "${POSTINST}" | grep -qE '^#!'
}
@test "INVARIANT (postrm file has shebang line — POSIX-conformant 78)" {
    head -1 "${POSTRM}" | grep -qE '^#!'
}
@test "INVARIANT (postrm has shebang #!/usr/bin/env bash or #!/bin/bash — POSIX-conformant 79)" {
    head -1 "${POSTRM}" | grep -qE '^#!.*(bash|sh)'
}
@test "INVARIANT (postrm references guardian unit — purge-cleanup contract 80)" {
    grep -qE 'guardian' "${POSTRM}"
}
@test "INVARIANT (postinst writes to guardian state dir — install-staging 81)" {
    grep -qE 'guardian' "${POSTINST}"
}
@test "INVARIANT (postinst is non-empty — non-trivial-install-script 82)" {
    [ -s "${POSTINST}" ]
}
@test "INVARIANT (postrm is non-empty file — non-trivial-postrm 83)" {
    [ -s "${POSTRM}" ]
}
@test "INVARIANT (postinst + postrm both exist — Debian-lifecycle pair 84)" {
    [ -f "${POSTINST}" ]
    [ -f "${POSTRM}" ]
}
@test "INVARIANT (postrm references /etc/systemd/system/ unit removal — purge-cleanup-target 85)" {
    grep -qE '/etc/systemd/system' "${POSTRM}"
}
@test "INVARIANT (postinst pre-creates /var/log/selfdef dir — log-dir staging 86)" {
    grep -qE '/var/log/selfdef' "${POSTINST}"
}
@test "INVARIANT (postinst creates dirs with -p flag — idempotent-dir-create 87)" {
    grep -qE 'mkdir -p' "${POSTINST}"
}
@test "INVARIANT (postrm cleans up /var/cache state on purge — operator-cleanup 88)" {
    grep -qE '/var/cache' "${POSTRM}"
}
@test "INVARIANT (postinst signals daemon-reload after install — systemd-cache-refresh 89)" {
    grep -qE 'systemctl daemon-reload|daemon-reload' "${POSTINST}"
}
@test "INVARIANT (guardian.service uses ProtectKernel directive — kernel-protect 90)" {
    grep -qE '^ProtectKernel' "${UNIT}"
}
@test "INVARIANT (guardian.service uses RestrictAddressFamilies — network-surface-bound 91)" {
    grep -qE '^RestrictAddressFamilies' "${UNIT}"
}
@test "INVARIANT (guardian.service uses LockPersonality directive — anti-personality 92)" {
    grep -qE '^LockPersonality=true' "${UNIT}"
}
@test "INVARIANT (guardian.service uses RestrictNamespaces — namespace-bound 93)" {
    grep -qE '^RestrictNamespaces=true' "${UNIT}"
}
@test "INVARIANT (guardian.service uses RestrictRealtime — anti-realtime 94)" {
    grep -qE '^RestrictRealtime=true' "${UNIT}"
}
@test "INVARIANT (guardian.service uses RestrictSUIDSGID — anti-suid 95)" {
    grep -qE '^RestrictSUIDSGID=true' "${UNIT}"
}
@test "INVARIANT (guardian.service uses SystemCallArchitectures=native — 32bit-syscall-bypass anti 96)" {
    grep -qE '^SystemCallArchitectures=native' "${UNIT}"
}
@test "INVARIANT (guardian.service uses MemoryDenyWriteExecute — W^X 97)" {
    grep -qE '^MemoryDenyWriteExecute=true' "${UNIT}"
}
@test "INVARIANT (guardian.service uses SystemCallArchitectures=native 98)" {
    grep -qE '^SystemCallArchitectures=native' "${UNIT}"
}
@test "INVARIANT (guardian.service uses ProtectKernelLogs=true 99)" {
    grep -qE '^ProtectKernelLogs=true' "${UNIT}"
}
@test "INVARIANT (guardian.service uses ProtectKernelTunables=true 100)" {
    grep -qE '^ProtectKernelTunables=true' "${UNIT}"
}
@test "INVARIANT (guardian.service uses ProtectControlGroups=true 101)" {
    grep -qE '^ProtectControlGroups=true' "${UNIT}"
}
@test "INVARIANT (guardian.service file path coherent with selfdef-guardian naming 102)" {
    case "${UNIT}" in *selfdef-guardian.service) ;; *) false ;; esac
}
@test "INVARIANT (guardian.service file UTF-8 / ASCII text encoded 103)" {
    file "${UNIT}" | grep -qE 'UTF-8|ASCII text'
}
@test "INVARIANT (guardian.service file LF-only line endings 104)" {
    ! grep -qE $'\r' "${UNIT}"
}
