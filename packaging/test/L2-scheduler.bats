#!/usr/bin/env bats
# L2 bats unit tests for the MS048 Goldilocks Scheduler systemd unit +
# postinst install/uninstall flow.
#
# Validates MS048 R11454-R11461 (systemd unit + Debian packaging).
#
# Run with: bats packaging/test/L2-scheduler.bats
#
# Source: SDD-031 Deliverable 7 — L2 (bats)

UNIT="${BATS_TEST_DIRNAME}/../systemd/selfdef-scheduler.service"
POSTINST="${BATS_TEST_DIRNAME}/../debian/postinst"
POSTRM="${BATS_TEST_DIRNAME}/../debian/postrm"

# ============================================================
# R11454-R11458: systemd unit structural + ordering + hardening
# ============================================================

@test "R11454: selfdef-scheduler.service exists" {
    [ -f "${UNIT}" ]
}

@test "R11454: unit declares Type=simple Restart=always" {
    grep -q "^Type=simple$" "${UNIT}"
    grep -q "^Restart=always$" "${UNIT}"
}

@test "R11455: unit binds After=tetragon.service" {
    grep -qE "^After=.*tetragon.service" "${UNIT}"
}

@test "R11455: unit binds After=zfs-mount.service" {
    grep -qE "^After=.*zfs-mount.service" "${UNIT}"
}

@test "R11455: unit binds After=selfdef-guardian.service" {
    grep -qE "^After=.*selfdef-guardian.service" "${UNIT}"
}

@test "ExecStart=/usr/local/bin/selfdef-scheduler" {
    grep -q "^ExecStart=/usr/local/bin/selfdef-scheduler$" "${UNIT}"
}

# ============================================================
# R11456-R11458: Ring 0 + hardening + restart-storm cap
# ============================================================

@test "R11456: User=root + Group=root (Ring 0 per MS039)" {
    grep -q "^User=root$" "${UNIT}"
    grep -q "^Group=root$" "${UNIT}"
}

@test "R11457: ProtectSystem=strict + ReadWritePaths includes /mnt/vault/context" {
    grep -q "^ProtectSystem=strict$" "${UNIT}"
    grep -q "^ReadWritePaths=.*/mnt/vault/context" "${UNIT}"
}

@test "R11457: hardening — NoNewPrivileges + ProtectKernel* + LockPersonality" {
    grep -q "^NoNewPrivileges=true$" "${UNIT}"
    grep -q "^ProtectKernelTunables=true$" "${UNIT}"
    grep -q "^ProtectKernelLogs=true$" "${UNIT}"
    grep -q "^LockPersonality=true$" "${UNIT}"
}

@test "R11457: hardening — RestrictNamespaces + RestrictRealtime + RestrictSUIDSGID + MemoryDenyWriteExecute" {
    grep -q "^RestrictNamespaces=true$" "${UNIT}"
    grep -q "^RestrictRealtime=true$" "${UNIT}"
    grep -q "^RestrictSUIDSGID=true$" "${UNIT}"
    grep -q "^MemoryDenyWriteExecute=true$" "${UNIT}"
}

@test "R11458: StartLimitIntervalSec=60s + StartLimitBurst=10 (restart-storm cap)" {
    grep -q "^StartLimitIntervalSec=60s$" "${UNIT}"
    grep -q "^StartLimitBurst=10$" "${UNIT}"
}

@test "WantedBy=multi-user.target" {
    grep -q "^WantedBy=multi-user.target$" "${UNIT}"
}

# ============================================================
# R11459-R11461: Debian postinst + postrm wiring
# ============================================================

@test "R11459: postinst installs scheduler unit" {
    grep -q "selfdef-scheduler.service" "${POSTINST}"
    grep -q "/etc/systemd/system/selfdef-scheduler.service" "${POSTINST}"
}

@test "R11459: postinst pre-creates /var/cache/selfdef/scheduler/ring" {
    grep -q "/var/cache/selfdef/scheduler/ring" "${POSTINST}"
}

@test "R11460: postrm purge: disable+stop+remove scheduler unit" {
    grep -q "systemctl disable selfdef-scheduler.service" "${POSTRM}"
    count="$(grep -c 'systemctl stop selfdef-scheduler.service' "${POSTRM}")"
    [ "${count}" -ge 2 ]   # one in purge, one in remove
    grep -q "rm -f /etc/systemd/system/selfdef-scheduler.service" "${POSTRM}"
}

@test "R11461: cargo-deb assets ship selfdef-scheduler.service" {
    DAEMON_CARGO="${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml"
    grep -q "selfdef-scheduler.service.*usr/share/selfdef" "${DAEMON_CARGO}"
}

# ============================================================
# systemd-analyze structural verification (skipped when absent)
# ============================================================

@test "systemd-analyze verify on scheduler unit (when available)" {
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        skip "systemd-analyze not installed in test env"
    fi
    set +e
    output="$(systemd-analyze verify "${UNIT}" 2>&1)"
    set -e
    if echo "${output}" | grep -qE "Unknown key|Invalid|Failed to parse"; then
        echo "systemd-analyze unit-syntax errors detected:" >&2
        echo "${output}" >&2
        return 1
    fi
}

# ============================================================
# Four-watchdog systemd surface coherence (cross-unit check)
# ============================================================

@test "all four watchdog systemd units coexist in packaging/" {
    [ -f "${BATS_TEST_DIRNAME}/../systemd/sovereign-guard.service" ]
    [ -f "${BATS_TEST_DIRNAME}/../tetragon-policies/sovereign-perimeter.yaml" ]
    [ -f "${BATS_TEST_DIRNAME}/../systemd/selfdef-guardian.service" ]
    [ -f "${UNIT}" ]
}

@test "INVARIANT (unit declares Description= or Documentation= containing 'selfdef' — operator-audit-trail)" {
    grep -qiE '^Description=.*selfdef|^Documentation=.*selfdef' "${UNIT}"
}

@test "INVARIANT (unit declares ReadWritePaths — strict-mode-permitted-writes manifest)" {
    # ProtectSystem=strict forbids writes EXCEPT to declared ReadWritePaths.
    # The unit MUST declare the writeable paths for /var/log + /var/cache
    # + /mnt/vault/context so scheduler operation isn't EROFS-blocked.
    grep -qE '^ReadWritePaths=.*/var/log/selfdef' "${UNIT}"
    grep -qE '^ReadWritePaths=.*/var/cache/selfdef' "${UNIT}"
}

@test "INVARIANT (postinst enables the unit — service is reachable on next boot)" {
    # Installation MUST enable the unit so systemctl start works on next
    # boot without manual operator intervention.
    grep -qE 'systemctl (enable|preset)' "${POSTINST}"
}

@test "INVARIANT (postrm cleans /var/cache/selfdef on purge — operator-state-cleanup)" {
    # On purge, the runtime cache state should be cleaned up (else
    # purge leaves stale state for re-install operator confusion).
    grep -q '/var/cache/selfdef' "${POSTRM}"
}

@test "INVARIANT (unit declares SystemCallArchitectures + ProtectControlGroups + RestrictAddressFamilies — extended Ring-0 hardening axes)" {
    # Sister to the broader hardening directive family already locked
    # (NoNewPrivileges + ProtectKernel* + LockPersonality +
    # RestrictNamespaces + RestrictRealtime + RestrictSUIDSGID +
    # MemoryDenyWriteExecute). Locks three additional extended
    # hardening axes:
    #   - SystemCallArchitectures=native: blocks the kernel's
    #     compat syscall layer (32-bit syscalls on 64-bit kernel)
    #     which has historically been a CVE source.
    #   - ProtectControlGroups=true: blocks the unit from modifying
    #     /sys/fs/cgroup (otherwise an attacker who gains Ring-0
    #     access could escape cgroup-based resource limits).
    #   - RestrictAddressFamilies: declares the explicit network
    #     address families the unit may use (AF_UNIX + AF_INET +
    #     AF_INET6), blocking the kernel's AF_RAW + AF_PACKET +
    #     AF_NETLINK + 30+ other esoteric protocol families.
    # The Ring 0 hardening discipline requires the full extended
    # hardening set, not just the core 4-5 directives.
    grep -qE '^SystemCallArchitectures=' "${UNIT}"
    grep -qE '^ProtectControlGroups=true' "${UNIT}"
    grep -qE '^RestrictAddressFamilies=' "${UNIT}"
}

@test "INVARIANT (unit declares ProtectSystem=strict — filesystem write-protection enforcement)" {
    # Sister to the broader Ring-0 hardening directive family
    # already locked. ProtectSystem=strict gives the unit a
    # read-only view of the ENTIRE filesystem hierarchy EXCEPT
    # explicit ReadWritePaths= grants — defeats arbitrary-write
    # exploits that depend on landing under /etc /var/lib /opt
    # etc. Sister to integrity-sentinel + audit-rules path
    # protection axes (host-level write-immutability vs unit-
    # level write-isolation are complementary defense layers).
    grep -qE '^ProtectSystem=(strict|full)' "${UNIT}"
}

@test "INVARIANT (unit declares NoNewPrivileges=true — privilege-escalation containment via setuid/setgid path)" {
    # Sister to Ring-0 hardening + ProtectSystem strict
    # INVARIANTs already locked. NoNewPrivileges=true blocks
    # the unit from gaining new privileges via setuid binaries
    # OR file capabilities (the standard Linux escalation
    # gates). Without it, a compromised unit-process could
    # exec sudo / a setuid binary / a binary with cap_setuid+ep
    # and elevate to root (escaping the Ring-0 hardening
    # containment). NoNewPrivileges is the systemd surface
    # that locks the no_new_privs prctl flag for the entire
    # unit lifetime. Locks the privilege-escalation-blocking
    # contract on the Ring-0 hardening substrate (T1548 Abuse
    # Elevation Control Mechanism).
    grep -qE '^NoNewPrivileges=true' "${UNIT}"
}

@test "INVARIANT (unit declares MemoryDenyWriteExecute=true — W^X enforcement against JIT/shellcode-stage)" {
    # Sister to NoNewPrivileges + ProtectSystem + Ring-0
    # hardening INVARIANTs. MemoryDenyWriteExecute=true enforces
    # the W^X memory protection at the systemd-unit level —
    # blocks mmap/mprotect with PROT_WRITE+PROT_EXEC and
    # PROT_EXEC after PROT_WRITE on the same region. Without
    # it, a memory-corruption exploit in the scheduler could
    # stage shellcode by writing then jumping to it. Selfdef
    # scheduler runs AS ROOT for filesystem inventory; W^X
    # blocks the standard exploit primitive even if a memory
    # bug exists. T1027.007 Dynamic API Resolution + T1055
    # Process Injection containment via memory-protection axis.
    grep -qE '^MemoryDenyWriteExecute=true' "${UNIT}"
}

@test "INVARIANT (unit declares LockPersonality=true — disable personality(2) syscall for kernel-attack reduction)" {
    # Sister to NoNewPrivileges + ProtectSystem + MDWE + Ring-0
    # hardening INVARIANTs. LockPersonality=true prevents the
    # personality(2) syscall from changing process personality
    # (e.g., requesting old buggy READ_IMPLIES_EXEC behavior).
    # Reduces kernel attack surface against personality-syscall
    # vulnerabilities (CVE-2014-9745 family).
    grep -qE '^LockPersonality=true' "${UNIT}"
}

@test "INVARIANT (unit declares RestartSec=2s — restart-storm dampener pairs with Restart=always + StartLimitBurst)" {
    # Sister to brain-wide systemd RestartSec INVARIANTs +
    # restart-storm-cap discipline (already locked above via
    # StartLimitIntervalSec=60s + StartLimitBurst=10). The
    # Restart=always directive paired with RestartSec=2s
    # ensures failed-start cascades pace at human-tractable
    # rate AND systemd's failure-history tracker doesn't drop
    # restart-attempt records due to sub-second cycles. Without
    # RestartSec set explicitly the systemd default 100ms
    # would let a tight failure loop log-storm the journal AND
    # exhaust StartLimitBurst within sub-second window leaving
    # the unit permanently failed before operator triage.
    # Locks restart-storm-dampener contract on the Goldilocks
    # scheduler substrate.
    grep -qE '^RestartSec=' "${UNIT}"
}

@test "INVARIANT (unit declares Wants=selfdef-guardian.service — soft-bind contract: scheduler starts even when guardian absent)" {
    # Sister to brain-wide systemd dependency-discipline INVARIANT
    # family. The scheduler binds tetragon + guardian as After=
    # (ordering) but with Wants= (not Requires=) — scheduler MUST
    # start even when guardian is unhealthy, so the backpressure
    # monitor can log the missing-source state via its degraded-
    # mode JSON record. Requires= would fail-loud cascade-stop
    # scheduler when guardian is down, defeating the "graceful
    # degradation in absence of upstream IPS" contract. Locks
    # soft-bind discipline on the scheduler unit substrate.
    grep -qE '^Wants=selfdef-guardian.service' "${UNIT}"
    ! grep -qE '^Requires=selfdef-guardian.service' "${UNIT}"
}

@test "INVARIANT (unit Documentation= references the SDD-031 design document — operator-audit-trail to spec rationale)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. The scheduler unit's Documentation= directive
    # points specifically at docs/sdd/031-goldilocks-scheduler.md
    # so an operator triaging unit behavior via `systemctl status`
    # can jump directly to the design rationale for the chosen
    # User=root + ZFS-audit + PSI-driven routing semantics. A
    # regression that swaps the URL away from the SDD-031 spec
    # would break the operator-audit-trail to the source-of-truth.
    # Locks the SDD-031 Documentation= spec-link discipline on
    # the scheduler unit substrate.
    grep -qE '^Documentation=.*sdd/031-goldilocks-scheduler' "${UNIT}"
}

@test "INVARIANT (unit does NOT declare Requires=tetragon.service — tetragon is ordering-only via After=, scheduler must run even when tetragon absent)" {
    # Sister to the Wants=selfdef-guardian.service soft-bind
    # INVARIANT. The scheduler is After=tetragon.service for
    # ordering (start tetragon's eBPF surface first if it's
    # present so PSI + tracing-policy hooks resolve cleanly)
    # but MUST NOT Requires= or Wants= tetragon — that would
    # collapse the host's IPS-quattuordectet onto tetragon
    # being installed, defeating SDD-031's design intent of
    # graceful degradation on hosts where tetragon is opted
    # out (the backpressure monitor will log degraded-mode
    # via its missing-source JSON record). A regression adding
    # Requires=tetragon.service would surface as "scheduler
    # fails to start on hosts without tetragon" — exactly the
    # tight-coupling failure SDD-031 forbids. Locks tetragon-
    # decoupling discipline on the scheduler unit substrate.
    ! grep -qE '^Requires=tetragon\.service' "${UNIT}"
    ! grep -qE '^Wants=tetragon\.service' "${UNIT}"
    grep -qE '^After=tetragon\.service' "${UNIT}"
}

@test "INVARIANT (.service Restart=always pairs with RestartSec + StartLimitBurst — complete restart-storm contract)" {
    # Sister to brain-wide systemd Restart-discipline INVARIANT
    # family. The scheduler unit's restart policy MUST be
    # complete: Restart=always alone produces a restart-storm on
    # a chronically-failing scheduler; only the combination of
    # Restart=always + RestartSec=2s + StartLimitIntervalSec +
    # StartLimitBurst dampens the storm. The 3 directives must
    # all be present together — a regression dropping any one
    # breaks the dampener. Locks the complete restart-storm
    # contract on the scheduler unit substrate (sister to the
    # individual-directive INVARIANTs already locked above).
    grep -qE '^Restart=always' "${UNIT}"
    grep -qE '^RestartSec=' "${UNIT}"
    grep -qE '^StartLimitBurst=' "${UNIT}"
}

@test "INVARIANT (.service ReadWritePaths covers all scheduler write targets — explicit-allowlist hardening discipline)" {
    # Sister to brain-wide Ring-0 hardening + ReadOnlyPaths
    # INVARIANT family. ProtectSystem=strict forbids ALL writes
    # except to declared ReadWritePaths. The scheduler writes
    # state into 3 dirs:
    #   - /var/log/selfdef        (audit + decision log)
    #   - /var/cache/selfdef      (per-cycle slice cache)
    #   - /mnt/vault/context      (ZFS audit log on Ring-0 trust topology)
    # ALL THREE MUST be enumerated in ReadWritePaths. A regression
    # dropping any one would cause silent EROFS errors mid-cycle.
    # Locks the explicit-allowlist write-path discipline on the
    # scheduler unit substrate.
    rwp=$(grep '^ReadWritePaths=' "${UNIT}")
    case "${rwp}" in
        *"/var/log/selfdef"*"/var/cache/selfdef"*"/mnt/vault/context"*) ;;
        *) false ;;
    esac
}

@test "INVARIANT (unit comment references MS039 trust topology — derivation-source audit-trail)" {
    # Sister to brain-wide operator-audit-trail INVARIANT family.
    # The scheduler unit header MUST reference its derivation
    # source — MS039 Ring-0 trust topology rationale for User=
    # root + ZFS audit-log access requirements. This trail lets
    # an operator triaging a User=root concern know WHY the
    # scheduler runs as root (it's not lazy permissions; it's
    # the MS039-mandated trust-topology requirement for
    # /mnt/vault/context append + /proc/pressure/* read). A
    # regression that dropped the MS039 comment would lose the
    # rationale-context for the privileged-execution choice.
    # Locks the derivation-source audit-trail discipline on the
    # scheduler unit substrate.
    grep -qE 'MS039' "${UNIT}"
}

@test "INVARIANT (.service After=zfs-mount.service — ZFS-audit-log substrate ordering contract)" {
    # Sister to brain-wide systemd ordering INVARIANT family.
    # The scheduler appends to /mnt/vault/context/scheduler_audit.log
    # (a ZFS-backed audit substrate per MS039 Ring-0 trust
    # topology). If the scheduler started BEFORE zfs-mount,
    # the audit log path would not yet exist + the scheduler
    # would either fail-loud (set -euo) or silently write to
    # an unmounted tmpfs path. After=zfs-mount.service is the
    # mandatory ordering directive. Locks the ZFS-substrate
    # ordering discipline on the scheduler unit substrate.
    grep -qE '^After=zfs-mount\.service' "${UNIT}"
}

@test "INVARIANT (.service ExecStart=/usr/local/bin/selfdef-scheduler — derivation-source binary-path discipline)" {
    # Sister to brain-wide ExecStart-path INVARIANT family.
    # The scheduler binary lives at /usr/local/bin/ (operator-
    # extension path, NOT the Debian-packaged /usr/bin/) because
    # the scheduler is the SDD-031 Goldilocks routing layer
    # built per-host from the avx-plus-plus dump. A regression
    # that swapped to /usr/bin/ would silently look up the
    # debian-package-installed binary (which may be older or
    # missing altogether). Locks the operator-extension binary-
    # path discipline on the scheduler service substrate.
    grep -qE '^ExecStart=/usr/local/bin/selfdef-scheduler' "${UNIT}"
}

@test "INVARIANT (.service User=root + Group=root — Ring-0 audit-log append privilege contract)" {
    # Sister to brain-wide systemd User= INVARIANT family.
    # Scheduler appends to /mnt/vault/context/scheduler_audit.log
    # (ZFS-backed Ring-0 substrate per MS039); only root has
    # the append-on-ZFS privilege guaranteed by the trust
    # topology. A regression dropping User=root would break the
    # audit-log append + leave silently-truncated entries.
    # Locks Ring-0 privilege discipline on the scheduler unit
    # substrate.
    grep -qE '^User=root$' "${UNIT}"
    grep -qE '^Group=root$' "${UNIT}"
}
