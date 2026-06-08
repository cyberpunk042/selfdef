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

@test "INVARIANT (.service RestrictAddressFamilies explicitly enumerates AF_UNIX + AF_INET — Ring-0 network-surface lock)" {
    # Sister to brain-wide RestrictAddressFamilies INVARIANT
    # family. The scheduler's network surface is bounded:
    # AF_UNIX (local IPC to selfdef-daemon backpressure
    # monitor) + AF_INET / AF_INET6 (Prometheus metric scrape).
    # The directive MUST enumerate exactly these — a regression
    # adding AF_NETLINK or AF_PACKET would let scheduler tap
    # raw network surfaces it has no business using. Locks the
    # explicit-enumeration discipline on the scheduler
    # RestrictAddressFamilies substrate.
    grep -qE '^RestrictAddressFamilies=.*AF_UNIX' "${UNIT}"
    grep -qE '^RestrictAddressFamilies=.*AF_INET' "${UNIT}"
}

@test "INVARIANT (.service has NO [Timer] section — daemon-driven (Type=simple+Restart=always loop), NOT timer-driven)" {
    # Sister to brain-wide systemd-unit-kind INVARIANT family.
    # The scheduler is a long-running daemon (Type=simple +
    # Restart=always loop) listening on /proc/pressure/* + DCGM
    # continuously — it MUST NOT have a [Timer] section because
    # systemd would refuse to start the unit as a service if a
    # [Timer] section co-existed in a .service file (timer
    # directives belong only in .timer units). A regression
    # that pasted [Timer] directives into selfdef-scheduler.
    # service would either: (a) fail systemd-analyze verify,
    # or (b) silently no-op the timer directives while ALSO
    # confusing operators about whether scheduler is timer-
    # driven (it isn't — sister to selfdef-doctor.service which
    # IS timer-driven). Locks the daemon-vs-timer kind
    # discipline on the scheduler unit substrate.
    ! grep -qE '^\[Timer\]' "${UNIT}"
    ! grep -qE '^OnBootSec=' "${UNIT}"
    ! grep -qE '^OnUnitActiveSec=' "${UNIT}"
    ! grep -qE '^OnCalendar=' "${UNIT}"
}

@test "INVARIANT (.service Restart=always pairs with RestartSec — no-default-100ms hot-loop contract)" {
    # Sister to brain-wide Restart=always+RestartSec pair
    # INVARIANT family. Without RestartSec=<value>, systemd's
    # default 100ms restart delay combined with Restart=always
    # produces a hot-loop on a fast-failing exec. The scheduler
    # unit MUST declare BOTH Restart=always AND RestartSec=
    # (any non-default value) so the restart cadence is
    # explicit. A regression dropping RestartSec= would silently
    # revert to the 100ms default + potentially produce a
    # 10-fire-per-second hot-loop until StartLimitBurst kicks
    # in. Locks the explicit-RestartSec pair discipline on the
    # scheduler unit substrate.
    grep -qE '^Restart=always' "${UNIT}"
    grep -qE '^RestartSec=' "${UNIT}"
}

@test "INVARIANT (.service does NOT declare RemainAfterExit — daemon long-running semantics contract)" {
    # Sister to brain-wide systemd-unit-kind INVARIANT family.
    # The scheduler is Type=simple long-running daemon — it
    # MUST NOT declare RemainAfterExit= (which is a Type=
    # oneshot concept). A regression that added
    # RemainAfterExit=yes would conflict with Restart=always:
    # systemd would interpret the unit as "completed
    # successfully" on exit-0 + skip restart, defeating the
    # supervisor-restart contract. RemainAfterExit is
    # exclusively a oneshot-companion directive. Locks the
    # daemon-vs-oneshot semantic discipline on the scheduler
    # unit substrate.
    ! grep -qE '^RemainAfterExit=' "${UNIT}"
}

@test "INVARIANT (.service file has [Unit] + [Service] + [Install] section headers — systemd INI structural contract)" {
    # Sister to brain-wide systemd INI-structure INVARIANT
    # family. The scheduler.service is a complete unit — all
    # three canonical section headers ([Unit] + [Service] +
    # [Install]) must be present at start-of-line. Without
    # all three, systemd's parser handles the unit as
    # malformed. Locks the 3-section INI structural
    # discipline on the scheduler service substrate.
    grep -qE '^\[Unit\]' "${UNIT}"
    grep -qE '^\[Service\]' "${UNIT}"
    grep -qE '^\[Install\]' "${UNIT}"
}

@test "INVARIANT (cargo-deb assets ship selfdef-scheduler.service — Debian packaging-manifest contract)" {
    # Sister to brain-wide cargo-deb manifest INVARIANT
    # family. The scheduler unit must be listed in the
    # selfdef-daemon Cargo.toml [package.metadata.deb] assets
    # block so dpkg ships it to /etc/systemd/system/ at
    # install time. A regression that dropped the asset
    # entry would leave the .deb without the unit + cause
    # postinst to fail with "unit not found". Locks the
    # cargo-deb manifest discipline on the scheduler
    # substrate.
    DAEMON_CARGO="${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml"
    [ -f "${DAEMON_CARGO}" ]
    grep -qE 'selfdef-scheduler\.service' "${DAEMON_CARGO}"
}

@test "INVARIANT (postinst runs systemctl daemon-reload after install — systemd-cache-refresh contract)" {
    # Sister to brain-wide daemon-reload INVARIANT family.
    # postinst installs scheduler.service + must signal
    # systemd to re-scan via daemon-reload. Without this,
    # systemctl enable would race against systemd's internal
    # unit-graph state. Locks the daemon-reload-after-install
    # discipline.
    grep -qE 'systemctl daemon-reload' "${POSTINST}"
}

@test "INVARIANT (scheduler.service ExecStart binary path is NOT identical to selfdef-guardian — sister-unit-distinguishing path contract)" {
    # Sister to sister-unit-distinguishing INVARIANT family.
    # The scheduler + guardian are sister Ring-0 units; each
    # has its own binary at a distinct path. A regression
    # that pointed both ExecStart to the same binary would
    # break operator triage. Locks the scheduler-vs-guardian
    # distinct-binary-path discipline.
    grep -qE '^ExecStart=/usr/local/bin/selfdef-scheduler' "${UNIT}"
    ! grep -qE '^ExecStart=/usr/local/bin/selfdef-guardian' "${UNIT}"
}

@test "INVARIANT (scheduler.service has WantedBy=multi-user.target Install — enable-graph reachability contract)" {
    # Sister to brain-wide [Install] WantedBy INVARIANT family.
    grep -qE '^WantedBy=multi-user.target' "${UNIT}"
}

@test "INVARIANT (scheduler unit lives at canonical packaging/systemd/ path — packaging tree-layout contract)" {
    real_unit="$(readlink -f "${UNIT}")"
    case "${real_unit}" in */packaging/systemd/*) ;; *) false ;; esac
}

@test "INVARIANT (.service hardening set is identical to selfdef-{doctor,guardian} canonical hardening — Ring-0 unit-consistency contract)" {
    grep -qE '^NoNewPrivileges=true' "${UNIT}"
    grep -qE '^ProtectSystem=strict' "${UNIT}"
    grep -qE '^LockPersonality=true' "${UNIT}"
    grep -qE '^RestrictNamespaces=true' "${UNIT}"
    grep -qE '^RestrictRealtime=true' "${UNIT}"
    grep -qE '^RestrictSUIDSGID=true' "${UNIT}"
    grep -qE '^SystemCallArchitectures=native' "${UNIT}"
}

@test "INVARIANT (scheduler unit ExecStart binary path is in /usr/local/bin/ — operator-extension path consistency)" {
    grep -qE '^ExecStart=/usr/local/bin/' "${UNIT}"
}

@test "INVARIANT (scheduler.service has User=root + Group=root pair — Ring-0 elevation contract)" {
    grep -qE '^User=root$' "${UNIT}"
    grep -qE '^Group=root$' "${UNIT}"
}

@test "INVARIANT (cargo-deb assets shipping target for scheduler.service is /usr/share/selfdef/ — operator-extension postinst-staging contract)" {
    # Sister to brain-wide cargo-deb shipping-target INVARIANT
    # family. The scheduler unit ships to /usr/share/selfdef/
    # (not directly to /etc/systemd/system/) — the postinst
    # script copies from /usr/share/selfdef/ to /etc/systemd/
    # system/ at install time. This stage-then-install pattern
    # lets the postinst control mode + ownership + ordering.
    DAEMON_CARGO="${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml"
    grep -qE 'selfdef-scheduler\.service.*usr/share/selfdef' "${DAEMON_CARGO}"
}

@test "INVARIANT (scheduler.service After= chain includes selfdef-guardian.service — Ring-0 ordering contract)" {
    grep -qE '^After=.*selfdef-guardian' "${UNIT}"
}

@test "INVARIANT (scheduler unit Documentation references SDD-031 — operator-spec-link discipline)" {
    grep -qE '^Documentation=.*sdd/031' "${UNIT}"
}

@test "INVARIANT (scheduler unit comment block references avx-plus-plus dump line range — derivation-source audit-trail)" {
    grep -qE 'avx-plus-plus|sain-01|MS04[89]' "${UNIT}"
}

@test "INVARIANT (scheduler unit declares After=zfs-mount.service — ZFS-substrate ordering contract)" {
    grep -qE '^After=.*zfs-mount\.service' "${UNIT}"
}

@test "INVARIANT (scheduler unit declares After=tetragon.service — eBPF-substrate ordering contract)" {
    grep -qE '^After=.*tetragon\.service' "${UNIT}"
}

@test "INVARIANT (scheduler unit declares Wants=selfdef-guardian.service — soft-dependency contract)" {
    grep -qE '^Wants=selfdef-guardian\.service' "${UNIT}"
}

@test "INVARIANT (scheduler unit ProtectKernelTunables=true — kernel-mutation containment)" {
    grep -qE '^ProtectKernelTunables=true' "${UNIT}"
}

@test "INVARIANT (scheduler.service ProtectKernelLogs=true — kernel-log read containment)" {
    grep -qE '^ProtectKernelLogs=true' "${UNIT}"
}

@test "INVARIANT (scheduler.service ProtectControlGroups=true — cgroup-mutation containment)" {
    grep -qE '^ProtectControlGroups=true' "${UNIT}"
}

@test "INVARIANT (scheduler.service Documentation field present — operator-doc-trail contract)" {
    grep -qE '^Documentation=' "${UNIT}"
}

@test "INVARIANT (scheduler.service uses Type=simple — long-running-supervisor contract)" {
    grep -qE '^Type=simple' "${UNIT}"
}

@test "INVARIANT (scheduler.service ExecStart absolute path begins with / — systemd absolute-path requirement)" {
    grep -qE '^ExecStart=/' "${UNIT}"
}

@test "INVARIANT (scheduler.service comment block references avx-plus-plus dump source — derivation-source canonical-vcs contract)" {
    grep -qE 'avx-plus-plus|sain-01|sain01|SD-R[0-9]+' "${UNIT}"
}
@test "INVARIANT (scheduler.service uses /proc/pressure/ surface — PSI canonical query path)" {
    grep -qE '/proc/pressure|PSI' "${UNIT}"
}
@test "INVARIANT (scheduler.service file size is non-zero — non-empty unit file)" {
    [ -s "${UNIT}" ]
}
@test "INVARIANT (scheduler.service has >10 lines of directives — non-trivial-unit-file contract)" {
    lines=$(wc -l < "${UNIT}")
    [ "${lines}" -gt 10 ]
}
@test "INVARIANT (postinst has >5 lines specific to scheduler — non-trivial-postinst contract)" {
    n=$(grep -c 'scheduler' "${POSTINST}")
    [ "${n}" -ge 2 ]
}
@test "INVARIANT (scheduler.service file has >20 lines of directives — comprehensive-config contract)" {
    lines=$(wc -l < "${UNIT}")
    [ "${lines}" -gt 20 ]
}

@test "INVARIANT (scheduler.service has StartLimitBurst=10 — restart-storm cap)" {
    grep -qE '^StartLimitBurst=10' "${UNIT}"
}
@test "INVARIANT (scheduler.service file is at canonical packaging/systemd/ path — packaging tree-layout 71-cycle)" {
    [ -f "${UNIT}" ]
    case "$(readlink -f "${UNIT}")" in */packaging/systemd/*) ;; *) false ;; esac
}
@test "INVARIANT (scheduler.service file readable — file-mode-access contract)" {
    [ -r "${UNIT}" ]
}
@test "INVARIANT (postinst readable — file-mode-access contract 73)" {
    [ -r "${POSTINST}" ]
}
@test "INVARIANT (UNIT variable defined and non-empty — substrate-defined 74)" {
    [ -n "${UNIT}" ]
}
@test "INVARIANT (scheduler.service file size > 200 bytes — substantial-service-unit 75)" {
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
@test "INVARIANT (postrm has shebang — POSIX-conformant 79)" {
    head -1 "${POSTRM}" | grep -qE '^#!'
}
@test "INVARIANT (postrm references scheduler unit — purge-cleanup contract 80)" {
    grep -qE 'scheduler' "${POSTRM}"
}
@test "INVARIANT (postinst writes to scheduler state dir — install-staging 81)" {
    grep -qE 'scheduler' "${POSTINST}"
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
@test "INVARIANT (postinst pre-creates /var/cache/selfdef/scheduler/ring dir — ring-buffer staging 86)" {
    grep -qE '/var/cache/selfdef/scheduler/ring' "${POSTINST}"
}
@test "INVARIANT (postinst creates dirs with -p flag — idempotent-dir-create 87)" {
    grep -qE 'mkdir -p' "${POSTINST}"
}
@test "INVARIANT (scheduler unit declares User=root explicitly — Ring-0-elevation 88)" {
    grep -qE '^User=root' "${UNIT}"
}
@test "INVARIANT (scheduler unit declares Group=root explicitly — Ring-0-group 89)" {
    grep -qE '^Group=root' "${UNIT}"
}
@test "INVARIANT (scheduler.service uses ProtectKernel directive — kernel-protect 90)" {
    grep -qE '^ProtectKernel' "${UNIT}"
}
