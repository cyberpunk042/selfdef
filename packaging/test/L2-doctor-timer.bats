#!/usr/bin/env bats
# L2 bats unit tests for selfdef-doctor.timer + selfdef-doctor.service.
# Locks the periodic-health-check surface against drift.
#
# Run with: bats packaging/test/L2-doctor-timer.bats

SERVICE="${BATS_TEST_DIRNAME}/../systemd/selfdef-doctor.service"
TIMER="${BATS_TEST_DIRNAME}/../systemd/selfdef-doctor.timer"
INIT="${BATS_TEST_DIRNAME}/../../crates/selfdef-cli/src/init.rs"
DAEMON_CARGO="${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml"

# ============================================================
# .service structural shape
# ============================================================

@test ".service file exists" {
    [ -f "${SERVICE}" ]
}

@test ".service declares Type=oneshot" {
    grep -q "^Type=oneshot$" "${SERVICE}"
}

@test ".service binds After=selfdefd.service + zfs-mount.service" {
    grep -qE "^After=.*selfdefd.service" "${SERVICE}"
    grep -qE "^After=.*zfs-mount.service" "${SERVICE}"
}

@test ".service ExecStart=/usr/bin/selfdefctl doctor" {
    grep -q "^ExecStart=/usr/bin/selfdefctl doctor$" "${SERVICE}"
}

@test ".service User=root + Group=root" {
    grep -q "^User=root$" "${SERVICE}"
    grep -q "^Group=root$" "${SERVICE}"
}

@test ".service TimeoutStartSec=300s (slow hosts with many modules)" {
    grep -q "^TimeoutStartSec=300s$" "${SERVICE}"
}

# ============================================================
# .service hardening (consistent with other selfdef-* units)
# ============================================================

@test ".service hardening — NoNewPrivileges + ProtectSystem=strict" {
    grep -q "^NoNewPrivileges=true$" "${SERVICE}"
    grep -q "^ProtectSystem=strict$" "${SERVICE}"
}

@test ".service hardening — ReadOnlyPaths lists doctor input dirs" {
    grep -q "^ReadOnlyPaths=.*/etc/selfdef" "${SERVICE}"
    grep -q "^ReadOnlyPaths=.*/etc/tetragon" "${SERVICE}"
    grep -q "^ReadOnlyPaths=.*/usr/local/bin" "${SERVICE}"
    grep -q "^ReadOnlyPaths=.*/usr/share/selfdef" "${SERVICE}"
}

@test ".service hardening — ProtectKernel{Tunables,Logs,ControlGroups}" {
    grep -q "^ProtectKernelTunables=true$" "${SERVICE}"
    grep -q "^ProtectKernelLogs=true$" "${SERVICE}"
    grep -q "^ProtectControlGroups=true$" "${SERVICE}"
}

@test ".service hardening — RestrictAddressFamilies=AF_UNIX (doctor is read-only, no network)" {
    grep -q "^RestrictAddressFamilies=AF_UNIX$" "${SERVICE}"
}

@test ".service hardening — LockPersonality + RestrictNamespaces + RestrictRealtime + RestrictSUIDSGID" {
    grep -q "^LockPersonality=true$" "${SERVICE}"
    grep -q "^RestrictNamespaces=true$" "${SERVICE}"
    grep -q "^RestrictRealtime=true$" "${SERVICE}"
    grep -q "^RestrictSUIDSGID=true$" "${SERVICE}"
}

# ============================================================
# .timer cadence + persistence
# ============================================================

@test ".timer file exists" {
    [ -f "${TIMER}" ]
}

@test ".timer OnBootSec=10min (first run after boot delay)" {
    grep -q "^OnBootSec=10min$" "${TIMER}"
}

@test ".timer OnUnitActiveSec=1h (hourly cadence per init checklist Step 11)" {
    grep -q "^OnUnitActiveSec=1h$" "${TIMER}"
}

@test ".timer RandomizedDelaySec=5min (fleet load spread)" {
    grep -q "^RandomizedDelaySec=5min$" "${TIMER}"
}

@test ".timer Persistent=true (catch up after host downtime)" {
    grep -q "^Persistent=true$" "${TIMER}"
}

@test ".timer Unit=selfdef-doctor.service" {
    grep -q "^Unit=selfdef-doctor.service$" "${TIMER}"
}

@test ".timer WantedBy=timers.target" {
    grep -q "^WantedBy=timers.target$" "${TIMER}"
}

# ============================================================
# Cargo-deb shipping + init checklist consistency
# ============================================================

@test "cargo-deb assets ship selfdef-doctor.service to /lib/systemd/system/" {
    grep -q "selfdef-doctor.service.*lib/systemd/system" "${DAEMON_CARGO}"
}

@test "cargo-deb assets ship selfdef-doctor.timer to /lib/systemd/system/" {
    grep -q "selfdef-doctor.timer.*lib/systemd/system" "${DAEMON_CARGO}"
}

@test "init checklist Step 11 references selfdef-doctor.timer (no vaporware)" {
    grep -q "systemctl enable --now selfdef-doctor.timer" "${INIT}"
}

# ============================================================
# systemd-analyze (skipped when absent)
# ============================================================

@test "systemd-analyze verify .service (when available)" {
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        skip "systemd-analyze not installed in test env"
    fi
    set +e
    output="$(systemd-analyze verify "${SERVICE}" 2>&1)"
    set -e
    if echo "${output}" | grep -qE "Unknown key|Invalid|Failed to parse"; then
        echo "systemd-analyze unit-syntax errors detected:" >&2
        echo "${output}" >&2
        return 1
    fi
}

@test "systemd-analyze verify .timer (when available)" {
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        skip "systemd-analyze not installed in test env"
    fi
    set +e
    output="$(systemd-analyze verify "${TIMER}" 2>&1)"
    set -e
    if echo "${output}" | grep -qE "Unknown key|Invalid|Failed to parse"; then
        echo "systemd-analyze unit-syntax errors detected:" >&2
        echo "${output}" >&2
        return 1
    fi
}

@test "INVARIANT (doctor-timer carries OnUnitActiveSec — recurrent re-armed cadence beyond OnBootSec one-shot)" {
    # Sister to many other selfdef timer units' OnUnitActiveSec
    # INVARIANTs across the brain. A one-shot timer that fires
    # only on OnBootSec would let a long-uptime host run for
    # weeks without health-check. The selfdef-doctor.timer MUST
    # carry OnUnitActiveSec=<period> so health-check runs
    # recurrently across long uptimes. Locks the recurrent-fire
    # contract — the foundational discipline that all selfdef-
    # doctor watchdog-of-watchdogs coverage depends on (without
    # recurrent-fire, the whole system substrate's monitoring
    # decays silently).
    grep -qE '^OnUnitActiveSec=' "${TIMER}"
}

@test "INVARIANT (doctor-timer carries Persistent=true — missed-fires catch up after long downtime)" {
    # Sister to many other selfdef timer-unit Persistent=true
    # INVARIANTs across the brain. Without Persistent=true,
    # systemd does NOT remember timer fires that were missed
    # during host downtime — a host that's been offline for
    # 24 hours misses ALL its scheduled health-check passes
    # for that window AND on next boot only fires the NEXT
    # scheduled fire (not the missed ones). With Persistent=
    # true, systemd records the last successful fire and on
    # boot fires immediately if the recurrent interval has
    # elapsed since then. Locks the missed-fire-catch-up
    # contract on the selfdef-doctor watchdog-of-watchdogs
    # substrate — the foundational discipline that ensures
    # long-uptime + offline-recovery coverage is never silent.
    grep -qE '^Persistent=true' "${TIMER}"
}

@test "INVARIANT (timer + service unit chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    [ -f "${TIMER}" ]
    [ "$(stat -c '%a' "${TIMER}")" = "644" ]
    [ -f "${SERVICE}" ]
    [ "$(stat -c '%a' "${SERVICE}")" = "644" ]
}

@test "INVARIANT (service unit carries Description= or Documentation= with selfdef identifier — operator-audit-trail)" {
    # Sister to brain-wide service-unit identity INVARIANTs.
    # selfdef-doctor.service MUST carry the selfdef identifier
    # in Description or Documentation so operator running
    # systemctl status / journalctl -t can immediately
    # identify the unit as selfdef-owned.
    [ -f "${SERVICE}" ]
    grep -qE '^(Description|Documentation)=.*selfdef' "${SERVICE}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes (entropy-baseline,
    # secure-boot-status, swap-encryption-detect, bootloader-
    # password-detect). The doctor probe runs ON the timer's
    # scheduled fire — executes ONCE, emits a verdict, then
    # exits. Type=simple would leave systemd thinking the probe
    # is a long-running daemon, breaking timer's OnSuccess /
    # OnUnitActiveSec semantics (which depend on the service
    # reaching inactive(dead) before the next fire). Locks
    # oneshot-probe contract on the selfdef-doctor substrate.
    [ -f "${SERVICE}" ]
    grep -qE '^Type=oneshot' "${SERVICE}"
}

@test "INVARIANT (.service hardening — SystemCallArchitectures=native — anti-32bit-syscall-bypass Ring-0 hardening axis)" {
    # Sister to brain-wide Ring-0 hardening INVARIANT family
    # (LockPersonality + MemoryDenyWriteExecute + ProtectKernelTunables
    # + ProtectKernelLogs + ProtectControlGroups + NoNewPrivileges
    # all already covered above). SystemCallArchitectures=native
    # restricts the doctor to the host's native syscall ABI —
    # blocks the 32-bit-syscall-on-64-bit-kernel bypass class
    # historically used to evade seccomp filters that only
    # covered the native syscall numbers. Locks native-ABI
    # discipline on the doctor service substrate.
    grep -q "^SystemCallArchitectures=native$" "${SERVICE}"
}

@test "INVARIANT (.timer Description references the doctor's hourly-cadence purpose — operator-audit-trail on timer unit)" {
    # Sister to brain-wide systemd Documentation/Description
    # INVARIANT family. The doctor.timer Description string is
    # what operators see in `systemctl list-timers` output;
    # naming it after the hourly-health-check purpose lets an
    # operator triage timer-firing log entries without opening
    # the unit file. Locks the operator-audit-trail discipline
    # on the doctor.timer substrate (sister to the .service's
    # Description/Documentation INVARIANT already locked
    # earlier in this suite).
    grep -qE '^Description=' "${TIMER}"
    grep -qiE 'selfdef|doctor|health' "${TIMER}"
}

@test "INVARIANT (.service ReadOnlyPaths enumeration covers all doctor read targets — explicit-allowlist hardening discipline)" {
    # Sister to brain-wide Ring-0 hardening INVARIANT family.
    # The doctor's ProtectSystem=strict alone forbids ALL
    # writes to /etc but ALSO would forbid reads on
    # mount-namespaced ProtectSystem=strict targets without
    # ReadOnlyPaths explicit-allowlist. The ReadOnlyPaths
    # directive MUST enumerate all 4 doctor input dirs
    # (/etc/selfdef, /etc/tetragon, /usr/local/bin,
    # /usr/share/selfdef) so a future regression that adds a
    # new doctor-input dir without ALSO adding it to
    # ReadOnlyPaths trips this assertion. Locks the explicit-
    # allowlist enumeration discipline on the doctor service
    # substrate (sister to the existing ReadOnlyPaths
    # individual-path INVARIANTs).
    count=$(grep -cE '^ReadOnlyPaths=' "${SERVICE}")
    [ "${count}" -eq 1 ]
    rop=$(grep '^ReadOnlyPaths=' "${SERVICE}")
    case "${rop}" in
        *"/etc/selfdef"*"/etc/tetragon"*"/usr/local/bin"*"/usr/share/selfdef"*) ;;
        *) false ;;
    esac
}

@test "INVARIANT (.service ExecStart points at /usr/bin/selfdefctl — packaging contract honored)" {
    # Sister to brain-wide ExecStart packaging-path INVARIANT
    # family. The doctor.service MUST invoke /usr/bin/selfdefctl
    # (Debian-package install path), not /usr/local/bin or
    # /opt/selfdef — those are operator-extension paths that
    # would bypass the package manifest. A regression that
    # switched ExecStart to /usr/local/bin would surface as
    # "doctor.timer fires but selfdefctl not found" on hosts
    # where the package shipped the binary to /usr/bin/. Locks
    # the Debian-package binary-path discipline on the doctor
    # service substrate.
    grep -qE '^ExecStart=/usr/bin/selfdefctl' "${SERVICE}"
}

@test "INVARIANT (.timer uses OnBootSec + OnUnitActiveSec — boot-delay + recurring cadence pair, NOT OnCalendar)" {
    # Sister to brain-wide timer-cadence INVARIANT family. The
    # doctor.timer uses OnBootSec=10min (delay first probe after
    # boot so OS finishes settling) + OnUnitActiveSec=1h
    # (recurring hourly cadence) — NOT OnCalendar=. A regression
    # that swapped to OnCalendar="*-*-* *:00:00" would fire at
    # absolute clock times which:
    #   (a) introduces fleet-coordination thundering-herd
    #       (every host fires at :00 simultaneously)
    #   (b) breaks the boot-delay grace period — a host that
    #       boots at :59 would fire its first probe before OS
    #       services have settled
    # Locks the OnBootSec+OnUnitActiveSec cadence discipline.
    grep -qE '^OnBootSec=' "${TIMER}"
    grep -qE '^OnUnitActiveSec=' "${TIMER}"
    ! grep -qE '^OnCalendar=' "${TIMER}"
}

@test "INVARIANT (.timer + .service files chmod 0644 — systemd unit-file convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable for systemctl-status visibility; root-write-only
    # to prevent operator-mode tampering). Locks unit-file mode
    # discipline on the doctor service + timer substrate.
    mode_service=$(stat -c '%a' "${SERVICE}")
    mode_timer=$(stat -c '%a' "${TIMER}")
    [ "${mode_service}" = "644" ]
    [ "${mode_timer}" = "644" ]
}

@test "INVARIANT (.service [Install] section + WantedBy=multi-user.target — packaging-enable surface for postinst)" {
    # Sister to brain-wide systemd [Install] INVARIANT family.
    # The doctor .service has [Install] WantedBy=multi-user.target
    # so the Debian postinst can `systemctl enable selfdef-
    # doctor.timer` AND have the underlying .service unit reachable
    # via the normal enable graph. Without [Install], systemctl
    # enable would be a no-op. Locks the [Install] section
    # discipline on the doctor service substrate.
    grep -qE '^\[Install\]' "${SERVICE}"
    grep -qE '^WantedBy=multi-user\.target' "${SERVICE}"
}

@test "INVARIANT (.service Documentation= references man:selfdefctl(1) — operator-doc-path contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. The doctor.service points operators at the
    # selfdefctl(1) man page for the actual doctor command
    # surface — the man page documents the gates + exit codes.
    # A regression that dropped Documentation= or pointed at
    # a non-existent URL would leave triaging operators with
    # no jumping-off point. Locks the man-page-Documentation
    # discipline on the doctor service substrate.
    grep -qE '^Documentation=man:selfdefctl' "${SERVICE}"
}

@test "INVARIANT (timer Unit=selfdef-doctor.service — explicit-binding contract)" {
    # Sister to brain-wide systemd timer-Unit binding INVARIANT
    # family. The .timer file MUST declare Unit=selfdef-doctor.
    # service so systemd binds the timer to the service even
    # if a future refactor renames the .timer file without
    # renaming the .service. Locks the explicit-binding
    # discipline on the doctor timer substrate.
    grep -qE '^Unit=selfdef-doctor\.service' "${TIMER}"
}

@test "INVARIANT (.service ExecStart command argument is exactly \"doctor\" — selfdefctl subcommand contract)" {
    # Sister to brain-wide ExecStart-args INVARIANT family.
    # The selfdef-doctor.service's ExecStart MUST be
    # /usr/bin/selfdefctl doctor (the `doctor` subcommand).
    # A regression that changed the arg to `audit` or dropped
    # the arg entirely would surface as selfdefctl printing
    # its help text instead of running the health check. Locks
    # the doctor-subcommand discipline on the doctor service
    # substrate.
    grep -qE '^ExecStart=/usr/bin/selfdefctl doctor$' "${SERVICE}"
}

@test "INVARIANT (.service declares NO Restart= directive — Type=oneshot anti-restart-storm contract)" {
    # Sister to brain-wide anti-restart-storm INVARIANT family
    # (already locked on watchdog .service substrates). The
    # doctor.service is Type=oneshot timer-driven — systemd
    # Restart=always|on-failure on a Type=oneshot would either
    # be a no-op or worse: trigger a restart storm where the
    # timer-fired oneshot loops on transient FAIL (e.g. /proc/
    # pressure unreadable for 200ms during ZFS unmount).
    # The .timer's OnUnitActiveSec=1h cadence IS the retry
    # mechanism; in-service Restart= would short-circuit the
    # cadence + flood journald. Locks the no-Restart= discipline
    # on the doctor service substrate.
    ! grep -qE '^Restart=' "${SERVICE}"
}

@test "INVARIANT (.timer Description= references the hourly-health-check purpose — operator-list-timers visibility contract)" {
    # Sister to brain-wide systemd timer Description= INVARIANT
    # family. The doctor.timer's Description= surfaces in
    # `systemctl list-timers --all` output; operators rely on
    # the description text to identify which selfdef-managed
    # timer they're looking at. A regression that swapped the
    # description for a generic "Selfdef doctor" without the
    # "hourly" / "health" qualifier would leave operators
    # parsing the Unit= field instead of the human-readable
    # Description=. Locks the timer-Description-purpose
    # discipline on the doctor.timer substrate.
    grep -qE '^Description=' "${TIMER}"
    grep -qiE 'Description=.*(hourly|periodic|health)' "${TIMER}"
}
