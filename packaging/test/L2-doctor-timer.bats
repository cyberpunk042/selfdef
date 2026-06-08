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

@test "INVARIANT (.timer Documentation= references man:selfdefctl(1) — operator-timer-doc-path contract)" {
    # Sister to .service Documentation= INVARIANT already
    # locked. The doctor.timer's Documentation= MUST also
    # reference the selfdefctl(1) man page so operators
    # triaging timer fires from `systemctl list-timers` can
    # jump directly to the docs without crossing-referencing
    # the service unit. A regression that left Documentation=
    # off the .timer (while present on .service) would force
    # operators to guess which man page applies. Locks the
    # timer-Documentation-man-page discipline on the doctor.
    # timer substrate.
    grep -qE '^Documentation=man:selfdefctl' "${TIMER}"
}

@test "INVARIANT (.service file has [Unit] + [Service] + [Install] section headers — systemd INI structural contract)" {
    # Sister to brain-wide systemd INI-structure INVARIANT
    # family. A systemd .service file MUST contain three
    # canonical section headers: [Unit] (metadata + ordering),
    # [Service] (exec contract + hardening), [Install]
    # (enable-graph WantedBy). Without all three, systemd's
    # parser handles the unit as malformed: missing [Unit]
    # strips Description/After/Documentation; missing
    # [Service] makes ExecStart/Type a no-op; missing
    # [Install] makes systemctl enable a no-op. The doctor.
    # service is a complete unit — all three must be present
    # at start-of-line. A regression that collapsed sections
    # or merged them would break systemd parsing. Locks the
    # 3-section INI structural discipline on the doctor
    # service substrate.
    grep -qE '^\[Unit\]' "${SERVICE}"
    grep -qE '^\[Service\]' "${SERVICE}"
    grep -qE '^\[Install\]' "${SERVICE}"
}

@test "INVARIANT (.timer file has [Unit] + [Timer] + [Install] section headers — systemd timer INI structural contract)" {
    # Sister to .service 3-section INVARIANT already locked.
    # A systemd .timer file MUST contain three canonical
    # section headers: [Unit] (metadata + ordering), [Timer]
    # (cadence directives OnBootSec/OnUnitActiveSec/etc),
    # [Install] (timers.target binding). Without [Timer] the
    # cadence directives are no-ops; without [Install]
    # `systemctl enable selfdef-doctor.timer` is a no-op.
    # Locks the 3-section INI structural discipline on the
    # doctor timer substrate.
    grep -qE '^\[Unit\]' "${TIMER}"
    grep -qE '^\[Timer\]' "${TIMER}"
    grep -qE '^\[Install\]' "${TIMER}"
}

@test "INVARIANT (.service [Unit] Description= references doctor identity — sister to .timer Description= already locked)" {
    # Sister to .timer Description= INVARIANT already locked.
    # The .service Description= MUST also identify the unit
    # as the doctor (operator-readable in `systemctl status`
    # output). The text MUST contain the doctor identifier.
    # Locks the service-Description-identity discipline.
    grep -qE '^Description=' "${SERVICE}"
    grep -qiE 'Description=.*(doctor|health)' "${SERVICE}"
}


@test "INVARIANT (.timer file is at canonical path packaging/systemd/ — packaging tree-layout contract)" {
    # Sister to brain-wide packaging layout INVARIANT family.
    # The .timer + .service files MUST live at packaging/
    # systemd/ so the cargo-deb assets list can reference
    # them via relative path. A regression that moved files
    # to packaging/units/ or modules/<module>/systemd/ would
    # break the cargo-deb manifest matching. Locks the
    # canonical packaging/systemd/ tree-layout discipline.
    [ -f "${TIMER}" ]
    [ -f "${SERVICE}" ]
    real_timer="$(readlink -f "${TIMER}")"
    real_service="$(readlink -f "${SERVICE}")"
    case "${real_timer}" in */packaging/systemd/*) ;; *) false ;; esac
    case "${real_service}" in */packaging/systemd/*) ;; *) false ;; esac
}

@test "INVARIANT (cargo-deb assets shipping paths are explicit /lib/systemd/system/ — not /etc/systemd/system/ — system-package directory discipline)" {
    # Sister to brain-wide systemd-shipping-directory INVARIANT
    # family. The cargo-deb assets MUST ship the unit files to
    # /lib/systemd/system/ (the system-package canonical
    # location per Debian Policy §9.3.1), NOT /etc/systemd/
    # system/ (which is reserved for operator-extension
    # overrides per FHS). A regression to /etc/* would risk
    # an operator's override file shadowing the package-
    # shipped unit + create a silent-divergence bug. Locks
    # the /lib/systemd/system shipping discipline on the
    # doctor cargo-deb manifest substrate.
    grep -qE 'lib/systemd/system' "${DAEMON_CARGO}"
    # Verify the doctor unit specifically targets /lib not /etc
    grep -qE 'selfdef-doctor\.(service|timer).*lib/systemd/system' "${DAEMON_CARGO}"
}

@test "INVARIANT (.timer + .service have no leading whitespace before section header — INI parser strictness)" {
    # Sister to brain-wide INI strictness INVARIANT family.
    # systemd's INI parser rejects leading-whitespace section
    # headers. A regression that mis-indented [Service] or
    # [Unit] would silently render the directives unparsed.
    ! grep -qE '^[[:space:]]+\[(Unit|Service|Install|Timer)\]' "${SERVICE}"
    ! grep -qE '^[[:space:]]+\[(Unit|Service|Install|Timer)\]' "${TIMER}"
}

@test "INVARIANT (.service hardening set is identical to selfdef-{guardian,scheduler} canonical hardening — Ring-0 unit-consistency contract)" {
    # Sister to brain-wide cross-unit hardening-consistency
    # INVARIANT family. The selfdef Ring-0 units (doctor/
    # guardian/scheduler) share the same canonical hardening
    # subset: NoNewPrivileges + ProtectSystem=strict +
    # LockPersonality + RestrictNamespaces + RestrictRealtime
    # + RestrictSUIDSGID + SystemCallArchitectures. A
    # regression that diverged any unit's hardening would
    # surface as security-baseline drift across the Ring-0
    # surface. Locks the cross-unit canonical hardening
    # consistency.
    grep -qE '^NoNewPrivileges=true' "${SERVICE}"
    grep -qE '^ProtectSystem=strict' "${SERVICE}"
    grep -qE '^LockPersonality=true' "${SERVICE}"
    grep -qE '^RestrictNamespaces=true' "${SERVICE}"
    grep -qE '^RestrictRealtime=true' "${SERVICE}"
    grep -qE '^RestrictSUIDSGID=true' "${SERVICE}"
    grep -qE '^SystemCallArchitectures=native' "${SERVICE}"
}

@test "INVARIANT (.timer's OnUnitActiveSec is hours-or-longer cadence — anti-too-frequent-probe contract)" {
    grep -qE '^OnUnitActiveSec=([0-9]+h|[0-9]+d)' "${TIMER}"
}

@test "INVARIANT (.timer's RandomizedDelaySec is bounded — anti-jitter-overflow contract)" {
    # Sister to brain-wide RandomizedDelaySec INVARIANT family.
    # RandomizedDelaySec=Xmin where X is bounded so the jitter
    # doesn't exceed the cadence (5min jitter on 1h cadence
    # OK; 5min jitter on 5min cadence would skew probes).
    grep -qE '^RandomizedDelaySec=[0-9]+(s|min|m)$' "${TIMER}"
}

@test "INVARIANT (cargo-deb assets list is reachable from packaging/ tree — Debian build manifest discoverable)" {
    [ -f "${DAEMON_CARGO}" ]
    grep -qE 'package.metadata.deb|\[\[package.metadata.deb.assets\]\]|maintainer-scripts' "${DAEMON_CARGO}"
}

@test "INVARIANT (init checklist Step 11 references --now on enable — boot-and-fire-immediately contract)" {
    grep -qE 'systemctl enable --now selfdef-doctor.timer' "${INIT}"
}

@test "INVARIANT (.timer file path matches the .service file path in same directory — sister-unit-co-location contract)" {
    [ "$(dirname "${TIMER}")" = "$(dirname "${SERVICE}")" ]
}

@test "INVARIANT (.timer cadence directives include at least 2 of OnBootSec/OnUnitActiveSec/OnCalendar — multi-cadence-mode contract)" {
    grep -qE '^(OnBootSec|OnUnitActiveSec|OnCalendar)=' "${TIMER}"
    count=$(grep -cE '^(OnBootSec|OnUnitActiveSec|OnCalendar)=' "${TIMER}")
    [ "${count}" -ge 2 ]
}

@test "INVARIANT (.service is invoked via .timer not directly enabled — Type=oneshot + .timer-trigger-only contract)" {
    grep -qE '^Type=oneshot' "${SERVICE}"
}

@test "INVARIANT (.timer's OnUnitActiveSec is paired with OnBootSec — boot+recurring pair contract)" {
    grep -qE '^OnBootSec=' "${TIMER}"
    grep -qE '^OnUnitActiveSec=' "${TIMER}"
}

@test "INVARIANT (cargo-deb maintainer-scripts manifest references postinst — Debian-package-lifecycle wiring contract)" {
    grep -qE 'maintainer-scripts|postinst' "${DAEMON_CARGO}"
}

@test "INVARIANT (.service [Unit] section comment block reference selfdef-doctor purpose — derivation-source audit-trail)" {
    head -10 "${SERVICE}" | grep -qE 'doctor|health|periodic'
}

@test "INVARIANT (cargo-deb manifest carries selfdef-doctor.timer asset entry distinct from .service — separate-file asset contract)" {
    grep -qE 'selfdef-doctor\.timer' "${DAEMON_CARGO}"
    grep -qE 'selfdef-doctor\.service' "${DAEMON_CARGO}"
}

@test "INVARIANT (.timer's WantedBy=timers.target — timer-enable-graph reachability)" {
    grep -qE '^WantedBy=timers.target' "${TIMER}"
}

@test "INVARIANT (.service Documentation field present — operator-doc-trail contract)" {
    grep -qE '^Documentation=' "${SERVICE}"
}

@test "INVARIANT (.timer's RandomizedDelaySec value is bounded under 10min — anti-jitter-overflow contract)" {
    grep -qE '^RandomizedDelaySec=[1-9]min$|^RandomizedDelaySec=[0-9]+s$' "${TIMER}"
}

@test "INVARIANT (.service ExecStart absolute path begins with / — systemd absolute-path requirement)" {
    grep -qE '^ExecStart=/' "${SERVICE}"
}

@test "INVARIANT (.timer file declares Unit= absolute path within selfdef namespace — namespace-scoped binding contract)" {
    grep -qE '^Unit=selfdef-' "${TIMER}"
}
@test "INVARIANT (.timer file declares OnUnitActiveSec timer-driven cadence — recurring-trigger contract)" {
    grep -qE '^OnUnitActiveSec=' "${TIMER}"
}
@test "INVARIANT (.service file size is non-zero — non-empty unit file)" {
    [ -s "${SERVICE}" ]
}
@test "INVARIANT (.service is not empty — non-trivial-unit-file contract)" {
    lines=$(wc -l < "${SERVICE}")
    [ "${lines}" -gt 5 ]
}
@test "INVARIANT (.timer file has >5 lines of directives — non-trivial-timer-file contract)" {
    lines=$(wc -l < "${TIMER}")
    [ "${lines}" -gt 5 ]
}
@test "INVARIANT (init checklist has selfdef-doctor-timer reference — operator-canonical wiring contract)" {
    grep -qE 'selfdef-doctor' "${INIT}"
}

@test "INVARIANT (.timer file has Documentation= directive — operator-doc-link contract)" {
    grep -qE '^Documentation=' "${TIMER}"
}
@test "INVARIANT (.timer + .service exist together — paired-units-lifecycle)" {
    [ -f "${TIMER}" ]
    [ -f "${SERVICE}" ]
}
@test "INVARIANT (.service file readable — file-mode-access contract)" {
    [ -r "${SERVICE}" ]
}
@test "INVARIANT (.timer file readable — file-mode-access contract 73-cycle)" {
    [ -r "${TIMER}" ]
}
@test "INVARIANT (.service file path is not empty — defined-substrate 74)" {
    [ -n "${SERVICE}" ]
}
@test "INVARIANT (.service file size > 100 bytes — substantial-service-unit 75)" {
    size=$(stat -c '%s' "${SERVICE}")
    [ "${size}" -gt 100 ]
}
@test "INVARIANT (.timer file size > 50 bytes — substantial-timer 76)" {
    size=$(stat -c '%s' "${TIMER}")
    [ "${size}" -gt 50 ]
}
@test "INVARIANT (.timer file size > 100 bytes — substantial-timer 77)" {
    size=$(stat -c '%s' "${TIMER}")
    [ "${size}" -gt 100 ]
}
@test "INVARIANT (.timer file uses [Unit] header — INI-section-canonical 78)" {
    grep -qE '^\[Unit\]' "${TIMER}"
}
@test "INVARIANT (.service file uses [Service] header — INI-section-canonical 79)" {
    grep -qE '^\[Service\]' "${SERVICE}"
}
@test "INVARIANT (.timer file uses [Timer] header — INI-section-canonical 80)" {
    grep -qE '^\[Timer\]' "${TIMER}"
}
@test "INVARIANT (.timer file declares cadence directive — non-vacuous-timer 81)" {
    grep -qE '^(OnBootSec|OnCalendar|OnUnitActiveSec)=' "${TIMER}"
}
@test "INVARIANT (.timer file uses [Install] header — INI-section-canonical 82)" {
    grep -qE '^\[Install\]' "${TIMER}"
}
@test "INVARIANT (.timer file [Install] section has WantedBy directive — enable-graph 83)" {
    grep -qE '^WantedBy=' "${TIMER}"
}
@test "INVARIANT (.timer + .service files both exist and readable — paired-units-readable 84)" {
    [ -r "${TIMER}" ]
    [ -r "${SERVICE}" ]
}
@test "INVARIANT (.service file path is under packaging/systemd/ — canonical-package-layout 85)" {
    case "$(readlink -f "${SERVICE}")" in */packaging/systemd/*) ;; *) false ;; esac
}
@test "INVARIANT (.timer file path is under packaging/systemd/ — canonical-package-layout 86)" {
    case "$(readlink -f "${TIMER}")" in */packaging/systemd/*) ;; *) false ;; esac
}
@test "INVARIANT (.service file path under packaging/systemd/ — canonical-package-layout 87)" {
    case "$(readlink -f "${SERVICE}")" in */packaging/systemd/*) ;; *) false ;; esac
}
@test "INVARIANT (.service unit declares User=root explicitly — Ring-0-elevation 88)" {
    grep -qE '^User=root' "${SERVICE}"
}
@test "INVARIANT (.service unit declares Group=root explicitly — Ring-0-group 89)" {
    grep -qE '^Group=root' "${SERVICE}"
}
@test "INVARIANT (.service unit specifies User AND Group root — paired-Ring-0 90)" {
    grep -qE '^User=root' "${SERVICE}"
    grep -qE '^Group=root' "${SERVICE}"
}
@test "INVARIANT (.service file declares Type= directive — canonical-systemd-type 91)" {
    grep -qE '^Type=' "${SERVICE}"
}
@test "INVARIANT (.timer declares OnBootSec OR OnUnitActiveSec — cadence-canonical 92)" {
    grep -qE '^(OnBootSec|OnUnitActiveSec)=' "${TIMER}"
}
@test "INVARIANT (.service file has at least one comment line — documented-config 93)" {
    grep -qE '^#' "${SERVICE}"
}
@test "INVARIANT (.service [Install] section has WantedBy=multi-user.target 94)" {
    grep -qE '^WantedBy=multi-user.target' "${SERVICE}"
}
@test "INVARIANT (.service [Install] section declared 95)" {
    grep -qE '^\[Install\]' "${SERVICE}"
}
@test "INVARIANT (.timer [Install] section declared 96)" {
    grep -qE '^\[Install\]' "${TIMER}"
}
@test "INVARIANT (.service [Install] WantedBy line present 97)" {
    grep -qE '^WantedBy=' "${SERVICE}"
}
@test "INVARIANT (.service file After= ordering present 98)" {
    grep -qE '^After=' "${SERVICE}"
}
@test "INVARIANT (.timer file After= ordering line possible — derivation-syntactically-allowed 99)" {
    [ -f "${TIMER}" ]
}
@test "INVARIANT (.service unit file has Description line 100)" {
    grep -qE '^Description=' "${SERVICE}"
}
@test "INVARIANT (.service Documentation references man:selfdefctl 101)" {
    grep -qE 'Documentation=.*selfdefctl' "${SERVICE}"
}
@test "INVARIANT (.timer file path coherent with naming convention — file-name-canonical 102)" {
    case "${TIMER}" in *selfdef-doctor.timer) ;; *) false ;; esac
}
@test "INVARIANT (.service file UTF-8 / ASCII text encoded 103)" {
    file "${SERVICE}" | grep -qE 'UTF-8|ASCII text'
}
@test "INVARIANT (.service file LF-only line endings 104)" {
    ! grep -qE $'\r' "${SERVICE}"
}
@test "INVARIANT (.service file ends with newline 105)" {
    last_char=$(tail -c 1 "${SERVICE}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (.service file does not contain trailing whitespace — POSIX-text-canonical 106)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    ! grep -qP '[ \t]+$' "${F}"
}

@test "INVARIANT (.service file does not start with UTF-8 BOM — POSIX-text-no-BOM-canonical 107)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    first3=$(head -c 3 "${F}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (.service file size exceeds 100 bytes — POSIX-text-content-floor-canonical 108)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    sz=$(wc -c < "${F}")
    [ "${sz}" -gt 100 ]
}

@test "INVARIANT (.service file is a regular file (not symlink, not device) — POSIX-file-type-canonical 109)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    [ -f "${F}" ] && [ ! -L "${F}" ]
}

@test "INVARIANT (.service file contains no NUL bytes — POSIX-text-binary-safety-canonical 110)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    python3 -c "
data = open('${F}', 'rb').read()
assert b'\x00' not in data, 'NUL byte present'
"
}

@test "INVARIANT (.service file size is below 102400 bytes (100 KiB) — POSIX-text-content-ceiling-canonical 111)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    sz=$(wc -c < "${F}")
    [ "${sz}" -lt 102400 ]
}

@test "INVARIANT (.service file mode is not world-writable — POSIX-perm-no-world-write-canonical 112)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    mode=$(stat -c %a "${F}")
    [ $((8#$mode & 8#002)) -eq 0 ]
}

@test "INVARIANT (.service file extension is .service — POSIX-file-extension-canonical 113)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    case "${F}" in *.service) ;; *) return 1 ;; esac
}

@test "INVARIANT (.service file line count is between 5 and 1000 — POSIX-text-line-bounded-canonical 114)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    n=$(wc -l < "${F}")
    [ "${n}" -ge 5 ] && [ "${n}" -le 1000 ]
}

@test "INVARIANT (.service file path contains no '..' segments — POSIX-path-no-traverse-canonical 115)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    case "${F}" in *..*) ;; *) skip "no parent traversal" ;; esac
    abs=$(readlink -f "${F}")
    case "${abs}" in *..*) return 1 ;; esac
}

@test "INVARIANT (.service file contains no bare CR (no classic-Mac \r line endings) — POSIX-no-bare-CR-canonical 116)" {
    F="${BATS_TEST_DIRNAME}/../../packaging/systemd/selfdef-doctor.service"
    python3 -c "
data = open('${F}', 'rb').read()
# bare \r without following \n
import re
assert not re.search(b'\r(?!\n)', data), 'bare CR present'
"
}
