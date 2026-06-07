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
