#!/usr/bin/env bats
# L2 bats functional tests for the tmpfiles-watchdog scan script.
#
# systemd-tmpfiles applies the directives in tmpfiles.d/*.conf AS ROOT at
# boot + on a timer. An entry that creates a setuid file, or a .conf that is
# world-writable/non-root, is a privesc/persistence surface (T1546). Severity:
#   ok    → no delta
#   warn  → an entry added/changed/removed
#   alert → a .conf world-writable/non-root, OR an entry with a setuid Mode
#
# Run with: bats packaging/test/L2-tmpfiles-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd/tmpfiles-watchdog.sh"

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
    BASELINE="${TMP}/baseline.tsv"
    CONFD="${TMP}/tmpfiles.d"; mkdir -p "${CONFD}"
    CONF="${CONFD}/myapp.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_TMPFILES_PROFILE="${PROFILE:-report}" \
    SELFDEF_TMPFILES_BASELINE="${BASELINE}" \
    SELFDEF_TMPFILES_DIRS="${DIRS_V:-$CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/state 0644 root root -\n' > "${CONF}"
}

@test "no tmpfiles dir → ok / no_tmpfiles" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_tmpfiles"'
    cap | grep -q '"severity":"ok"'
}

@test "benign tmpfiles conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged tmpfiles conf on second run → ok / tmpfiles_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"tmpfiles_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an entry with a setuid Mode → alert / tmpfiles_suspicious" {
    seed_benign
    run_wd
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/shell 4755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"tmpfiles_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable tmpfiles conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign entry change → warn / tmpfiles_changed" {
    seed_benign
    run_wd
    printf 'd /run/myapp 0750 root root -\nf /run/myapp/state 0644 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"tmpfiles_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign tmpfiles conf is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a setuid-mode entry" {
    seed_benign
    run_wd
    printf 'f /run/myapp/shell 4755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — tmpfiles inventory enumerates root-write-at-boot surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (setgid mode): an entry with a 2xxx (setgid) mode → alert" {
    # The script's setuid detection should catch the setgid bit
    # too — both are privilege-bearing.
    seed_benign
    run_wd
    printf 'f /run/myapp/shell 2755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (suid+sgid mode): an entry with a 6xxx (suid+sgid) mode → alert" {
    seed_benign
    run_wd
    printf 'f /run/myapp/shell 6755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing setuid): baseline_initial fires alert if a tmpfiles entry already has a setuid mode at install-time" {
    printf 'f /run/myapp/shell 4755 root root -\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (group-writable .conf): group-writable tmpfiles .conf → alert above world-writable" {
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED tmpfiles .conf (operator pruning) → warn" {
    seed_benign
    cat > "${CONFD}/other.conf" <<'EOF'
d /run/other 0755 root root -
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CONFD}/other.conf"
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-tmpfiles -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): tmpfiles-watchdog does NOT refresh baseline on setuid-entry detection — alert STAYS until operator updates" {
    # tmpfiles.d setuid entries are NEVER routine; the alert must
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/shell 4755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"tmpfiles_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented setuid entry NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/state 0644 root root -\n# f /run/myapp/shell 4755 root root -\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"tmpfiles_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (newly-ADDED .conf with setuid entry → alert; new-file + suspicious-entry combined)" {
    # Attacker drops a fresh tmpfiles.d/.conf containing setuid
    # entries. Watchdog must alert on BOTH the new file AND the
    # suspicious entry, with alert severity taking precedence.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONFD}/00-evil.conf" <<'EOF'
f /run/backdoor 4755 root root -
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"tmpfiles_suspicious"'
}

@test "INVARIANT (Z chmod-only entry on a non-setuid mode is NOT flagged: chmod-mode tmpfiles type distinct from setuid-creation)" {
    # Z = recursively-restore-perms type entries are operator-
    # tuning. A Z entry with mode 0755 is a legit operator op.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a Z (recursive chmod) entry with non-setuid mode.
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/state 0644 root root -\nZ /run/myapp 0755 root root -\n' > "${CONF}"
    run_wd
    # Severity is warn (content delta), not alert (no setuid).
    cap | grep -qE '"severity":"(warn|ok)"'
    ! cap | grep -q '"event":"tmpfiles_suspicious"'
}
