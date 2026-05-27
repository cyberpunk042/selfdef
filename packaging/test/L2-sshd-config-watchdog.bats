#!/usr/bin/env bats
# L2 bats functional tests for the sshd-config-watchdog scan script.
#
# Watches the SSH daemon's EFFECTIVE config (via `sshd -T`) for dangerous
# directives — a remote-facing root-exec surface: AuthorizedKeysCommand /
# ForceCommand pointing at attacker code, PermitRootLogin yes,
# PermitEmptyPasswords yes — plus a content hash of sshd_config{,.d} to
# catch Match-block / drop-in changes the global dump doesn't surface.
#
# `sshd -T` is stubbed via a fake sshd (SELFDEF_SSHD_BIN) that emits a
# controllable effective-config; the config files use the existing
# SELFDEF_SSHD_CONFIG_FILE / SELFDEF_SSHD_CONFD seams in a tmp sandbox.
#
# Run with: bats packaging/test/L2-sshd-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sshd-config-watchdog/systemd/sshd-config-watchdog.sh"

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
    # Fake sshd: `sshd -T` dumps the effective config we control.
    export SELFDEF_TEST_SSHD_EFF="${TMP}/eff.txt"
    FAKESSHD="${TMP}/sshd"
    cat > "${FAKESSHD}" <<'FAKESSHD'
#!/usr/bin/env bash
cat "${SELFDEF_TEST_SSHD_EFF}" 2>/dev/null || true
FAKESSHD
    chmod +x "${FAKESSHD}"
    BASELINE="${TMP}/baseline.tsv"
    CFG="${TMP}/sshd_config"; printf '# managed\nPort 22\n' > "${CFG}"
    CONFD="${TMP}/sshd_config.d"; mkdir -p "${CONFD}"
}

teardown() { rm -rf "${TMP}"; }

# Write the effective-config the fake sshd will emit.
eff() { printf '%s\n' "$@" > "${SELFDEF_TEST_SSHD_EFF}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SSHD_PROFILE="${PROFILE:-report}" \
    SELFDEF_SSHD_BASELINE="${BASELINE}" \
    SELFDEF_SSHD_BIN="${SSHD_BIN:-$FAKESSHD}" \
    SELFDEF_SSHD_CONFIG_FILE="${CFG}" \
    SELFDEF_SSHD_CONFD="${CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

BENIGN=( "permitrootlogin no" "passwordauthentication no" "permitemptypasswords no" "forcecommand none" "x11forwarding yes" )

# ============================================================
# ok tier
# ============================================================

@test "no sshd binary and no config → ok / no_sshd" {
    SSHD_BIN="${TMP}/nonexistent-sshd" CFG="${TMP}/nonexistent-config" run_wd
    cap | grep -q '"event":"no_sshd"'
    cap | grep -q '"severity":"ok"'
}

@test "benign effective config, first run → ok / baseline_initial" {
    eff "${BENIGN[@]}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / sshd_config_intact" {
    eff "${BENIGN[@]}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sshd_config_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — dangerous directive
# ============================================================

@test "ForceCommand pointing under a writable root → alert / sshd_config_dangerous_directive" {
    eff "${BENIGN[@]}"
    run_wd                                   # benign baseline
    eff "permitrootlogin no" "forcecommand /tmp/getshell" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sshd_config_dangerous_directive"'
    cap | grep -q '"severity":"alert"'
}

@test "AuthorizedKeysCommand under a writable root → alert" {
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "authorizedkeyscommand /dev/shm/getkeys" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "PermitRootLogin yes → alert" {
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin yes" "forcecommand none" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "PermitEmptyPasswords yes → alert" {
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "permitemptypasswords yes" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign directive value change → warn / sshd_config_changed" {
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "passwordauthentication no" "permitemptypasswords no" "forcecommand none" "x11forwarding no"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sshd_config_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "ForceCommand at a trusted existing path is NOT flagged" {
    eff "permitrootlogin no" "forcecommand /usr/sbin/nologin" "x11forwarding yes"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a hardened benign config (root login off, no force command) is NOT flagged" {
    eff "${BENIGN[@]}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on a dangerous directive" {
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "forcecommand /tmp/getshell" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
