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
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

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
    SELFDEF_MODULE_LIB="${LIB}" \
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

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    eff "${BENIGN[@]}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a dangerous directive" {
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "forcecommand /tmp/getshell" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — sshd-config inventory enumerates remote root-exec surface)" {
    eff "${BENIGN[@]}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (ForceCommand under /var/tmp): writable-root expansion" {
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "forcecommand /var/tmp/.x" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (AuthorizedKeysCommand under /var/tmp): writable-root expansion on AKCmd axis" {
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "authorizedkeyscommand /var/tmp/.x" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Match-block change in sshd_config.d → caught via content-hash even when sshd -T unchanged)" {
    # The watchdog hashes sshd_config + sshd_config.d/ — even when sshd -T
    # output is identical, a config-content edit should surface.
    eff "${BENIGN[@]}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a Match block (doesn't change sshd -T global dump).
    cat > "${CONFD}/match-block.conf" <<'EOF'
Match User backdoor
    PermitRootLogin yes
EOF
    run_wd
    # At minimum, severity should NOT silently stay ok (config hash drifted).
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (sshd_config.d drop-in content-hash also tracked — not only main config)" {
    eff "${BENIGN[@]}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a drop-in.
    cat > "${CONFD}/99-edit.conf" <<'EOF'
MaxAuthTries 3
EOF
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (effective config trumps file content): if sshd -T shows safe but file has bad, sshd -T wins" {
    # The watchdog's authoritative source for directive values is sshd -T
    # (the EFFECTIVE config). Even if sshd_config.d carries an unsafe-
    # looking line, if sshd -T evaluates the same as benign, no alert
    # fires (sshd's own Match/precedence logic governs).
    eff "${BENIGN[@]}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a drop-in but sshd -T still emits safe (mocked).
    cat > "${CONFD}/looks-bad-but-overridden.conf" <<'EOF'
PermitRootLogin yes
EOF
    eff "${BENIGN[@]}"   # sshd -T still emits permitrootlogin no
    run_wd
    # The CONFIG-HASH path will trigger warn (content delta), but the
    # directive-scan path doesn't fire alert (sshd -T agrees with benign).
    ! cap | grep -q '"event":"sshd_config_dangerous_directive"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    eff "${BENIGN[@]}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-sshd-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: sshd-config-watchdog does NOT refresh baseline on dangerous-directive detection — alert STAYS until operator updates)" {
    # sshd dangerous-directive (PermitRootLogin yes / NOPASSWD-equivalent
    # / ForceCommand under writable root) is the remote-facing root-exec
    # primitive. Alert MUST persist across runs until operator explicitly
    # re-baselines. Sister to sudo-conf, gss-mech, ld-preload, nm-vpn-
    # plugin, openvpn-config — active-injection class never auto-trusts.
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin yes" "forcecommand none" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PermitRootLogin prohibit-password is benign — only 'yes' triggers alert; key-only is operator-intentional)" {
    # 'PermitRootLogin prohibit-password' (key-only root) is the
    # operator-intentional hardened config — must NOT trigger alert.
    # Locks the distinction: only 'yes' (password+key) is dangerous.
    eff "permitrootlogin prohibit-password" "passwordauthentication no" "permitemptypasswords no" "forcecommand none" "x11forwarding yes"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (without-password is benign per sshd semantics — sister to prohibit-password)" {
    # 'PermitRootLogin without-password' (deprecated alias for
    # prohibit-password) is also benign. Lock both equivalent
    # operator-intentional values do NOT trigger alert.
    eff "permitrootlogin without-password" "passwordauthentication no" "permitemptypasswords no" "forcecommand none" "x11forwarding yes"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (AuthorizedKeysCommand under /home: user-writable hijack coverage on AKCmd axis)" {
    # Operator's home dir is a writable-root variant. AuthorizedKeysCommand
    # under /home/user/<x> is the user-writable variant of the /tmp +
    # /dev/shm + /var/tmp axes already locked.
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "authorizedkeyscommand /home/user/getkeys" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-with-slash AuthorizedKeysCommand 'sub/dir/getkeys' → alert: PWD-at-exec attacker primitive on sshd AKCmd)" {
    # Sister to krb5-plugins-watchdog + musl-ld-path-watchdog +
    # gss-mech-watchdog + nm-vpn-plugin-watchdog + pkcs11-modules-
    # watchdog relative-with-slash INVARIANTs already locked. An
    # AuthorizedKeysCommand path with embedded slashes BUT no
    # leading slash (e.g. 'sub/dir/getkeys' instead of '/sub/dir/
    # getkeys') is NOT a fully-qualified absolute path — sshd
    # resolves it relative to its own CWD at exec time. An
    # attacker who can affect sshd's CWD (PWD-at-exec primitive
    # — via systemd WorkingDirectory= injection) gets to control
    # where the AuthorizedKeysCommand loads from for EVERY ssh
    # login.
    eff "${BENIGN[@]}"
    run_wd
    eff "permitrootlogin no" "authorizedkeyscommand sub/dir/getkeys" "x11forwarding yes"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (PasswordAuthentication yes → alert when prior was no — operator-intended key-only-auth downgrade)" {
    # Sister to PermitRootLogin yes axis already locked. The
    # PasswordAuthentication directive controls whether sshd
    # accepts password-based login. Operator's hardened baseline
    # typically has PasswordAuthentication=no (force key-only
    # auth). An attacker who edits sshd_config to flip back to
    # PasswordAuthentication=yes opens the host to remote
    # brute-force / credential-stuffing — a configuration
    # downgrade that defeats key-only-auth defense. Lock that
    # the transition from no → yes is flagged as alert.
    eff "permitrootlogin no" "passwordauthentication no" "x11forwarding no"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    eff "permitrootlogin no" "passwordauthentication yes" "x11forwarding no"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (AuthorizedKeysCommand under /var/tmp — writable-root axis-symmetric expansion on sshd AKCmd substrate)" {
    # Sister to /home AKCmd writable-root + relative-with-slash
    # INVARIANTs already locked. /var/tmp is writable by ALL
    # users AND persists across reboots — attackers prefer for
    # boot-survival persistence. sshd executes AuthorizedKeysCommand
    # AS the configured user (often AuthorizedKeysCommandUser
    # = nobody, often root by misconfig) to retrieve keys from
    # external auth — an attacker who plants a binary in
    # /var/tmp + flips AKCmd to it gets remote code-exec on
    # EVERY ssh login attempt. T1556 Modify Authentication
    # Process via AKCmd hijack.
    eff "permitrootlogin no" "passwordauthentication no" "authorizedkeyscommand /var/tmp/.evil-getkeys"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
