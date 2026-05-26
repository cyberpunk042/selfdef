#!/usr/bin/env bash
# selfdef sshd-config-watchdog — boot + daily delta of the
# EFFECTIVE sshd configuration vs a learned baseline.
#
# sshd is the primary remote-access surface. ssh-hardening writes
# + checks the directives IT manages; ssh-authkeys-watchdog
# watches key files. Neither catches a dangerous directive added
# via an unmanaged drop-in or a Match block, e.g.:
#
#   echo 'PermitRootLogin yes'                  >> sshd_config.d/zz.conf
#   echo 'AuthorizedKeysCommand /tmp/getkeys'   >> sshd_config.d/zz.conf
#   printf 'Match User svc\n  ForceCommand /tmp/x\n' >> sshd_config
#
# This watchdog records:
#   1. the EFFECTIVE merged config (sshd -T) for a curated set of
#      security-relevant directives — catches a change no matter
#      which file caused it; and
#   2. a content hash of sshd_config + sshd_config.d/*.conf —
#      catches Match blocks (sshd -T shows only the global config)
#      and any other edit.
#
# Records (each line: kind<TAB>key<TAB>value):
#   cfg:<directive>:<value>  — effective value (sshd -T)
#   file:<path>:<sha12>      — hash of each config file
#
# Severity:
#   ok    → no delta
#   warn  → any effective directive changed / file hash changed
#   alert → a dangerous value: permitrootlogin yes,
#           permitemptypasswords yes, or an
#           authorizedkeyscommand/forcecommand target under
#           /tmp /home /dev/shm, world-writable, or bare

set -u

PROFILE="${SELFDEF_SSHD_PROFILE:-report}"
BASELINE="${SELFDEF_SSHD_BASELINE:-/var/lib/selfdef/sshd-config-baseline.tsv}"
SSHD_BIN="${SELFDEF_SSHD_BIN:-}"
SSHD_CONFIG="${SELFDEF_SSHD_CONFIG_FILE:-/etc/ssh/sshd_config}"
SSHD_CONFD="${SELFDEF_SSHD_CONFD:-/etc/ssh/sshd_config.d}"

# Curated security-relevant directives (lowercase as sshd -T
# emits them). Stable across sshd versions; high signal.
KEYS=" permitrootlogin passwordauthentication permitemptypasswords \
pubkeyauthentication authorizedkeyscommand authorizedkeyscommanduser \
forcecommand permittunnel allowtcpforwarding gatewayports x11forwarding \
usepam kbdinteractiveauthentication challengeresponseauthentication \
authorizedkeysfile allowusers allowgroups denyusers denygroups \
permituserenvironment acceptenv subsystem allowagentforwarding \
streamlocalbindunlink maxauthtries logingracetime "

# Locate sshd if not overridden.
if [[ -z "$SSHD_BIN" ]]; then
    for c in /usr/sbin/sshd /sbin/sshd "$(command -v sshd 2>/dev/null || true)"; do
        [[ -n "$c" && -x "$c" ]] && { SSHD_BIN="$c"; break; }
    done
fi
# An override pointing at a non-executable path is treated as absent.
[[ -n "$SSHD_BIN" && ! -x "$SSHD_BIN" ]] && SSHD_BIN=""

# If neither sshd nor a config exists, the host has no ssh server
# — nothing to watch. No-op cleanly (ok).
if [[ -z "$SSHD_BIN" && ! -f "$SSHD_CONFIG" ]]; then
    logger -t selfdef-sshd-config -- '{"tag":"selfdef-sshd-config","severity":"ok","event":"no_sshd","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

is_suspicious_path() {
    local p="$1"
    case "$p" in
        none|"") return 1 ;;
        /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) return 0 ;;
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        *) return 0 ;;  # bare/relative — abnormal for sshd exec dir
    esac
}

# 1. Effective config via sshd -T (test mode dumps merged config).
if [[ -n "$SSHD_BIN" ]]; then
    eff="$("$SSHD_BIN" -T 2>/dev/null || true)"
    if [[ -n "$eff" ]]; then
        while IFS= read -r line; do
            key="${line%% *}"; key="${key,,}"
            case " $KEYS " in *" $key "*) ;; *) continue ;; esac
            val="${line#* }"
            printf 'cfg\t%s\t%s\n' "$key" "$val" >> "$current"
            case "$key" in
                permitrootlogin)
                    [[ "${val,,}" == "yes" ]] && suspicious+=("permitrootlogin=yes") ;;
                permitemptypasswords)
                    [[ "${val,,}" == "yes" ]] && suspicious+=("permitemptypasswords=yes") ;;
                authorizedkeyscommand|forcecommand)
                    # first token of the command
                    prog="${val%% *}"
                    is_suspicious_path "$prog" && suspicious+=("${key}=>${prog}") ;;
            esac
        done <<< "$eff"
    fi
fi

# 2. Content hash of the config files (catches Match blocks +
#    drop-ins sshd -T's global dump does not surface).
hashfiles=()
[[ -f "$SSHD_CONFIG" ]] && hashfiles+=("$SSHD_CONFIG")
if [[ -d "$SSHD_CONFD" ]]; then
    for f in "$SSHD_CONFD"/*.conf; do [[ -f "$f" ]] && hashfiles+=("$f"); done
fi
for f in "${hashfiles[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
done

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if (( ${#suspicious[@]} > 0 )); then
    mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)
fi

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp_str=$(IFS='|'; echo "${suspicious[*]:-}")
    sev="ok"; [[ ${#suspicious[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-sshd-config -- "$(printf '{"tag":"selfdef-sshd-config","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="sshd_config_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="sshd_config_dangerous_directive"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="sshd_config_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-sshd-config","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-sshd-config -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sshd-config-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sshd-config-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
