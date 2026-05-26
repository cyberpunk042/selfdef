#!/usr/bin/env bash
# selfdef nfs-exports-watchdog — boot + daily delta of the NFS
# server export table vs a learned baseline.
#
# nfs-mount-watchdog covers the CLIENT (mounts); this watches the
# SERVER /etc/exports for dangerous grants:
#
#   /          *(rw,no_root_squash,insecure)   # whole FS, remote root
#   /srv/data  *(rw)                            # writable to ANY host
#   /etc       192.168.0.0/16(ro)               # leak system config
#
# no_root_squash maps a remote root client to LOCAL root → an
# attacker who mounts the export writes files as root (plant a
# setuid binary, edit /etc) — instant compromise (T1199/T1133).
# A wildcard host `*` exports to anyone; `insecure` allows mounts
# from unprivileged source ports (any local user on the client).
#
# Records (each line: kind<TAB>dir<TAB>value):
#   file:<path>:<sha12>          — hash of each exports file
#   export:<dir>:<host>(<opts>)  — each host clause per directory
#
# Severity:
#   ok    → no delta
#   warn  → any export added / removed / changed
#   alert → a NEWLY-ADDED dangerous export: no_root_squash; a `*`
#           wildcard host with rw; `insecure`; or exporting / or a
#           sensitive path (/etc /home /root /boot /usr ...)

set -u

PROFILE="${SELFDEF_NFSEXP_PROFILE:-report}"
BASELINE="${SELFDEF_NFSEXP_BASELINE:-/var/lib/selfdef/nfs-exports-baseline.tsv}"
EXPORTS="${SELFDEF_NFSEXP_FILE:-/etc/exports}"
EXPORTSD="${SELFDEF_NFSEXP_D:-/etc/exports.d}"

is_sensitive_dir() {
    case "$1" in
        /|/etc|/etc/*|/home|/home/*|/root|/root/*|/boot|/boot/*|/usr|/usr/*|/var|/bin|/sbin|/lib*) return 0 ;;
        *) return 1 ;;
    esac
}

# Echo a danger tag for a host clause "host(opts)" exporting <dir>.
scan_clause() {  # dir clause
    local dir="$1" clause="$2" host opts
    host="${clause%%(*}"
    opts="${clause#*(}"; opts="${opts%)}"
    [[ ",$opts," == *",no_root_squash,"* || "$opts" == *no_root_squash* ]] && echo "no_root_squash:${dir}@${host}"
    [[ "$host" == "*" || "$host" == "" ]] && [[ "$opts" == *rw* ]] && echo "wildcard-rw:${dir}@${host:-*}"
    [[ ",$opts," == *",insecure,"* || "$opts" == *insecure* ]] && echo "insecure:${dir}@${host}"
    is_sensitive_dir "$dir" && echo "sensitive-export:${dir}@${host}"
}

files=()
[[ -f "$EXPORTS" ]] && files+=("$EXPORTS")
if [[ -d "$EXPORTSD" ]]; then
    for f in "$EXPORTSD"/*.exports; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-nfs-exports -- '{"tag":"selfdef-nfs-exports","severity":"ok","event":"no_exports","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a baseline_susp=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    while IFS= read -r line; do
        line="${line%%#*}"
        read -r -a F <<< "$line"
        [[ ${#F[@]} -lt 1 ]] && continue
        dir="${F[0]}"
        [[ -z "$dir" || "$dir" != /* ]] && continue
        # Remaining tokens are host(opts) clauses.
        for ((i=1; i<${#F[@]}; i++)); do
            clause="${F[$i]}"
            printf 'export\t%s\t%s\n' "$dir" "$clause" >> "$current"
            while IFS= read -r tag; do
                [[ -n "$tag" ]] && baseline_susp+=("$tag")
            done < <(scan_clause "$dir" "$clause")
        done
        # An export line with NO host clause (just a dir) defaults to
        # world-export on many configs — flag it too.
        if [[ ${#F[@]} -eq 1 ]]; then
            printf 'export\t%s\t%s\n' "$dir" "(nohost)" >> "$current"
            baseline_susp+=("no-host-clause:${dir}")
        fi
    done < "$f"
done

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp=()
    (( ${#baseline_susp[@]} > 0 )) && mapfile -t susp < <(printf '%s\n' "${baseline_susp[@]}" | sort -u)
    susp_str=$(IFS='|'; echo "${susp[*]:-}")
    sev="ok"; [[ ${#susp[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-nfs-exports -- "$(printf '{"tag":"selfdef-nfs-exports","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

declare -a suspicious=()
while IFS= read -r aline; do
    [[ "$aline" == export$'\t'* ]] || continue
    IFS=$'\t' read -r _k dir clause <<< "$aline"
    while IFS= read -r tag; do
        [[ -n "$tag" ]] && suspicious+=("$tag")
    done < <(scan_clause "$dir" "$clause")
done <<< "$added"
(( ${#suspicious[@]} > 0 )) && mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)

severity="ok"; event="nfs_exports_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="nfs_exports_dangerous"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="nfs_exports_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-nfs-exports","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-nfs-exports -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-nfs-exports-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-nfs-exports-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
