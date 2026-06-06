#!/usr/bin/env bash
# dns-shield — apply.
#
# Renders the chosen blocklist profile (+ operator additions +
# minus allowlist) into a bracketed block in /etc/hosts. Only the
# region between BEGIN/END markers is selfdef's; everything else
# in /etc/hosts is preserved byte-for-byte.
#
# Idempotent: re-running with the same input writes byte-identical
# output. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="dns-shield"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_DNS_SHIELD_CONFIG:-/etc/selfdef/modules/dns-shield.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
BLOCKLISTS_SRC="${SELFDEF_DNS_SHIELD_BLOCKLISTS:-${MODULE_DIR}/blocklists}"
HOSTS_FILE="${SELFDEF_HOSTS_FILE:-/etc/hosts}"
OPERATOR_DIR="${SELFDEF_DNS_SHIELD_DIR:-/etc/selfdef/dns-shield}"
OPERATOR_FILE="${SELFDEF_DNS_SHIELD_OPERATOR_FILE:-${OPERATOR_DIR}/operator.txt}"
ALLOW_FILE="${SELFDEF_DNS_SHIELD_ALLOW_FILE:-${OPERATOR_DIR}/allowlist.txt}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$BLOCKLISTS_SRC" ]] || die "blocklist source dir missing: $BLOCKLISTS_SRC"
[[ -w "$HOSTS_FILE" || "$DRY_RUN" == "1" ]] || die "$HOSTS_FILE not writable (need root)"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "base")
case "$PROFILE" in
    base|strict) ;;
    *) die "profile must be base|strict, got '$PROFILE'" ;;
esac

# Build the list of files we'll union.
BLOCK_SOURCES=("${BLOCKLISTS_SRC}/base.txt")
[[ "$PROFILE" == "strict" ]] && BLOCK_SOURCES+=("${BLOCKLISTS_SRC}/strict.txt")
[[ -r "$OPERATOR_FILE" ]] && BLOCK_SOURCES+=("$OPERATOR_FILE")

mkdir -p "$OPERATOR_DIR"

# Build the canonical merged list: strip comments + blanks, dedup,
# subtract allowlist, sort.
tmp_merged="$(mktemp)"
for f in "${BLOCK_SOURCES[@]}"; do
    [[ -r "$f" ]] || continue
    grep -v '^#' "$f" | grep -v '^$' | tr -d '\r' >> "$tmp_merged"
done
sort -u "$tmp_merged" -o "$tmp_merged"

if [[ -r "$ALLOW_FILE" ]]; then
    tmp_allow="$(mktemp)"
    grep -v '^#' "$ALLOW_FILE" | grep -v '^$' | tr -d '\r' | sort -u > "$tmp_allow"
    tmp_filtered="$(mktemp)"
    comm -23 "$tmp_merged" "$tmp_allow" > "$tmp_filtered"
    mv "$tmp_filtered" "$tmp_merged"
    rm -f "$tmp_allow"
fi

count=$(wc -l < "$tmp_merged" | tr -d ' ')

# Render the /etc/hosts block. The metadata comment carries profile
# + count but NOT a render-timestamp — including the timestamp would
# defeat idempotency (the timestamp differs on every apply, forcing
# a re-write of /etc/hosts even when the actual blocklist content
# hasn't changed, bumping the mtime and tripping watchdog
# inventory diffs unnecessarily). The cmp -s idempotency check
# below depends on the rendered block being byte-stable across
# runs with identical input.
tmp_block="$(mktemp)"
{
    echo "$DNS_SHIELD_BEGIN"
    echo "# profile=$PROFILE count=$count"
    while IFS= read -r domain; do
        # Bare + www. variants.
        echo "0.0.0.0 $domain"
        echo "0.0.0.0 www.$domain"
    done < "$tmp_merged"
    echo "$DNS_SHIELD_END"
} > "$tmp_block"
rm -f "$tmp_merged"

# Splice the block into /etc/hosts: remove any prior bracketed
# block, then append the new one.
tmp_hosts="$(mktemp)"
if grep -q "^${DNS_SHIELD_BEGIN}$" "$HOSTS_FILE" 2>/dev/null; then
    awk -v begin="$DNS_SHIELD_BEGIN" -v end="$DNS_SHIELD_END" '
        BEGIN { skip = 0 }
        $0 == begin { skip = 1; next }
        $0 == end   { skip = 0; next }
        skip == 0   { print }
    ' "$HOSTS_FILE" > "$tmp_hosts"
else
    cp "$HOSTS_FILE" "$tmp_hosts"
fi
cat "$tmp_block" >> "$tmp_hosts"
rm -f "$tmp_block"

# Idempotency check: same content → no write.
if cmp -s "$tmp_hosts" "$HOSTS_FILE"; then
    rm -f "$tmp_hosts"
    emit_status "ok" "dns-shield profile=$PROFILE count=$count (no change)"
    exit 0
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would update $HOSTS_FILE (profile=$PROFILE count=$count)"
    rm -f "$tmp_hosts"
else
    install -m 0644 "$tmp_hosts" "$HOSTS_FILE"
    rm -f "$tmp_hosts"
fi

emit_status "ok" "dns-shield profile=$PROFILE count=$count changed=1"
