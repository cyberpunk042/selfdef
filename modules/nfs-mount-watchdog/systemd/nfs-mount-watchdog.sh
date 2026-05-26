#!/usr/bin/env bash
# selfdef nfs-mount-watchdog — verify network mounts carry
# nosuid + nodev.
#
# A network filesystem is, by definition, content the local
# host does NOT control. If it's mounted WITHOUT nosuid, a
# setuid-root binary placed on the export (by whoever controls
# the server, or a MITM on an unencrypted NFS link) is honored
# by the client → any local user runs it → instant root.
# nodev likewise blocks device-node tricks from the export.
#
# Network fs types checked: nfs, nfs4, cifs, smb3, smbfs,
# fuse.sshfs, ceph, glusterfs, afs.
#
# Severity:
#   ok    → no network mounts, or all carry nosuid+nodev
#   warn  → a network mount missing nodev (but has nosuid)
#   alert → a network mount missing nosuid (the root vector)

set -u

PROFILE="${SELFDEF_NFSMOUNT_PROFILE:-report}"

NET_FSTYPES="nfs nfs4 cifs smb3 smbfs fuse.sshfs ceph glusterfs afs"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# findmnt: TARGET FSTYPE OPTIONS for network fs types only.
if command -v findmnt >/dev/null 2>&1; then
    for t in $NET_FSTYPES; do
        findmnt -rno TARGET,OPTIONS -t "$t" 2>/dev/null
    done > "$tmp"
fi

total=0; no_nosuid=0; no_nodev=0
nosuid_sample=(); nodev_sample=()

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    total=$((total + 1))
    target="${line%% *}"
    opts="${line#* }"
    if [[ ",$opts," != *",nosuid,"* ]]; then
        no_nosuid=$((no_nosuid + 1))
        (( ${#nosuid_sample[@]} < 6 )) && nosuid_sample+=("$target")
    fi
    if [[ ",$opts," != *",nodev,"* ]]; then
        no_nodev=$((no_nodev + 1))
        (( ${#nodev_sample[@]} < 6 )) && nodev_sample+=("$target")
    fi
done < "$tmp"

severity="ok"; event="network_mounts_hardened"
if (( total == 0 )); then
    event="no_network_mounts"
elif (( no_nosuid > 0 )); then
    severity="alert"; event="network_mount_missing_nosuid"
elif (( no_nodev > 0 )); then
    severity="warn"; event="network_mount_missing_nodev"
fi

ns=$(IFS='|'; echo "${nosuid_sample[*]:-}")
nd=$(IFS='|'; echo "${nodev_sample[*]:-}")

json=$(printf '{"tag":"selfdef-nfs-mount","severity":"%s","event":"%s","profile":"%s","network_mounts":%d,"missing_nosuid":%d,"missing_nodev":%d,"nosuid_sample":"%s","nodev_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$total" "$no_nosuid" "$no_nodev" "$ns" "$nd")
logger -t selfdef-nfs-mount -- "$json"

for m in "${nosuid_sample[@]}"; do logger -t selfdef-nfs-mount-detail -- "MISSING_NOSUID ${m}"; done
for m in "${nodev_sample[@]}";  do logger -t selfdef-nfs-mount-detail -- "MISSING_NODEV ${m}"; done

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
