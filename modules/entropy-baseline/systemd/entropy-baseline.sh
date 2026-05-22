#!/usr/bin/env bash
# selfdef entropy-baseline — verify entropy posture.
#
# Modern Linux (5.18+) treats the random pool as
# always-CSPRNG-ready after initial seeding; entropy_avail
# is largely informational. But the SEED itself can be
# weak on entropy-starved hosts (early-boot cloud VM,
# headless server with no hwrng):
#   - getrandom() may BLOCK forever pre-seed
#   - some libraries fall back to /dev/urandom which is
#     ALSO weak pre-seed
#   - apps generating session keys at boot → predictable
#
# This module checks:
#   1. entropy_avail at run time (>=256 healthy)
#   2. presence of an entropy daemon (jitterentropy,
#      haveged, rng-tools-rngd) OR hardware RNG node
#   3. CRNG ready state (kernel logs "random: crng init
#      done" after seed)
#
# Severity:
#   ok    → entropy_avail >= 256 AND CRNG-init-done seen
#           AND (daemon present OR hwrng present)
#   warn  → entropy_avail < 256 OR no daemon AND no hwrng
#   alert → entropy_avail < 64 AND no daemon (very bad
#           — crypto on this host is risky)

set -u

PROFILE="${SELFDEF_ENTROPY_PROFILE:-report}"
THRESHOLD="${SELFDEF_ENTROPY_THRESHOLD:-256}"

entropy=0
if [[ -r /proc/sys/kernel/random/entropy_avail ]]; then
    entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
fi

# Entropy daemons we recognize.
daemon_active=0
daemon_name=""
for unit in jitterentropy.service haveged.service rngd.service rng-tools.service; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        daemon_active=1
        daemon_name="$unit"
        break
    fi
done

# Hardware RNG presence.
hwrng=0
hwrng_path=""
if [[ -e /sys/class/misc/hw_random/rng_available ]]; then
    available=$(cat /sys/class/misc/hw_random/rng_available 2>/dev/null || echo "")
    if [[ -n "$available" && "$available" != "" ]]; then
        hwrng=1
        hwrng_path="$available"
    fi
fi
# CPU-side hwrng: drng/rdrand on Intel, padlock on VIA.
cpu_rng=""
if grep -qE '\brdrand\b|\brdseed\b' /proc/cpuinfo 2>/dev/null; then
    cpu_rng="rdrand/rdseed"
fi

# CRNG init done?
crng_done=0
if command -v dmesg >/dev/null 2>&1; then
    # Many systems have dmesg restricted; soft-fail.
    if dmesg 2>/dev/null | grep -q "random: crng init done"; then
        crng_done=1
    fi
fi
# Alternative: /sys interface.
if [[ "$crng_done" -eq 0 && -r /proc/sys/kernel/random/uuid ]]; then
    # If we can read a fresh uuid from urandom, CRNG IS up.
    crng_done=1
fi

severity="ok"
event="entropy_ok"
detail=""

if (( entropy < 64 )) && (( daemon_active == 0 )) && (( hwrng == 0 )) && [[ -z "$cpu_rng" ]]; then
    severity="alert"
    event="entropy_starved"
    detail="entropy=$entropy daemon=none hwrng=none cpu_rng=none — crypto on this host is risky"
elif (( entropy < THRESHOLD )) || ( (( daemon_active == 0 )) && (( hwrng == 0 )) && [[ -z "$cpu_rng" ]] ); then
    severity="warn"
    event="entropy_low"
    detail="entropy=$entropy threshold=$THRESHOLD daemon=${daemon_name:-none} hwrng=${hwrng_path:-none} cpu_rng=${cpu_rng:-none}"
fi

json=$(printf '{"tag":"selfdef-entropy","severity":"%s","event":"%s","profile":"%s","entropy_avail":%d,"threshold":%d,"daemon":"%s","hwrng":"%s","cpu_rng":"%s","crng_init_done":%d,"detail":"%s"}' \
    "$severity" "$event" "$PROFILE" "$entropy" "$THRESHOLD" "${daemon_name:-none}" "${hwrng_path:-none}" "${cpu_rng:-none}" "$crng_done" "$detail")
logger -t selfdef-entropy -- "$json"

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
