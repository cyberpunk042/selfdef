#!/usr/bin/env bash
# selfdef bootloader-password-detect — verify GRUB2 has a
# password configured (preferably PBKDF2-hashed via
# grub2-mkpasswd-pbkdf2).
#
# Severity:
#   ok    → password directive found AND uses password_pbkdf2
#   warn  → plaintext `password` directive used (deprecated)
#   alert → no password directive at all (physical-access
#          attacker can edit boot params at GRUB menu)
#   ok    → bootloader is not GRUB (other bootloaders out of
#          scope; future modules can cover them)

set -u

PROFILE="${SELFDEF_BOOTLOADER_PROFILE:-report}"

# Discover GRUB config locations across distros.
CANDIDATES=(
    "/boot/grub/grub.cfg"
    "/boot/grub2/grub.cfg"
    "/boot/efi/EFI/redhat/grub.cfg"
    "/boot/efi/EFI/centos/grub.cfg"
    "/boot/efi/EFI/almalinux/grub.cfg"
    "/boot/efi/EFI/rocky/grub.cfg"
    "/boot/efi/EFI/fedora/grub.cfg"
    "/boot/efi/EFI/ubuntu/grub.cfg"
    "/boot/efi/EFI/debian/grub.cfg"
)
USER_CONF=(
    "/etc/grub.d/40_custom"
    "/etc/grub.d/01_users"
)

found_cfg=""
for c in "${CANDIDATES[@]}"; do
    [[ -f "$c" ]] && { found_cfg="$c"; break; }
done

if [[ -z "$found_cfg" ]]; then
    json=$(printf '{"tag":"selfdef-bootloader-password","severity":"ok","event":"no_grub","profile":"%s"}' "$PROFILE")
    logger -t selfdef-bootloader-password -- "$json"
    exit 0
fi

# Scan for password directives across grub.cfg AND user
# fragments (operator-edited; grub-mkconfig pulls these into
# the rendered grub.cfg).
search_files=("$found_cfg")
for uc in "${USER_CONF[@]}"; do
    [[ -r "$uc" ]] && search_files+=("$uc")
done

has_password_plain=0
has_password_pbkdf2=0
has_set_superusers=0

for f in "${search_files[@]}"; do
    [[ -r "$f" ]] || continue
    # set superusers="..." indicates the user-set is present.
    if grep -qE '^\s*set\s+superusers\s*=' "$f"; then has_set_superusers=1; fi
    # password_pbkdf2 <user> grub.pbkdf2.sha512...
    if grep -qE '^\s*password_pbkdf2\b' "$f"; then has_password_pbkdf2=1; fi
    # Plaintext: password <user> <plaintext>
    if grep -qE '^\s*password\s+[A-Za-z0-9_-]+\s+\S' "$f"; then has_password_plain=1; fi
done

severity="ok"
event="grub_password_pbkdf2"
detail=""

if (( has_password_pbkdf2 )); then
    if (( has_set_superusers )); then
        severity="ok"
        event="grub_password_pbkdf2"
    else
        severity="warn"
        event="grub_password_pbkdf2_no_superuser"
        detail="password_pbkdf2 present but no set superusers — directive may be unreachable"
    fi
elif (( has_password_plain )); then
    severity="warn"
    event="grub_password_plaintext"
    detail="deprecated plaintext password directive (use grub2-mkpasswd-pbkdf2)"
else
    severity="alert"
    event="grub_no_password"
    detail="no password directive — physical-access attacker can edit boot params (init=/bin/sh, single-user mode)"
fi

json=$(printf '{"tag":"selfdef-bootloader-password","severity":"%s","event":"%s","profile":"%s","grub_cfg":"%s","has_pbkdf2":%d,"has_plaintext":%d,"has_superusers":%d,"detail":"%s"}' \
    "$severity" "$event" "$PROFILE" "$found_cfg" "$has_password_pbkdf2" "$has_password_plain" "$has_set_superusers" "$detail")
logger -t selfdef-bootloader-password -- "$json"

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
