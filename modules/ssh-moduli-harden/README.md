# ssh-moduli-harden

Prunes weak Diffie-Hellman moduli from `/etc/ssh/moduli`
so the SSH key exchange can't negotiate a weak DH group.
Companion to `ssh-hardening` (which tightens
`sshd_config` KEX/MAC/cipher lists). CIS 5.2.x.

## Why this matters

`/etc/ssh/moduli` holds the Diffie-Hellman group
parameters used by the `diffie-hellman-group-exchange-*`
key-exchange algorithms. During KEX, the client requests
a group of a given size and the server picks a matching
modulus from this file.

If the file contains weak (small) moduli:
- A 1024-bit DH group is within reach of nation-state
  precomputation (the **Logjam** attack class,
  CVE-2015-4000) — the session key can be recovered.
- Even 2048-bit is now considered the floor; CIS + modern
  guidance want >= 3072-bit.

`ssh-hardening` can restrict the KEX *algorithm* list, but
if `diffie-hellman-group-exchange-sha256` is permitted
(it commonly is, for compatibility), the *moduli file*
still governs which group sizes are on the menu. This
module removes the weak entries so a weak group can't be
selected even if the algorithm is allowed.

## Profiles

| Profile | Keeps moduli ≥ | Use |
|---|---|---|
| `strong` (default) | 3072-bit | CIS-aligned; modern hosts |
| `minimum` | 2048-bit | broader client compatibility; still drops the dangerous 1024-bit groups |

## Refuse-to-brick

An EMPTY moduli file breaks `diffie-hellman-group-
exchange` KEX entirely (sshd can't offer a group). So
apply.sh counts the moduli that would survive the filter
FIRST, and **aborts** if that count is zero — telling the
operator to regenerate strong moduli with `ssh-keygen -M
generate` / `-M screen` before retrying. The original is
backed up to `/var/lib/selfdef/ssh-moduli.bak` (restored
on uninstall).

## MITRE coverage

- **T1557** Adversary-in-the-Middle — a weak DH group lets
  an attacker who can record the session later recover the
  key + decrypt (Logjam-class).
- **T1040** Network Sniffing — recorded-then-decrypted SSH
  traffic.
- **T1600.001** Weaken Encryption: Reduce Key Space —
  weak moduli ARE a reduced key space; pruning them is the
  direct mitigation.

## Operator workflow

```bash
# Inspect modulus sizes present
awk '!/^#/ && NF==5 {print $5}' /etc/ssh/moduli | sort -n | uniq -c

# Apply (strong = >= 3072)
sudo selfdefctl modules apply ssh-moduli-harden

# Verify no weak moduli remain
sudo selfdefctl modules check ssh-moduli-harden

# If the file would be emptied (rare — minimal/old image),
# regenerate strong moduli first (SLOW — minutes to hours):
sudo ssh-keygen -M generate -O bits=4096 /tmp/moduli.candidates
sudo ssh-keygen -M screen -f /tmp/moduli.candidates /etc/ssh/moduli
sudo selfdefctl modules apply ssh-moduli-harden

# Restart sshd to pick up (moduli is read per-connection, so
# usually no restart needed; restart to be safe)
sudo systemctl restart ssh   # or sshd
```

## Caveats

- **Very old SSH clients** that only support 1024/2048-bit
  DHGEX will fail to connect under `strong`. Use `minimum`
  for compatibility, or (better) configure those clients
  to use curve25519 KEX (which doesn't use moduli at all).
- **curve25519-sha256 / ecdh-* KEX don't use moduli** —
  hosts whose `sshd_config` KexAlgorithms is curve25519-
  only are unaffected by this file. This module is belt-
  and-suspenders for hosts that still permit DHGEX.
- **Regenerating moduli is slow** (`ssh-keygen -M screen`
  can take a long time) — only needed in the rare
  empty-after-filter case.
- **moduli is re-read per connection** — no sshd restart
  strictly required, but restart to be certain.

## Coexistence

- **ssh-hardening**: the primary companion — ssh-hardening
  sets `KexAlgorithms` (which algorithms), this prunes the
  moduli (which DH group sizes). Apply both for complete
  SSH-KEX hardening.
- **ssh-wrap (MS014)**: client-side SSH defense; orthogonal
  to this server-side moduli pruning.
- **fail2ban-bridge**: network-IP-layer SSH defense;
  orthogonal to the crypto layer.
