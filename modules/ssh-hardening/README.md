# ssh-hardening

sshd_config baseline drop-in. Disables the most-attacked sshd
defaults (root login, password auth, X11 forwarding) + restricts
crypto to a modern allowlist. Paranoid profile adds AllowGroups
ssh hard-restriction.

## Refuse-to-brick guards

| Guard | Failure mode prevented |
|---|---|
| `sshd -t` validation after install | A syntactically-broken config rolls back to operator's previous file |
| paranoid `selfdef_acknowledge_allowgroups = true` | AllowGroups ssh locks out non-ssh-group users; opt-in flag forces operator to confirm their user IS in the ssh group before applying |
| Backup-restore pattern | apply.sh copies the existing 50-selfdef.conf to a .selfdef-rollback.<pid> backup, installs the new one, validates; on failure restores backup |

A bad sshd_config locks the operator out of remote access — this
module's guards make that impossible via the apply path.

## Profiles

| Profile | Auth | Crypto allowlist | Rate-limit | Group restriction |
|---|---|---|---|---|
| `standard` (default) | PermitRootLogin no, PasswordAuthentication no, X11 off, no forwarding | curve25519 + ECDH NIST + DH-group16/18; ssh-ed25519 + rsa-sha2; ChaCha20-Poly1305 + AES-GCM + AES-CTR; sha2-512/256-ETM + UMAC-128-ETM | MaxAuthTries 4, LoginGraceTime 60, MaxSessions 10 | None |
| `paranoid` | Same as standard | Same | MaxAuthTries 2, LoginGraceTime 30, MaxSessions 5, MaxStartups 2:30:10 | **AllowGroups ssh** (hard lockout for non-members) |

## MITRE coverage

- **T1110** Brute Force — MaxAuthTries + LoginGraceTime narrow
  the brute-force window. fail2ban-bridge module (future) adds
  IP-level lockout.
- **T1110.001** Brute Force: Password Guessing — PasswordAuthentication
  off forces key-only auth (no online password guessing).
- **T1078** Valid Accounts — AllowGroups ssh (paranoid)
  restricts to operator-curated group.
- **T1021.004** Remote Services: SSH — strong crypto allowlist
  blocks downgrade attacks against weak KEX/MAC.
- **T1133** External Remote Services — DisableForwarding yes
  (paranoid) blocks SSH tunneling as an exfil/pivot vector.

## Why these crypto choices

| Algorithm class | Allowed | Excluded (default sshd has these on some distros) |
|---|---|---|
| KEX | curve25519, ECDH-P256/384/521, DH-group16/18-sha512 | DH-group1-sha1, DH-group14-sha1 (Logjam-vulnerable) |
| HostKey | ssh-ed25519, rsa-sha2-256/512 | ssh-rsa (SHA-1 signature — deprecated 2020+) |
| Cipher | chacha20-poly1305, AES-GCM, AES-CTR | aes*-cbc (BEAST + padding-oracle), 3des-cbc, blowfish-cbc, arcfour |
| MAC | sha2-512/256-ETM, umac-128-ETM | sha1-* (truncation attacks), md5-* |

Sources: Mozilla "modern" SSH baseline, NIST SP 800-131A, IETF
RFC 9142 KEX algorithm recommendations.

## Operator workflow

```bash
# Verify your key is in authorized_keys BEFORE applying
ssh-add -L | head        # what's in agent
cat ~/.ssh/authorized_keys

# Apply standard profile
sudo selfdefctl modules apply ssh-hardening

# Test from ANOTHER terminal/session — KEEP YOUR EXISTING SSH
# SESSION ALIVE in case the new config breaks login
ssh operator@thishost

# Once you've confirmed standard works, switch to paranoid:
sudo grep -q '^ssh:' /etc/group || sudo groupadd ssh
sudo gpasswd -a "$USER" ssh
# Edit /etc/selfdef/modules/ssh-hardening.toml:
#   profile = "paranoid"
#   selfdef_acknowledge_allowgroups = true
sudo selfdefctl modules apply ssh-hardening
```

## Operator-extension

`/etc/ssh/sshd_config.d/60-operator.conf` (lex-order LATER →
overrides selfdef's defaults). Common operator overrides:
- `Match` blocks per-user / per-network
- `AcceptEnv LANG LC_*`
- Custom AuthorizedKeysFile path

selfdef NEVER touches operator-prefixed files.

## Coexistence with selfdef-ssh-wrap

`selfdef-ssh-wrap` (per SDD-052) is a CLIENT-SIDE per-user SSH
wrapper that emits OCSF events for outbound ssh. ssh-hardening is
SERVER-SIDE sshd config. They're orthogonal — different sides of
the SSH connection.
