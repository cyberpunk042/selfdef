# umask-baseline

Operator-default umask tightening. Default distro umask (0022) leaves
operator-created files world-readable (`-rw-r--r--`). This module
sets the default to 0027 (group profile) or 0077 (strict profile),
reducing the information-leak surface for files the operator creates.

## Profiles

| Profile | umask | File mode (post-mask) | Dir mode (post-mask) | Use |
|---|---|---|---|---|
| `group` (default) | 0027 | -rw-r----- | drwxr-x--- | Operator-team workflows; group-readable shared dirs |
| `strict` | 0077 | -rw------- | drwx------ | Single-operator hosts; owner-only |

## Why this matters

A typical operator-workflow `vim ~/secrets/api-tokens` results in:

```
$ ls -l ~/secrets/api-tokens
-rw-r--r-- 1 operator operator  4096 ...
```

That file is now world-readable. Any process running as ANY user
(including compromised-by-attacker low-privilege accounts like
`nobody`, `_apt`, `systemd-resolve`) can read it.

With `umask 0027`:

```
$ ls -l ~/secrets/api-tokens
-rw-r----- 1 operator operator  4096 ...
```

World denied. Group-readable only if a non-operator user happens to
be in the operator's group.

With `umask 0077` (strict):

```
$ ls -l ~/secrets/api-tokens
-rw------- 1 operator operator  4096 ...
```

Owner-only.

## Files installed

| Path | Purpose |
|---|---|
| `/etc/profile.d/50-selfdef-umask.sh` | Sourced by every interactive bash/zsh login |
| `/etc/login.defs.d/50-selfdef-umask.conf` | PAM/login(1) consultation for non-interactive sessions (cron, ssh pre-shell, useradd new-account creation) |

Two surfaces because each handles a different invocation path:
- `/etc/profile.d/*.sh` covers interactive shells.
- `login.defs UMASK` covers cron, ssh `command=`, useradd defaults.

## MITRE coverage

- **T1222** File and Directory Permissions Modification — defender
  side: operator-default-tight ensures files don't START
  world-readable. Attacker who later wants to make them readable
  must explicitly chmod, which is auditable.
- **T1083** File and Directory Discovery — narrower attacker
  surface; many files become invisible to unprivileged listing.

## Takes effect on NEXT shell

Setting `/etc/profile.d/50-selfdef-umask.sh` doesn't change the
CURRENT shell's umask — it's sourced by NEW shell invocations.
The operator must:

```bash
# Verify the file is in place
ls -l /etc/profile.d/50-selfdef-umask.sh

# Open a new shell to inherit the new umask
exec bash      # or just log out + back in

# Verify
umask          # expect 0027 (group profile) or 0077 (strict)
```

## Operator-extension

`/etc/profile.d/60-operator-umask.sh` (lex-order LATER →
overrides). For per-user overrides, operator adds to `~/.bashrc`
or `~/.zshrc`. selfdef NEVER touches operator-prefixed files.

## Caveats

- **Build systems often need 0022** for installed-package
  visibility (libraries readable by all users at runtime). The
  group profile (0027) handles this correctly when the library
  group is set right; strict (0077) WILL break library access for
  non-operator runtime users. Use group on hosts running daemons.
- **The 50-selfdef-umask.sh runs at LOGIN**. Long-running daemons
  spawned via systemd inherit umask from the SYSTEMD service unit,
  NOT from this file. Operator sets per-unit `UMask=0027` on
  daemon unit files; the systemd-system default is 0022 and
  separately governed.
- **Some operators rely on 0022** for static-content servers
  (nginx serving /var/www/* expects world-readable). Operator
  evaluates per-host before applying strict.

## Coexistence with selfdef-collector-auditd

audit-rules paranoid profile's universal exec watch captures every
SUID-exec event. With strict-profile umask, fewer files have stale
group/world permissions for the auditd surface to flag as drift.
