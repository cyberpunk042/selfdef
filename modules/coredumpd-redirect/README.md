# coredumpd-redirect

Redirect systemd-coredump storage to `/var/lib/selfdef/coredumps/`
with strict permissions (mode 0700 root:root). Composes with the
kernel-lockdown module's `fs.suid_dumpable=0` setting to allow
operator-controlled forensic preservation WITHOUT leaking SUID
process state to group-readable locations.

## The problem this solves

Default systemd-coredump writes to `/var/lib/systemd/coredump/`
with permissions that allow systemd-coredump-related tools to
read. SUID binaries (sudo, ping, mount, su, passwd) that crash
write coredumps containing the SUID's elevated-privilege memory
state — passwords, tokens, key material. If those coredumps land
in any location readable by non-root users, that's a
**T1003.008 OS Credential Dumping / Proc Filesystem** equivalent
via crash artifact.

`kernel-lockdown`'s `fs.suid_dumpable=0` blocks suid coredumps
entirely. That's the safe-by-default. But operators may WANT
SUID coredumps for forensic analysis (caught an exploit
mid-crash, wants the heap state). This module gives that opt-in:
preserve dumps, but to a path NO unprivileged process can read.

## Profiles

| Profile | Storage | Use |
|---|---|---|
| `redirect` (default) | `/var/lib/selfdef/coredumps/` mode 0700 root:root, no compression, 4G ProcessSizeMax, 20G MaxUse | Default; forensic preservation |
| `disabled` | `Storage=none` | Operator-explicit opt-out; metadata in journal only |

## Interaction with kernel-lockdown

| `kernel-lockdown` profile | `coredumpd-redirect` profile | Effective behavior |
|---|---|---|
| (not applied) | not applied | SUID coredumps → /var/lib/systemd/coredump/ — **information leak risk** |
| balanced or strict | not applied | `fs.suid_dumpable=0` blocks SUID coredumps; non-SUID still dumped to OS default |
| (not applied) | redirect | All coredumps → /var/lib/selfdef/coredumps/ mode 0700 |
| balanced or strict | redirect | `fs.suid_dumpable=0` blocks SUID; non-SUID → /var/lib/selfdef/coredumps/ mode 0700 |
| (not applied) | disabled | systemd-coredump receives metadata; nothing written |

The **recommended stack** is `kernel-lockdown=balanced` +
`coredumpd-redirect=redirect`. SUID processes don't dump (block
secret leak); non-SUID processes (browsers, IDEs, AI tools) DO
dump to a protected operator-readable location.

## Operator extension

The shipped drop-in lives at `/etc/systemd/coredump.conf.d/
50-selfdef.conf`. Operator-tuned overrides drop at e.g.
`60-operator.conf` (lex-order LATER → overrides ours). selfdef
NEVER touches operator-prefixed files.

## Forensic workflow

After a crash:
```bash
# List recent coredumps with metadata
coredumpctl list

# Drill into a specific PID's coredump
coredumpctl info <PID>

# Dump the core file to read in gdb / eu-readelf etc.
sudo coredumpctl dump <PID> > /tmp/inspect.core
sudo gdb /path/to/exe /tmp/inspect.core
```

`coredumpctl` automatically locates the file in the redirected
dir; no operator path-wrangling.

## Cleanup

Coredumps are space-hungry (4G ProcessSizeMax × many crashes).
systemd-coredump auto-prunes per the `MaxUse=20G` + `KeepFree=10G`
directives. Operator can manually drop the dir:

```bash
sudo find /var/lib/selfdef/coredumps -mtime +30 -type f -delete
```

Uninstalling the module does NOT delete the coredump dir
(preserves operator-collected forensic data). Operator must
`rm -rf /var/lib/selfdef/coredumps/` manually to reclaim.
