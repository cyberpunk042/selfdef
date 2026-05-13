# selfdef-ssh-wrap install

The wrapper is a drop-in replacement for `ssh`. You install the binary
somewhere on PATH and point a symlink at it.

## 1. Install the binary

```bash
cargo build --release -p selfdef-ssh-wrap
sudo install -m 0755 target/release/selfdef-ssh-wrap /usr/local/bin/
```

## 2. Shadow `ssh` for your user

Make `~/.local/bin/ssh` resolve before `/usr/bin/ssh`:

```bash
mkdir -p ~/.local/bin
ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh

# Ensure ~/.local/bin precedes /usr/bin in PATH.
# In ~/.zshrc or ~/.bashrc:
#   export PATH="$HOME/.local/bin:$PATH"
```

`which ssh` should now print `/home/<you>/.local/bin/ssh`. Existing scripts
and tooling that exec `ssh` will route through the wrapper transparently.

## 3. Drop the policy file

```bash
mkdir -p ~/.config/selfdef
cp packaging/ssh-wrap-policy.toml.example ~/.config/selfdef/ssh-wrap.toml
```

Edit to taste. The default policy denies agent forwarding, X11 forwarding,
and port forwarding for every host; per-host blocks opt specific hosts in.

## 4. Wire events into the daemon (optional)

The wrapper appends OCSF events to `~/.local/share/selfdef/ssh-wrap.jsonl`.
To see them in the daemon's event store, enable the eventstream collector:

```toml
# /etc/selfdef/selfdef.toml
[collectors.eventstream]
enabled = true
paths = ["/home/<you>/.local/share/selfdef/ssh-wrap.jsonl"]
read_from = "end"
```

The daemon needs read access to the file. Either run the daemon as your
user (single-user laptops) or `chmod 0644` the file and add a `setgid`
directory in between so newly appended lines stay readable.

## 5. Sanity-check

```bash
ssh -V                       # passes through, no wrap
ssh user@example.com         # wrap engaged: events appended, policy applied
ssh -A user@example.com      # wrap strips -A; emits a policy-strip event
cat ~/.local/share/selfdef/ssh-wrap.jsonl | tail -3
```

## Environment variable overrides

- `SELFDEF_SSH_PATH=/usr/bin/ssh` — real ssh binary to exec (default).
- `SELFDEF_SSH_POLICY=/path/to/policy.toml` — override policy location.
- `SELFDEF_SSH_EVENT_LOG=/path/to/events.jsonl` — override event log path.

## Caveats

- The wrapper can't see what happens *inside* an established session — it
  observes connection lifecycle and the args you passed, not the remote
  shell activity.
- Host key change detection is left to ssh itself
  (`StrictHostKeyChecking=accept-new` is the default policy). When ssh
  refuses a connection due to changed host keys, the wrapper logs the
  failed exit code; the actual "REMOTE HOST IDENTIFICATION HAS CHANGED"
  message comes from ssh on stderr to your terminal.
- For agent forwarding inside an already-established session
  (`~C -A`), the wrapper has no visibility. Set `AllowAgentForwarding no`
  on the *server* side as defense-in-depth.
