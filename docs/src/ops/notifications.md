# Notifications

The notifier chain is the operator-facing output of every
finding. When the responder dispatches a finding (any event
with `category_uid = 2`), `NotifyAction` walks the configured
channels in order, posting until one succeeds.

Two channels ship today: `ntfy` and `signal-cli`.

## ntfy

[ntfy.sh](https://ntfy.sh) is the simplest path: a public
broker (or self-host) plus an Android / iOS / desktop client.

```toml
[notifier]
channels = ["ntfy"]

[notifier.ntfy]
url = "https://ntfy.example.org"
topic = "selfdef-alerts-yourname"
token_file = "/etc/selfdef/secrets/ntfy.token"
```

The `token_file` is optional (only needed if your topic is
auth-restricted). Mode `0600 root:selfdef`.

## Signal (signal-cli)

[signal-cli](https://github.com/AsamK/signal-cli) is a Java
CLI that drives a paired Signal account. End-to-end encrypted
notifications, no third-party broker.

```toml
[notifier]
channels = ["signal", "ntfy"]   # signal first, fall back to ntfy

[notifier.signal]
binary = "/usr/bin/signal-cli"
account = "+15551234567"        # your registered number
recipient = "+15557654321"      # who to notify
```

Pair the `signal-cli` account with `--register`/`--verify`
out-of-band before pointing selfdef at it. The daemon
invokes `signal-cli send -a $account $recipient -m "$body"`
per finding.

## Channel chain semantics

`channels` is ordered. The first channel that succeeds wins;
the rest are skipped. If every channel fails, the failure
itself becomes an event (logged with `selfdef.notifier`
source) so a silent outage is visible in
`selfdefctl events tail`.

A channel that's listed but missing required config is
**silently skipped at startup** with a `channel skipped —
missing config` log line. (Audit finding F-2026-054 flags this
as a usability gap — a future PR may add a startup warning
for `[notifier.X]` blocks present in config but not listed in
`channels`.)

## Testing

```bash
# In dry-run, the responder logs what it would do without
# actually invoking actions.
[responder]
dry_run = true
allowed_actions = ["notify"]
```

Then trigger a synthetic finding via `selfdefctl events emit`
(see the `selfdefctl --help` output) or by replaying a
detection corpus through the daemon.

## Rotating credentials

Notifier credentials are loaded **once** at daemon startup
(`SECURITY.md:75-78`). Editing the token file does not take
effect until the daemon restarts. This is intentional:
mid-flight rotation is a deliberate operator action, not a
side effect of editing a file.

Rotate with:

```bash
sudo -e /etc/selfdef/secrets/ntfy.token
sudo systemctl restart selfdefd
```
