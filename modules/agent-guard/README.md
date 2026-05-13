# agent-guard

Tetragon TracingPolicies for AI agents running in Docker / Podman /
containerd containers. Detects (and, in `enforce`, kills) the
classic agent-jailbreak behaviours:

| Policy | What it watches | Default action (audit / enforce) |
| --- | --- | --- |
| `etc-write-guard` | `security_file_open` with write intent under `/etc/` | Post / Sigkill |
| `container-shell-guard` | `execve` of `bash` / `sh` / `dash` / `zsh` / `ash` | Post / Sigkill |
| `egress-guard` | `tcp_connect` to non-allowlisted destinations | Post / Sigkill |
| `securemessage-guard` | Open of a future SecureMessage endpoint | Post (stub) |
| `gpu-device-guard` | `security_file_open` on `/dev/nvidia*` (or operator-defined device prefixes) by a binary outside the allowlist | Post / Sigkill |

Every selector includes `matchNamespaces: { Pid: NotIn: [host_ns] }`
so host-level processes are exempt. The agent runs in a non-host PID
namespace by virtue of being inside a container; the rules
trigger only there.

## Why a separate module from `tetragon`

`tetragon` is the substrate: config, event JSONL, metrics endpoint,
policy drop directory. This module is *one* policy bundle that
lives on top of that substrate. Future policy bundles (e.g.
`host-hardening-guard`, `k8s-admin-guard`) would be peer modules,
not children of this one, all consuming `tetragon-tracing` +
`tetragon-policies`.

## Profiles

- **`audit` (default)** — every enabled policy installs with
  `action: Post`. Tetragon emits an event on every match; nothing
  is killed. **Start here.** Watch the daemon's event stream for
  noise, populate `egress_allowlist`, etc., before flipping the
  profile.
- **`enforce`** — every enabled policy installs with `action:
  Sigkill` by default. A match terminates the offending process.

Per-policy action overrides (`etc_write_action`,
`shell_exec_action`, `egress_action`, `securemessage_action`)
accept `default` (follow profile), `post`, or `sigkill`. This lets
operators ramp policies up individually rather than flipping the
whole bundle at once.

## Config

```toml
profile = "audit"   # or "enforce"

etc_write_enabled = true
etc_write_action  = "default"   # default | post | sigkill

shell_exec_enabled = true
shell_exec_action  = "default"

# Egress: CSV of CIDRs that ARE allowed. An empty allowlist with
# audit mode is silent; an empty allowlist with enforce mode means
# "kill on every outbound connection from a container". Audit your
# real traffic first.
egress_enabled   = true
egress_action    = "default"
egress_allowlist = "10.0.0.0/24, 198.51.100.10/32"

# SecureMessage endpoint: leave unset until the host has one. The
# stub policy stays dormant — the placeholder path matches nothing.
securemessage_enabled  = true
securemessage_action   = "default"
securemessage_endpoint = ""

# GPU device guard. Watches in-container opens of GPU device nodes
# (NVIDIA by default; add more prefixes via `gpu_device_paths` for
# AMD ROCm / Intel Habana / etc.). `gpu_device_allowlist` is the
# CSV of in-container binary paths permitted to access them — empty
# = match every binary. Populate before flipping to enforce, else
# every container touching a GPU dies.
gpu_device_enabled   = true
gpu_device_action    = "default"
gpu_device_paths     = ""    # empty = use shipped NVIDIA defaults
gpu_device_allowlist = "/usr/local/bin/python3, /usr/bin/torchrun"
```

## Container scope — why `Pid != host_ns` and not pod labels

Tetragon's `matchPodSelector` requires the Kubernetes data plane;
Docker / Podman / containerd-standalone don't surface pod labels to
Tetragon. The cleanest scope on a non-k8s host is "anything not in
the host's PID namespace" — true for every container runtime worth
the name. Operators who run multiple container workloads on one
host and want narrower scoping should layer a second selector by
binary path (e.g. only match if the originating process is
`/usr/bin/python3` running inside the container) in a derivative
policy.

## Practical operator workflow

1. Land `tetragon` first (`phase = "pre"`).
2. Enable `agent-guard` in `audit`. Run for at least a week. Watch
   for false positives in `selfdefctl events alerts`.
3. Populate `egress_allowlist` with the actual destinations your
   agents need (your model API gateway, your SecureMessage endpoint,
   internal Prometheus push, etc.).
4. Flip a single policy to `sigkill` via its per-policy override.
   Watch. Repeat.
5. Once every policy is at `sigkill` individually, flip `profile =
   "enforce"` so future policies added to the bundle inherit the
   right default.

## Not-shipped extensions

- **Pod-label-aware variants** of the same policies, gated on
  `matchPodSelector` instead of `matchNamespaces`. Ship one of these
  alongside if you run k8s.

Track those in `docs/src/modules-roadmap.md` if you want them later.
