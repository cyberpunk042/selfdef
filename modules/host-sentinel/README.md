# host-sentinel

Host-level Tetragon TracingPolicies for detection surfaces that
MS016 originally specified as aya-rs eBPF programs. Two of the five
deferred SDD-032 programs ship here as Tetragon policies; the
remaining three (`proc-ancestry`, `hidden-process`, `tcp-fingerprint`)
genuinely need ground-up eBPF and stay deferred until the kernel-
toolchain bring-up arc.

## Policies shipped

| Policy | Substitutes for | Kprobe |
|---|---|---|
| `kmod-watch.yaml` | MS016 `kmod-watch` | `do_init_module` (kernel module load) |
| `ld-preload-watch.yaml` | MS016 `ld-preload-watch` | `security_file_open` on `/etc/ld.so.preload` |

## Scope

agent-guard's policies all carry `matchNamespaces: Pid NotIn host_ns`
to scope detection to non-host PID namespaces (containers). The
host-sentinel policies do the OPPOSITE — they match the host PID
namespace ONLY. The two modules can run side-by-side without policy-
name collisions; each one's events flow through Tetragon's JSONL
pipeline + the existing tetragon collector crate.

## Profiles

- `audit` (default) — `matchActions: Post` on every detection. Events
  flow to the JSONL pipeline + bus + correlator; no termination.
  Operator-readable surface for tuning.
- `enforce` — apply.sh rewrites `Post` to `Sigkill` on the
  ld-preload-watch policy only. kmod-watch stays Post in both
  profiles because killing a kernel-module-loading process when the
  module is already in-kernel is closing the barn door — the event
  is more useful as a notify/audit signal than as a kill.

## Install

`selfdefctl modules apply host-sentinel` after tetragon is up.

## Why not just extend agent-guard?

agent-guard's `matchNamespaces` filter is hardcoded in every policy
file. Inverting it for host scope would either fork agent-guard's
apply.sh or require operator-confusing profile gymnastics. Cleaner
to ship a sibling module with the right default selector. They share
Tetragon's policy_dir → /v1/modules/install-plan's `path_conflicts`
will surface the dir as a known overlap (informational; both
modules write distinct policy filenames into the same dir).
