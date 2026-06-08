# SDD-082 — Root-fixture security suites split (green the coherence harness under a non-root runner)

**Status:** implemented
**Author:** selfdef IPS authority chain
**Closes:** the residual `four-watchdog coherence harness` CI failure —
after SDD-080 took it from 66 failing L2 layers to 4, the last 4 were a
root-vs-non-root environment mismatch, not a code defect.
**Owner:** the host detection-watchdog test fleet (`packaging/test/L2-*`)
+ the CI workflow (`.github/workflows/ci.yml`).
**Last updated:** 2026-06-08.

## Problem

Four L2 watchdog suites build fixtures that require **root**:

| Suite | Root-requiring fixture |
|---|---|
| `L2-unowned-files-watchdog` | `chown` to an unresolved uid/gid (99999:99999) to fake nouser/nogroup files |
| `L2-suid-sgid-watchdog` | setuid/setgid bit fixtures detected against a root-owned baseline |
| `L2-integrity-sentinel` | ownership/attestation baselines |
| `L2-time-skew-watchdog` | chronyc-fixture set designed for the root sandbox |

`L2-unowned-files-watchdog` even documents it in-file: *"Tests chown
files to an unresolved uid/gid, so they must run as root (true in the
CI/root sandbox)."* The authors designed these for a **root CI sandbox**.
But the `coherence` job runs `scripts/test/coherence.sh` as the non-root
GitHub `runner` user, so the `chown`/setuid fixtures fail to materialise
and the suites fail. All four pass cleanly as root (148 tests each).

Running the *whole* harness as root is the wrong hammer: coherence.sh
also runs the cargo + ruff + shellcheck layers, whose toolchains live in
the runner's home, and changing every other suite's uid could flip
currently-passing assertions. The fix must be surgical.

## Design

Two halves, mirroring the producer/consumer split discipline:

1. **Declare the requirement + skip under non-root.** Each of the four
   suites gains a `setup()` guard:
   ```bash
   [[ "$(id -u)" -eq 0 ]] || skip "requires root CI sandbox (SDD-082); covered by four-watchdog-root job"
   ```
   Under the non-root `coherence` harness the suites now **skip** (148
   skips, exit 0) instead of failing — so the harness goes green without
   touching the 200+ other suites' environment. Run as root (locally or
   the job below) they execute fully.

2. **Cover them in a dedicated root job.** A new `coherence-root` CI job
   runs exactly these four suites as root (`sudo bats …`). They are pure
   shell (no cargo/toolchain), so the job is a minimal checkout + bats +
   `sudo bats`. It is wired into the `build` gate's `needs` list, so the
   security detections stay CI-verified — they are not silently dropped.

This is the test sibling of SDD-080: SDD-080 made the *owner-heuristic*
suites hermetic under any runner; SDD-082 handles the suites that
genuinely need root by declaring the requirement and giving them a root
home in CI.

## Verification

```
# non-root: all four skip, harness stays green
$ for s in integrity-sentinel suid-sgid-watchdog time-skew-watchdog unowned-files-watchdog; do
    runuser -u nobody -- bats packaging/test/L2-$s.bats; done
#   → 148 skipped, 0 failures each (exit 0)

# root: the coherence-root job command runs them fully
$ sudo bats packaging/test/L2-{integrity-sentinel,suid-sgid-watchdog,\
    time-skew-watchdog,unowned-files-watchdog}.bats
#   → 592 tests, 0 failures

$ python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"  # valid
```

Trajectory: the four-watchdog harness went 66 → 4 (SDD-080) → 0 (this
SDD), with the four root-requiring security detections now CI-verified in
a dedicated root job rather than silently red.

## Open questions

- **D-1**: Should MORE of the L2 fleet move to the root job for fuller
  fidelity (some watchdogs detect root-owned-file tampering that is only
  partially exercised under a non-root runner)? **Recommendation:** no
  for now — only the four that genuinely *need* root are split; the rest
  are hermetic under any runner (SDD-080) and keep their fast non-root
  coverage in the main harness. Revisit only if a detection gap surfaces.
