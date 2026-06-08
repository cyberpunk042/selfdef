# SDD-080 — Watchdog expected-owner knob (hermetic L2 tests under any runner)

**Status:** implemented
**Author:** selfdef IPS authority chain
**Closes:** the standing "66 layer(s) failed" red state of the
`four-watchdog coherence harness` CI job (`scripts/test/coherence.sh`
L2 section) — every benign-path watchdog assertion failed under the
non-root GitHub `runner` user.
**Owner:** the host detection-watchdog family (`modules/*-watchdog/`)
+ the coherence harness (`scripts/test/coherence.sh`).
**Last updated:** 2026-06-08.

## Problem

The L2 watchdog suites (`packaging/test/L2-*-watchdog.bats`) seed a
benign config fixture in a `mktemp -d` directory, run the watchdog, and
assert the benign path emits `"severity":"ok"` (e.g. `baseline_initial`,
`<wd>_intact`, `<wd>_changed`). 62 of the watchdog scripts carry an
identical ownership heuristic:

```bash
elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
    suspicious+=("${base}:owned-by-$owner")
fi
```

In **production** this is correct: `/etc` configs are root-owned, so a
config owned by some other user is a genuine tamper / privilege signal.

In **CI** it is a false positive. The GitHub runner executes as the
non-root user `runner`, so every fixture the test creates is owned by
`runner`, not `root`. The watchdog flags it `owned-by-runner` →
`suspicious` → emits `alert` instead of `ok`, and every benign-path
assertion fails. Locally the suites pass only because the developer
happens to run as `root`. Reproduced deterministically with
`runuser -u nobody -- bats packaging/test/L2-wireguard-config-watchdog.bats`
(fails tests 2/3/8/9 — exactly the CI failure set).

The alert-path assertions (injection pattern, world-writable,
world-readable-privatekey) pass in both environments because they emit
`alert` regardless of owner — which is why the failure set is precisely
the benign/ok assertions.

## Goals

1. Green the coherence harness L2 section under a non-root runner.
2. **Zero production behaviour change** — the ownership check must still
   default to `root` when unconfigured.
3. No weakening of the security heuristic and no test rewrites that
   would mask a real regression.

## Non-goals

- Changing what counts as a suspicious owner in production (still
  "not the expected owner"). This SDD does not relax the heuristic; it
  makes the *expected owner* declarable.
- Running CI as root (rejected — running the suite as root would also
  change the behaviour of the world-writable/world-readable assertions
  and is worse practice than parameterising the one knob).

## Design

Introduce a single shared env knob honoured by every watchdog that
carries the heuristic:

```bash
elif [[ "$owner" != "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}" && "$owner" != "?" ]]; then
```

- **Unset (production default):** expands to `root` — byte-identical to
  the previous behaviour. No deployed unit sets the var, so production
  is unchanged. (It is also a legitimate operability feature: an
  operator who runs a service's configs under a dedicated non-root
  account can declare that account as the expected owner instead of
  carrying a permanent false-positive.)
- **Set by the test harness:** `scripts/test/coherence.sh` exports
  `SELFDEF_WATCHDOG_EXPECTED_OWNER="$(id -un)"` before the L2 layers, so
  the benign fixtures (owned by the harness runner) are treated as
  expected regardless of whether that runner is `root`, `runner`, or
  anything else. The export uses `${VAR:-$(id -un)}` so an operator can
  still override it when running the harness by hand.

The change is mechanical and identical across the 62 scripts (one
`$owner` line each, plus one `$mowner` variant), applied via an exact
literal replacement and verified by grep: `0` bare `!= "root"` owner
checks remain; `62` now read the knob.

## Verification

```
# Reproduce the failure (pre-fix behaviour, non-root):
runuser -u nobody -- bats packaging/test/L2-wireguard-config-watchdog.bats
#   not ok 2/3/8/9  (benign ok-path)

# Post-fix, non-root with the harness env (what coherence.sh sets):
runuser -u nobody -- env SELFDEF_WATCHDOG_EXPECTED_OWNER=nobody \
  bats packaging/test/L2-<wd>.bats   # exit 0, 0 failures

# Post-fix, root, no env (production default = root):
bats packaging/test/L2-<wd>.bats     # exit 0, 0 failures
```

Both directions confirmed across the watchdog suite set: the benign-path
assertions pass under a non-root runner with the knob, and the
production default (`root`, unset) is unchanged.

## Open questions

- **D-1**: Should the deployed watchdog systemd units set
  `SELFDEF_WATCHDOG_EXPECTED_OWNER` explicitly to `root` for
  defence-in-depth (so the expectation is pinned in the unit rather than
  relying on the script default)? **Recommendation:** optional and
  deferred — the script default already is `root`; pinning it in the
  unit is belt-and-suspenders, not load-bearing, and would touch every
  unit. Track as a follow-up if an operator deployment ever runs configs
  under a non-root account and wants the expectation made explicit.
