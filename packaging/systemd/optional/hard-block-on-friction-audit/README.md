# Opt-in: hard-block container runtimes on a failed hardware-integrity gate

**Finding F-2026-098.** By default the MS046 friction-audit gate
(`sovereign-guard.service`) is only **ordered** before the container runtimes
(`Before=podman.service docker.service containerd.service`). systemd `Before=`
is ordering, **not** a requirement — so a host that **fails** the PCIe / ZFS /
memory integrity gate still starts podman/docker/containerd; the failure is
*audited* (OCSF event + `selfdef_friction_audit_failing_total` metric +
`SelfdefFrictionAuditFailingGate` alert), not *enforced* at boot.

These drop-ins upgrade that to a **hard requirement**: each runtime gains
`Requires=sovereign-guard.service`, so it refuses to start unless the gate
succeeded (the oneshot exited 0).

## Why this is opt-in, not the default

`friction-audit` reads hardware sensors. A **false-positive** reading (a flaky
PCIe enumeration, a transient ZFS state) would, with this enabled, prevent
**every container on the host** from starting — a self-inflicted outage. Whether
fail-closed-at-boot is the right posture is a per-deployment call:

- **Enable** on hosts where a tampered/degraded platform must not run workloads
  at all (high-assurance, sain-01-class).
- **Leave default** (audit-only) where availability outweighs boot-time
  enforcement; rely on the alert + an operator runbook instead.

## Install

```bash
# Pick the runtime(s) you actually run; you do not need all three.
for rt in podman docker containerd; do
  sudo install -d "/etc/systemd/system/${rt}.service.d"
  sudo cp "${rt}.service.d/10-sovereign-guard-hardblock.conf" \
          "/etc/systemd/system/${rt}.service.d/"
done
sudo systemctl daemon-reload
```

Verify the dependency is live:

```bash
systemctl show -p Requires podman.service | grep sovereign-guard
```

## Remove (revert to audit-only)

```bash
for rt in podman docker containerd; do
  sudo rm -f "/etc/systemd/system/${rt}.service.d/10-sovereign-guard-hardblock.conf"
done
sudo systemctl daemon-reload
```

## Recovery if a gate false-positive blocks boot

If a bad reading wedges the runtimes, either remove the drop-in (above) from a
recovery shell, or mask the requirement for one boot:

```bash
sudo systemctl edit --runtime podman.service   # add [Unit]\nRequires=
# or boot with the drop-in dir renamed, then investigate friction-audit:
sudo /usr/local/bin/friction-audit ; echo "exit=$?"
```

See `docs/sdd/027-friction-audit-system.md` and the runbook
`friction-audit-pcie.md` for gate semantics.
