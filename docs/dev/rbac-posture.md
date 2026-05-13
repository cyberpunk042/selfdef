# Kubernetes RBAC posture check (operator runbook)

`agent-guard`'s `scope = "pod-label"` mode bounds policy
enforcement by a pod label (`pod_label_key=pod_label_value`).
That makes the cluster's RBAC posture part of the threat model:
any subject with `patch` on `pods/labels` in the target
namespace can move the boundary — either opting unrelated pods
into agent-guard's policies (denial-of-service-of-attention) or
opting the protected pod out (defeat).

This document explains the recommended posture and how to verify
it with `selfdefctl rbac check`.

## When this applies

Only relevant when `agent-guard` is using `scope = "pod-label"`
in its module config. If `scope = "container"` (the default,
host-bound scope via Tetragon's `matchNamespaces`), RBAC
doesn't gate the policy boundary — every container on the host
is in scope regardless.

```toml
# /etc/selfdef/modules/agent-guard.toml
profile = "audit"
scope = "pod-label"
pod_label_key   = "selfdef.io/agent"
pod_label_value = "true"
```

## Recommended posture

- Only **cluster-admin** and any **documented narrow
  ServiceAccount** may PATCH pod labels in namespaces where
  agent-guard runs.
- None of these subjects should be granted `patch` on `pods`
  (full or `labels` sub-resource) — the four built-in probes
  the CLI runs by default cover the common-mistake matrix
  (F-2027-007):
    - `system:authenticated` — any cred-bearing principal.
    - `system:unauthenticated` — the anonymous group.
    - `system:masters` — the kubeadm bootstrap superuser
      group; granting it to humans bypasses every cluster
      RBAC check by design.
    - `system:serviceaccount:default:default` — the default
      ServiceAccount in the default namespace; pods that
      forget to set `serviceAccountName` run as this and any
      RoleBinding on it leaks to every such pod.
- Document the narrow ServiceAccounts that legitimately need
  label PATCH (e.g. a CD pipeline that re-labels pods on
  rollout) and probe them via `--as`.

## Running the check

### Read-only mode (no cluster access required)

Prints the posture recommendation + the exact kubectl commands
the operator should run:

```sh
selfdefctl rbac check
```

Use this on the daemon host (or anywhere a copy of
`/etc/selfdef/modules/agent-guard.toml` lives). No kubectl, no
kubeconfig.

### Probe mode (kubectl access required)

Shells out to `kubectl auth can-i patch pods
--subresource=labels --as=<subject>` for the built-in subjects
plus any operator-supplied `--as`:

```sh
selfdefctl rbac check --probe \
    --as my-deploy-bot-sa \
    --as ci-system-user
```

The check exits non-zero if any probed subject can patch pod
labels — the cluster's RBAC posture doesn't match the
recommended one. `--warn-only` suppresses the exit code if you
prefer a CI step that reports without blocking.

### Namespace scoping

By default the check probes cluster-wide. To scope to one
namespace:

```sh
selfdefctl rbac check --probe --namespace selfdef-agents
```

## Caveats

- `kubectl auth can-i` reports the effective permission for the
  caller's current context impersonating `--as`. The result
  reflects whatever role bindings exist at probe time; rotating
  RoleBindings after the check has been run requires re-running
  the check.
- The check probes a fixed set of four built-in subjects
  (`system:authenticated`, `system:unauthenticated`,
  `system:masters`, `system:serviceaccount:default:default`),
  plus any operator-supplied `--as` subjects (F-2027-007). A
  cluster with a malicious narrow ServiceAccount that the
  operator doesn't think to probe will pass — the check is
  documentation + spot-checking, not a cluster-wide
  enumeration.
- Cluster enumeration (listing every Role/RoleBinding that
  grants pods patch) is a heavier task and not in scope here.
  For that, use `rbac-tool` or `kubectl-who-can`.

## Tests

`crates/selfdef-cli/tests/cli_rbac_check.rs` ships 7
integration tests using a stubbed `kubectl` on PATH:

- `rbac_check_reports_not_applicable_when_scope_is_container`
- `rbac_check_without_probe_prints_recommended_posture`
- `rbac_check_with_probe_clean_posture_exits_zero`
- `rbac_check_with_probe_flags_overly_permissive_subject`
- `rbac_check_warn_only_suppresses_exit_failure`
- `rbac_check_with_extra_as_subjects_probes_them_too`
- `rbac_check_namespace_arg_is_passed_to_kubectl`

The stub kubectl is a small bash script that maps `--as=<subj>`
to the kubectl `yes`/`no` exit-code contract; no real cluster
is required at test time.
