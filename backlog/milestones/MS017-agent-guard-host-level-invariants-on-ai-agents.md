# MS017 — agent-guard — host-level invariants on AI agents in Docker / Podman / containerd

> Parent: `backlog/milestones/INDEX.md` row MS017.
> Source: `modules/agent-guard/` (module.toml 32L + README.md + install/{apply,check,uninstall,lib}.sh totalling 514L + policies/ + profiles/). 5-policy bundle: etc-write / container-shell / egress / SecureMessage / GPU-device. 2 profiles (audit / enforce). 2 scope strategies (container / pod-label). All entries below extract verbatim. No invention.

## Epics (E0171–E0180)

| Epic ID | Phrase | Source |
|---|---|---|
| E0171 | Mission — Tetragon TracingPolicies for AI agents running in Docker / Podman / containerd containers; detects (in audit) + kills (in enforce) the classic agent-jailbreak behaviours | `modules/agent-guard/README.md` § header |
| E0172 | Module manifest — name=agent-guard / version=0.3.0 / category=hardening; depends_on=[tetragon]; consumes=[tetragon-tracing, tetragon-policies]; requires binary=tetragon; instanced=false (single bundle per host); phase=main (after tetragon substrate in pre + before observability in post) | `modules/agent-guard/module.toml` |
| E0173 | 5-policy bundle catalog — etc-write-guard (security_file_open with write intent under /etc/) / container-shell-guard (execve of bash/sh/dash/zsh/ash) / egress-guard (tcp_connect to non-allowlisted) / securemessage-guard (open of future SecureMessage endpoint) / gpu-device-guard (security_file_open on /dev/nvidia* by binary outside allowlist); every selector includes matchNamespaces Pid NotIn [host_ns] so host-level processes exempt | `modules/agent-guard/README.md` § policy table + § Container scope |
| E0174 | Separation rationale — tetragon is the substrate (config / event JSONL / metrics endpoint / policy drop directory); agent-guard is ONE policy bundle living on top; future bundles (host-hardening-guard / k8s-admin-guard) are peer modules NOT children; all consume tetragon-tracing + tetragon-policies | `modules/agent-guard/README.md` § "Why a separate module from tetragon" |
| E0175 | Profiles — audit (default; action=Post; every match emits event; nothing killed; "Start here") + enforce (action=Sigkill; match terminates offending process); per-policy action overrides (etc_write_action / shell_exec_action / egress_action / securemessage_action / gpu_device_action) accept default(follow-profile)|post|sigkill; lets operators ramp policies up individually rather than flipping whole bundle at once | `modules/agent-guard/README.md` § Profiles + `modules/agent-guard/module.toml` § profiles |
| E0176 | Config (TOML) — profile / scope / pod_label_key + pod_label_value (when scope=pod-label) / etc_write_{enabled,action} / shell_exec_{enabled,action} / egress_{enabled,action,allowlist} / securemessage_{enabled,action,endpoint} / gpu_device_{enabled,action,paths,allowlist}; CSV-formatted allowlists | `modules/agent-guard/README.md` § Config |
| E0177 | Container scope strategy 1 — `container` (default; selector matchNamespaces Pid NotIn [host_ns]; captures every non-host PID namespace = every container; for Docker / Podman / containerd-standalone or k8s without per-pod labeling) | `modules/agent-guard/README.md` § "Container scope" container |
| E0178 | Container scope strategy 2 — `pod-label` (selector matchPodSelector matchLabels.<key>=<value>; narrower; only pods carrying configured label fire; Kubernetes hosts; lets unrelated workloads on same node run untouched; requires pod_label_key + pod_label_value; apply.sh refuses without them; shipped defaults selfdef.io/agent="true") | `modules/agent-guard/README.md` § "Container scope" pod-label |
| E0179 | Practical operator workflow — 5 steps: (1) Land tetragon first (phase=pre); (2) Enable agent-guard in audit, run ≥1 week, watch `selfdefctl events alerts` for false positives; (3) Populate egress_allowlist with actual destinations (model API gateway / SecureMessage endpoint / internal Prometheus push); (4) Flip single policy to sigkill via per-policy override, watch, repeat; (5) Once every policy is sigkill individually, flip profile=enforce so future policies inherit right default | `modules/agent-guard/README.md` § "Practical operator workflow" |
| E0180 | Not-shipped extensions — 4-policy bundle + GPU-device guard covers AI-machine threat model in roadmap; future per-pod allowlists under pod-label scope (today egress_allowlist + gpu_device_allowlist apply uniformly; follow-up could vary by pod_label_value so different agent classes get different permissions); install scripts (apply.sh 147L / check.sh 92L / lib.sh 214L / uninstall.sh 61L) materialize the bundle | `modules/agent-guard/README.md` § "Not-shipped extensions" + `modules/agent-guard/install/` |

## Modules (M00421–M00446)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00421 | Manifest — name=agent-guard | `modules/agent-guard/module.toml` | E0172 |
| M00422 | Manifest — version=0.3.0 | `modules/agent-guard/module.toml` | E0172 |
| M00423 | Manifest — category=hardening | `modules/agent-guard/module.toml` | E0172 |
| M00424 | Manifest — depends_on=[tetragon] | `modules/agent-guard/module.toml` | E0172 |
| M00425 | Manifest — consumes=[tetragon-tracing, tetragon-policies] | `modules/agent-guard/module.toml` | E0172 |
| M00426 | Manifest — requires binary=tetragon | `modules/agent-guard/module.toml` | E0172 |
| M00427 | Manifest — instanced=false (single bundle per host) | `modules/agent-guard/module.toml` | E0172 |
| M00428 | Manifest — phase=main | `modules/agent-guard/module.toml` | E0172 |
| M00429 | Manifest — install kind=script with apply/check/uninstall | `modules/agent-guard/module.toml` | E0172 |
| M00430 | Manifest — profiles default=audit / available=[audit, enforce] | `modules/agent-guard/module.toml` | E0175 |
| M00431 | Policy 1 — etc-write-guard (security_file_open with write intent under /etc/; Post/Sigkill) | `modules/agent-guard/README.md` § policy table | E0173 |
| M00432 | Policy 2 — container-shell-guard (execve of bash/sh/dash/zsh/ash; Post/Sigkill) | `modules/agent-guard/README.md` § policy table | E0173 |
| M00433 | Policy 3 — egress-guard (tcp_connect to non-allowlisted destinations; Post/Sigkill) | `modules/agent-guard/README.md` § policy table | E0173 |
| M00434 | Policy 4 — securemessage-guard (Open of future SecureMessage endpoint; Post stub) | `modules/agent-guard/README.md` § policy table | E0173 |
| M00435 | Policy 5 — gpu-device-guard (security_file_open on /dev/nvidia* by binary outside allowlist; Post/Sigkill) | `modules/agent-guard/README.md` § policy table | E0173 |
| M00436 | Selector invariant — every selector includes matchNamespaces Pid NotIn [host_ns] (host-level processes exempt) | `modules/agent-guard/README.md` § header | E0173 |
| M00437 | Profile audit — default; every enabled policy action=Post; Tetragon emits event on every match; nothing killed | `modules/agent-guard/README.md` § Profiles audit | E0175 |
| M00438 | Profile enforce — every enabled policy action=Sigkill; match terminates offending process | `modules/agent-guard/README.md` § Profiles enforce | E0175 |
| M00439 | Per-policy override — `etc_write_action` / `shell_exec_action` / `egress_action` / `securemessage_action` / `gpu_device_action` accept default|post|sigkill | `modules/agent-guard/README.md` § Profiles | E0175 |
| M00440 | Container scope — matchNamespaces Pid NotIn [host_ns] (default; captures every non-host PID namespace) | `modules/agent-guard/README.md` § Container scope | E0177 |
| M00441 | Pod-label scope — matchPodSelector matchLabels.<key>=<value>; pod_label_key + pod_label_value required; default `selfdef.io/agent: "true"` | `modules/agent-guard/README.md` § Container scope | E0178 |
| M00442 | install/apply.sh (147L) — materializes Tetragon TracingPolicy YAML files into /etc/tetragon/tracing-policies/ per config | `modules/agent-guard/install/apply.sh` | E0180 |
| M00443 | install/check.sh (92L) — operator-readable status of installed policies (which files present, which actions effective, profile mode) | `modules/agent-guard/install/check.sh` | E0180 |
| M00444 | install/lib.sh (214L) — shared helpers (CSV parsing for allowlists; profile-mode resolution; YAML emission with selector + action injection) | `modules/agent-guard/install/lib.sh` | E0180 |
| M00445 | install/uninstall.sh (61L) — removes agent-guard-* TracingPolicy files cleanly (does NOT touch sovereign-kernel-fence.yaml per MS012 perimeter coexistence) | `modules/agent-guard/install/uninstall.sh` + MS012 | E0180 |
| M00446 | Future extension (not shipped) — per-pod allowlists under pod-label scope; vary egress_allowlist + gpu_device_allowlist by pod_label_value | `modules/agent-guard/README.md` § "Not-shipped extensions" | E0180 |

## Features (F01921–F02040)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F01921 | agent-guard ships Tetragon TracingPolicies for AI agents in Docker / Podman / containerd | `modules/agent-guard/README.md` § header | E0171 | composite | false |
| F01922 | Detects classic agent-jailbreak behaviours | `modules/agent-guard/README.md` § header | E0171 | composite | false |
| F01923 | In audit profile detects only; in enforce profile kills | `modules/agent-guard/README.md` § header | E0171 | composite | false |
| F01924 | module.toml field — name=agent-guard | `modules/agent-guard/module.toml` | M00421 | composite | true |
| F01925 | module.toml field — version=0.3.0 | `modules/agent-guard/module.toml` | M00422 | composite | true |
| F01926 | module.toml field — summary="Tetragon TracingPolicies for AI agents in containers — etc-write / shell-exec / egress / SecureMessage / GPU-device" | `modules/agent-guard/module.toml` | M00421 | composite | true |
| F01927 | module.toml field — category=hardening | `modules/agent-guard/module.toml` | M00423 | composite | true |
| F01928 | module.toml field — depends_on=[tetragon] | `modules/agent-guard/module.toml` | M00424 | composite | true |
| F01929 | module.toml field — conflicts=[] | `modules/agent-guard/module.toml` | M00424 | composite | true |
| F01930 | module.toml field — provides=[] | `modules/agent-guard/module.toml` | M00424 | composite | true |
| F01931 | module.toml field — consumes=[tetragon-tracing, tetragon-policies] | `modules/agent-guard/module.toml` | M00425 | composite | true |
| F01932 | module.toml requires — binary=tetragon | `modules/agent-guard/module.toml` | M00426 | composite | true |
| F01933 | module.toml field — instanced=false (single bundle per host) | `modules/agent-guard/module.toml` | M00427 | composite | true |
| F01934 | module.toml comment — per-policy enable/disable + action override via module config (not by spawning instances) | `modules/agent-guard/module.toml` § comment | M00427 | composite | false |
| F01935 | module.toml field — phase=main | `modules/agent-guard/module.toml` | M00428 | composite | true |
| F01936 | phase=main rationale — runs AFTER tetragon substrate (pre) is configured + daemon live | `modules/agent-guard/module.toml` § comment | M00428 | composite | false |
| F01937 | phase=main rationale — runs BEFORE any post module (observability) builds a metrics scrape | `modules/agent-guard/module.toml` § comment | M00428 | composite | false |
| F01938 | [install] kind=script | `modules/agent-guard/module.toml` | M00429 | composite | true |
| F01939 | [install] apply=install/apply.sh | `modules/agent-guard/module.toml` | M00429 | composite | true |
| F01940 | [install] check=install/check.sh | `modules/agent-guard/module.toml` | M00429 | composite | true |
| F01941 | [install] uninstall=install/uninstall.sh | `modules/agent-guard/module.toml` | M00429 | composite | true |
| F01942 | [profiles] default=audit | `modules/agent-guard/module.toml` | M00430 | composite | true |
| F01943 | [profiles] available=[audit, enforce] | `modules/agent-guard/module.toml` | M00430 | composite | true |
| F01944 | Policy 1 — etc-write-guard | `modules/agent-guard/README.md` § policy table | M00431 | composite | true |
| F01945 | etc-write-guard hook — security_file_open with write intent under /etc/ | `modules/agent-guard/README.md` § policy table | M00431 | composite | false |
| F01946 | etc-write-guard audit action — Post | `modules/agent-guard/README.md` § policy table | M00431 + M00437 | composite | false |
| F01947 | etc-write-guard enforce action — Sigkill | `modules/agent-guard/README.md` § policy table | M00431 + M00438 | composite | false |
| F01948 | Policy 2 — container-shell-guard | `modules/agent-guard/README.md` § policy table | M00432 | composite | true |
| F01949 | container-shell-guard hook — execve of bash | `modules/agent-guard/README.md` § policy table | M00432 | composite | false |
| F01950 | container-shell-guard hook — execve of sh | `modules/agent-guard/README.md` § policy table | M00432 | composite | false |
| F01951 | container-shell-guard hook — execve of dash | `modules/agent-guard/README.md` § policy table | M00432 | composite | false |
| F01952 | container-shell-guard hook — execve of zsh | `modules/agent-guard/README.md` § policy table | M00432 | composite | false |
| F01953 | container-shell-guard hook — execve of ash | `modules/agent-guard/README.md` § policy table | M00432 | composite | false |
| F01954 | container-shell-guard audit action — Post | `modules/agent-guard/README.md` § policy table | M00432 + M00437 | composite | false |
| F01955 | container-shell-guard enforce action — Sigkill | `modules/agent-guard/README.md` § policy table | M00432 + M00438 | composite | false |
| F01956 | Policy 3 — egress-guard | `modules/agent-guard/README.md` § policy table | M00433 | composite | true |
| F01957 | egress-guard hook — tcp_connect to non-allowlisted destinations | `modules/agent-guard/README.md` § policy table | M00433 | composite | false |
| F01958 | egress-guard audit action — Post | `modules/agent-guard/README.md` § policy table | M00433 + M00437 | composite | false |
| F01959 | egress-guard enforce action — Sigkill | `modules/agent-guard/README.md` § policy table | M00433 + M00438 | composite | false |
| F01960 | Policy 4 — securemessage-guard | `modules/agent-guard/README.md` § policy table | M00434 | composite | true |
| F01961 | securemessage-guard hook — Open of future SecureMessage endpoint | `modules/agent-guard/README.md` § policy table | M00434 | composite | false |
| F01962 | securemessage-guard action — Post (stub; stays dormant until placeholder path is populated) | `modules/agent-guard/README.md` § policy table + § Config | M00434 | composite | false |
| F01963 | Policy 5 — gpu-device-guard | `modules/agent-guard/README.md` § policy table | M00435 | composite | true |
| F01964 | gpu-device-guard hook — security_file_open on /dev/nvidia* by binary outside allowlist | `modules/agent-guard/README.md` § policy table | M00435 | composite | false |
| F01965 | gpu-device-guard audit action — Post | `modules/agent-guard/README.md` § policy table | M00435 + M00437 | composite | false |
| F01966 | gpu-device-guard enforce action — Sigkill | `modules/agent-guard/README.md` § policy table | M00435 + M00438 | composite | false |
| F01967 | Selector invariant — every selector includes matchNamespaces Pid NotIn [host_ns] | `modules/agent-guard/README.md` § header | M00436 | composite | false |
| F01968 | Selector invariant — host-level processes are exempt | `modules/agent-guard/README.md` § header | M00436 | composite | false |
| F01969 | Selector invariant — agent runs in non-host PID namespace by virtue of being inside a container | `modules/agent-guard/README.md` § header | M00436 | composite | false |
| F01970 | Selector invariant — rules trigger only there | `modules/agent-guard/README.md` § header | M00436 | composite | false |
| F01971 | Separation rationale — tetragon is the substrate | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | false |
| F01972 | tetragon provides config | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | true |
| F01973 | tetragon provides event JSONL | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | true |
| F01974 | tetragon provides metrics endpoint | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | true |
| F01975 | tetragon provides policy drop directory | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | true |
| F01976 | agent-guard is ONE policy bundle that lives on top of substrate | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | false |
| F01977 | Future peer bundle example — host-hardening-guard | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | true |
| F01978 | Future peer bundle example — k8s-admin-guard | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | true |
| F01979 | All bundles consume tetragon-tracing + tetragon-policies | `modules/agent-guard/README.md` § "Why a separate module" | E0174 | composite | false |
| F01980 | Profile audit — default | `modules/agent-guard/README.md` § Profiles | M00437 | composite | true |
| F01981 | Profile audit — every enabled policy installs with action=Post | `modules/agent-guard/README.md` § Profiles | M00437 | composite | false |
| F01982 | Profile audit — Tetragon emits event on every match | `modules/agent-guard/README.md` § Profiles | M00437 | composite | false |
| F01983 | Profile audit — nothing is killed | `modules/agent-guard/README.md` § Profiles | M00437 | composite | false |
| F01984 | Profile audit — "Start here" | `modules/agent-guard/README.md` § Profiles | M00437 | composite | false |
| F01985 | Profile audit — watch daemon's event stream for noise + populate egress_allowlist before flipping | `modules/agent-guard/README.md` § Profiles | M00437 | composite | false |
| F01986 | Profile enforce — every enabled policy installs with action=Sigkill by default | `modules/agent-guard/README.md` § Profiles | M00438 | composite | true |
| F01987 | Profile enforce — match terminates the offending process | `modules/agent-guard/README.md` § Profiles | M00438 | composite | false |
| F01988 | Per-policy override — etc_write_action | `modules/agent-guard/README.md` § Profiles | M00439 | composite | true |
| F01989 | Per-policy override — shell_exec_action | `modules/agent-guard/README.md` § Profiles | M00439 | composite | true |
| F01990 | Per-policy override — egress_action | `modules/agent-guard/README.md` § Profiles | M00439 | composite | true |
| F01991 | Per-policy override — securemessage_action | `modules/agent-guard/README.md` § Profiles | M00439 | composite | true |
| F01992 | Per-policy override — gpu_device_action | `modules/agent-guard/README.md` § Config | M00439 | composite | true |
| F01993 | Per-policy override values — default | post | sigkill | `modules/agent-guard/README.md` § Profiles | M00439 | composite | false |
| F01994 | Per-policy override `default` means follow profile | `modules/agent-guard/README.md` § Profiles | M00439 | composite | false |
| F01995 | Per-policy override lets operators ramp policies up individually | `modules/agent-guard/README.md` § Profiles | M00439 | composite | false |
| F01996 | Config knob — profile = "audit" or "enforce" | `modules/agent-guard/README.md` § Config | E0176 | composite | true |
| F01997 | Config knob — scope = "container" or "pod-label" | `modules/agent-guard/README.md` § Config | E0176 | composite | true |
| F01998 | Config knob — pod_label_key (only used when scope=pod-label; default selfdef.io/agent) | `modules/agent-guard/README.md` § Config | M00441 | composite | true |
| F01999 | Config knob — pod_label_value (only used when scope=pod-label; default "true") | `modules/agent-guard/README.md` § Config | M00441 | composite | true |
| F02000 | Config knob — etc_write_enabled (bool) | `modules/agent-guard/README.md` § Config | M00431 | composite | true |
| F02001 | Config knob — shell_exec_enabled (bool) | `modules/agent-guard/README.md` § Config | M00432 | composite | true |
| F02002 | Config knob — egress_enabled (bool) | `modules/agent-guard/README.md` § Config | M00433 | composite | true |
| F02003 | Config knob — egress_allowlist (CSV of CIDRs that ARE allowed) | `modules/agent-guard/README.md` § Config | M00433 | composite | true |
| F02004 | Empty allowlist in audit mode — silent (no events) | `modules/agent-guard/README.md` § Config | M00433 | composite | false |
| F02005 | Empty allowlist in enforce mode — kill on every outbound connection from a container | `modules/agent-guard/README.md` § Config | M00433 | composite | false |
| F02006 | Operator should audit real traffic first before populating allowlist | `modules/agent-guard/README.md` § Config | M00433 | composite | false |
| F02007 | Config knob — securemessage_enabled (bool) | `modules/agent-guard/README.md` § Config | M00434 | composite | true |
| F02008 | Config knob — securemessage_endpoint (default empty; stub policy stays dormant) | `modules/agent-guard/README.md` § Config | M00434 | composite | true |
| F02009 | Config knob — gpu_device_enabled (bool) | `modules/agent-guard/README.md` § Config | M00435 | composite | true |
| F02010 | Config knob — gpu_device_paths (CSV; empty=use shipped NVIDIA defaults; add prefixes for AMD ROCm / Intel Habana) | `modules/agent-guard/README.md` § Config | M00435 | composite | true |
| F02011 | Config knob — gpu_device_allowlist (CSV of in-container binary paths permitted; empty=match every binary) | `modules/agent-guard/README.md` § Config | M00435 | composite | true |
| F02012 | GPU device guard warning — populate allowlist BEFORE flipping to enforce or every container touching GPU dies | `modules/agent-guard/README.md` § Config | M00435 | composite | false |
| F02013 | Container scope strategy `container` (default) — selector matchNamespaces Pid NotIn [host_ns] | `modules/agent-guard/README.md` § "Container scope" | M00440 | composite | true |
| F02014 | Container scope `container` — for Docker / Podman / containerd-standalone | `modules/agent-guard/README.md` § "Container scope" | M00440 | composite | false |
| F02015 | Container scope `container` — or k8s when you don't want to label every agent pod | `modules/agent-guard/README.md` § "Container scope" | M00440 | composite | false |
| F02016 | Container scope `container` — matches every non-host PID namespace (captures every container worth the name) | `modules/agent-guard/README.md` § "Container scope" | M00440 | composite | false |
| F02017 | Container scope strategy `pod-label` — selector matchPodSelector matchLabels.<key>=<value> | `modules/agent-guard/README.md` § "Container scope" | M00441 | composite | true |
| F02018 | Container scope `pod-label` — narrower (only pods carrying configured label fire policy) | `modules/agent-guard/README.md` § "Container scope" | M00441 | composite | false |
| F02019 | Container scope `pod-label` — for Kubernetes hosts | `modules/agent-guard/README.md` § "Container scope" | M00441 | composite | false |
| F02020 | Container scope `pod-label` — lets unrelated workloads on same node run untouched | `modules/agent-guard/README.md` § "Container scope" | M00441 | composite | false |
| F02021 | Container scope `pod-label` — requires pod_label_key + pod_label_value | `modules/agent-guard/README.md` § "Container scope" | M00441 | composite | false |
| F02022 | Container scope `pod-label` — apply.sh refuses without them | `modules/agent-guard/README.md` § "Container scope" | M00441 | composite | false |
| F02023 | Container scope `pod-label` — shipped defaults selfdef.io/agent: "true" | `modules/agent-guard/README.md` § "Container scope" | M00441 | composite | false |
| F02024 | Pod label example — apiVersion v1 / kind Pod / labels selfdef.io/agent "true" | `modules/agent-guard/README.md` § "Container scope" | M00441 | composite | true |
| F02025 | Operators with multiple container workloads on one host should layer second selector by binary path | `modules/agent-guard/README.md` § "Container scope" | M00440 | composite | false |
| F02026 | Workflow step 1 — Land tetragon first (phase=pre) | `modules/agent-guard/README.md` § Workflow | E0179 | composite | false |
| F02027 | Workflow step 2 — Enable agent-guard in audit, run for at least a week, watch for false positives in `selfdefctl events alerts` | `modules/agent-guard/README.md` § Workflow | E0179 | composite | false |
| F02028 | Workflow step 3 — Populate egress_allowlist with actual destinations agents need | `modules/agent-guard/README.md` § Workflow | E0179 | composite | false |
| F02029 | Workflow step 3 destination example — model API gateway | `modules/agent-guard/README.md` § Workflow | E0179 | composite | true |
| F02030 | Workflow step 3 destination example — SecureMessage endpoint | `modules/agent-guard/README.md` § Workflow | E0179 | composite | true |
| F02031 | Workflow step 3 destination example — internal Prometheus push | `modules/agent-guard/README.md` § Workflow | E0179 | composite | true |
| F02032 | Workflow step 4 — Flip single policy to sigkill via its per-policy override, watch, repeat | `modules/agent-guard/README.md` § Workflow | E0179 | composite | false |
| F02033 | Workflow step 5 — Once every policy at sigkill individually, flip profile=enforce so future policies inherit right default | `modules/agent-guard/README.md` § Workflow | E0179 | composite | false |
| F02034 | install/apply.sh (147 lines) | `modules/agent-guard/install/apply.sh` | M00442 | composite | false |
| F02035 | install/check.sh (92 lines) | `modules/agent-guard/install/check.sh` | M00443 | composite | false |
| F02036 | install/lib.sh (214 lines) — shared helpers | `modules/agent-guard/install/lib.sh` | M00444 | composite | false |
| F02037 | install/uninstall.sh (61 lines) | `modules/agent-guard/install/uninstall.sh` | M00445 | composite | false |
| F02038 | Future extension — per-pod allowlists under pod-label scope (today egress_allowlist + gpu_device_allowlist apply to every scoped pod uniformly) | `modules/agent-guard/README.md` § "Not-shipped extensions" | M00446 | composite | false |
| F02039 | Future extension — egress_allowlist + gpu_device_allowlist vary by pod_label_value so different agent classes get different permissions | `modules/agent-guard/README.md` § "Not-shipped extensions" | M00446 | composite | false |
| F02040 | Composite — agent-guard is the canonical example of selfdef host-level invariants on AI agents in containers; 5-policy bundle + 2 profiles (audit default + enforce) + per-policy ramp-up + 2 scope strategies (container default + pod-label) + practical 5-step workflow + ~500-line install scripts | `modules/agent-guard/` + `modules/agent-guard/README.md` | E0171 + E0172 + E0173 + E0174 + E0175 + E0176 + E0177 + E0178 + E0179 + E0180 | composite | false |

## Requirements (R03841–R04080)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R03841 | agent-guard ships Tetragon TracingPolicies for AI agents running in Docker / Podman / containerd containers | `modules/agent-guard/README.md` § header | F01921 | non-negotiable | false | 10 |
| R03842 | agent-guard detects classic agent-jailbreak behaviours | `modules/agent-guard/README.md` § header | F01922 | non-negotiable | false | 10 |
| R03843 | agent-guard audits in `audit` profile; kills in `enforce` profile | `modules/agent-guard/README.md` § header | F01923 | non-negotiable | false | 10 |
| R03844 | module.toml name = agent-guard | `modules/agent-guard/module.toml` | F01924 | non-negotiable | true | 10 |
| R03845 | module.toml version = 0.3.0 | `modules/agent-guard/module.toml` | F01925 | non-negotiable | true | 10 |
| R03846 | module.toml summary verbatim — "Tetragon TracingPolicies for AI agents in containers — etc-write / shell-exec / egress / SecureMessage / GPU-device" | `modules/agent-guard/module.toml` | F01926 | non-negotiable | true | 10 |
| R03847 | module.toml category = hardening | `modules/agent-guard/module.toml` | F01927 | non-negotiable | true | 10 |
| R03848 | module.toml depends_on = [tetragon] | `modules/agent-guard/module.toml` | F01928 | non-negotiable | true | 10 |
| R03849 | module.toml conflicts = [] | `modules/agent-guard/module.toml` | F01929 | non-negotiable | true | 10 |
| R03850 | module.toml provides = [] | `modules/agent-guard/module.toml` | F01930 | non-negotiable | true | 10 |
| R03851 | module.toml consumes = [tetragon-tracing, tetragon-policies] | `modules/agent-guard/module.toml` | F01931 | non-negotiable | true | 10 |
| R03852 | module.toml requires binary = tetragon | `modules/agent-guard/module.toml` | F01932 | non-negotiable | true | 10 |
| R03853 | module.toml instanced = false (single bundle per host) | `modules/agent-guard/module.toml` | F01933 | non-negotiable | true | 10 |
| R03854 | module.toml comment — per-policy enable/disable + action override via module config NOT spawning instances | `modules/agent-guard/module.toml` § comment | F01934 | non-negotiable | false | 10 |
| R03855 | module.toml phase = main | `modules/agent-guard/module.toml` | F01935 | non-negotiable | true | 10 |
| R03856 | phase=main runs after tetragon substrate (which ships in pre) is configured + daemon live | `modules/agent-guard/module.toml` § comment | F01936 | non-negotiable | false | 10 |
| R03857 | phase=main runs before any post module (observability) builds a metrics scrape | `modules/agent-guard/module.toml` § comment | F01937 | non-negotiable | false | 10 |
| R03858 | module.toml [install] kind = script | `modules/agent-guard/module.toml` | F01938 | non-negotiable | true | 10 |
| R03859 | module.toml [install] apply = install/apply.sh | `modules/agent-guard/module.toml` | F01939 | non-negotiable | true | 10 |
| R03860 | module.toml [install] check = install/check.sh | `modules/agent-guard/module.toml` | F01940 | non-negotiable | true | 10 |
| R03861 | module.toml [install] uninstall = install/uninstall.sh | `modules/agent-guard/module.toml` | F01941 | non-negotiable | true | 10 |
| R03862 | module.toml [profiles] default = audit | `modules/agent-guard/module.toml` | F01942 | non-negotiable | true | 10 |
| R03863 | module.toml [profiles] available = [audit, enforce] | `modules/agent-guard/module.toml` | F01943 | non-negotiable | true | 10 |
| R03864 | Policy etc-write-guard exists | `modules/agent-guard/README.md` § policy table | F01944 | non-negotiable | true | 10 |
| R03865 | etc-write-guard hooks `security_file_open` with write intent under `/etc/` | `modules/agent-guard/README.md` § policy table | F01945 | non-negotiable | false | 10 |
| R03866 | etc-write-guard audit action = Post | `modules/agent-guard/README.md` § policy table | F01946 | non-negotiable | false | 10 |
| R03867 | etc-write-guard enforce action = Sigkill | `modules/agent-guard/README.md` § policy table | F01947 | non-negotiable | false | 10 |
| R03868 | Policy container-shell-guard exists | `modules/agent-guard/README.md` § policy table | F01948 | non-negotiable | true | 10 |
| R03869 | container-shell-guard hooks execve of bash | `modules/agent-guard/README.md` § policy table | F01949 | non-negotiable | true | 10 |
| R03870 | container-shell-guard hooks execve of sh | `modules/agent-guard/README.md` § policy table | F01950 | non-negotiable | true | 10 |
| R03871 | container-shell-guard hooks execve of dash | `modules/agent-guard/README.md` § policy table | F01951 | non-negotiable | true | 10 |
| R03872 | container-shell-guard hooks execve of zsh | `modules/agent-guard/README.md` § policy table | F01952 | non-negotiable | true | 10 |
| R03873 | container-shell-guard hooks execve of ash | `modules/agent-guard/README.md` § policy table | F01953 | non-negotiable | true | 10 |
| R03874 | container-shell-guard audit action = Post | `modules/agent-guard/README.md` § policy table | F01954 | non-negotiable | false | 10 |
| R03875 | container-shell-guard enforce action = Sigkill | `modules/agent-guard/README.md` § policy table | F01955 | non-negotiable | false | 10 |
| R03876 | Policy egress-guard exists | `modules/agent-guard/README.md` § policy table | F01956 | non-negotiable | true | 10 |
| R03877 | egress-guard hooks `tcp_connect` to non-allowlisted destinations | `modules/agent-guard/README.md` § policy table | F01957 | non-negotiable | false | 10 |
| R03878 | egress-guard audit action = Post | `modules/agent-guard/README.md` § policy table | F01958 | non-negotiable | false | 10 |
| R03879 | egress-guard enforce action = Sigkill | `modules/agent-guard/README.md` § policy table | F01959 | non-negotiable | false | 10 |
| R03880 | Policy securemessage-guard exists | `modules/agent-guard/README.md` § policy table | F01960 | non-negotiable | true | 10 |
| R03881 | securemessage-guard hooks Open of a future SecureMessage endpoint | `modules/agent-guard/README.md` § policy table | F01961 | non-negotiable | false | 10 |
| R03882 | securemessage-guard action = Post (stub) | `modules/agent-guard/README.md` § policy table | F01962 | non-negotiable | false | 10 |
| R03883 | securemessage-guard stays dormant until the host has a SecureMessage endpoint | `modules/agent-guard/README.md` § Config | F01962 | non-negotiable | false | 10 |
| R03884 | Policy gpu-device-guard exists | `modules/agent-guard/README.md` § policy table | F01963 | non-negotiable | true | 10 |
| R03885 | gpu-device-guard hooks security_file_open on /dev/nvidia* (or operator-defined device prefixes) by binary outside allowlist | `modules/agent-guard/README.md` § policy table | F01964 | non-negotiable | false | 10 |
| R03886 | gpu-device-guard audit action = Post | `modules/agent-guard/README.md` § policy table | F01965 | non-negotiable | false | 10 |
| R03887 | gpu-device-guard enforce action = Sigkill | `modules/agent-guard/README.md` § policy table | F01966 | non-negotiable | false | 10 |
| R03888 | Selector invariant — every selector includes matchNamespaces Pid NotIn [host_ns] | `modules/agent-guard/README.md` § header | F01967 | non-negotiable | false | 10 |
| R03889 | Selector invariant — host-level processes are exempt | `modules/agent-guard/README.md` § header | F01968 | non-negotiable | false | 10 |
| R03890 | Selector invariant — agent runs in non-host PID namespace by virtue of being inside a container | `modules/agent-guard/README.md` § header | F01969 | non-negotiable | false | 10 |
| R03891 | Selector invariant — rules trigger only there | `modules/agent-guard/README.md` § header | F01970 | non-negotiable | false | 10 |
| R03892 | tetragon is the substrate (config / event JSONL / metrics endpoint / policy drop directory) | `modules/agent-guard/README.md` § "Why a separate module" | F01971 + F01972 + F01973 + F01974 + F01975 | non-negotiable | false | 10 |
| R03893 | agent-guard is ONE policy bundle that lives on top of tetragon substrate | `modules/agent-guard/README.md` § "Why a separate module" | F01976 | non-negotiable | false | 10 |
| R03894 | Future policy bundles (e.g. host-hardening-guard, k8s-admin-guard) would be peer modules | `modules/agent-guard/README.md` § "Why a separate module" | F01977 + F01978 | non-negotiable | false | 10 |
| R03895 | Future policy bundles NOT children of agent-guard | `modules/agent-guard/README.md` § "Why a separate module" | F01977 | non-negotiable | false | 10 |
| R03896 | All bundles consume tetragon-tracing + tetragon-policies | `modules/agent-guard/README.md` § "Why a separate module" | F01979 | non-negotiable | false | 10 |
| R03897 | Profile audit is the default | `modules/agent-guard/README.md` § Profiles | F01980 | non-negotiable | true | 10 |
| R03898 | Profile audit installs every enabled policy with action=Post | `modules/agent-guard/README.md` § Profiles | F01981 | non-negotiable | false | 10 |
| R03899 | Profile audit — Tetragon emits event on every match | `modules/agent-guard/README.md` § Profiles | F01982 | non-negotiable | false | 10 |
| R03900 | Profile audit — nothing is killed | `modules/agent-guard/README.md` § Profiles | F01983 | non-negotiable | false | 10 |
| R03901 | Profile audit — "Start here" | `modules/agent-guard/README.md` § Profiles | F01984 | non-negotiable | false | 10 |
| R03902 | Profile audit — operator watches daemon event stream for noise before flipping | `modules/agent-guard/README.md` § Profiles | F01985 | non-negotiable | false | 10 |
| R03903 | Profile audit — operator populates egress_allowlist before flipping | `modules/agent-guard/README.md` § Profiles | F01985 | non-negotiable | false | 10 |
| R03904 | Profile enforce — every enabled policy installs with action=Sigkill by default | `modules/agent-guard/README.md` § Profiles | F01986 | non-negotiable | true | 10 |
| R03905 | Profile enforce — match terminates the offending process | `modules/agent-guard/README.md` § Profiles | F01987 | non-negotiable | false | 10 |
| R03906 | Per-policy override etc_write_action accepts default | post | sigkill | `modules/agent-guard/README.md` § Profiles | F01988 + F01993 | non-negotiable | true | 10 |
| R03907 | Per-policy override shell_exec_action accepts default | post | sigkill | `modules/agent-guard/README.md` § Profiles | F01989 + F01993 | non-negotiable | true | 10 |
| R03908 | Per-policy override egress_action accepts default | post | sigkill | `modules/agent-guard/README.md` § Profiles | F01990 + F01993 | non-negotiable | true | 10 |
| R03909 | Per-policy override securemessage_action accepts default | post | sigkill | `modules/agent-guard/README.md` § Profiles | F01991 + F01993 | non-negotiable | true | 10 |
| R03910 | Per-policy override gpu_device_action accepts default | post | sigkill | `modules/agent-guard/README.md` § Config | F01992 + F01993 | non-negotiable | true | 10 |
| R03911 | Per-policy override `default` means follow profile | `modules/agent-guard/README.md` § Profiles | F01994 | non-negotiable | false | 10 |
| R03912 | Per-policy override lets operators ramp policies up individually rather than flipping whole bundle | `modules/agent-guard/README.md` § Profiles | F01995 | non-negotiable | false | 10 |
| R03913 | Config knob — `profile` = "audit" or "enforce" | `modules/agent-guard/README.md` § Config | F01996 | non-negotiable | true | 10 |
| R03914 | Config knob — `scope` = "container" or "pod-label" | `modules/agent-guard/README.md` § Config | F01997 | non-negotiable | true | 10 |
| R03915 | Config knob — `pod_label_key` (only used when scope=pod-label; default `selfdef.io/agent`) | `modules/agent-guard/README.md` § Config | F01998 | non-negotiable | true | 10 |
| R03916 | Config knob — `pod_label_value` (only used when scope=pod-label; default `"true"`) | `modules/agent-guard/README.md` § Config | F01999 | non-negotiable | true | 10 |
| R03917 | Config knob — `etc_write_enabled` (bool) | `modules/agent-guard/README.md` § Config | F02000 | non-negotiable | true | 10 |
| R03918 | Config knob — `shell_exec_enabled` (bool) | `modules/agent-guard/README.md` § Config | F02001 | non-negotiable | true | 10 |
| R03919 | Config knob — `egress_enabled` (bool) | `modules/agent-guard/README.md` § Config | F02002 | non-negotiable | true | 10 |
| R03920 | Config knob — `egress_allowlist` (CSV of CIDRs that ARE allowed) | `modules/agent-guard/README.md` § Config | F02003 | non-negotiable | true | 10 |
| R03921 | egress_allowlist semantics — empty allowlist with audit mode is silent | `modules/agent-guard/README.md` § Config | F02004 | non-negotiable | false | 10 |
| R03922 | egress_allowlist semantics — empty allowlist with enforce mode means "kill on every outbound connection from a container" | `modules/agent-guard/README.md` § Config | F02005 | non-negotiable | false | 10 |
| R03923 | egress_allowlist semantics — audit your real traffic first | `modules/agent-guard/README.md` § Config | F02006 | non-negotiable | false | 10 |
| R03924 | Config knob — `securemessage_enabled` (bool) | `modules/agent-guard/README.md` § Config | F02007 | non-negotiable | true | 10 |
| R03925 | Config knob — `securemessage_endpoint` (default empty; stub policy stays dormant) | `modules/agent-guard/README.md` § Config | F02008 | non-negotiable | true | 10 |
| R03926 | Config knob — `gpu_device_enabled` (bool) | `modules/agent-guard/README.md` § Config | F02009 | non-negotiable | true | 10 |
| R03927 | Config knob — `gpu_device_paths` (CSV; empty=use shipped NVIDIA defaults; add prefixes for AMD ROCm / Intel Habana / etc.) | `modules/agent-guard/README.md` § Config | F02010 | non-negotiable | true | 10 |
| R03928 | Config knob — `gpu_device_allowlist` (CSV of in-container binary paths permitted; empty=match every binary) | `modules/agent-guard/README.md` § Config | F02011 | non-negotiable | true | 10 |
| R03929 | gpu_device_allowlist warning — populate before flipping to enforce, else every container touching a GPU dies | `modules/agent-guard/README.md` § Config | F02012 | non-negotiable | false | 10 |
| R03930 | Container scope `container` (default) — selector matchNamespaces Pid NotIn [host_ns] | `modules/agent-guard/README.md` § "Container scope" | F02013 | non-negotiable | true | 10 |
| R03931 | Container scope `container` — for Docker | `modules/agent-guard/README.md` § "Container scope" | F02014 | non-negotiable | true | 10 |
| R03932 | Container scope `container` — for Podman | `modules/agent-guard/README.md` § "Container scope" | F02014 | non-negotiable | true | 10 |
| R03933 | Container scope `container` — for containerd-standalone | `modules/agent-guard/README.md` § "Container scope" | F02014 | non-negotiable | true | 10 |
| R03934 | Container scope `container` — or k8s when you don't want to label every agent pod | `modules/agent-guard/README.md` § "Container scope" | F02015 | non-negotiable | true | 10 |
| R03935 | Container scope `container` — matches every non-host PID namespace | `modules/agent-guard/README.md` § "Container scope" | F02016 | non-negotiable | false | 10 |
| R03936 | Container scope `container` — captures every container worth the name | `modules/agent-guard/README.md` § "Container scope" | F02016 | non-negotiable | false | 10 |
| R03937 | Container scope `pod-label` — selector matchPodSelector matchLabels.<key>=<value> | `modules/agent-guard/README.md` § "Container scope" | F02017 | non-negotiable | true | 10 |
| R03938 | Container scope `pod-label` — narrower (only pods carrying configured label fire policy) | `modules/agent-guard/README.md` § "Container scope" | F02018 | non-negotiable | false | 10 |
| R03939 | Container scope `pod-label` — for Kubernetes hosts | `modules/agent-guard/README.md` § "Container scope" | F02019 | non-negotiable | true | 10 |
| R03940 | Container scope `pod-label` — lets unrelated workloads on same node run untouched | `modules/agent-guard/README.md` § "Container scope" | F02020 | non-negotiable | false | 10 |
| R03941 | Container scope `pod-label` — requires `pod_label_key` and `pod_label_value` in the config | `modules/agent-guard/README.md` § "Container scope" | F02021 | non-negotiable | false | 10 |
| R03942 | Container scope `pod-label` — apply.sh refuses without them | `modules/agent-guard/README.md` § "Container scope" | F02022 | non-negotiable | false | 10 |
| R03943 | Container scope `pod-label` — shipped defaults `selfdef.io/agent: "true"` | `modules/agent-guard/README.md` § "Container scope" | F02023 | non-negotiable | false | 10 |
| R03944 | Container scope `pod-label` — operator must label agent pods accordingly | `modules/agent-guard/README.md` § "Container scope" | F02024 | non-negotiable | true | 10 |
| R03945 | Container scope `pod-label` — pod YAML example apiVersion=v1 / kind=Pod / labels.selfdef.io/agent="true" | `modules/agent-guard/README.md` § "Container scope" | F02024 | non-negotiable | true | 10 |
| R03946 | Operators running multiple container workloads should layer second selector by binary path in derivative policy | `modules/agent-guard/README.md` § "Container scope" | F02025 | non-negotiable | false | 10 |
| R03947 | Workflow step 1 — Land `tetragon` first (phase="pre") | `modules/agent-guard/README.md` § Workflow | F02026 | non-negotiable | false | 10 |
| R03948 | Workflow step 2 — Enable `agent-guard` in `audit` | `modules/agent-guard/README.md` § Workflow | F02027 | non-negotiable | false | 10 |
| R03949 | Workflow step 2 — Run for at least a week | `modules/agent-guard/README.md` § Workflow | F02027 | non-negotiable | false | 10 |
| R03950 | Workflow step 2 — Watch for false positives in `selfdefctl events alerts` | `modules/agent-guard/README.md` § Workflow | F02027 | non-negotiable | false | 10 |
| R03951 | Workflow step 3 — Populate `egress_allowlist` with actual destinations agents need | `modules/agent-guard/README.md` § Workflow | F02028 | non-negotiable | false | 10 |
| R03952 | Workflow step 3 example destination — model API gateway | `modules/agent-guard/README.md` § Workflow | F02029 | non-negotiable | true | 10 |
| R03953 | Workflow step 3 example destination — SecureMessage endpoint | `modules/agent-guard/README.md` § Workflow | F02030 | non-negotiable | true | 10 |
| R03954 | Workflow step 3 example destination — internal Prometheus push | `modules/agent-guard/README.md` § Workflow | F02031 | non-negotiable | true | 10 |
| R03955 | Workflow step 4 — Flip a single policy to `sigkill` via its per-policy override | `modules/agent-guard/README.md` § Workflow | F02032 | non-negotiable | false | 10 |
| R03956 | Workflow step 4 — Watch, repeat | `modules/agent-guard/README.md` § Workflow | F02032 | non-negotiable | false | 10 |
| R03957 | Workflow step 5 — Once every policy is at `sigkill` individually, flip `profile = "enforce"` | `modules/agent-guard/README.md` § Workflow | F02033 | non-negotiable | false | 10 |
| R03958 | Workflow step 5 — Flipping `profile="enforce"` makes future policies inherit the right default | `modules/agent-guard/README.md` § Workflow | F02033 | non-negotiable | false | 10 |
| R03959 | install/apply.sh exists at `modules/agent-guard/install/apply.sh` | `modules/agent-guard/install/apply.sh` | F02034 | non-negotiable | false | 10 |
| R03960 | install/check.sh exists at `modules/agent-guard/install/check.sh` | `modules/agent-guard/install/check.sh` | F02035 | non-negotiable | false | 10 |
| R03961 | install/lib.sh exists at `modules/agent-guard/install/lib.sh` (shared helpers) | `modules/agent-guard/install/lib.sh` | F02036 | non-negotiable | false | 10 |
| R03962 | install/uninstall.sh exists at `modules/agent-guard/install/uninstall.sh` | `modules/agent-guard/install/uninstall.sh` | F02037 | non-negotiable | false | 10 |
| R03963 | install/apply.sh materializes Tetragon TracingPolicy YAML files into /etc/tetragon/tracing-policies/ per config | `modules/agent-guard/install/apply.sh` | M00442 | non-negotiable | false | 10 |
| R03964 | install/check.sh emits operator-readable status of installed policies | `modules/agent-guard/install/check.sh` | M00443 | non-negotiable | false | 10 |
| R03965 | install/lib.sh contains CSV parsing for allowlists | `modules/agent-guard/install/lib.sh` | M00444 | non-negotiable | false | 10 |
| R03966 | install/lib.sh contains profile-mode resolution | `modules/agent-guard/install/lib.sh` | M00444 | non-negotiable | false | 10 |
| R03967 | install/lib.sh contains YAML emission with selector + action injection | `modules/agent-guard/install/lib.sh` | M00444 | non-negotiable | false | 10 |
| R03968 | install/uninstall.sh removes agent-guard-* TracingPolicy files | `modules/agent-guard/install/uninstall.sh` | M00445 | non-negotiable | false | 10 |
| R03969 | install/uninstall.sh does NOT touch sovereign-kernel-fence.yaml (MS012 perimeter coexistence) | `modules/agent-guard/install/uninstall.sh` + MS012 | M00445 | non-negotiable | false | 10 |
| R03970 | Future extension — per-pod allowlists under pod-label scope (today applies uniformly) | `modules/agent-guard/README.md` § "Not-shipped extensions" | F02038 | non-negotiable | false | 10 |
| R03971 | Future extension — egress_allowlist + gpu_device_allowlist vary by pod_label_value | `modules/agent-guard/README.md` § "Not-shipped extensions" | F02039 | non-negotiable | false | 10 |
| R03972 | agent-guard is the canonical example of selfdef host-level invariants on AI agents in containers | `modules/agent-guard/` | E0171 | non-negotiable | false | 10 |
| R03973 | agent-guard threat model covers AI-machine in this repo's roadmap | `modules/agent-guard/README.md` § "Not-shipped extensions" | E0180 | non-negotiable | false | 10 |
| R03974 | agent-guard depends_on tetragon module (MS006 module catalog) | `modules/agent-guard/module.toml` + MS006 | M00424 | non-negotiable | false | 10 |
| R03975 | agent-guard policies live at `/etc/tetragon/tracing-policies/agent-guard-*.yaml` (per MS012 § Coverage 1) | MS012 § Coverage 1 + `modules/agent-guard/install/apply.sh` | M00442 | non-negotiable | false | 10 |
| R03976 | agent-guard policies cohabit `/etc/tetragon/tracing-policies/` with sovereign-os `sovereign-kernel-fence.yaml` (per MS012) | MS012 § Coverage 1 | M00445 | non-negotiable | false | 10 |
| R03977 | agent-guard policies are container-scoped; sovereign-kernel-fence is host-scoped (MS012 boundary statement) | MS012 § Coverage 1 boundary | E0173 | non-negotiable | false | 10 |
| R03978 | agent-guard policy_name prefix `agent-guard-` is the selfdef audit-trail discriminator (MS012 § Coverage 5) | MS012 § Coverage 5 + `modules/agent-guard/install/apply.sh` | E0173 | non-negotiable | false | 10 |
| R03979 | agent-guard events flow through selfdef-collector-tetragon (MS016 + MS002) onto local bus | MS016 + MS002 | E0173 | non-negotiable | false | 10 |
| R03980 | Project boundary — agent-guard authorship is selfdef team (MS012 § Coverage 1 selfdef authority) | MS012 § Coverage 1 | F01975 | non-negotiable | false | 10 |
| R03981 | Project boundary — sovereign-os does NOT author agent-guard policies (cross-repo binding via Tetragon as merge agent only) | MS012 + MS007 + SDD-038 | E0174 | non-negotiable | false | 10 |
| R03982 | Project boundary — agent-guard does NOT touch sovereign-kernel-fence.yaml (operator-respected separation) | MS012 § Coverage 1 + `modules/agent-guard/install/uninstall.sh` | M00445 | non-negotiable | false | 10 |
| R03983 | Project boundary — sovereign-os may subscribe to agent-guard events via NATS bridge (MS015) with mTLS | MS015 + MS007 + SDD-038 | E0173 | non-negotiable | false | 10 |
| R03984 | Project boundary — Oracle-Triage (MS004 E0036) may carry agent-guard policy-strike events for cross-repo correlation | MS004 E0036 + SDD-038 | E0173 | non-negotiable | false | 10 |
| R03985 | Integration with MS001 selfdef daemon core — daemon hosts the apply/check/uninstall lifecycle | MS001 + `modules/agent-guard/install/` | E0180 | non-negotiable | false | 10 |
| R03986 | Integration with MS002 collector fabric — selfdef-collector-tetragon ingests agent-guard events into local bus | MS002 + MS016 + `crates/selfdef-collector-tetragon/` | E0173 | non-negotiable | false | 10 |
| R03987 | Integration with MS003 correlator — egress-guard / etc-write-guard / shell-exec-guard / gpu-device-guard fire correlation rules in the daemon | MS003 + `modules/agent-guard/README.md` § policy table | E0173 | non-negotiable | false | 10 |
| R03988 | Integration with MS003 responder — Sigkill action in enforce profile is Tetragon-side; daemon-side responder may trigger additional actions (ZFS snapshot, notification fan-out) | MS003 + `modules/agent-guard/README.md` § Profiles | E0175 | non-negotiable | false | 10 |
| R03989 | Integration with MS004 14 notifier integrations — agent-guard events feed all 14 notifier channels (per MS005 orchestrator) | MS004 + MS005 + `modules/agent-guard/README.md` § Workflow | E0173 | non-negotiable | false | 10 |
| R03990 | Integration with MS005 notifier engine + orchestrator — agent-guard event severity drives notifier routing | MS005 + `modules/agent-guard/README.md` § Profiles | E0173 | non-negotiable | false | 10 |
| R03991 | Integration with MS006 14 functional modules — agent-guard is the canonical example of `[install] kind=script` with apply/check/uninstall | MS006 + `modules/agent-guard/module.toml` | M00429 | non-negotiable | false | 10 |
| R03992 | Integration with MS007 typed-mirror crates — agent-guard manifest schema may be mirrored for cross-repo audit | MS007 + SDD-038 | M00421 | non-negotiable | false | 10 |
| R03993 | Integration with MS008 SAIN-01 — agent-guard is a baseline module on SAIN-01 deployment | MS008 + `modules/agent-guard/README.md` § header | E0171 | non-negotiable | false | 10 |
| R03994 | Integration with MS009 audit cycles — phase-6/40-module-audit covers agent-guard module against 27-SDD charter | MS009 phase-6 40-module-audit | M00421 | non-negotiable | false | 10 |
| R03995 | Integration with MS010 hardware-aware modules — agent-guard module.toml MAY add [requires_hardware] gpu_count_min=1 for gpu-device-guard policy in future iteration | MS010 + `modules/agent-guard/README.md` § Config | M00435 | non-negotiable | true | 10 |
| R03996 | Integration with MS011 operator dashboard — dashboard Modules tab shows agent-guard install state + profile + per-policy action | MS011 + `modules/agent-guard/install/check.sh` | M00443 | non-negotiable | false | 10 |
| R03997 | Integration with MS012 perimeter coexistence — agent-guard policy_name prefix discriminator is the audit-trail invariant | MS012 § Coverage 5 + `modules/agent-guard/install/apply.sh` | E0173 | non-negotiable | false | 10 |
| R03998 | Integration with MS013 27-SDD charter — agent-guard has NO dedicated SDD (codified in README + module.toml + install scripts); future SDD slot available if scope grows | MS013 + `docs/sdd/` ledger | E0171 | non-negotiable | false | 10 |
| R03999 | Integration with MS014 SSH-wrap — both ssh-wrap and agent-guard are client/host-defense modules with different scopes (ssh-wrap=outbound ssh; agent-guard=container-internal) | MS014 + `modules/agent-guard/README.md` § header | E0171 | non-negotiable | false | 10 |
| R04000 | Integration with MS015 NATS messaging — agent-guard events propagate cross-host via NATS bridge | MS015 + `modules/agent-guard/README.md` § header | E0173 | non-negotiable | false | 10 |
| R04001 | Integration with MS016 eBPF + Tetragon — selfdef-collector-tetragon consumes agent-guard events (policy_name starts with `agent-guard-` per MS012) | MS016 + MS012 | E0173 | non-negotiable | false | 10 |
| R04002 | Audit-trail invariant — agent-guard events keep policy_name field set to `agent-guard-<policy>` | MS012 § Coverage 5 + `modules/agent-guard/install/apply.sh` | E0173 | non-negotiable | false | 10 |
| R04003 | Audit-trail invariant — daemon component label `selfdef.agent-guard` (per MS016 attack-coverage convention) | MS016 + `docs/src/detect/attack_coverage.md` | E0173 | non-negotiable | false | 10 |
| R04004 | Failure mode — tetragon not running → apply.sh refuses (`requires binary=tetragon` per module.toml) | `modules/agent-guard/module.toml` requires | F01932 | non-negotiable | false | 10 |
| R04005 | Failure mode — scope=pod-label without pod_label_key/value → apply.sh refuses | `modules/agent-guard/README.md` § "Container scope" | F02022 | non-negotiable | false | 10 |
| R04006 | Failure mode — empty egress_allowlist + enforce profile → kills every outbound from container (operator-warned in Config docs) | `modules/agent-guard/README.md` § Config | F02005 | non-negotiable | false | 10 |
| R04007 | Failure mode — empty gpu_device_allowlist + enforce profile + gpu_device_enabled=true → kills every container touching a GPU (operator-warned in Config docs) | `modules/agent-guard/README.md` § Config | F02012 | non-negotiable | false | 10 |
| R04008 | Failure mode — invalid CIDR in egress_allowlist → apply.sh refuses | `modules/agent-guard/install/apply.sh` + `modules/agent-guard/install/lib.sh` CSV parsing | M00444 | non-negotiable | false | 10 |
| R04009 | Failure mode — invalid pod_label_key/value (kubernetes label restrictions) → apply.sh refuses | `modules/agent-guard/install/apply.sh` | M00442 | non-negotiable | false | 10 |
| R04010 | Failure mode — invalid per-policy action (not one of default|post|sigkill) → apply.sh refuses | `modules/agent-guard/install/apply.sh` | M00442 | non-negotiable | false | 10 |
| R04011 | Failure mode — gpu_device_paths missing AND default NVIDIA paths absent → policy installs with empty path list (no-op match) | `modules/agent-guard/install/apply.sh` + `modules/agent-guard/README.md` § Config | F02010 | non-negotiable | false | 10 |
| R04012 | Doctrine — agent-guard ships in audit profile by default (safety: nothing kills until operator opts in) | `modules/agent-guard/README.md` § Profiles + `modules/agent-guard/module.toml` [profiles] default | F01942 + F01980 | non-negotiable | false | 10 |
| R04013 | Doctrine — operator ramps per-policy individually before flipping bundle profile to enforce | `modules/agent-guard/README.md` § Workflow | F02032 + F02033 | non-negotiable | false | 10 |
| R04014 | Doctrine — operator audits real traffic ≥1 week before populating allowlists | `modules/agent-guard/README.md` § Workflow + § Config | F02006 + F02027 | non-negotiable | false | 10 |
| R04015 | Doctrine — Sigkill is per-process, NOT per-container (Tetragon kprobe action) | `modules/agent-guard/README.md` § policy table | F01987 | non-negotiable | false | 10 |
| R04016 | Doctrine — every selector includes matchNamespaces Pid NotIn [host_ns] invariantly | `modules/agent-guard/README.md` § header | F01967 | non-negotiable | false | 10 |
| R04017 | Doctrine — agent-guard is hardening module (category=hardening per module.toml) | `modules/agent-guard/module.toml` | F01927 | non-negotiable | false | 10 |
| R04018 | Doctrine — peer policy bundles compose at the module level (future host-hardening-guard, k8s-admin-guard) | `modules/agent-guard/README.md` § "Why a separate module" | F01977 + F01978 | non-negotiable | false | 10 |
| R04019 | Doctrine — every peer policy bundle consumes tetragon-tracing + tetragon-policies (composability) | `modules/agent-guard/README.md` § "Why a separate module" | F01979 | non-negotiable | false | 10 |
| R04020 | Doctrine — agent-guard ENFORCES the AI-agent-defense invariant: agents-in-containers cannot escape host trust boundary | `modules/agent-guard/README.md` § header | E0171 | non-negotiable | false | 10 |
| R04021 | Audit-cycle integration — MS009 phase-6 40-module-audit covers agent-guard against 27-SDD charter (M00342 anti-patterns + style rules) | MS009 phase-6 40-module-audit + MS013 | M00421 | non-negotiable | false | 10 |
| R04022 | Audit-cycle integration — MS009 phase-7 50-integration-audit covers agent-guard cohabitation with sovereign-kernel-fence | MS009 phase-7 50-integration-audit + MS012 | E0173 | non-negotiable | false | 10 |
| R04023 | Audit-cycle integration — MS009 phase-6 80-security-audit covers agent-guard threat-model coverage | MS009 phase-6 80-security-audit + `modules/agent-guard/README.md` § "Not-shipped extensions" | E0180 | non-negotiable | false | 10 |
| R04024 | Audit-cycle integration — F-2026-NNN findings may record agent-guard policy gaps + operator-experience issues | MS009 99-findings-ledger | E0179 | non-negotiable | false | 10 |
| R04025 | Operator-facing command (implied per architecture) — `selfdefctl modules apply agent-guard` triggers install/apply.sh | architecture + `modules/agent-guard/install/apply.sh` | M00442 | non-negotiable | true | 10 |
| R04026 | Operator-facing command (implied per architecture) — `selfdefctl modules check agent-guard` triggers install/check.sh | architecture + `modules/agent-guard/install/check.sh` | M00443 | non-negotiable | true | 10 |
| R04027 | Operator-facing command (implied per architecture) — `selfdefctl modules uninstall agent-guard` triggers install/uninstall.sh | architecture + `modules/agent-guard/install/uninstall.sh` | M00445 | non-negotiable | true | 10 |
| R04028 | Operator-facing command (implied per architecture) — `selfdefctl modules info agent-guard` shows profile + per-policy action effective | architecture + MS006 + MS010 SD-R84 | E0176 | non-negotiable | true | 10 |
| R04029 | Operator-facing command (implied per architecture) — `selfdefctl events alerts --module=agent-guard` filters event stream | architecture + `modules/agent-guard/README.md` § Workflow | F02027 | non-negotiable | true | 10 |
| R04030 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_agent_guard_policy_strike_total{policy,action}` | architecture + MS009 phase-6 80-security-audit | E0173 | non-negotiable | true | 10 |
| R04031 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_agent_guard_egress_allowlist_size` | architecture | F02003 | non-negotiable | true | 10 |
| R04032 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_agent_guard_profile_mode{mode}` | architecture | E0175 | non-negotiable | true | 10 |
| R04033 | Composability — operators may write derivative policies (layered selectors) under `rules/tetragon/` outside agent-guard module bundle | `modules/agent-guard/README.md` § "Container scope" + `rules/tetragon/` | F02025 | non-negotiable | true | 10 |
| R04034 | Composability — derivative policies retain matchNamespaces Pid NotIn [host_ns] invariant | `modules/agent-guard/README.md` § header + § "Container scope" | F01967 + F02025 | non-negotiable | false | 10 |
| R04035 | Composability — operator's derivative policies may match by binary path (`/usr/bin/python3 running inside container`) for narrower scope | `modules/agent-guard/README.md` § "Container scope" | F02025 | non-negotiable | true | 10 |
| R04036 | Test plan (implied; MS009 audit cycle phase-6 70-tests) — apply.sh idempotency: re-running apply.sh on same config produces no diff | architecture + MS009 phase-6 70-tests | M00442 | non-negotiable | false | 10 |
| R04037 | Test plan (implied) — check.sh exit-code semantics: 0=ok / 1=drift / 2=hard-fail (parsing operator-readable output) | architecture + `modules/agent-guard/install/check.sh` | M00443 | non-negotiable | false | 10 |
| R04038 | Test plan (implied) — uninstall.sh leaves no agent-guard-*.yaml in policy directory | architecture + `modules/agent-guard/install/uninstall.sh` | M00445 | non-negotiable | false | 10 |
| R04039 | Test plan (implied) — uninstall.sh does NOT remove sovereign-kernel-fence.yaml (cohabitation invariant) | MS012 + `modules/agent-guard/install/uninstall.sh` | M00445 | non-negotiable | false | 10 |
| R04040 | Test plan (implied) — pod-label scope: missing pod_label_key fails apply | `modules/agent-guard/install/apply.sh` + `modules/agent-guard/README.md` § "Container scope" | F02022 | non-negotiable | false | 10 |
| R04041 | Test plan (implied) — egress_allowlist parses CSV CIDRs and rejects invalid | `modules/agent-guard/install/lib.sh` + `modules/agent-guard/install/apply.sh` | F02003 + M00444 | non-negotiable | false | 10 |
| R04042 | Test plan (implied) — gpu_device_paths empty → shipped NVIDIA defaults used | `modules/agent-guard/install/apply.sh` + `modules/agent-guard/README.md` § Config | F02010 | non-negotiable | false | 10 |
| R04043 | Test plan (implied) — per-policy override `default` resolves to profile-mode action | `modules/agent-guard/install/lib.sh` profile resolution + `modules/agent-guard/README.md` § Profiles | F01994 | non-negotiable | false | 10 |
| R04044 | Test plan (implied) — per-policy override `sigkill` always installs Sigkill regardless of profile=audit | `modules/agent-guard/install/lib.sh` + `modules/agent-guard/README.md` § Profiles | F01993 | non-negotiable | false | 10 |
| R04045 | Test plan (implied) — per-policy override `post` always installs Post regardless of profile=enforce | `modules/agent-guard/install/lib.sh` + `modules/agent-guard/README.md` § Profiles | F01993 | non-negotiable | false | 10 |
| R04046 | Cross-repo correlation — agent-guard event `policy_name`=`agent-guard-etc-write` flows into Oracle-Triage MS004 E0036 channel for sovereign-os-side awareness | MS004 E0036 + `modules/agent-guard/README.md` § policy table | E0173 | non-negotiable | false | 10 |
| R04047 | Cross-repo correlation — sovereign-os MAY use agent-guard signals to decide ZFS snapshot rollback (sovereign-os responder hook) | MS003 + MS004 E0036 | E0175 | non-negotiable | false | 10 |
| R04048 | Cross-repo correlation — agent-guard event metadata (NOT policy YAML content) flows in NATS bridge | MS015 + `modules/agent-guard/README.md` § header | E0173 | non-negotiable | false | 10 |
| R04049 | Cross-repo correlation — sovereign-os does NOT modify selfdef agent-guard YAMLs (selfdef authoring authority per MS012) | MS012 § Coverage 1 + architecture | F01976 | non-negotiable | false | 10 |
| R04050 | Cross-repo correlation — sovereign-os enforces its sovereign-kernel-fence at host scope; agent-guard enforces container-scope (per MS012 boundary) | MS012 § Coverage 1 boundary | E0173 | non-negotiable | false | 10 |
| R04051 | Threat-model coverage — etc-write-guard catches container processes writing to /etc/ (common privilege-escalation precursor) | `modules/agent-guard/README.md` § policy table + § header | M00431 | non-negotiable | false | 10 |
| R04052 | Threat-model coverage — container-shell-guard catches container processes spawning interactive shells (common breakout vector) | `modules/agent-guard/README.md` § policy table | M00432 | non-negotiable | false | 10 |
| R04053 | Threat-model coverage — egress-guard catches container processes connecting to unauthorized destinations (C2 / exfiltration) | `modules/agent-guard/README.md` § policy table | M00433 | non-negotiable | false | 10 |
| R04054 | Threat-model coverage — securemessage-guard reserves observation channel for future SecureMessage endpoint (data plane discriminator) | `modules/agent-guard/README.md` § policy table + § Config | M00434 | non-negotiable | false | 10 |
| R04055 | Threat-model coverage — gpu-device-guard catches container processes opening GPU device nodes outside allowlist (GPU privilege escalation / model theft) | `modules/agent-guard/README.md` § policy table | M00435 | non-negotiable | false | 10 |
| R04056 | Threat-model invariant — every catch is event + (optional) Sigkill; never silent | `modules/agent-guard/README.md` § Profiles | M00437 + M00438 | non-negotiable | false | 10 |
| R04057 | Threat-model invariant — host processes never matched (matchNamespaces Pid NotIn [host_ns]) | `modules/agent-guard/README.md` § header | F01967 | non-negotiable | false | 10 |
| R04058 | Threat-model invariant — sovereign-os Stage-2+ team authors sovereign-kernel-fence; selfdef team authors agent-guard (no overlap per MS012) | MS012 + `modules/agent-guard/README.md` § header | F01975 + F01976 | non-negotiable | false | 10 |
| R04059 | Threat-model invariant — Tetragon merges both policy sets at kernel level; selfdef + sovereign-os daemons discriminate via policy_name prefix | MS012 § Coverage 5 + MS016 selfdef-collector-tetragon | E0173 | non-negotiable | false | 10 |
| R04060 | Operator workflow invariant — start in audit | `modules/agent-guard/README.md` § Workflow | F01984 + F02027 | non-negotiable | false | 10 |
| R04061 | Operator workflow invariant — ramp per-policy individually | `modules/agent-guard/README.md` § Workflow | F02032 | non-negotiable | false | 10 |
| R04062 | Operator workflow invariant — flip whole profile last (after all per-policy at sigkill) | `modules/agent-guard/README.md` § Workflow | F02033 | non-negotiable | false | 10 |
| R04063 | Operator workflow invariant — populate egress_allowlist + gpu_device_allowlist BEFORE flipping to enforce | `modules/agent-guard/README.md` § Workflow + § Config | F02006 + F02012 | non-negotiable | false | 10 |
| R04064 | Operator workflow invariant — audit ≥1 week before flipping anything | `modules/agent-guard/README.md` § Workflow | F02027 | non-negotiable | false | 10 |
| R04065 | Module bundle convention — agent-guard is the canonical 5-policy bundle; future bundles follow the same shape (manifest + profiles + per-policy actions + install scripts + README) | `modules/agent-guard/` + `modules/agent-guard/README.md` § "Why a separate module" | F01977 + F01978 | non-negotiable | false | 10 |
| R04066 | Module bundle convention — derivative policies live OUTSIDE the bundle (in `rules/tetragon/`) when they don't fit the bundle's policy set | `rules/tetragon/` + `modules/agent-guard/README.md` § "Container scope" | F02025 | non-negotiable | false | 10 |
| R04067 | Module bundle convention — agent-guard depends_on tetragon at module-graph level (NOT linker level — Tetragon is a binary requirement per `requires`) | `modules/agent-guard/module.toml` | F01928 + F01932 | non-negotiable | false | 10 |
| R04068 | Module bundle convention — agent-guard ships under `category=hardening` (peer to future host-hardening-guard, k8s-admin-guard) | `modules/agent-guard/module.toml` + `modules/agent-guard/README.md` § "Why a separate module" | F01927 + F01977 + F01978 | non-negotiable | false | 10 |
| R04069 | Module bundle convention — instanced=false (single bundle per host); per-policy config replaces per-instance config | `modules/agent-guard/module.toml` + § comment | F01933 + F01934 | non-negotiable | false | 10 |
| R04070 | Module bundle convention — phase=main ensures correct ordering (tetragon in pre / agent-guard in main / observability in post) | `modules/agent-guard/module.toml` + § comment | F01935 + F01936 + F01937 | non-negotiable | false | 10 |
| R04071 | Composite — agent-guard 0.3.0 is the operator-facing AI-agent host defense module; 5 policies + 2 profiles + 2 scope strategies + 5-step workflow + 514-line install scripts + 32-line manifest + README covering all of above | `modules/agent-guard/` + `modules/agent-guard/module.toml` + `modules/agent-guard/README.md` + `modules/agent-guard/install/` | E0171 + E0172 + E0173 + E0174 + E0175 + E0176 + E0177 + E0178 + E0179 + E0180 | non-negotiable | false | 10 |
| R04072 | Composite — agent-guard threat-model: AI agents in Docker / Podman / containerd cannot escape host trust via /etc/ writes / interactive shells / egress C2 / SecureMessage hijack / GPU device escalation | `modules/agent-guard/README.md` § header + § policy table | E0171 | non-negotiable | false | 10 |
| R04073 | Composite — agent-guard policy bundle is the canonical Tetragon TracingPolicy authoring style for selfdef (peer bundles will mirror this shape) | `modules/agent-guard/` + `modules/agent-guard/README.md` § "Why a separate module" | E0174 | non-negotiable | false | 10 |
| R04074 | Composite — agent-guard uses audit-first ramp strategy (safety doctrine: nothing kills until operator has watched audit events) | `modules/agent-guard/README.md` § Profiles + § Workflow | E0175 + E0179 | non-negotiable | false | 10 |
| R04075 | Composite — agent-guard cohabits with sovereign-kernel-fence (MS012 doctrine: container-scope vs host-scope; no overlap) | MS012 + `modules/agent-guard/README.md` § header | E0173 + R03977 | non-negotiable | false | 10 |
| R04076 | Composite — agent-guard 5 policies map to 5 OCSF event kinds with discriminator `policy_name=agent-guard-*` (MS012 § Coverage 5 + MS016 detect mapping) | MS012 § Coverage 5 + MS016 § attack coverage | R03978 | non-negotiable | false | 10 |
| R04077 | Composite — agent-guard integrates with MS001-MS016 milestones (daemon core / collectors / correlator+responder / 14 notifiers + orchestrator / 14 functional modules / typed mirrors / SAIN-01 / audit cycles / hardware-aware / dashboard / perimeter coexistence / SDD charter / SSH-wrap / NATS / eBPF+Tetragon) | MS001-MS016 + `modules/agent-guard/` | E0171 | non-negotiable | false | 10 |
| R04078 | Composite — agent-guard module.toml is the canonical reference operator example for category=hardening / phase=main / depends_on substrate / [profiles] default-and-available / [install] kind=script | `modules/agent-guard/module.toml` + MS006 module spec | F01924 | non-negotiable | false | 10 |
| R04079 | Composite — agent-guard install scripts (apply 147L + check 92L + lib 214L + uninstall 61L = 514L total) demonstrate the SDD-006 shared module-script lib pattern in practice | `modules/agent-guard/install/` + SDD-006 + MS021 | F02034 + F02035 + F02036 + F02037 | non-negotiable | false | 10 |
| R04080 | Composite — agent-guard is the canonical "host-level invariants on AI agents in Docker / Podman / containerd" module per INDEX MS017 row; 5-policy bundle covers the operator-stated AI-machine threat model; future host-hardening-guard / k8s-admin-guard are peer bundles consuming the same tetragon substrate; agent-guard authority is selfdef team (sovereign-kernel-fence authority is sovereign-os Stage-2+ per MS012 boundary); audit-trail discriminator via policy_name prefix `agent-guard-`; events flow through selfdef-collector-tetragon + local bus + correlator + responder + 14 notifier integrations; NATS bridge (MS015) propagates cross-host; Oracle-Triage MS004 E0036 carries cross-repo escalation | INDEX.md MS017 + `modules/agent-guard/` + MS001-MS016 | E0171 + E0172 + E0173 + E0174 + E0175 + E0176 + E0177 + E0178 + E0179 + E0180 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS016: 21120 + 2400 = 23520 sub-requirements when MS017 lands

## Cross-references

- Module root: `modules/agent-guard/` (module.toml 32L + README.md + install/{apply 147L, check 92L, lib 214L, uninstall 61L} + policies/ + profiles/)
- Tetragon TracingPolicy directory (where agent-guard-*.yaml is installed): `/etc/tetragon/tracing-policies/`
- Sister cohabitating policy: `sovereign-os` repo's `sovereign-kernel-fence.yaml` (host-scope; MS012 § Coverage 1)
- Audit-trail discriminator: `policy_name` field starts with `agent-guard-` (MS012 § Coverage 5)
- Detection rule: `defense_evasion/ssh_wrap_policy_strip.yml` is selfdef's MITRE T1098 mapping convention; agent-guard policies map similarly (MS016 § attack coverage)
- Sister milestones: MS001 daemon core (apply/check/uninstall lifecycle) / MS002 collector fabric (selfdef-collector-tetragon ingests agent-guard events) / MS003 correlator+responder+store-sink / MS004 14 notifier integrations + MS004 E0036 Oracle-Triage cross-repo / MS005 notifier engine+orchestrator / MS006 14 functional modules (agent-guard is one) / MS007 typed-mirror crates / MS008 SAIN-01 (baseline module) / MS009 audit cycles (phase-6/-7 module + integration audit) / MS010 hardware-aware modules (future gpu_count_min requires) / MS011 operator dashboard (Modules tab) / MS012 perimeter coexistence (container-vs-host scope split) / MS013 27-SDD charter / MS014 SSH-wrap (sister host/client defense) / MS015 NATS messaging (cross-host event propagation) / MS016 eBPF + Tetragon (selfdef-collector-tetragon ingester)
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (sovereign-os reads agent-guard events via NATS subscription with mTLS; NOT crate import; NOT YAML editing)
