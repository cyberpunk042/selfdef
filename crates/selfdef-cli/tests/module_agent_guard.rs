//! Dry-run smoke tests for the `agent-guard` module.
//!
//! Hermetic: each test builds a scratch tempdir with a writable
//! tetragon policy_dir + a host config, then runs apply.sh and
//! verifies the rendered TracingPolicy YAMLs land with the right
//! action (`Post` in audit, `Sigkill` in enforce) and that
//! per-policy overrides + the egress allowlist splice correctly.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn module_dir() -> PathBuf {
    workspace_root().join("modules/agent-guard")
}

fn write_file(path: &Path, body: &str) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

struct Fixture {
    _root: tempfile::TempDir,
    config_path: PathBuf,
    tetragon_config: PathBuf,
    policy_dir: PathBuf,
    /// SDD-006 v2 / F-2026-050: per-test manifest path. The
    /// shared lib reads MODULE_INSTALLED_MANIFEST; the tests
    /// set it to a tempdir path so apply.sh's
    /// `module_record_file` calls don't pollute the host's
    /// `/var/lib/selfdef/installed/`.
    manifest_path: PathBuf,
}

fn fixture(host_config: &str) -> Fixture {
    let root_holder = tempfile::tempdir().unwrap();
    let root = root_holder.path().to_path_buf();
    let policy_dir = root.join("tetragon.tp.d");
    std::fs::create_dir_all(&policy_dir).unwrap();

    let tetragon_config = root.join("tetragon.toml");
    write_file(
        &tetragon_config,
        &format!("policy_dir = \"{}\"\n", policy_dir.display()),
    );

    let config_path = root.join("agent-guard.toml");
    write_file(&config_path, host_config);

    let manifest_path = root.join("agent-guard.manifest");

    Fixture {
        _root: root_holder,
        config_path,
        tetragon_config,
        policy_dir,
        manifest_path,
    }
}

fn run_apply(fx: &Fixture) -> Output {
    Command::new("bash")
        .arg(module_dir().join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_AGENT_GUARD_CONFIG", &fx.config_path)
        .env("SELFDEF_TETRAGON_CONFIG", &fx.tetragon_config)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn apply.sh")
}

fn last_stdout_line(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn read_policy(fx: &Fixture, name: &str) -> String {
    let p = fx.policy_dir.join(format!("selfdef-agent-{name}.yaml"));
    std::fs::read_to_string(p).unwrap_or_default()
}

#[test]
fn audit_profile_renders_post_action_for_every_enabled_policy() {
    let fx = fixture("profile = \"audit\"\n");
    let out = run_apply(&fx);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    for name in [
        "etc-write-guard",
        "container-shell-guard",
        "egress-guard",
        "securemessage-guard",
        "gpu-device-guard",
    ] {
        let body = read_policy(&fx, name);
        assert!(!body.is_empty(), "policy {name} was not rendered",);
        assert!(
            body.contains("- action: Post"),
            "policy {name} did not get Post action in audit:\n{body}",
        );
        assert!(
            !body.contains("- action: Sigkill"),
            "policy {name} unexpectedly has Sigkill in audit:\n{body}",
        );
    }
    let line = last_stdout_line(&out);
    assert!(
        line.contains("profile=audit") && line.contains("installed=5"),
        "got: {line}",
    );
}

#[test]
fn enforce_profile_renders_sigkill_for_default_actions() {
    let fx = fixture("profile = \"enforce\"\n");
    let out = run_apply(&fx);
    assert!(out.status.success());
    // etc-write, shell-exec, egress, gpu-device all flip to Sigkill.
    for name in [
        "etc-write-guard",
        "container-shell-guard",
        "egress-guard",
        "gpu-device-guard",
    ] {
        let body = read_policy(&fx, name);
        assert!(
            body.contains("- action: Sigkill"),
            "policy {name} did not get Sigkill in enforce:\n{body}",
        );
    }
    // securemessage stays Post (stub, dormant until endpoint is configured).
    let sm = read_policy(&fx, "securemessage-guard");
    assert!(
        sm.contains("- action: Post"),
        "securemessage stub should stay Post:\n{sm}",
    );
}

#[test]
fn gpu_default_render_keeps_nvidia_prefixes_and_drops_match_binaries() {
    // Default audit profile, no GPU config keys set. The policy should
    // ship with NVIDIA device prefixes intact and the matchBinaries
    // selector dropped so the rule matches every in-container binary
    // touching those device nodes.
    let fx = fixture("profile = \"audit\"\n");
    let out = run_apply(&fx);
    assert!(out.status.success(), "apply failed");
    let body = read_policy(&fx, "gpu-device-guard");
    assert!(
        body.contains("/dev/nvidia"),
        "missing NVIDIA prefix:\n{body}"
    );
    assert!(
        body.contains("/dev/nvidia-uvm"),
        "missing UVM prefix:\n{body}",
    );
    assert!(
        !body.contains("matchBinaries:"),
        "matchBinaries should have been dropped with empty allowlist:\n{body}",
    );
    assert!(
        !body.contains("__SELFDEF_GPU_ALLOWLIST_PLACEHOLDER__"),
        "placeholder must not survive rendering:\n{body}",
    );
}

#[test]
fn gpu_allowlist_when_set_keeps_match_binaries_with_operator_values() {
    let fx = fixture(
        "profile = \"audit\"\n\
         gpu_device_allowlist = \"/usr/local/bin/python3, /usr/bin/torchrun\"\n",
    );
    let out = run_apply(&fx);
    assert!(out.status.success(), "apply failed");
    let body = read_policy(&fx, "gpu-device-guard");
    assert!(
        body.contains("matchBinaries:"),
        "matchBinaries selector should be kept with non-empty allowlist:\n{body}",
    );
    assert!(
        body.contains("/usr/local/bin/python3"),
        "first allowlist binary missing:\n{body}",
    );
    assert!(
        body.contains("/usr/bin/torchrun"),
        "second allowlist binary missing:\n{body}",
    );
    assert!(
        !body.contains("__SELFDEF_GPU_ALLOWLIST_PLACEHOLDER__"),
        "placeholder must not survive:\n{body}",
    );
}

#[test]
fn gpu_custom_device_paths_replace_shipped_defaults() {
    // Operator extends to AMD ROCm + Intel Habana device nodes.
    let fx = fixture(
        "profile = \"audit\"\n\
         gpu_device_paths = \"/dev/kfd, /dev/accel\"\n",
    );
    let out = run_apply(&fx);
    assert!(out.status.success(), "apply failed");
    let body = read_policy(&fx, "gpu-device-guard");
    assert!(
        body.contains("/dev/kfd"),
        "operator path /dev/kfd missing:\n{body}",
    );
    assert!(
        body.contains("/dev/accel"),
        "operator path /dev/accel missing:\n{body}",
    );
    assert!(
        !body.contains("/dev/nvidia"),
        "shipped NVIDIA defaults should have been replaced:\n{body}",
    );
}

#[test]
fn gpu_disabled_drops_policy_file() {
    let fx = fixture("profile = \"audit\"\ngpu_device_enabled = false\n");
    let stale = fx.policy_dir.join("selfdef-agent-gpu-device-guard.yaml");
    write_file(&stale, "stale: true\n");
    let out = run_apply(&fx);
    assert!(out.status.success(), "apply failed");
    assert!(!stale.exists(), "disabled gpu policy must be removed");
    let line = last_stdout_line(&out);
    assert!(
        line.contains("installed=4") && line.contains("disabled=1"),
        "got: {line}",
    );
}

#[test]
fn per_policy_action_override_wins_over_profile() {
    // enforce profile globally, but pin etc-write to post.
    let fx = fixture("profile = \"enforce\"\netc_write_action = \"post\"\n");
    let out = run_apply(&fx);
    assert!(out.status.success());
    let etc = read_policy(&fx, "etc-write-guard");
    assert!(
        etc.contains("- action: Post"),
        "per-policy override ignored:\n{etc}",
    );
    let sh = read_policy(&fx, "container-shell-guard");
    assert!(
        sh.contains("- action: Sigkill"),
        "shell-exec should still get enforce default:\n{sh}",
    );
}

#[test]
fn disabled_policy_is_not_rendered_and_stale_render_is_cleaned_up() {
    let fx = fixture("profile = \"audit\"\nshell_exec_enabled = false\n");
    // Pre-seed a stale file for shell-exec to make sure apply removes it.
    let stale = fx
        .policy_dir
        .join("selfdef-agent-container-shell-guard.yaml");
    write_file(&stale, "stale: true\n");

    let out = run_apply(&fx);
    assert!(out.status.success(), "apply failed");
    assert!(
        !stale.exists(),
        "stale policy file must be removed when disabled",
    );
    // Other policies still rendered.
    assert!(!read_policy(&fx, "etc-write-guard").is_empty());
    let line = last_stdout_line(&out);
    assert!(
        line.contains("installed=4") && line.contains("disabled=1"),
        "got: {line}",
    );
}

#[test]
fn egress_allowlist_is_spliced_into_the_rendered_policy() {
    let fx = fixture("profile = \"audit\"\negress_allowlist = \"10.0.0.0/24, 198.51.100.10/32\"\n");
    let out = run_apply(&fx);
    assert!(out.status.success());
    let body = read_policy(&fx, "egress-guard");
    assert!(
        body.contains("10.0.0.0/24"),
        "first allowlisted CIDR missing:\n{body}",
    );
    assert!(
        body.contains("198.51.100.10/32"),
        "second allowlisted CIDR missing:\n{body}",
    );
    assert!(
        !body.contains("0.0.0.0/0"),
        "placeholder CIDR must be replaced:\n{body}",
    );
}

#[test]
fn securemessage_endpoint_substitution_when_set() {
    let fx =
        fixture("profile = \"audit\"\nsecuremessage_endpoint = \"/run/selfdef/securemsg.sock\"\n");
    let out = run_apply(&fx);
    assert!(out.status.success());
    let body = read_policy(&fx, "securemessage-guard");
    assert!(
        body.contains("/run/selfdef/securemsg.sock"),
        "endpoint not spliced:\n{body}",
    );
    assert!(
        !body.contains("__SELFDEF_SECUREMESSAGE_DISABLED__"),
        "placeholder must be replaced:\n{body}",
    );
}

#[test]
fn rejects_invalid_profile() {
    let fx = fixture("profile = \"spicy\"\n");
    let out = run_apply(&fx);
    assert!(!out.status.success(), "should refuse invalid profile");
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("audit|enforce"),
        "got: {line}",
    );
}

#[test]
fn check_passes_after_apply_and_fails_when_action_drifts() {
    let fx = fixture("profile = \"audit\"\n");
    run_apply(&fx);

    let check_ok = Command::new("bash")
        .arg(module_dir().join("install/check.sh"))
        .env("SELFDEF_AGENT_GUARD_CONFIG", &fx.config_path)
        .env("SELFDEF_TETRAGON_CONFIG", &fx.tetragon_config)
        .output()
        .expect("spawn check.sh");
    assert!(
        check_ok.status.success(),
        "check should pass after apply: stdout={} stderr={}",
        String::from_utf8_lossy(&check_ok.stdout),
        String::from_utf8_lossy(&check_ok.stderr),
    );

    // Tamper: rewrite a policy to Sigkill, then check should fail.
    let etc = fx.policy_dir.join("selfdef-agent-etc-write-guard.yaml");
    let body = std::fs::read_to_string(&etc).unwrap();
    let drifted = body.replace("- action: Post", "- action: Sigkill");
    std::fs::write(&etc, drifted).unwrap();

    let check_bad = Command::new("bash")
        .arg(module_dir().join("install/check.sh"))
        .env("SELFDEF_AGENT_GUARD_CONFIG", &fx.config_path)
        .env("SELFDEF_TETRAGON_CONFIG", &fx.tetragon_config)
        .output()
        .expect("spawn check.sh");
    assert!(!check_bad.status.success(), "drifted check should fail");
    let line = last_stdout_line(&check_bad);
    assert!(line.contains("drift"), "got: {line}");
}

#[test]
fn uninstall_removes_every_module_policy() {
    let fx = fixture("profile = \"audit\"\n");
    run_apply(&fx);
    let names = [
        "etc-write-guard",
        "container-shell-guard",
        "egress-guard",
        "securemessage-guard",
        "gpu-device-guard",
    ];
    for n in names {
        assert!(
            fx.policy_dir
                .join(format!("selfdef-agent-{n}.yaml"))
                .exists(),
            "missing pre-uninstall: {n}",
        );
    }

    let out = Command::new("bash")
        .arg(module_dir().join("install/uninstall.sh"))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_AGENT_GUARD_CONFIG", &fx.config_path)
        .env("SELFDEF_TETRAGON_CONFIG", &fx.tetragon_config)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn uninstall.sh");
    assert!(out.status.success(), "uninstall failed");
    for n in names {
        assert!(
            !fx.policy_dir
                .join(format!("selfdef-agent-{n}.yaml"))
                .exists(),
            "policy still present after uninstall: {n}",
        );
    }
    // policy_dir itself must remain — that's tetragon's, not ours.
    assert!(fx.policy_dir.is_dir());
    // SDD-006 v2 / F-2026-050: the manifest should have been
    // cleared on uninstall.
    assert!(
        !fx.manifest_path.exists(),
        "manifest must be cleared after uninstall",
    );
}

#[test]
fn manifest_records_every_rendered_policy() {
    // SDD-006 v2 / F-2026-050: apply.sh records every rendered
    // file into the manifest so uninstall.sh has a complete
    // list. Verify the manifest contents match what we see on
    // disk.
    let fx = fixture("profile = \"audit\"\n");
    let out = run_apply(&fx);
    assert!(
        out.status.success(),
        "apply failed; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let manifest_body =
        std::fs::read_to_string(&fx.manifest_path).expect("manifest must exist after apply");
    let recorded: std::collections::BTreeSet<&str> =
        manifest_body.lines().filter(|l| !l.is_empty()).collect();
    let on_disk: std::collections::BTreeSet<String> = std::fs::read_dir(&fx.policy_dir)
        .unwrap()
        .map(|e| e.unwrap().path().display().to_string())
        .filter(|p| p.ends_with(".yaml"))
        .collect();
    let recorded_owned: std::collections::BTreeSet<String> =
        recorded.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        recorded_owned, on_disk,
        "manifest does not match on-disk rendered policies",
    );
}

#[test]
fn manifest_deduplicates_across_reapply() {
    // Two apply runs in a row must not duplicate manifest
    // entries (the v2 helper's `grep -Fxq` guard).
    let fx = fixture("profile = \"audit\"\n");
    assert!(run_apply(&fx).status.success());
    let after_first = std::fs::read_to_string(&fx.manifest_path).unwrap();
    assert!(run_apply(&fx).status.success());
    let after_second = std::fs::read_to_string(&fx.manifest_path).unwrap();
    assert_eq!(
        after_first, after_second,
        "manifest must be byte-stable across re-apply",
    );
}

#[test]
fn uninstall_with_no_manifest_falls_back_to_legacy_enum() {
    // Migration path: an operator who upgraded from pre-v2
    // selfdef has rendered policies on disk but no manifest.
    // uninstall.sh's fallback must still clean them up.
    let fx = fixture("profile = \"audit\"\n");
    run_apply(&fx);
    // Wipe the manifest to simulate pre-v2 install state.
    std::fs::remove_file(&fx.manifest_path).unwrap();
    let names = [
        "etc-write-guard",
        "container-shell-guard",
        "egress-guard",
        "securemessage-guard",
        "gpu-device-guard",
    ];
    for n in names {
        assert!(
            fx.policy_dir
                .join(format!("selfdef-agent-{n}.yaml"))
                .exists(),
            "missing pre-uninstall: {n}",
        );
    }

    let out = Command::new("bash")
        .arg(module_dir().join("install/uninstall.sh"))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_AGENT_GUARD_CONFIG", &fx.config_path)
        .env("SELFDEF_TETRAGON_CONFIG", &fx.tetragon_config)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn uninstall.sh");
    assert!(out.status.success(), "uninstall failed");
    for n in names {
        assert!(
            !fx.policy_dir
                .join(format!("selfdef-agent-{n}.yaml"))
                .exists(),
            "policy still present after legacy-fallback uninstall: {n}",
        );
    }
}

// -------------------------------------------------- pod-label scope
//
// Verify that `scope = "pod-label"` rewrites every rendered policy
// to use `matchPodSelector` instead of `matchNamespaces`. The
// container-scope default is regression-tested by the
// audit-profile test above (which still expects the
// matchNamespaces / host_ns shape).

#[test]
fn pod_label_scope_swaps_match_namespaces_for_match_pod_selector() {
    let fx = fixture(
        "profile = \"audit\"\n\
         scope = \"pod-label\"\n\
         pod_label_key = \"selfdef.io/agent\"\n\
         pod_label_value = \"true\"\n",
    );
    let out = run_apply(&fx);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    for name in [
        "etc-write-guard",
        "container-shell-guard",
        "egress-guard",
        "securemessage-guard",
        "gpu-device-guard",
    ] {
        let body = read_policy(&fx, name);
        assert!(!body.is_empty(), "policy {name} not rendered");
        assert!(
            body.contains("matchPodSelector:"),
            "policy {name} did not pick up matchPodSelector:\n{body}",
        );
        assert!(
            body.contains("selfdef.io/agent: \"true\""),
            "policy {name} missing operator label key/value:\n{body}",
        );
        assert!(
            !body.contains("matchNamespaces:"),
            "policy {name} still has matchNamespaces under pod-label scope:\n{body}",
        );
        assert!(
            !body.contains("host_ns"),
            "policy {name} still references host_ns:\n{body}",
        );
    }
}

#[test]
fn container_scope_default_keeps_match_namespaces() {
    // Sanity check: the default scope leaves matchNamespaces in place
    // for every policy. Belt-and-braces alongside the audit / enforce
    // profile tests, which test the same condition implicitly.
    let fx = fixture("profile = \"audit\"\n");
    let out = run_apply(&fx);
    assert!(out.status.success());
    for name in [
        "etc-write-guard",
        "container-shell-guard",
        "egress-guard",
        "securemessage-guard",
        "gpu-device-guard",
    ] {
        let body = read_policy(&fx, name);
        assert!(
            body.contains("matchNamespaces:"),
            "policy {name} lost matchNamespaces under default scope:\n{body}",
        );
        assert!(
            !body.contains("matchPodSelector:"),
            "policy {name} picked up matchPodSelector under default scope:\n{body}",
        );
    }
}

#[test]
fn pod_label_scope_refuses_without_required_keys() {
    let fx = fixture(
        "profile = \"audit\"\n\
         scope = \"pod-label\"\n",
    );
    let out = run_apply(&fx);
    assert!(
        !out.status.success(),
        "should refuse: missing pod_label_key"
    );
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("pod_label_key"),
        "got: {line}",
    );
}

#[test]
fn rejects_invalid_scope_value() {
    let fx = fixture("profile = \"audit\"\nscope = \"weird\"\n");
    let out = run_apply(&fx);
    assert!(!out.status.success(), "should refuse invalid scope");
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("container|pod-label"),
        "got: {line}",
    );
}

#[test]
fn pod_label_scope_preserves_gpu_match_binaries_when_allowlist_set() {
    // The gpu matchBinaries-drop awk anchors on the matchNamespaces
    // line; render_pod_scope runs *after* it, so a non-empty
    // allowlist must still produce a valid policy with both the
    // allowlist and the pod-selector spliced in.
    let fx = fixture(
        "profile = \"audit\"\n\
         scope = \"pod-label\"\n\
         pod_label_key = \"selfdef.io/agent\"\n\
         pod_label_value = \"true\"\n\
         gpu_device_allowlist = \"/usr/local/bin/python3\"\n",
    );
    let out = run_apply(&fx);
    assert!(out.status.success(), "apply failed");
    let body = read_policy(&fx, "gpu-device-guard");
    assert!(
        body.contains("matchBinaries:"),
        "matchBinaries kept under pod-label scope when allowlist is set:\n{body}",
    );
    assert!(
        body.contains("/usr/local/bin/python3"),
        "operator binary missing under pod-label scope:\n{body}",
    );
    assert!(
        body.contains("matchPodSelector:"),
        "pod selector missing:\n{body}",
    );
    assert!(
        !body.contains("matchNamespaces:"),
        "matchNamespaces leaked through pod-label scope:\n{body}",
    );
}

#[test]
fn reapply_is_byte_stable_for_every_rendered_policy() {
    // F-2026-062: idempotent reapply was tested for the tetragon
    // module only. Add the same coverage to agent-guard so a
    // regression that made apply.sh non-deterministic on the same
    // input would fail loudly.
    let fx = fixture(
        "profile = \"audit\"\n\
         egress_allowlist = \"10.0.0.0/24\"\n\
         gpu_device_allowlist = \"/usr/local/bin/python3\"\n",
    );
    let first = run_apply(&fx);
    assert!(first.status.success(), "first apply failed");

    let names = [
        "etc-write-guard",
        "container-shell-guard",
        "egress-guard",
        "securemessage-guard",
        "gpu-device-guard",
    ];
    let snapshot_first: Vec<(String, Vec<u8>)> = names
        .iter()
        .map(|n| {
            let p = fx.policy_dir.join(format!("selfdef-agent-{n}.yaml"));
            (n.to_string(), std::fs::read(&p).unwrap())
        })
        .collect();

    let second = run_apply(&fx);
    assert!(second.status.success(), "second apply failed");

    for (name, before) in &snapshot_first {
        let p = fx.policy_dir.join(format!("selfdef-agent-{name}.yaml"));
        let after = std::fs::read(&p).unwrap();
        assert_eq!(
            before, &after,
            "policy {name} render changed across reapply with identical config",
        );
    }
}

mod common;

/// SDD-005 D-2a / Test-1: dry-run must be a no-op. The
/// apply tests above assert the live-positive paths produce
/// the right rendered output; this asserts the dry-run path
/// mutates nothing on disk under the policy_dir or the
/// manifest path. A regression making dry-run write a policy
/// would have passed silently — every existing test only
/// checked the status JSON.
#[test]
fn dry_run_apply_must_be_a_noop_on_disk() {
    let fx = fixture("profile = \"audit\"\n");
    let scope = fx.policy_dir.parent().unwrap().to_path_buf();
    let before = common::snapshot_tree(&scope);
    let out = Command::new("bash")
        .arg(module_dir().join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_AGENT_GUARD_CONFIG", &fx.config_path)
        .env("SELFDEF_TETRAGON_CONFIG", &fx.tetragon_config)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn apply.sh");
    assert!(
        out.status.success(),
        "dry-run apply must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let after = common::snapshot_tree(&scope);
    common::assert_tree_unchanged(&before, &after);
}
