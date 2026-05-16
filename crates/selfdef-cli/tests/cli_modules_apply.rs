//! End-to-end integration test for `selfdefctl modules apply` and friends.
//!
//! Builds a hermetic catalog of two stub modules in a tempdir, writes
//! a host config that activates both, then runs the binary with
//! `--host-config` + `--dir` overrides. Exercises the CLI from the
//! same surface an operator uses.

use std::path::Path;
use std::process::Command;

// F-2027-051: helpers live in common/mod.rs.
mod common;
use common::write_executable;

fn binary() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is populated by cargo for integration tests.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn write_module(catalog: &Path, slug: &str, deps: &[&str], apply_body: &str) {
    write_module_full(catalog, slug, deps, /*instanced*/ false, apply_body);
}

fn write_module_full(catalog: &Path, slug: &str, deps: &[&str], instanced: bool, apply_body: &str) {
    let depline = if deps.is_empty() {
        String::new()
    } else {
        let q: Vec<String> = deps.iter().map(|d| format!("\"{d}\"")).collect();
        format!("depends_on = [{}]\n", q.join(", "))
    };
    let inst = if instanced { "instanced = true\n" } else { "" };
    let manifest = format!(
        "name = \"{slug}\"\nversion = \"0.0.0\"\nsummary = \"stub\"\ncategory = \"test\"\n{inst}{depline}\n[install]\nkind = \"script\"\napply = \"install/apply.sh\"\ncheck = \"install/check.sh\"\n"
    );
    std::fs::create_dir_all(catalog.join(slug)).unwrap();
    std::fs::write(catalog.join(slug).join("module.toml"), manifest).unwrap();
    write_executable(&catalog.join(slug).join("install/apply.sh"), apply_body);
    let check = format!(
        "#!/usr/bin/env bash\necho '{{\"module\":\"{slug}\",\"status\":\"ok\",\"message\":\"check ok\"}}'\n"
    );
    write_executable(&catalog.join(slug).join("install/check.sh"), &check);
}

struct Fixture {
    _root: tempfile::TempDir,
    catalog: std::path::PathBuf,
    host_config: std::path::PathBuf,
}

fn fixture(host_body: &str) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();

    // alpha (no deps); beta depends on alpha. Both emit "ok" so apply
    // and check are happy.
    let body_alpha = "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"alpha applied\"}'\n";
    let body_beta = "#!/usr/bin/env bash\necho '{\"module\":\"beta\",\"status\":\"ok\",\"message\":\"beta applied\"}'\n";
    write_module(&catalog, "alpha", &[], body_alpha);
    write_module(&catalog, "beta", &["alpha"], body_beta);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, host_body).unwrap();

    Fixture {
        _root: root,
        catalog,
        host_config,
    }
}

fn run(bin: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        // Use any config file we don't depend on — `--config` is the
        // global flag; pass /dev/null so the daemon config loader
        // doesn't refuse.
        .arg("--config")
        .arg("/dev/null")
        .args(args)
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn apply_runs_modules_in_dependency_order() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Alpha must appear before beta.
    let i_alpha = stdout.find("alpha [apply]").expect("alpha line");
    let i_beta = stdout.find("beta [apply]").expect("beta line");
    assert!(i_alpha < i_beta, "alpha did not run before beta:\n{stdout}");
    assert!(stdout.contains("Summary: 2 ok"), "stdout: {stdout}");
}

#[test]
fn apply_only_filter_skips_excluded_modules() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
            "--only",
            "alpha",
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("alpha [apply]"));
    assert!(!stdout.contains("beta [apply]"), "stdout: {stdout}");
}

#[test]
fn check_reports_ok_for_active_modules() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    let out = run(
        &binary(),
        &[
            "modules",
            "check",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("Summary: 2 ok"), "stdout: {stdout}");
}

#[test]
fn apply_returns_nonzero_when_any_module_fails() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    // Overwrite beta's apply.sh to fail.
    let bad = "#!/usr/bin/env bash\necho '{\"module\":\"beta\",\"status\":\"failed\",\"message\":\"boom\"}'\nexit 1\n";
    write_executable(&fx.catalog.join("beta/install/apply.sh"), bad);

    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
            "--dry-run",
        ],
    );
    assert!(
        !out.status.success(),
        "should exit non-zero on module failure"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Summary: 1 ok, 0 skipped, 1 failed"),
        "stdout: {stdout}"
    );
}

#[test]
fn empty_host_config_is_a_noop() {
    let fx = fixture(""); // no [modules.*] sections
    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Applying 0 module(s)"), "stdout: {stdout}");
}

#[test]
fn apply_runs_multiple_instances_of_a_multi_instance_module() {
    // Two instances of the same `multi` module run in alphabetical
    // order. Each instance gets its own SELFDEF_MULTI_CONFIG path
    // (defaulting to /etc/selfdef/modules/multi.<instance>.toml,
    // overridable per host entry).
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();

    // The stub echoes whichever config path it received, so we can
    // assert each instance is invoked with the expected env var.
    let body = "#!/usr/bin/env bash\necho \"{\\\"module\\\":\\\"multi\\\",\\\"status\\\":\\\"ok\\\",\\\"message\\\":\\\"$SELFDEF_MULTI_CONFIG\\\"}\"\n";
    write_module_full(&catalog, "multi", &[], /*instanced*/ true, body);

    let host_config = root.path().join("modules.toml");
    let tunnel_cfg = root.path().join("tunnel.toml");
    let publish_cfg = root.path().join("publish.toml");
    std::fs::write(&tunnel_cfg, "x = 1\n").unwrap();
    std::fs::write(&publish_cfg, "x = 2\n").unwrap();
    std::fs::write(
        &host_config,
        format!(
            "[modules.\"multi#tunnel\"]\nconfig = \"{}\"\n[modules.\"multi#publish\"]\nconfig = \"{}\"\n",
            tunnel_cfg.display(),
            publish_cfg.display(),
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_selfdefctl"))
        .args([
            "--config",
            "/dev/null",
            "modules",
            "apply",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Both instances show in alphabetical order — publish before tunnel.
    let i_pub = stdout.find("multi#publish").expect("publish line");
    let i_tun = stdout.find("multi#tunnel").expect("tunnel line");
    assert!(
        i_pub < i_tun,
        "expected multi#publish before multi#tunnel:\n{stdout}"
    );
    // Each instance got its instance-specific config path on stdout.
    assert!(
        stdout.contains(publish_cfg.to_str().unwrap()),
        "stdout did not mention publish cfg: {stdout}"
    );
    assert!(
        stdout.contains(tunnel_cfg.to_str().unwrap()),
        "stdout did not mention tunnel cfg: {stdout}"
    );
    assert!(stdout.contains("Summary: 2 ok"), "stdout: {stdout}");
}

/// SD-R14 + SD-R16: end-to-end gate exercise via the CLI surface.
///
/// alpha is unrestricted, beta declares `memory_gib_min = 9_999_999`
/// (no real host will ever have ~10 PiB of RAM). Apply must keep
/// alpha and skip beta with the SD-R14 stderr block — and the apply
/// summary must reflect 1 ok, not 2.
#[test]
fn sdr16_apply_skips_modules_unmet_hardware_requirements_e2e() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();

    let body = "#!/usr/bin/env bash\necho '{\"module\":\"$slug\",\"status\":\"ok\",\"message\":\"applied\"}'\n";
    let body_alpha = body.replace("$slug", "alpha");
    let body_beta = body.replace("$slug", "beta");

    // alpha: ordinary unrestricted stub.
    write_module(&catalog, "alpha", &[], &body_alpha);

    // beta: same shape but with an unmeetable [requires_hardware]
    // block patched into module.toml after write_module's standard
    // manifest write.
    write_module(&catalog, "beta", &[], &body_beta);
    let beta_toml = catalog.join("beta/module.toml");
    let mut manifest = std::fs::read_to_string(&beta_toml).unwrap();
    manifest.push_str("\n[requires_hardware]\nmemory_gib_min = 9999999\n");
    std::fs::write(&beta_toml, manifest).unwrap();

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n[modules.beta]\n").unwrap();

    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "rc={:?}\nstdout: {stdout}\nstderr: {stderr}",
        out.status.code(),
    );
    // The gate skip block lands on stderr (SD-R14 contract).
    assert!(
        stderr.contains("SD-R14 hardware-aware module gate"),
        "gate banner missing on stderr: {stderr}"
    );
    assert!(
        stderr.contains("beta"),
        "beta should appear in skip block: {stderr}"
    );
    assert!(
        stderr.contains("memory_gib_min = 9999999"),
        "predicate citation missing: {stderr}"
    );
    // Apply path only runs the kept set.
    assert!(
        stdout.contains("alpha [apply]"),
        "alpha must still apply: {stdout}"
    );
    assert!(
        !stdout.contains("beta [apply]"),
        "beta should not have applied: {stdout}"
    );
    assert!(
        stdout.contains("Summary: 1 ok"),
        "summary count wrong: {stdout}"
    );
}

/// SD-R14 + SD-R15: `modules check-hardware` returns rc=0 and the
/// human + JSON outputs partition correctly when invoked against the
/// same hard-to-meet fixture used above.
#[test]
fn sdr16_check_hardware_e2e_human_and_json() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let stub =
        "#!/usr/bin/env bash\necho '{\"module\":\"x\",\"status\":\"ok\",\"message\":\"\"}'\n";
    write_module(&catalog, "alpha", &[], stub);
    write_module(&catalog, "beta", &[], stub);
    let beta_toml = catalog.join("beta/module.toml");
    let mut manifest = std::fs::read_to_string(&beta_toml).unwrap();
    manifest.push_str("\n[requires_hardware]\nmemory_gib_min = 9999999\n");
    std::fs::write(&beta_toml, manifest).unwrap();

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n[modules.beta]\n").unwrap();

    // Human-readable.
    let out = run(
        &binary(),
        &[
            "modules",
            "check-hardware",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("WOULD APPLY"), "stdout: {stdout}");
    assert!(stdout.contains("WOULD SKIP"), "stdout: {stdout}");
    assert!(stdout.contains("alpha"), "stdout: {stdout}");
    assert!(stdout.contains("beta"), "stdout: {stdout}");

    // JSON.
    let out = run(
        &binary(),
        &[
            "modules",
            "check-hardware",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--json",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("\"kept\":"), "stdout: {stdout}");
    assert!(stdout.contains("\"skipped\":"), "stdout: {stdout}");
    assert!(stdout.contains("\"beta\""), "stdout: {stdout}");
}

/// SD-R39: `selfdefctl modules info <slug> --with-host-status`
/// probes the host and surfaces the gate verdict inline.
#[test]
fn sdr39_modules_info_with_host_status_surfaces_gate_verdict() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let stub =
        "#!/usr/bin/env bash\necho '{\"module\":\"x\",\"status\":\"ok\",\"message\":\"\"}'\n";
    write_module(&catalog, "ungated", &[], stub);
    write_module(&catalog, "gated-unmeetable", &[], stub);
    let m_toml = catalog.join("gated-unmeetable/module.toml");
    let mut manifest = std::fs::read_to_string(&m_toml).unwrap();
    manifest.push_str("\n[requires_hardware]\nmemory_gib_min = 9999999\n");
    std::fs::write(&m_toml, manifest).unwrap();

    // Ungated module → "applies on any host" green tick
    let out = run(
        &binary(),
        &[
            "modules",
            "info",
            "ungated",
            "--dir",
            catalog.to_str().unwrap(),
            "--with-host-status",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("host_status:"), "header missing: {stdout}");
    assert!(
        stdout.contains("applies on any host"),
        "expected pass-through: {stdout}"
    );

    // Gated module with unmeetable predicate → "X predicate(s) unmet"
    let out = run(
        &binary(),
        &[
            "modules",
            "info",
            "gated-unmeetable",
            "--dir",
            catalog.to_str().unwrap(),
            "--with-host-status",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("host_status:"), "header missing: {stdout}");
    assert!(
        stdout.contains("predicate(s) unmet"),
        "unmet count missing: {stdout}"
    );
    assert!(
        stdout.contains("memory_gib_min = 9999999"),
        "predicate detail missing: {stdout}"
    );
}

/// SD-R38: `selfdefctl modules check-hardware --caps <path>` reads
/// a saved HardwareCapabilities JSON instead of probing. Operators
/// preview "would this catalog land on a SAIN-01 box?" from a dev
/// workstation.
#[test]
fn sdr38_check_hardware_with_caps_dry_runs_against_saved_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let stub =
        "#!/usr/bin/env bash\necho '{\"module\":\"x\",\"status\":\"ok\",\"message\":\"\"}'\n";
    write_module(&catalog, "needs-big-vram", &[], stub);
    let m_toml = catalog.join("needs-big-vram/module.toml");
    let mut manifest = std::fs::read_to_string(&m_toml).unwrap();
    manifest.push_str("\n[requires_hardware]\ngpu_vram_gib_min = 64\n");
    std::fs::write(&m_toml, manifest).unwrap();
    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.needs-big-vram]\n").unwrap();

    // Synthesized SAIN-01-shaped caps: RTX PRO 6000 with 98 GiB
    // VRAM passes the gate.
    let caps_path = root.path().join("sain01.caps.json");
    std::fs::write(
        &caps_path,
        r#"{
            "schema_version": "1.2.0",
            "probed_at": "2026-05-16T00:00:00Z",
            "host_tag": null,
            "cpu": {"vendor":"AuthenticAMD","model_name":"AMD Ryzen 9 9900X",
              "physical_cores":12,"logical_threads":24,
              "sse4_2":true,"avx":true,"avx2":true,"fma":true,
              "avx512f":true,"avx512dq":true,"avx512bw":true,"avx512vl":true,
              "avx512vnni":true,"avx512bf16":true,"avx512fp16":true,
              "avx512vbmi":true,"avx512vbmi2":true,
              "recommended_march":"znver5","recommended_compile_flags":[]},
            "memory":{"total_bytes":274877906944,"at_least_256gb":true,"at_least_512gb":false},
            "gpu":{"device_count":1,"device_nodes":[],"devices":[
              {"vram_bytes":105226698752,"power_limit_watts":600,"power_draw_watts":275,
               "model_hint":"NVIDIA RTX PRO 6000 Blackwell"}
            ]},
            "pcie":{"gen4_or_higher_x8_slot_count":2,"dual_x8_present":true},
            "sain01_match":{"overall":"FullMatch","cpu_avx512_vnni":true,
              "cpu_avx512_bf16":true,"memory_at_least_256gb":true,
              "gpu_count_at_least_2":false,"motherboard_proart_x870e":null,
              "pcie_dual_x8_present":true},
            "wasm_aot":{"target_triple":"x86_64-unknown-linux-gnu","target_cpu":"znver5",
              "target_features":"+avx512f,+avx2,+fma","compile_command_hint":""}
        }"#,
    )
    .unwrap();

    // With --caps: SAIN-01 snapshot → module passes.
    let out = run(
        &binary(),
        &[
            "modules",
            "check-hardware",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--caps",
            caps_path.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("WOULD APPLY"), "stdout: {stdout}");
    assert!(
        stdout.contains("needs-big-vram"),
        "module name missing: {stdout}"
    );
    assert!(
        !stdout.contains("WOULD SKIP"),
        "module should pass under saved SAIN-01 caps: {stdout}"
    );
    // HOST SNAPSHOT block reflects the loaded JSON, not the test
    // runner's actual host.
    assert!(stdout.contains("AMD Ryzen 9 9900X"), "{stdout}");
    assert!(stdout.contains("256 GiB"), "{stdout}");
}

/// SD-R36: `selfdefctl modules graph` emits Graphviz DOT.
/// Plain mode (no --with-hardware-gate): nodes have just a label,
/// dependency arrows draw active dep edges only.
#[test]
fn sdr36_modules_graph_emits_valid_dot_dependencies() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    let out = run(
        &binary(),
        &[
            "modules",
            "graph",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("// SD-R36: selfdefctl modules graph"),
        "header missing: {stdout}"
    );
    assert!(stdout.contains("digraph selfdef_modules {"), "{stdout}");
    assert!(stdout.contains("\"alpha\""), "{stdout}");
    assert!(stdout.contains("\"beta\""), "{stdout}");
    // beta depends on alpha in fixture() → DOT direction alpha → beta.
    assert!(
        stdout.contains("\"alpha\" -> \"beta\""),
        "dependency arrow missing: {stdout}"
    );
}

/// SD-R36 with --with-hardware-gate: nodes get fillcolor by SD-R14
/// verdict; unmeetable predicates become tooltips.
#[test]
fn sdr36_modules_graph_with_hardware_gate_color_codes_nodes() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let stub =
        "#!/usr/bin/env bash\necho '{\"module\":\"x\",\"status\":\"ok\",\"message\":\"\"}'\n";
    write_module(&catalog, "alpha", &[], stub);
    write_module(&catalog, "beta", &[], stub);
    // beta declares an unmeetable mem requirement.
    let beta_toml = catalog.join("beta/module.toml");
    let mut manifest = std::fs::read_to_string(&beta_toml).unwrap();
    manifest.push_str("\n[requires_hardware]\nmemory_gib_min = 9999999\n");
    std::fs::write(&beta_toml, manifest).unwrap();
    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n[modules.beta]\n").unwrap();

    let out = run(
        &binary(),
        &[
            "modules",
            "graph",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--with-hardware-gate",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("SD-R14 hardware gate: ON"),
        "gate banner missing: {stdout}"
    );
    // alpha has no [requires_hardware] → lightblue (default keep
    // colour for ungated modules).
    assert!(
        stdout.contains("\"alpha\" [label=\"alpha\", style=filled, fillcolor=lightblue"),
        "alpha colour wrong: {stdout}"
    );
    // beta requires 10 PiB → lightcoral (skipped).
    assert!(
        stdout.contains("\"beta\" [label=\"beta\", style=filled, fillcolor=lightcoral"),
        "beta colour wrong: {stdout}"
    );
    // Tooltip carries the predicate.
    assert!(
        stdout.contains("tooltip=\"memory_gib_min = 9999999"),
        "tooltip missing: {stdout}"
    );
}

/// SD-R35: `selfdefctl modules info <slug>` prints the
/// [requires_hardware] block when present — operators inspecting a
/// module see EVERY predicate the gate will enforce, without
/// running the probe.
#[test]
fn sdr35_modules_info_surfaces_requires_hardware_block() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(catalog.join("hw-gated")).unwrap();
    std::fs::create_dir_all(catalog.join("plain")).unwrap();
    // hw-gated declares 4 predicates; plain has no block.
    std::fs::write(
        catalog.join("hw-gated/module.toml"),
        r#"
name = "hw-gated"
version = "0.0.0"
summary = "fixture with hardware gate"
category = "test"
[requires_hardware]
avx512_vnni                = true
avx512_bf16                = true
gpu_vram_gib_min           = 8
wasm_aot_features_required = "+avx512vnni"
"#,
    )
    .unwrap();
    std::fs::write(
        catalog.join("plain/module.toml"),
        "name = \"plain\"\nversion = \"0.0.0\"\nsummary = \"no gate\"\n",
    )
    .unwrap();

    // hw-gated → block present, every set predicate cited
    let out = run(
        &binary(),
        &[
            "modules",
            "info",
            "hw-gated",
            "--dir",
            catalog.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("requires_hardware:"),
        "missing header: {stdout}"
    );
    assert!(stdout.contains("avx512_vnni = true"), "{stdout}");
    assert!(stdout.contains("avx512_bf16 = true"), "{stdout}");
    assert!(stdout.contains("gpu_vram_gib_min = 8"), "{stdout}");
    assert!(stdout.contains("wasm_aot_features_required"), "{stdout}");

    // plain → no block, no header
    let out = run(
        &binary(),
        &[
            "modules",
            "info",
            "plain",
            "--dir",
            catalog.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        !stdout.contains("requires_hardware:"),
        "block should be omitted on plain module: {stdout}"
    );
}

/// SD-R27: the human output of `modules check-hardware` carries a
/// HOST SNAPSHOT block surfacing the probed CPU/memory/GPU/sain01
/// figures so operators see WHY a gate fired without separately
/// running `selfdefctl hardware probe`. JSON adds a `host_snapshot`
/// field with the full HardwareCapabilities object.
#[test]
fn sdr27_check_hardware_human_includes_host_snapshot_block() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let stub =
        "#!/usr/bin/env bash\necho '{\"module\":\"a\",\"status\":\"ok\",\"message\":\"\"}'\n";
    write_module(&catalog, "alpha", &[], stub);
    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n").unwrap();

    let out = run(
        &binary(),
        &[
            "modules",
            "check-hardware",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("HOST SNAPSHOT"),
        "snapshot block missing: {stdout}"
    );
    assert!(
        stdout.contains("CPU      :"),
        "CPU summary missing: {stdout}"
    );
    assert!(
        stdout.contains("Memory   :"),
        "memory summary missing: {stdout}"
    );
    assert!(
        stdout.contains("GPUs     :"),
        "GPU summary missing: {stdout}"
    );
    assert!(
        stdout.contains("Sain01   :"),
        "Sain01 summary missing: {stdout}"
    );
}

#[test]
fn sdr27_check_hardware_json_carries_host_snapshot_field() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let stub =
        "#!/usr/bin/env bash\necho '{\"module\":\"a\",\"status\":\"ok\",\"message\":\"\"}'\n";
    write_module(&catalog, "alpha", &[], stub);
    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n").unwrap();

    let out = run(
        &binary(),
        &[
            "modules",
            "check-hardware",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--json",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    // Parse to make sure it's valid JSON and carries the expected
    // top-level keys.
    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("invalid JSON: {e}\n{stdout}"));
    assert!(v.get("host_snapshot").is_some(), "missing host_snapshot");
    let snap = &v["host_snapshot"];
    assert!(snap.get("cpu").is_some(), "snapshot missing cpu");
    assert!(snap.get("memory").is_some(), "snapshot missing memory");
    assert!(snap.get("gpu").is_some(), "snapshot missing gpu");
    assert!(
        snap.get("sain01_match").is_some(),
        "snapshot missing sain01_match"
    );
    // SD-R25 forward-compat: the per-device array shape lands inside.
    assert!(
        snap["gpu"].get("devices").is_some(),
        "snapshot.gpu missing devices array"
    );
}

#[test]
fn apply_rejects_instance_keys_against_non_instanced_module() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let body =
        "#!/usr/bin/env bash\necho '{\"module\":\"single\",\"status\":\"ok\",\"message\":\"\"}'\n";
    write_module_full(&catalog, "single", &[], /*instanced*/ false, body);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.\"single#a\"]\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_selfdefctl"))
        .args([
            "--config",
            "/dev/null",
            "modules",
            "apply",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    assert!(!out.status.success(), "should refuse non-instanced module");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not declared `instanced = true`"),
        "stderr: {stderr}"
    );
}
