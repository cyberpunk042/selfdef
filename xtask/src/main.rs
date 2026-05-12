//! Build helper. Standard cargo doesn't know how to build the BPF crate
//! because it lives outside the main workspace and targets `bpfel-unknown-none`.
//! This task drives that build.
//!
//! Usage:
//!   cargo xtask build-bpf            # debug build
//!   cargo xtask build-bpf --release  # optimized
//!   cargo xtask install-bpf [path]   # copy to /usr/lib/selfdef (or custom)

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

const EBPF_CRATE_DIR: &str = "bpf/selfdef-bpf";
const BPF_TARGET: &str = "bpfel-unknown-none";
const BIN_NAME: &str = "selfdef-bpf";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("build-bpf") => build_bpf(&args[1..]),
        Some("install-bpf") => install_bpf(&args[1..]),
        Some(other) => {
            eprintln!("unknown task: {other}");
            usage();
            std::process::exit(2);
        }
        None => {
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    eprintln!("usage: cargo xtask <task>");
    eprintln!();
    eprintln!("tasks:");
    eprintln!("  build-bpf [--release]      Compile the BPF programs to bpfel-unknown-none.");
    eprintln!("  install-bpf [<dest>]       Copy the compiled object to <dest>");
    eprintln!("                             (default: /usr/lib/selfdef/selfdef.bpf.o).");
    eprintln!();
    eprintln!("prerequisites (run once):");
    eprintln!("  rustup toolchain install nightly");
    eprintln!("  rustup component add rust-src --toolchain nightly");
    eprintln!("  cargo +nightly install bpf-linker");
}

fn build_bpf(args: &[String]) -> Result<()> {
    let release = args.iter().any(|s| s == "--release");

    let mut cmd = Command::new("cargo");
    cmd.arg("+nightly")
        .arg("build")
        .arg("--manifest-path")
        .arg(format!("{EBPF_CRATE_DIR}/Cargo.toml"))
        .arg("--target")
        .arg(BPF_TARGET)
        .arg("-Z")
        .arg("build-std=core");
    if release {
        cmd.arg("--release");
    }

    eprintln!("→ {cmd:?}");
    let status = cmd.status().context("invoking cargo for BPF build")?;
    if !status.success() {
        bail!("BPF build failed: {status:?}");
    }

    let profile = if release { "release" } else { "debug" };
    let out = PathBuf::from(EBPF_CRATE_DIR)
        .join("target")
        .join(BPF_TARGET)
        .join(profile)
        .join(BIN_NAME);
    if !out.exists() {
        bail!("expected BPF artifact at {} not found", out.display());
    }
    println!("{}", out.display());
    Ok(())
}

fn install_bpf(args: &[String]) -> Result<()> {
    let dest = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/lib/selfdef/selfdef.bpf.o"));

    // Reuse build-bpf to ensure we install the latest --release artifact.
    build_bpf(&["--release".to_string()])?;
    let source = PathBuf::from(EBPF_CRATE_DIR)
        .join("target")
        .join(BPF_TARGET)
        .join("release")
        .join(BIN_NAME);

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir -p {}", parent.display()))?;
    }
    std::fs::copy(&source, &dest)
        .with_context(|| format!("cp {} -> {}", source.display(), dest.display()))?;
    eprintln!("installed → {}", dest.display());
    Ok(())
}
