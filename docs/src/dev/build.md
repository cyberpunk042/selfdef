# Building from source

## Prerequisites

- Rust toolchain pinned by `rust-toolchain.toml` at the repo root
  (`rustup` will pick it up automatically; CI uses the same version).
- A C toolchain (`build-essential` on Debian/Ubuntu) for native deps
  pulled in by `rusqlite` (bundled SQLite) and the eBPF builds.
- For the eBPF crate (`bpf/selfdef-bpf`), a recent `bpf-linker` —
  see [the eBPF build doc](./ebpf.md) for the exact incantation.

## Workspace build

```bash
# Format / lint / test before pushing.
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo deny check
cargo audit
```

The full test suite is hermetic — every integration test stages
its own tempdir fixture; no host state required.

## Release build

```bash
cargo build --release --locked
```

Release builds are reproducible in CI: see
[`ops/verify_release.md`](../ops/verify_release.md) for the
`SOURCE_DATE_EPOCH`, `--remap-path-prefix`, and codegen-units
settings the release pipeline applies.

## Packaging the .deb

```bash
cargo install cargo-deb        # one-time
cargo deb -p selfdef-daemon
```

Output lands under `target/debian/`. Install with
`sudo dpkg -i ...`; the `postinst` (`packaging/debian/postinst`)
creates the `selfdef:selfdef` user, the state / config / secrets
directories, and copies `config/selfdef.toml.example` to
`/etc/selfdef/selfdef.toml` if no config exists yet.

## Iterating on a single crate

```bash
cargo test -p selfdef-cli                # one crate
cargo test -p selfdef-cli --test module_agent_guard
```

The CLI integration tests under `crates/selfdef-cli/tests/`
spawn `bash` on the modules' `install/*.sh` scripts in
hermetic tempdirs; running them locally requires `bash`,
`sha256sum`, `diff`, plus whatever the specific module
script declares as `requires` (see each module's
`module.toml`).

## Running the daemon outside systemd

For local dev you can run `selfdefd` directly:

```bash
SELFDEF_CONFIG=./local-selfdef.toml \
  cargo run -p selfdef-daemon --release
```

A minimal local config is one TOML file with a writable
`[store].hot_path`. Everything else defaults to safe-off.
