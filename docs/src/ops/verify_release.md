# Verifying a release

Every selfdef release is published with:

- the `.deb` package and its per-file cosign signature (`.deb.sig`)
- a CycloneDX SBOM and its per-file signature (`.sbom.json.sig`)
- a `SHA256SUMS` manifest of every artifact, with a Sigstore signature
  bundle (`SHA256SUMS.sig` + `SHA256SUMS.pem`)

All signatures are produced via Sigstore **keyless signing** — the cert
chain ties the signature to the GitHub Actions identity that built the
release, so verification gates on *who* built it, not on a long-lived key
that could leak.

## Quickstart: verify with the manifest

The manifest path verifies the whole release with one cosign call.

```bash
TAG=v0.1.0
REPO=cyberpunk042/selfdef

# 1. Download the manifest + signature + cert and the artifacts.
curl -fLO https://github.com/$REPO/releases/download/$TAG/SHA256SUMS
curl -fLO https://github.com/$REPO/releases/download/$TAG/SHA256SUMS.sig
curl -fLO https://github.com/$REPO/releases/download/$TAG/SHA256SUMS.pem
curl -fLO https://github.com/$REPO/releases/download/$TAG/selfdef_${TAG#v}_amd64.deb
curl -fLO https://github.com/$REPO/releases/download/$TAG/selfdef-$TAG.sbom.json

# 2. Verify the signature on the manifest itself.
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp "https://github.com/$REPO/.github/workflows/release.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS

# 3. Verify the artifacts match the manifest.
sha256sum -c SHA256SUMS
```

If step 2 fails, the manifest is not from this repo's release workflow —
do not install. If step 3 fails, an artifact was modified after signing.

## Per-file verification

Each `.deb` and `.sbom.json` is also individually signed:

```bash
cosign verify-blob \
  --signature selfdef_${TAG#v}_amd64.deb.sig \
  --certificate-identity-regexp "https://github.com/$REPO/.github/workflows/release.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  selfdef_${TAG#v}_amd64.deb
```

## Reproducible builds

Release builds set:

- `SOURCE_DATE_EPOCH` to the tagged commit's author timestamp
- `--remap-path-prefix` to strip the runner's `$GITHUB_WORKSPACE` and
  `$CARGO_HOME` from embedded paths
- `[profile.release] codegen-units = 1` + `strip = "symbols"` +
  `panic = "abort"` (see `Cargo.toml`)
- `CARGO_BUILD_INCREMENTAL=false`

The intent: given the same source revision and the same Rust toolchain
(`rust-toolchain.toml` pins this), two independent builders should
produce byte-identical `.deb` artifacts. Verifying this end-to-end is on
the roadmap as a CI job that rebuilds and `diffoscope`s the result.

## Dependency review (cargo-vet)

The `supply-chain/` directory holds the cargo-vet policy. New
dependencies (or version bumps of existing ones) should be reviewed and
certified via `cargo vet certify` before they land. The weekly `audit`
workflow runs `cargo vet` and surfaces any uncertified diffs.
