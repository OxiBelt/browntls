# Maintenance

## Current baseline

browntls has a Cargo workspace (`browntls-crypto`, `browntls-pki`, `browntls`,
`browntls-tokio`, `browntls-ktls`, and the unpublished test tools `browntls-e2e` and `browntls-entropy`) described in
[Architecture](Architecture.md), with no published releases. The
[contributor guide](../CONTRIBUTING.md) owns workflow and commit rules; the
[security policy](../SECURITY.md) owns disclosure and support.

These conventions adapt [OxiBelt](https://github.com/OxiBelt/OxiBelt)'s separation
of contributor policy, agent orientation, technical documentation, and evidence.
They do not import its proxy, WAF, image, or beta-promotion contracts.

## Routine maintenance

Review dependency and GitHub Actions updates weekly. Dependabot covers GitHub
Actions, the Cargo workspace, and the digest-pinned base images of the
[Docker end-to-end](../tests/e2e/README.md) peers. Those peers install the
distribution's current OpenSSL and GnuTLS packages when built, so their exact
versions can change between runs; each job summary records them. Review generated changes before merging; there
is no automatic merge policy.

Run repository checks for every change. Review weekly scheduled failures, update
documentation when tools or workflows change, and report unrun checks accurately.
Use independent qualified batches rather than letting an unrelated blocker hide
completed work. Keep exact deferred versions, reasons, owners, and tracking issues.

Pin third-party Actions to full commit SHAs with release comments. Pin downloaded
tools to explicit versions and verified SHA-256 checksums from official upstream
releases. Review workflow permissions and PR input handling; do not expose secrets
or use privileged PR execution for untrusted changes.

GitHub private vulnerability reporting must be enabled before advertising its
reporting link. Recheck it after repository setting changes. Hosted branch rules
and other security features require a separate decision; these documents do not
claim they are configured.

## Rust workspace requirements

The workspace was introduced with the toolchain pin (now Rust 1.100.0, also the
MSRV), a committed `Cargo.lock` used with `--locked`, format/Clippy/test/doc
CI, QEMU and native multi-architecture test jobs, `no_std` builds, and
`cargo deny` (advisories, licenses, bans, sources) with a checksum-pinned
binary. `cargo deny` reads the same RustSec database as `cargo audit`; a
separate `cargo audit` job is not added because no upstream-published checksum
is available for its release binaries. Outstanding items are tracked in the
[roadmap](Roadmap.md#governance-gaps): `cargo vet` admission, continuous
fuzzing, and named independent review of `unsafe` code and cryptography.

### Independent manifests and lockfiles

| Manifest | Lockfile | Checked by |
|---|---|---|
| `Cargo.toml` (workspace) | `Cargo.lock` | Every Rust CI job with `--locked`; `cargo deny` |
| `fuzz/Cargo.toml` (cargo-fuzz project, outside the workspace) | `fuzz/Cargo.lock` | The stable fuzz-harness CI job and the Fuzz workflow with `--locked`; `cargo deny` with the same `deny.toml` |

Dependabot covers both. The fuzz project's extra dependencies (`libfuzzer-sys`
and its build-time `cc`, `arbitrary`, `rcgen`, and the RustCrypto crates the
crypto targets use as differential oracles, the same set as
`browntls-crypto`'s dev-dependencies) are development tooling:
`safe-to-run` is the bar once `cargo vet` is adopted. `libfuzzer-sys` carries
LLVM's libFuzzer (C++, NCSA licence), which `deny.toml` admits for the exact
locked version of that crate only; the exception is due for review by
2027-05-15 and has to be revisited whenever the version changes.

### Optional compression dependencies

The `zlib`, `brotli` and `zstd` features of `browntls` pull in `miniz_oxide`
(with `adler2`), `brotli` (with `brotli-decompressor`, `alloc-no-stdlib`,
`alloc-stdlib`) and `ruzstd`. All are pure Rust from crates.io, have no build
script and no native code, and carry licences already on the allow list. As
used here, `miniz_oxide`, `adler2`, `brotli-decompressor` and the two `alloc-*`
crates forbid `unsafe`, and the `brotli` encoder has none outside its
unused FFI module; `ruzstd` contains `unsafe` in its decoder ring buffer. They
parse peer-controlled data during the handshake, so they are runtime
dependencies (`safe-to-deploy`), are reached only when a feature is enabled,
and run under the length limits described in
[Architecture](Architecture.md#certificate-compression-rfc-8879) and under the
`cert_decompress` fuzz target. None has a `cargo vet` audit yet.

### Tokio dependency

The workspace requires `tokio` 1.53 or later (`[workspace.dependencies]` in
the root manifest; the fuzz project repeats the bound). The lower bound is the
newest of Tokio's long-term support lines, which receive backported fixes for
at least a year: 1.53.x is supported until September 2027 (1.51.x until March
2027; 1.47.x ended in September 2026). Raise the bound when Tokio names a
newer LTS line, and before the line it names ends. `Cargo.lock` holds the
newest release, so CI's `Tokio lower bound` job also builds and tests
`browntls-tokio` and `browntls-ktls` (its `tokio` feature) against the first
release of the bound.

`browntls-tokio` uses `tokio`'s I/O traits (`AsyncRead`, `AsyncWrite`,
`AsyncBufRead`, `ReadBuf`), which need no `tokio` feature, and the runtime is
the application's. Its default `coop` feature enables `tokio`'s `rt` feature
for the task budget (`tokio::task::coop`); `rt` compiles the runtime's code
but adds no dependency. Either build of `tokio` pulls in
`pin-project-lite` only (MIT, and Apache-2.0 OR MIT); both are pure Rust, and `tokio`
contains `unsafe` code (none of it reached by browntls data parsing, which
stays in `browntls`). It is a runtime dependency (`safe-to-deploy`) of
`browntls-tokio`, and of `browntls-ktls` with its `tokio` feature (below),
with no `cargo vet` audit yet. The test-only
features (`rt`, `rt-multi-thread`, `macros`, `net`, `io-util`, `time`,
`test-util`, adding `mio`, `socket2`,
`bytes` and `tokio-macros`) and `tokio-rustls` with rustls's `ring` provider
are dev-dependencies (`safe-to-run`). The optional `tokio` feature of
`browntls-ktls` (`AsyncKtlsStream`, Linux only) enables Tokio's `net`, which
adds `mio` (MIT) and `socket2` (MIT OR Apache-2.0), both on `libc`, as runtime dependencies of
that feature alone, also without a `cargo vet` audit yet. `browntls-ktls`
itself depends on `libc` (MIT OR Apache-2.0, Linux only, without default
features) for its kernel TLS system calls (`src/sys.rs`), a runtime
dependency whatever its features, also without a `cargo vet` audit yet.
Each of the two crates' manifests carries the
metadata a crates.io release needs (description, documentation, readme,
keywords, categories, an `include` list and the licence file), but they
stay `publish = false` with the rest of the workspace until the release
prerequisites below are met.

### Fuzzing

[`fuzz/`](../fuzz/README.md) holds cargo-fuzz targets for the handshake
message codecs, the record deframer, certificate decompression, PEM, X.509
path validation, CRLs and the client and server connections, and one target
per topic of the public API, which together must reach every public function
of the library crates (checked in CI by `scripts/fuzz/api_coverage.py`; the
few exemptions are listed with their reasons in
`fuzz/api-coverage-exemptions.txt`). CI builds the harnesses with the pinned
stable toolchain and runs them over generated seeds; the Fuzz workflow fuzzes
the targets as a matrix with a pinned nightly toolchain: briefly on pull
requests for the targets whose sources changed, and daily for twenty minutes
per target and architecture, keeping corpora in the Actions cache. The nightly
toolchain and `cargo-fuzz` versions are pinned in the workflow and upgraded
explicitly. Longer campaigns are still run by hand and recorded with the
change they support: revision, toolchain, targets, duration and outcome. A
crash is handled as a potential vulnerability under
[SECURITY.md](../SECURITY.md); inputs and reports go to the private evidence
repository below, never to public issues, logs or CI artifacts, which is why
a failing CI job prints only the target, the kind of finding and the input's
hash, and saves no corpus to the Actions cache, which pull requests can read
(the failing input may be a corpus entry).

The original prerequisites, which remain the bar for each new crate or
boundary:

- Public purpose and layout, supported platforms, feature matrix, MSRV, and
  pinned Rust toolchain. Keep toolchain and dependency upgrades explicit.
- A documented lockfile policy and reproducible resolution for CI. Inventory
  every independent manifest, lockfile, vendored source, and native dependency.
- Runnable format, Clippy, unit, integration, and documentation checks. Test the
  MSRV and supported feature combinations; add fuzzing for untrusted parsers and
  protocol state before exposing them as supported behavior.
- `cargo audit`, `cargo deny` advisory/license/source checks, and `cargo vet`
  admission with real evidence. Use `safe-to-deploy` for runtime dependencies and
  `safe-to-run` for development/build-only dependencies. Define exact exception
  ownership and expiry instead of broad bypasses.
- Unsafe-code policy and independent review appropriate to the implemented
  kernel, FFI, crypto, or syscall boundaries. Add platform integration gates
  alongside those implementations; minikube availability alone is not coverage.
- Cargo update automation for each actual dependency graph. Add other ecosystems,
  container images, or vendored sources when introduced.

In the current maintainer environment, run Cargo or pnpm commands through the
privileged command channel when using local caches. Set `CARGO_TARGET_DIR` to
`/tmp/rust/target`. This is an execution-environment convention, not a dependency
on that host path in source code or CI; CI must use its own temporary directory.

## Release prerequisites

Publishing is unavailable until release automation and an initial support policy
are established and reviewed. Do not infer permission to publish from permission
to commit or push source.

Before the first release:

1. Establish versioning, package ownership, supported targets, feature coverage,
   and the crate publication/artifact verification process.
2. Add a changelog and compatibility or migration notes, including rollback
   limits. Record API, protocol, provider, feature, MSRV, and kernel requirements.
3. Validate the exact candidate revision with all applicable checks and security
   review. Document evidence gaps and affected surrounding surfaces.
4. Create and verify a signed annotated SemVer tag at that exact revision. Tags
   become immutable once pushed; fix mistakes with a new version, never a retag.
5. Review package contents, provenance, dependency inventory, and checksums for
   the actual artifacts. Obtain explicit authorization to publish and verify the
   resulting registry/release artifacts after publication.

Release automation must encode these checks before it is enabled. There is no
beta/stable soak interval or promotion automation in this initial baseline.

## Private security evidence

Store security scan results and tracking evidence only in the private repository
`OxiBelt/browntls-private-resources`. Before writing, verify that destination and
its private visibility. Do not store security findings in public CI artifacts.

Record immutable source revisions, tool versions, scope, findings, validation,
coverage gaps, and limitations. Sanitize credentials and personal data; hash
retained evidence and use signed commits with the required assistance notice.
Keep each finding independently traceable. Read back hosted writes and verify
signatures. Keep undisclosed findings out of public commit messages and links.

No security scan was performed as part of the documentation bootstrap. Current
CI is not a security assessment of a TLS implementation.
