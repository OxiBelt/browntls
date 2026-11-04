# Maintenance

## Current baseline

browntls has a Cargo workspace (`browntls-crypto`, `browntls-pki`, `browntls`)
described in [Architecture](Architecture.md), with no published releases. The
[contributor guide](../CONTRIBUTING.md) owns workflow and commit rules; the
[security policy](../SECURITY.md) owns disclosure and support.

These conventions adapt [OxiBelt](https://github.com/OxiBelt/OxiBelt)'s separation
of contributor policy, agent orientation, technical documentation, and evidence.
They do not import its proxy, WAF, image, or beta-promotion contracts.

## Routine maintenance

Review dependency and GitHub Actions updates weekly. Dependabot covers GitHub
Actions and the Cargo workspace. Review generated changes before merging; there
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

The workspace was introduced with the toolchain pin (Rust 1.99.1, also the
MSRV), a committed `Cargo.lock` used with `--locked`, format/Clippy/test/doc
CI, QEMU and native multi-architecture test jobs, `no_std` builds, and
`cargo deny` (advisories, licenses, bans, sources) with a checksum-pinned
binary. `cargo deny` reads the same RustSec database as `cargo audit`; a
separate `cargo audit` job is not added because no upstream-published checksum
is available for its release binaries. Outstanding items are tracked in the
[roadmap](Roadmap.md#governance-gaps): `cargo vet` admission, fuzzing of
parsers and protocol state, and named independent review of `unsafe` code and
cryptography.

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
