# Contributing to browntls

browntls is a Rust TLS library project in initial development. Its crates are
unreleased and have no stable API or support commitment yet. This document is
the source of truth for contributor workflow; [AGENTS.md](AGENTS.md) provides
agent orientation and [Architecture](docs/Architecture.md) the design.

## Repository layout

Root documents describe the project and its policies. Rust crates live in
`crates/`, technical documentation in `docs/`, cross-testing and CI helpers in
`scripts/`, portable repository checks in `tests/scripts/`, the Docker
end-to-end harness in `tests/e2e/`, and GitHub automation in `.github/`. Do not create empty runtime directories to imply an
architecture.

Use repository-relative paths in documentation and contribution descriptions.
State explicitly when a command must run outside the repository root.

## Contribution workflow

1. Identify the affected behavior and applicable policies before editing.
2. Make the smallest coherent change. Discuss architecture separately from
   this repository's initial maintenance setup.
3. Add regression coverage for changed behavior, especially security-sensitive
   checks. Do not remove or suppress tests merely to make CI pass.
4. Update documentation for behavior, compatibility, tooling, and workflow changes.
5. Run applicable checks and report failures, omissions, and environmental limits.
6. Clean up generated files and resources; review the complete diff before landing.

Contributors normally use a branch and pull request. Maintainers may land
explicitly authorized work directly on `main`; the same signing, attribution,
review, and validation rules apply. No automatic merge or publication is implied.

## Local checks

Run from the repository root with Python 3.10 or newer, Git, and
[actionlint](https://github.com/rhysd/actionlint) 1.7.12 installed:

```sh
python3 -B -m unittest discover -s tests/scripts -p 'test_*.py'
python3 -B tests/scripts/check_markdown_links.py --repo-root .
actionlint -shellcheck= -pyflakes=
git diff --check
git diff --cached --check
git show --format= --check HEAD
```

The Markdown check examines Git-tracked files, including newly staged files.
Stage intended additions before checking their links. The checker covers inline
and explicit reference links, images, relative targets, and Markdown anchors;
it is not a complete CommonMark parser. External HTTP(S) and mail links are not
fetched. CI uses the same checks and pins the downloaded actionlint archive by
SHA-256. Optional shellcheck and pyflakes integrations are disabled so the
documented actionlint result does not depend on host-installed analyzers.

These checks validate repository maintenance files, not TLS correctness.

Rust checks (the toolchain is pinned by `rust-toolchain.toml`):

```sh
cargo fmt --all --check
rustfmt --edition 2024 --check crates/browntls/tests/cases/*.rs
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTFLAGS='--cfg browntls_force_soft' cargo test -p browntls-crypto --locked
```

Accelerated backends for other CPUs are exercised under QEMU user-mode
emulation with `scripts/cross-test.sh <profile> -p browntls-crypto`; the script
header lists the profiles and the Ubuntu packages it needs. CI additionally
runs native aarch64 and riscv64 jobs, `no_std` builds and `cargo deny`.

The Docker end-to-end matrix runs browntls against OpenSSL, GnuTLS and itself
in separate containers for x86-64-v3, aarch64 and riscv64 (natively and under
QEMU with vector crypto). It needs Docker and the musl target of the
architecture; see [Docker end-to-end tests](tests/e2e/README.md):

```sh
python3 -B -m unittest discover -s tests/e2e -p 'test_*.py'
python3 tests/e2e/e2e.py build --arch amd64
python3 tests/e2e/e2e.py run --arch amd64 --suite openssl
```

There are no Kubernetes test gates.

## Commit messages and signatures

All contribution commits must be cryptographically signed. Use Conventional
Commits with an imperative summary:

```text
<type>(<scope>): <subject>
```

Types: `feat`, `fix`, `chore`, `docs`, `ci`, `refactor`, `security`, `tests`,
or `perf`. Choose a responsibility-based scope. Put literal identifiers, paths,
and commands in inline code spans when used in prose. Keep messages portable,
sanitized, and understandable without session-specific artifacts.

```sh
git commit -S
git verify-commit HEAD
```

Verify hosted signatures after pushing. Release tags must also be signed and
verified; see the [release prerequisites](docs/Maintenance.md#release-prerequisites).

## LLM assistance notices

If any LLM agent participated in preparing or reviewing a contribution, disclose
that assistance on each affected commit, issue, comment, pull request, review,
or other account-authored contribution. Human review does not remove the notice
requirement. Identify the actual agent; never attribute another tool's work to
Codex.

For every Codex-assisted commit, append this trailer after a blank line:

```text
Assisted-by: Codex <codex@openai.com>
```

For other agents, use an `Assisted-by` trailer identifying the agent, without
inventing an email identity. For comments, PR descriptions, and other prose,
include an equivalent visible notice, such as `Assisted-by: Codex
<codex@openai.com>`. Keep the notice when editing an existing contribution.

## Security requirements

Follow [SECURITY.md](SECURITY.md) for undisclosed findings. Do not expose an
unpatched vulnerability through public issues, PRs, logs, or commit descriptions.

Treat peer-controlled TLS data and caller-controlled configuration as untrusted.
For relevant changes, describe the trust boundary, attacker-controlled inputs,
failure behavior, compatibility effects, and remaining risks. Preserve certificate
and peer verification, key isolation, protocol state, and bounded resource use.
Never weaken a security default without explicit review, tests, and documentation.

Do not add externally reachable panics or silently ignore security-sensitive
errors. Split Rust modules by responsibility, keep protocol policy separate from
OS effects, and review files above 750 lines as an advisory signal rather than
a hard size gate. Do not introduce allocation, dispatch, or synchronization solely
to split a hot path.

First-party Rust must deny unsafe code by default when introduced. Any unsafe,
FFI, or kernel boundary needs a documented narrow exception, safety invariants,
a named non-author reviewer, and relevant Miri, sanitizer, fuzz, or syscall
evidence with applicability limits. Architecture and supported platforms must be
established before claiming those boundaries are safe.

Review direct and transitive dependencies, features, sources, build scripts,
licenses, maintenance, and unsafe code. Security-critical additions and exceptions
need a named owner and tracking issue. Exceptions must be exact, justified, and
time-bounded. Never invent cargo-vet audits or use wildcard exemptions.

## Tests and temporary resources

Generate test certificates, keys, configurations, and logs per run in temporary
directories. Clean them up on failure where practical. Do not commit real secrets,
generated private keys, build artifacts, or security scan evidence.

Docker checks, and Kubernetes checks if introduced, must be reproducible
locally and in CI. Rootful and rootless Docker may be used where available;
do not assume that both exist. Account for remote-daemon mount paths, use
run-specific names or labels, and clean up only resources created by the run.
Never use broad prune commands or delete unrelated minikube workloads.

## Pull request checklist

- Explain the behavior change, affected area, and compatibility implications.
- Use signed Conventional Commits and disclose every LLM-assisted contribution.
- Include relevant tests, documentation, and exact validation results or limits.
- Describe security boundaries and independent review for high-risk changes.
- Review dependency, unsafe-code, and release requirements when applicable.
- Remove temporary artifacts and confirm resource cleanup.

Public contributions are made under the repository's [Apache-2.0 license](LICENSE).
