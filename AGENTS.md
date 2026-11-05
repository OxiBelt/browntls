# Agent guidance

browntls is an independent Rust TLS library project with intended kernel
integration. Its architecture is described in [Architecture](docs/Architecture.md)
and its status in [Roadmap](docs/Roadmap.md). browntls does not depend on rustls
at run time (rustls is only an interoperability test oracle), and no kernel
mechanism has been designed yet.

## Source of truth

[CONTRIBUTING.md](CONTRIBUTING.md) governs contribution workflow, validation,
security requirements, signed commits, and LLM assistance notices. Follow it
when this orientation file diverges. See [maintenance](docs/Maintenance.md) for
dependency and release prerequisites and [SECURITY.md](SECURITY.md) for reporting
and disclosure.

Current layout:

- Root Markdown files: project and contributor guidance.
- `crates/browntls-crypto/`: primitives and architecture backends (the only
  crate permitted to contain `unsafe`, confined to backend modules).
- `crates/browntls-pki/`: PKI types and certificate path validation.
- `crates/browntls/`: TLS protocol, provider mount point and providers.
- `crates/browntls-e2e/`: command-line TLS peer for the Docker end-to-end tests
  (test tooling, not published).
- `docs/`: technical and maintenance documentation.
- `scripts/`: QEMU cross-testing and CI helpers.
- `tests/scripts/`: portable repository checks and their regression tests.
- `tests/e2e/`: Docker end-to-end interoperability matrix and its harness tests.
- `.github/`: workflows, contribution templates, and update automation.

## Working principles

Inspect the affected code and policies before editing. Make bounded changes,
preserve documented behavior, and update tests and documentation together.
Report evidence separately from inference, including skipped checks and limits.
Never present successful documentation CI as validation of a TLS implementation.

Delegate only when useful tools are available and the task has a clear boundary.
Parallelize independent investigation; give write tasks non-overlapping
ownership. Require concise evidence and verification from workers. Prefer
independent review of cryptography, unsafe/FFI, kernel boundaries, parsing,
protocol state, concurrency, and resource limits. If independent review is
unavailable, report that limit rather than inventing a reviewer. Do not bind
this workflow to particular model names or subscription capabilities.

Start security review from a trustworthy baseline and cover the change plus
affected surrounding surfaces. Expand coverage when evidence warrants it;
record gaps explicitly. Do not run a monolithic repository scan by default.

## Attribution and disclosure

Every LLM-assisted commit and account-authored issue, comment, PR, or review
needs the assistance notice required by CONTRIBUTING.md. Keep commit context
portable: no absolute host paths, session aliases, private evidence links,
credentials, or undisclosed vulnerability details.

For validated report-worthy vulnerabilities, use one private repository advisory
per finding until disclosure is authorized. Preview the exact payload and obtain
explicit approval before submitting or publishing an advisory. Verify identity,
repository, immutable source revision, duplicates, permissions, and visibility;
read back writes. Do not request a CVE unless explicitly authorized. If private
reporting is unavailable, stop that submission rather than using a public issue.
