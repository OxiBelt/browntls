# Security policy

## Scope and support

browntls is an independent Rust TLS library project with intended kernel
integration. It is in initial development: there is no TLS implementation,
published release, or production-readiness claim. Protocol architecture,
cryptographic providers, public APIs, platforms, and kernel mechanisms remain
undecided. No cryptographic certification is claimed.

`main` is the supported development branch for triage and fixes; it is not a
stable release. No released versions or backport commitments currently exist.
Establish release support and end-of-support rules before the first publication.

Reports affecting repository code, documentation, dependency choices, build and
CI configuration, or official future artifacts are in scope when they establish
a realistic unsafe outcome. A dependency issue matters when browntls's use is
affected. There are no blanket finding-class exclusions or accepted-risk waivers.

## Threat boundaries and security requirements

These are requirements for future design and review, not implemented controls:

- Treat peer-controlled protocol bytes, certificates, extensions, and negotiation
  state as untrusted. Preserve authentication and protocol state; reject invalid
  data safely and bound CPU, memory, buffering, and other attacker-driven work.
- Protect private keys, session secrets, randomness, and sensitive plaintext.
  Do not expose them through logs, errors, serialization, or test evidence.
- Validate caller-controlled configuration and provider selection. Security
  failures must produce safe errors rather than silent verification bypasses,
  fallback to weaker policy, or externally reachable panics.
- Review privilege, ownership, memory, lifetime, concurrency, and cleanup across
  userspace/kernel, syscall, FFI, and unsafe-code boundaries when introduced.
- Preserve build and release integrity across dependencies, native code, build
  scripts, Actions, tool downloads, signing, and publication credentials.

Severity depends on demonstrated reachability, attacker prerequisites, supported
configuration, and impact. Missing future functionality alone does not establish
a vulnerability; insecure implemented behavior or misleading guidance can.
Development status is not a blanket reason to suppress meaningful findings.

## Private reporting

Use [GitHub private vulnerability reporting](https://github.com/OxiBelt/browntls/security/advisories/new).
Do not disclose an unpatched vulnerability in public issues, discussions, pull
requests, commits, or CI artifacts. If private reporting is unavailable, do not
substitute a public channel containing vulnerability details; wait for maintainers
to restore a private reporting route.

Include the affected immutable revision or release, relevant configuration and
platform, attacker prerequisites, impact, and a minimal safe reproduction when
available. Sanitize logs and never submit production credentials or secret keys.
This policy does not authorize testing systems you do not own or operate.

## Response and disclosure

Maintainers validate reports, assess affected boundaries and upstream dependencies,
and coordinate remediation privately. There are no guaranteed response deadlines.
Credit reporters with their consent. Coordinate cryptographic and provider issues
with affected upstreams when appropriate.

Keep one repository security advisory per validated report-worthy finding. Keep
reports in private triage or draft state until a supported fix or actionable
mitigation is verified and publication is explicitly authorized. Obtain explicit
approval of each exact advisory submission or publication payload, verify its
visibility and duplicates, and read it back after writing. Do not request a CVE
unless explicitly authorized. There is no fixed embargo period; maintainers
coordinate timing based on remediation, upstream dependencies, and exposure.

Store scan results and tracking evidence only in the private repository
`OxiBelt/browntls-private-resources`, with source revisions, checksums, sanitized
evidence, and coverage limitations. Follow the contribution signing and LLM
assistance requirements. Do not put undisclosed details or private evidence links
in public contribution messages.

## Current limitations

Repository documentation and workflow checks do not establish TLS correctness,
kernel safety, cryptographic assurance, or a completed security assessment.
Review and test each implemented trust boundary as it is introduced. Report
unreviewed surfaces and unrun checks explicitly rather than claiming coverage.
