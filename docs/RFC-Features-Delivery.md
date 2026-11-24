# New RFC capabilities implementation and review

Phase 0 establishes the [baseline](RFC-Features-Baseline.md) and the
[standards and oracle matrix](RFC-Features-Standards.md). Those reports
are the starting point for separately reviewed feature phases. Recheck
the pinned source, standards, registries and peer capability before
starting each phase, and carry forward any gaps still applicable.

## Follow-on stack boundaries

Open one stack per major phase. Name an accountable owner and a
separate reviewer at kickoff. Base the next phase on reviewed
prerequisites, and keep each layer buildable with the tests for its own
behavior. Where policy or interoperability is undecided, document the
blocking question and mark that portion deferred.

| Phase | Suggested review layers, bottom to top | Gate and independent reviewer |
| --- | --- | --- |
| **1. ML-DSA PKI** | Primitive and provider admission → signature verification and X.509/CRL dispatch → private-key association, fixtures and public PKI qualification. | Resolve implementation ownership and dependency review before adopting any backend. Require FIPS vectors for all three parameter sets and valid/invalid RFC 9881 encoding fixtures. Assign a cryptography/side-channel reviewer and a PKI path-validation reviewer. |
| **2. ML-DSA TLS** | Provider scheme mapping → opt-in TLS 1.3 authentication and role checks → adapters, applicable QUIC/DTLS paths, and interoperability. | Phase 1 must provide usable verification and signing. Pin the current draft or published replacement. Require exact-scheme and failure tests on both supported providers, and record gaps for transport/extension combinations or peers without evidence. Assign a TLS authentication and transcript reviewer. |
| **3. RFC 9963** | Native and custom signer capability plus verifier dispatch → explicit client-auth policy and CertificateRequest/CertificateVerify handling → API and exact-scheme qualification. | Require advertised, scheme-correct client use and negative controls for server use, absent offers and wrong DigestInfo. Keep server authentication and RSASSA-PSS support in the regression matrix. Assign a TLS role-policy and RSA encoding reviewer. |
| **4. ECH key logging** | Narrow capture of the KEM secret under logging authorization → client/shared/split path eligibility and label formatting → app-facing entry points and synthetic diagnostic fixtures. | Companion RFC hardening Phase 5 supplies feature-off controls and the Linux file sink. Confirm those controls at the chosen feature baseline. Decide a safe split termination policy with the reviewer before adding secret handling. Assign an ECH/HPKE and secret-lifecycle reviewer. |
| **5. TLS 1.3 application policy** | Examples for exact existing builders and refusal tests → preset and adapter reach if approved by the configuration owner. | Keep existing TLS 1.2 compatibility and verify explicit TLS 1.3 selection under both providers. Assign a configuration and compatibility reviewer. |
| **6. HPKE modes** | Resolve the application, target specification and suite matrix → scoped primitive and vectors → provider/API evidence and base-mode ECH regressions. | Defer additional modes until there is a concrete application and reviewed specification. Qualify each chosen mode and suite independently, with provider and alloc reach stated. Assign an HPKE protocol and cryptography reviewer. |
| **7. DTLS options** | Within the DTLS phase, use independent series for early data, ECH and post-handshake auth. For each, review datagram state first, then blocking/Tokio/facade reach and peer tests. | Each option needs an RFC-backed state model, resource bounds and loss/reorder tests. Early data depends on companion Phase 1 replay protections plus a DTLS-specific cross-connection decision. ECH must satisfy DTLS transcript and AAD rules. PHA needs independently tracked flights and request contexts. Assign a DTLS state/reliability reviewer and domain reviewers for replay, ECH or authentication as applicable. |
| **8. HTTPS/SVCB** | Caller-supplied resolution contract → service selection and TLS configuration adapter → fixtures, facade usage and DNS oracle. | Agree which policy the application supplies before designing the API. Require malformed-RRset, mandatory-key, fallback and origin-identity assertions. Assign a DNS service-binding and certificate-identity reviewer. |
| **9. Integration** | Cross-phase regressions → public adapters, deployment and architecture qualification → documentation and evidence handoff. | Review against the final integrated commit and the applicable standards. Assign a separate integration reviewer to reconcile evidence and unresolved gaps across stacks. |

## Acceptance and review

- Keep applicability explicit. Trace client and server, buffered and
  unbuffered core, acceptors, blocking and Tokio, QUIC-TLS, DTLS
  datagrams and UDP, kTLS handoff and facade. Where a transport or
  provider cannot support the behavior, cite its contract and test
  the boundary when useful. Where it can, include a representative
  direct assertion as well as shared-core coverage. Preserve
  feature-off builds and applicable alloc and embedded checks.
- Exercise valid, invalid and malformed inputs, configuration defaults,
  negotiated roles and versions, and provider equivalence where both
  providers implement a feature. Use fixed peer versions and assert
  the protocol or algorithm actually selected. For new public parser
  or state inputs, extend affected fuzz coverage. Choose cross-target,
  forced-software, Docker or minikube evidence from the affected
  surfaces. Record failures and distinguish isolated reruns from the
  original run.
- Follow [contribution policy](../CONTRIBUTING.md#independent-review).
  Give each non-author reviewer the actual diff, its parent, affected
  surrounding code, proposed contract and retained evidence. Record the
  named reviewer, revision, verification, findings and gaps. Resolve
  blocking findings and submit material follow-up changes for review.
  Leave substantive sensitive changes unlanded when a reviewer is
  unavailable.
- Use [dependency rules](Maintenance.md) for new security-critical
  code or dependencies, including named ownership and tracking.
  Review constant-time behavior, zeroization and resource budgets where
  relevant. Keep runtime and hardware claims tied to actual evidence,
  and use the [private reporting process](../SECURITY.md#private-reporting)
  for report-worthy findings.
- Draft bodies include the affected behavior, API/default and
  compatibility effects, trust boundaries, validation commands and
  results, limitations, review provenance and stack navigation. Use
  signed Conventional Commits and visible assistance notices. Keep
  public evidence portable and sanitized.
