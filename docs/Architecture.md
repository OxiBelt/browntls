# Architecture

This document describes the design of browntls: a TLS 1.2 / TLS 1.3 library,
with DTLS over datagrams, written from scratch in Rust, targeting the
feature level of rustls 0.23, with its own cryptographic primitives behind a
pluggable provider interface.
Implementation status is tracked in [Status](#status); the
[contributor guide](../CONTRIBUTING.md) and [security policy](../SECURITY.md)
govern how changes land.

## Crates

```text
browntls-crypto   primitives; no_std (alloc and std optional); arch backends;
                  no required dependencies (optional getrandom)
       ^
       | (feature "native", default)
browntls-core -----> browntls-pki   PKI types, PEM, X.509 path validation;
  crypto::*  (mount point)           no_std + alloc; no cryptography
  crypto::native     (default provider, browntls-crypto)
  crypto::rustcrypto (optional provider, RustCrypto crates)
       ^
       |
browntls-tokio      Tokio AsyncRead/AsyncWrite streams over browntls-core
browntls-ktls       Linux kernel TLS offload of browntls-core connections
       ^
       | (features "tokio" and "ktls"; browntls-core always)
browntls            the crate applications depend on; no code of its own:
                    its root is browntls-core, browntls::tokio is
                    browntls-tokio and browntls::ktls is browntls-ktls
```

| Crate | Role | `unsafe` |
|---|---|---|
| `browntls-crypto` | Hashes, MACs, KDFs, AEADs, key exchange, signatures, KEM, HPKE, CPU detection, OS entropy | Denied crate-wide; allowed only in architecture backend modules, CPU detection, zeroisation and the system-call trampoline |
| `browntls-pki` | Certificate/key/name/time types, PEM, X.509 path building, name and revocation checks | Forbidden |
| `browntls-core` | Record layer, handshake state machines, configuration, provider traits and providers | Forbidden |
| `browntls-tokio` | Asynchronous client and server streams for Tokio over the buffered connection API, and over the unbuffered one (`browntls_tokio::unbuffered`) | Forbidden |
| `browntls-ktls` | Hands buffered connections to Linux kernel TLS and drives what follows (`KtlsStream`; `AsyncKtlsStream` on Tokio sockets with the `tokio` feature) | Denied crate-wide; allowed only in `src/sys.rs`: the kernel TLS socket options, `sendmsg`/`recvmsg` control messages, `sendfile` and the other system calls listed under [Linux kernel TLS](#linux-kernel-tls-browntls-ktls) |
| `browntls` | The crate applications depend on: re-exports `browntls-core` at its root and, by feature, `browntls-tokio` as `browntls::tokio` and `browntls-ktls` as `browntls::ktls`; no code of its own (see [Facade crate](#facade-crate-browntls)) | Forbidden |

`browntls-pki` performs no cryptography: signatures are checked through the
`SignatureVerificationAlgorithm` trait supplied by the active provider. This
keeps certificate policy independent of any particular primitive library.
An algorithm is selected by its key and signature `AlgorithmIdentifier`s,
compared byte for byte except for `id-RSASSA-PSS`, whose equivalent
parameter encodings (RFC 4055) are first mapped to one canonical constant
(`AlgorithmIdentifier::matches_public_key` and `matches_signature`, used by
path validation and by handshake signature verification alike).
Certificate and CRL parsers also compare supported PSS inner and outer
signature parameters semantically. They retain the original signed bytes.
PSS certificate and signing-key pairing and path loop checks compare the
actual key and its restrictions, including the exact minimum salt length.

For ML-DSA (RFC 9881), `browntls-pki` has the `id-ml-dsa-44`, `-65` and
`-87` identifiers (`alg_id::ML_DSA_*`), each naming both the key and the
signature algorithm with parameters absent, and matches them byte for byte
like any other identifier, so an encoding with parameters (NULL included)
matches no algorithm. It also enforces the RFC 9881 §5 key usage rule: a
`keyUsage` extension on a certificate with an ML-DSA key must assert at
least one of digitalSignature, nonRepudiation, keyCertSign and cRLSign, and
none of keyEncipherment, dataEncipherment, keyAgreement, encipherOnly and
decipherOnly. Path validation checks it for the end entity and every
intermediate (not for trust anchors) and reports
`Error::KeyUsageNotPermittedForPublicKey`; a delegated OCSP responder
certificate that breaks it is refused with `OcspError::DelegateKeyUsage`.
The crate ships no ML-DSA verifier: the signatures are checked by the
provider's algorithms, which in the built-in providers means the native
provider's opt-in table (see
[ML-DSA certificate verification][ml-dsa-verification]).

### Facade crate (`browntls`)

`browntls` is the one dependency of an application. It exists as a separate
crate because of the dependency order above: `browntls-tokio` and
`browntls-ktls` depend on the protocol crate, and a crate that re-exports
them depends on them, so the protocol crate cannot be that crate (Cargo
rejects such a dependency cycle). The protocol crate is therefore
`browntls-core`, and `browntls` sits on top of all three.

Its `src/lib.rs` holds three re-exports and no other public item:

| Path | Is | Present |
|---|---|---|
| `browntls::*` | `browntls_core::*` (`pub use browntls_core::*`) | always |
| `browntls::tokio` | the crate `browntls-tokio` (`pub use browntls_tokio as tokio`) | feature `tokio` |
| `browntls::ktls` | the crate `browntls-ktls` (`pub use browntls_ktls as ktls`) | feature `ktls` |

The items are the ones those crates define, not copies or wrappers:
`browntls::ClientConfig` and `browntls_core::ClientConfig` are one type, and
so are `browntls::tokio::TlsConnector` and `browntls_tokio::TlsConnector`. A
library written against `browntls-core` or `browntls-tokio` therefore works
with an application that depends on `browntls`, as long as both resolve to
the same version of the crate behind. `browntls-tokio` re-exports the
protocol crate itself (`browntls_tokio::browntls`), so
`browntls::tokio::browntls::ClientConfig` is the same type once more
(`crates/browntls/tests/tokio.rs` passes one value through both paths).

Where this document says where code lives it names the crate that defines it
(`browntls_core::kernel`, `browntls_tokio::unbuffered`,
`browntls_ktls::routing`). An application reaches the same items as
`browntls::kernel`, `browntls::tokio::unbuffered` and
`browntls::ktls::routing`.

#### Feature forwarding

Every feature of the three crates behind the facade, except the `fuzzing`
feature of `browntls-core` (see below), exists in it under the same name and
turns that feature on in each of those crates that has it (the table under
[Cargo features](#cargo-features-browntls-core) lists what the features of
`browntls-core` do):

- The facade takes the three crates without their default features, so its
  own feature set alone decides what is built: `default-features = false`
  on `browntls` turns off the defaults of all of them.
- The default set is the one of `browntls-core` (`std`, `native`, `tls12`,
  `logging`, `prefer-post-quantum`) plus `coop`, the one default of
  `browntls-tokio` that `browntls-core` does not have. The defaults of
  `browntls-ktls` (`native`, `tls12`, `logging`) are among them.
- `tokio` and `ktls` enable the optional crates, and `std`, which both need.
  With both, `browntls-ktls` is built with its own `tokio` feature, so
  `browntls::ktls::AsyncKtlsStream` exists exactly then.
- A feature that an optional crate shares (`native`, `rustcrypto`, `tls12`,
  `logging` for both; `prefer-post-quantum`, `zlib`, `brotli`, `zstd` for
  `browntls-tokio`) reaches that crate only when the crate is enabled and
  does not enable it (`browntls-tokio?/tls12`). The same holds for `coop`,
  which does nothing without `tokio`. `ocsp` is the exception: it enables
  `tokio`, since it is `browntls::tokio::revocation`.
- `alloc` is present because `browntls-core` has it; it gates nothing.

`browntls-core`'s `fuzzing` feature is not offered. It opens unstable entry
points into private codecs for the [fuzz targets](../fuzz/README.md) and is
not a supported API, so the facade has no feature that turns it on, and the
fuzz project depends on `browntls-core` directly. This is not a barrier:
Cargo builds one `browntls-core` for the whole dependency graph, so if any
other package in an application's graph enables `browntls-core/fuzzing`,
the module is also nameable as `browntls::fuzzing` through the glob
re-export.

`tests/scripts/check_facade_features.py` reads the manifests of the facade
and of the three crates behind it and fails when a feature of one of them
is missing from the facade (other than `fuzzing`) or is not passed on, when
the default sets differ, when an optional crate has no feature that enables
it, or when the facade takes a crate with its default features. It also
fails when a facade feature turns on a feature of another name in those
crates or `browntls-core/fuzzing`, when a feature that does not enable an
optional crate names it with a strong reference (`browntls-tokio/tls12`,
which would pull the crate in, instead of `browntls-tokio?/tls12`), and when
a default feature enables an optional crate. A feature is added to the
facade in the change that adds it to one of those crates.

#### The name `browntls::tokio`

The module has the name of the external crate `tokio`, which an application
on Tokio depends on as well. Paths that start at `browntls` and paths that
start at `tokio` do not meet, so this compiles:

```text
use browntls::tokio::TlsConnector;
use tokio::net::TcpStream;
```

Bringing the module itself into scope under its bare name changes what
`tokio` means in that scope. Measured with the pinned toolchain (Rust
1.100.0, edition 2024) in a crate that depends on both:

| In scope | Then | Result |
|---|---|---|
| `use browntls::tokio;` | `use tokio::net::TcpStream;`, `tokio::net::TcpStream` in a type, `#[tokio::main]` | Errors: `tokio` is the module, which has no `net` or `main` (E0432, E0433) |
| `use browntls::*;` | `use tokio::net::TcpStream;`, `#[tokio::main]` | Error E0659: `tokio` is ambiguous between the glob import and the external crate |
| `use browntls::*;` | `tokio::net::TcpStream` in a type | Error E0433: the glob import wins and the module has no `net` |
| `use browntls::*;` | `tokio::TlsConnector` | Compiles, naming `browntls::tokio::TlsConnector` |
| either | `use ::tokio::net::TcpStream;`, `::tokio::runtime::Runtime` in a type (leading `::`) | Compiles: always the external crate |
| either | `#[::tokio::main]` | Errors (E0432 after `use browntls::tokio;`, E0659 after the glob): the code the attribute generates names `tokio` without the leading `::` |
| `use browntls::tokio as tls;` | `tls::TlsConnector`, `use tokio::net::TcpStream;` | Compiles |

An application on Tokio therefore names items by path
(`browntls::tokio::TlsConnector`) or imports the module under another name,
and does not glob-import the crate root. The crate's own tests and the
end-to-end peer follow the first form. `browntls::ktls` has no such
namesake among the project's dependencies.

#### Without `std`

The crate is `#![no_std]`. Without the `std` feature its root is
`browntls-core` built without `std` (the unbuffered API with `alloc`), and
the `tokio` and `ktls` features are off, since each of them enables `std`.
CI lints that configuration on the x86-64 host target with each provider
(`--lib --no-default-features --features native`, and the same with
`rustcrypto`); no job builds
`browntls-core` or the facade for a target without an operating system (the
`Build without std` job covers `browntls-crypto` and `browntls-pki`).

#### Facade tests

- `crates/browntls/tests/facade.rs`: a handshake and application data over
  loopback TCP between a client and a server that name every item through
  `browntls`, and probes of the root's features (`native`, `rustcrypto`,
  `tls12`, `prefer-post-quantum`, the compression features) that fail or
  do not compile when the facade's feature does not reach `browntls-core`.
- `tests/tokio.rs` (feature `tokio`): a handshake through
  `browntls::tokio`, the identity of the types behind both paths, the
  `revocation` module with `ocsp`, and `AsyncKtlsStream` with `ktls`.
- `tests/ktls.rs` (feature `ktls`, Linux): a client hands its connection to
  the running kernel through `browntls::ktls`, or gets it back unharmed
  where the kernel has no `tls` module; the `routing` module with `native`.
- The examples of the crate documentation and of its README are compiled
  as doctests and not run (the README's with `tokio`, `ktls` and `native`
  on Linux).
- CI (`.github/workflows/rust.yml`): the workspace jobs build and test the
  crate with every feature at once, where another crate's features can hide
  one the facade fails to pass on; Clippy also runs with the default set,
  with `tokio` alone, with `ktls` alone, with `std` and `native` only, with
  `rustcrypto` in place of `native`, and without `std`; the
  `Facade feature sets` job runs the tests with the default set, `tokio`,
  `ktls`, `tokio,ktls,ocsp`, and `std` and `native` only (no TLS 1.2,
  X25519 first), with the kernel's `tls` module loaded.
- The [Docker end-to-end](../tests/e2e/README.md) peer `browntls-e2e` depends
  on `browntls` alone (default features off; `std`, `native`, `tls12`,
  `prefer-post-quantum`, `tokio`, `coop`), so that matrix exercises the
  blocking connections and the Tokio streams through the paths an
  application uses. It does not enable `ktls`.

These tests show that the paths and features of the facade reach the crates
behind it. They are not a second test suite of the protocol, the streams or
the offload: that evidence is the one of the crates behind, listed under
[Testing strategy](#testing-strategy).

#### Where code goes

Nothing is implemented in `crates/browntls`. New protocol code goes into
`browntls-core`, code that needs Tokio into `browntls-tokio`, code that
needs Linux kernel TLS into `browntls-ktls`; the facade changes only when
one of them gains or loses a feature, or when another crate joins it as a
module. Its `src/lib.rs` carries the crate documentation, the re-exports and
the doctest hook for the README.

### Certificate service identity

For TLS, DTLS and QUIC, the default verifier checks the end-entity SAN
against a caller-supplied reference under RFC 9525. DNS and IP connections
use their existing `ServerName` as a reference. A `ClientServerIdentity`
lets a client choose an ordered `ServiceIdentity` separately from the
routing name. The reference order determines the validated identity when
multiple entries match. DNS and IP identities use their respective SAN
types. URI and SRV identities also match the scheme or service label.
Applications choose which alternatives to include, including any DNS
fallback for a service scoped by URI or SRV. The subject common name is
outside identity verification.

For example, the Tokio buffered client can authenticate an SRV identity
while sending the endpoint name in SNI:

```rust
use browntls::{ClientServerIdentity, ReferenceIdentifier, ServiceIdentity, SrvId};
use browntls::pki_types::ServerName;

let route = ServerName::try_from("edge.example")?;
let service = SrvId::try_from("_imaps.mail.example")?;
let policy = ServiceIdentity::new(vec![ReferenceIdentifier::Srv(service)])?;
let identity = ClientServerIdentity::new(route, policy);
let stream = connector.connect_with_identity(identity, socket).await?;
let matched = stream.get_ref().1.matched_service_identity();
```

The unbuffered Tokio connector and the core TLS, DTLS and QUIC APIs offer
the same policy. Linux kTLS uses the authenticated userspace result. The
low-level `EndEntityCert::verify_service_identity` checks the leaf SAN
and returns the matching reference. Callers using it directly must also
verify the certificate path and the peer's proof of possession.

Existing configurations with underscores in DNS labels need valid DNS names
and corresponding certificates. An underscore is required at the start of
an SRV service label. Caller-supplied Unicode DNS names use nontransitional
UTS #46 with STD3 checks. Certificate and wire identifiers use ASCII
A-labels. Wildcard DNS SANs cover one complete leftmost label and can be
disabled per reference set. URI and SRV DNS portions use exact matching.

URI and SRV path constraints apply to the relevant SAN type throughout a
path. An excluded or unprocessable constrained name rejects the path even
if a different SAN would match the reference. URI constraints use the DNS
authority host, so a bare SIP URI may satisfy identity matching on an
unconstrained path but cannot satisfy URI name constraints.

The client caches the matched identity with certificate-authenticated
sessions and requires the original reference policy, routing name and
configuration binding before resuming or offering early data. A custom
certificate verifier must explicitly support the new verification hook to
authenticate a reference set. PSK-only and raw-key authentication do not
supply a certificate identity.

### Certificate inspection

`browntls-pki` parses a certificate once, eagerly: every field and extension
it interprets is decoded and validated before any check runs. That parsed
view is public as `Cert` (the rustls-webpki name), so applications inspect
exactly what path validation sees rather than reparsing the DER with another
library. `Cert::try_from` applies the strict policy used for end entities and
intermediates (strict DER, version 3, no duplicate decoded extension, no
unknown critical extension) to any certificate, CA or not; `EndEntityCert`
dereferences to it and adds the verification methods. Parsing checks no
signature, validity period or trust.

- Extensions: every extension as an undecoded `Extension`, and typed views of
  the ones the parser decodes (basic constraints, key usage, extended key
  usage, subject and authority key identifiers, subject alternative names,
  name constraints, CRL distribution points). Values validated at parse time
  iterate without errors. Two parts that path validation reads leniently are
  parsed strictly on access instead: each CRL distribution point, and the
  issuer names of an authority key identifier. Both report
  `ExtensionValueInvalid`, and both reject empty `GeneralNames`. Changing the
  parser to reject them up front would have changed which certificates path
  validation accepts. The revocation code's extensions are decoded by free
  functions in `browntls_pki::ocsp`: `authorityInfoAccess`
  (`ocsp_responder_uris`, `ca_issuer_uris`), the TLS Feature extension
  (`must_staple`) and `id-pkix-ocsp-nocheck` (`has_ocsp_nocheck`).
- Names: `GeneralName` covers every RFC 5280 choice; the ones the crate does
  not decode keep their tag and contents. `Name` parses an X.501 name (issuer,
  subject, trust anchor subject, `directoryName`, TLS `DistinguishedName`)
  into RDNs and attributes. It checks the structure with DER's minimal
  lengths and rejects empty RDNs, `SET OF` elements out of order (X.690
  §11.6), an attribute repeated within an RDN, value tags of a universal type
  in the wrong form, and names over 64 KiB. Each attribute value is checked
  only as one element (tag, form and minimal outer length): its contents are
  not parsed, so an `INTEGER` or `BOOLEAN` value need not be valid DER of its
  type. A string accessor checks the contents of the UTF-8-compatible string
  types.
  `valid_dns_names` returns the `dNSName`s that server name verification can
  match, which is not a substitute for `verify_is_valid_for_subject_name`.
- Signatures: `SignedData` reads the `SEQUENCE { tbs, AlgorithmIdentifier,
  BIT STRING }` of a certificate, CRL or certification request, or takes a raw
  (message, algorithm, signature) triple, and verifies it against a
  `SubjectPublicKeyInfo` with `SignedData::verify_signature`, which runs the
  signature check path validation uses, including the RSASSA-PSS canonical
  forms. Like path
  validation, it takes the key as a complete `SubjectPublicKeyInfo` or as its
  contents (a trust anchor's form); the two cannot be confused.

Everything returned borrows from the input, and work is linear in input
lengths that the parser already bounds (64 KiB per certificate element, 4 GiB
for a signed structure's `tbs`).

### Certificate revocation

The built-in server-certificate and client-certificate verifiers accept an
optional `RevocationPolicy`. The policy starts in strict leaf mode.
`check_full_chain` extends coverage to intermediates and `best_effort`
allows an indeterminate result. The connection exposes that result through
`peer_revocation_status`. Configured CRLs continue to apply under their own
depth, freshness, and missing-status rules.

OCSP responses are checked against the certificate and its verified issuer.
A response can be signed by the issuer or a directly issued responder
authorized for OCSP signing. Authenticated revocation takes precedence over
affirmative evidence. A certificate marked Must-Staple requires a fresh
good staple. TLS 1.2 carries server staples in CertificateStatus. TLS 1.3
carries per-certificate staples in CertificateEntry, including client
authentication when requested. With the policy enabled, the client offers the
RFC 6962 SCT extension. SCTs from certificates, authenticated OCSP responses,
and negotiated TLS extensions are verified against configured log keys.
Version 2 SCTs (RFC 9162) are not fed into this evaluation or CRLite; they
have their own policy, `browntls::transparency` through the facade (see
[CT 2.0 in TLS](#ct-20-in-tls)).

CRLite reads Mozilla Clubcard V3 and V4 filters. The application authenticates
the source and supplies the full filter, ordered deltas, expiry, generation,
and CT log keys as a unit. A verified timestamp in a covered log interval
allows lookup by the issuer's SPKI hash and certificate serial. Missing
coverage, missing enrollment, and expired data provide no good result. A
snapshot can be atomically replaced through `SharedRevocationData` with
`std`. The application owns distribution, rollback protection across
process restarts, and publisher authentication.

Live OCSP is independently opt-in. Buffered, unbuffered, and QUIC
connections expose `pending_revocation` and `resolve_peer_revocation`.
They verify the path and the peer's proof of possession before requesting
network evidence. The driver supplies DER or reports unavailability and
the verifier makes the authentication decision. Drivers must authorize
responder destinations for the verified issuer and refresh their status
cache within signed validity. `browntls-tokio` can drive this step with an
application-provided transport. `ServerStapleResolver` validates and
atomically installs server leaf staples and withholds expired responses.

Revocation-enabled certificate authentication uses a full handshake each
time. Revocation-aware post-handshake authentication exposes the new
identity only after the response and Finished verify. Pending checks and
outstanding revocation-aware authentication block kernel handoff. See
[browntls-tokio](../crates/browntls-tokio/README.md) for application
integration.

### Certificate Transparency 2.0 (RFC 9162)

`browntls_pki::transparency` holds the TLS-independent part of CT 2.0, beside
the RFC 6962 code in `browntls_pki::sct`. Like the rest of `browntls-pki` it
needs only `alloc` and contains no cryptography: SHA-256 and signature
verification are passed in. `browntls-core` negotiates the TLS extension
(`transparency_info`, type 52) on top of it; see
[CT 2.0 in TLS](#ct-20-in-tls) below. Through the facade the TLS side is
`browntls::transparency` and the PKI module `browntls::pki_types::transparency`.

It serves three callers:

- A TLS client creates a `CtV2Verifier` from a `CtV2Policy` (trusted logs,
  optionally trusted tree heads, budgets), the end-entity certificate and the
  issuer's SPKI. It hands over the `TransItemList` of each delivery
  mechanism: `verify_embedded` (certificate extension 1.3.101.75),
  `verify_ocsp_response` (the list `SingleResponse::transparency_info` and
  `VerifiedOcspStatus::transparency_info` return) and
  `verify_tls_extension`. Each call returns a `CtV2Report` of counters;
  `verified` lists the SCTs whose signatures verified with their source and,
  when found, their inclusion evidence. An OCSP response whose single
  response repeats the Transparency Information extension, or holds one
  that is not an `OCTET STRING`, does not parse (as for the RFC 6962 SCT
  list), so it is not usable revocation evidence either.
- A server or submitter parses and encodes lists and items (`TransItemList`,
  `TransItem`) and checks `has_sct` before sending a list (§6.4).
- An auditor verifies tree heads, inclusion proofs and consistency proofs
  standalone through `CtV2Log` and the `merkle` module.

An SCT is accepted when its log is configured, its timestamp lies in the log's
window and no later than the verification time (plus a configurable tolerance),
its extensions are ordered (§4.8) and the log's signature over the `TransItem`
of the reconstructed entry verifies. The entry binds the timestamp, the issuer
key hash and the certificate; for a precertificate the TBSCertificate is rebuilt
without the 1.3.101.75 extension and the RFC 6962 SCT list extension (§8.1.2).
Signatures are ECDSA P-256 with SHA-256 or Ed25519, derived from the log's key.

Inclusion evidence is recorded for a verified SCT when an inclusion proof of the
same log verifies its leaf against a tree head of the proof's tree size with a
timestamp not older than the SCT. The tree head comes from the application
(`trusted_tree_heads`) or from any delivered list, and its signature is verified
only when a proof needs it. The proof, the tree head and the SCT may arrive
through different mechanisms. The tree size is bound only by the signed tree
head: a path of the same shape verifies for other sizes, so evidence is never
recorded without a verified or trusted head. Consistency proofs in lists are
counted as ignored by the verifier; checking them needs two tree heads the
auditor holds.

Merkle verification follows the algorithms of §2.1.3.2 and §2.1.4.2 step by
step. Paths longer than 64 (inclusion) or 65 (consistency) nodes are
rejected before any hashing. The verifier bounds the list length, item count,
extension and signature lengths, signature verifications and hash
operations per instance (`CtV2Options`); exceeding a budget is an error, not
a silent truncation.

§6.3 defines `TransItemList` as non-empty while §6.5 lets a server send an
empty list in the TLS extension. `verify_tls_extension` accepts an empty
extension body or an empty list; the strict parser, the certificate
extension and the OCSP extension reject an empty list.

The PKI tests check the public verifier and auditor APIs against
[Python and OpenSSL fixtures][ct-independent], including both log signature
algorithms and proofs from an independently constructed tree. The fixtures
cover certificates and the CT list extracted from OCSP. Public CT 2.0 log
interoperability, the HTTP API of §5, log operation, monitoring, and the
final STH log parameter (§4.1) remain outside this evidence.

[ct-independent]: ../crates/browntls-pki/tests/data/ct_v2_independent/README.md

#### CT 2.0 in TLS

`browntls_core::transparency` holds the configuration types; the protocol
work is in the handshake and in the WebPKI server verifier (§6.5, §8.1).

- Server: `CertifiedKey::set_transparency_info` installs an encoded
  `TransItemList`, refusing one that does not parse, has no SCT (§6.4) or
  exceeds 65535 octets. The list is sent only when the ClientHello offered
  the extension and the certificate is X.509 (not a raw public key): in the
  TLS 1.2 ServerHello, or on the end entity's TLS 1.3 CertificateEntry.
  A resumed handshake carries none (§6.5).
- Client offer: an empty extension in the ClientHello when
  `ServerCertVerifier::requests_transparency_info` says so (the WebPKI
  verifier does when it has a CT 2.0 policy) or when
  `ClientConfig::request_transparency_info` is set, and never with a
  verifier that requires raw public keys. Whether a server's extension
  was solicited is decided by the ClientHello actually sent. A verifier
  that wraps a CT-enabled WebPKI verifier forwards
  `requests_transparency_info` and `verify_server_cert_with_context`.
  The connection records `transparency_info` and `status_request` from the
  effective ClientHello. A missing offer or lost context returns
  `CertificateError::TransparencyOfferRequired` (`certificate_unknown`)
  before evaluation, as required by §8.1.6.
- Client policy: `ServerCertVerifierBuilder::with_certificate_transparency`
  takes `CtV2Requirements` (trusted logs as `CtV2LogConfig`, trusted tree
  heads, `min_verified_scts`, `min_distinct_logs`, `require_inclusion`,
  `CtV2Options` budgets and the SHA-256 of `RevocationDigests`); `build`
  checks every log key and refuses two logs sharing an ID or a key, the key
  compared in a normalised form (complete `SubjectPublicKeyInfo` or its
  contents, compressed or uncompressed point): an SCT's signature does not
  cover its log ID, so one SCT could otherwise count for two logs. For the
  same reason distinct logs are counted by key. Every SCT signs the hash
  of the end entity's issuer key (§4.7): the first intermediate of the
  validated path, or its trust anchor. Without a revocation policy that
  path is the one the verifier validated; a revocation policy may leave
  several candidate paths to a live query, so the verifier then validates
  the path once more, without revocation, to learn the issuer. It runs
  `CtV2Verifier` over three sources: the certificate's Transparency
  Information extension, the list in a stapled OCSP response
  (only when that response authenticates against the issuer) and the TLS
  extension. Too few SCTs or logs fail with
  `CertificateError::InsufficientTransparency` (`certificate_unknown`); an
  evidence error such as an exceeded budget with
  `InvalidTransparencyEvidence` (`bad_certificate`). Direct callers
  evaluate local evidence with `verify_server_cert_with_context` and
  `ServerCertVerificationContext::LocalEvidence`. Context-free methods
  return `TransparencyOfferRequired` when the verifier has a CT policy.
- What a connection reports: `peer_transparency_info` (the extension body,
  unverified, also without a policy) and `peer_transparency_status`
  (`TransparencyStatus` counts) on `ClientConnection` and
  `UnbufferedClientConnection`. A custom verifier receives the body in
  `CertificateEvidence::transparency_info` and reports a status through
  `ServerCertVerifier::verify_server_cert_with_context`.
- Peer errors: a list that does not parse is `decode_error` in the codec (an
  empty body and an empty list are accepted, §6.5), as is a non-empty body
  in the ClientHello; an extension the client did not offer is
  `unsupported_extension`; one in a resuming TLS 1.2 ServerHello is
  `illegal_parameter` (§8.1.1). In TLS 1.3 only the end entity's entry is
  read; the extension on another entry is ignored.
- Resumption: the certificate is not evaluated again, so a resumed
  connection reports neither items nor a status; the policy held when the
  session was established.
- Client certificates: RFC 9162 defines no CT for them. The extension is
  never requested in a CertificateRequest, and a client Certificate that
  carries it is refused as unsolicited.

Interactions with other features:

- Encrypted Client Hello: the outer ClientHello carries the offer like the
  inner one. When ECH is accepted the policy applies to the hidden name's
  certificate. When it is rejected the policy also applies to the public
  name's certificate that authenticates the rejection, so a client-facing
  server without CT 2.0 evidence makes the client fail with
  `InsufficientTransparency` rather than return its retry configurations:
  they are authenticated by that certificate, and CT is what would reveal
  a mis-issued one.
- QUIC-TLS and DTLS tests check certificate authentication with both
  offers and refusal when the CT offer is absent. DTLS tests include the
  address-bound cookie retry in both versions.
- Early data is sent only on resumption or with an external PSK, before
  any server certificate arrives. A resumption evaluates no certificate;
  an RFC 9973 handshake (certificate with an external PSK) evaluates the
  certificate like a full handshake, after the 0-RTT data was sent.
- Delegated credentials (RFC 9345): the policy covers the end-entity
  certificate that signs the credential; the credential is not logged.
- `Acceptor`, `UnbufferedAcceptor` and the Tokio `LazyConfigAcceptor`: the
  configuration chosen after the ClientHello supplies the list through
  its certificate resolver, and the offer is read from that ClientHello.
- Exported authenticators (RFC 9261) use the `ExportedAuthenticator`
  verification context with live revocation disabled. An entry carrying
  `transparency_info` is refused as unsolicited. Under a CT 2.0 policy an
  authenticator therefore passes only with SCTs embedded in its certificate.

The TLS tests run browntls against itself on both providers through
buffered and unbuffered core and Tokio connections, including the lazy
acceptor. A blocking Linux kTLS test checks the userspace CT decision
before handoff and authenticated data exchange after handoff.

## Crypto provider mount point

`browntls_core::crypto` defines the provider interface, modelled on rustls 0.23
so that existing provider designs map onto it:

- `CryptoProvider`: cipher suites, key-exchange groups, signature
  verification algorithms, secure random source and private-key loader. A
  process default can be installed; configurations can also be built with an
  explicit provider.
- Traits for each capability: hashing, HMAC, HKDF (TLS 1.3), PRF (TLS 1.2),
  record protection (`Tls13AeadAlgorithm`, `Tls12AeadAlgorithm`,
  `Tls12BlockCipherAlgorithm`, `MessageEncrypter`, `MessageDecrypter`), key
  exchange (`SupportedKxGroup`,
  `ActiveKeyExchange`, including hybrid post-quantum groups), signing
  (`SigningKey`, `Signer`), randomness and key loading, plus hooks that export
  traffic secrets for kernel TLS offload.

Extracted secrets (`ExtractedSecrets`) are in the form Linux kernel TLS takes.
TLS 1.2 AES-GCM gives record `seq` the explicit nonce `seed + seq` (modulo
2^64, the seed coming from the key block), and the extracted IV carries the
explicit nonce of the next record: the kernel counts up from the value it is
given, so it continues the library's sequence exactly. TLS 1.3 and
ChaCha20-Poly1305 nonces are the IV XORed with the sequence number on both
sides.

Providers shipped in the `browntls-core` crate:

| Provider | Feature | Backing |
|---|---|---|
| `crypto::native` | `native` (default) | `browntls-crypto` |
| `crypto::rustcrypto` | `rustcrypto` | RustCrypto crates |

A provider is plain data (static trait objects), so applications can build a
mixed provider, for example native AEADs with RustCrypto signatures, or supply
their own implementation of any trait;
`crates/browntls-core/tests/native_mixed.rs` shows the pattern. When exactly one
provider feature is enabled it becomes the implicit default; with both enabled,
the application installs one explicitly.

### Algorithm tiers (native provider)

Everything RFC 9846 §9.1 makes mandatory or recommended is preferred. The
remaining TLS 1.3 algorithms that RFC 9846 defines form a non-preferred tier:
they come after every other entry of each preference list, so they are only
negotiated when a peer shares nothing earlier.

| Kind | Preferred (default order) | Non-preferred tier (default) | Opt-in only (`ALL_*` lists) |
|---|---|---|---|
| TLS 1.3 suites | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 | AES-128-CCM, then AES-128-CCM-8 (64-bit tag; no kernel TLS export) | |
| TLS 1.2 suites | ECDHE with AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 (ECDSA and RSA) | ECDHE AES-CBC: AES-256-CBC-SHA384, AES-128-CBC-SHA256, then AES-256-CBC-SHA, AES-128-CBC-SHA (ECDSA and RSA; RFC 5289, RFC 8422); Encrypt-then-MAC only by default; no kernel TLS export | |
| Groups | X25519MLKEM768, X25519, P-256, P-384 | X448, then FFDHE2048, FFDHE3072, FFDHE4096 (TLS 1.3 only, RFC 10015 §3) | FFDHE6144, FFDHE8192 (server cost 10 to 20 ms per handshake); the other ML-KEM groups and P-521 |
| Signature schemes | ECDSA, Ed25519, RSA-PSS (rsae), RSA PKCS #1 v1.5 | Ed448, then `rsa_pss_pss_sha512/384/256` (RSASSA-PSS public keys) | `mldsa44`, `mldsa65`, `mldsa87` after every default scheme (TLS 1.3 only, experimental: `SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13`, see [below](#ml-dsa-tls-13-authentication-opt-in-experimental)); `rsa_pkcs1_sha512/384/256_legacy` after every default scheme (a TLS 1.3 client's `CertificateVerify` only: `SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY`, see [below](#legacy-rsa-client-authentication-in-tls-13-rfc-9963-opt-in)) |
| Certificate and CRL signatures only (no TLS scheme) | the algorithms of the signature schemes above | | ML-DSA-44, -65, -87 (`ALL_VERIFICATION_ALGS_WITH_ML_DSA`, see [below](#ml-dsa-certificate-verification-native-provider-opt-in)) |

A browntls server applies the same ranking whatever the client's order:
within each tier it follows the client's order of suites (or its own with
`ignore_client_order`) and its own order of groups (the first of its groups
the client sent a key share for, otherwise the first both support), but it
picks a non-preferred suite or group only when
no preferred one is mutually supported, and it answers a key share for a
non-preferred group with a HelloRetryRequest when a preferred group is
available (`CipherSuite::is_non_preferred`, `NamedGroup::is_non_preferred`).
With AES-128-CCM-8, a server that rejects 0-RTT fails the handshake once 2^7
records have failed authentication under the client handshake key (RFC 9147
Appendix B.3), including the client's own early-data records.

The RustCrypto provider does not implement the non-preferred tier.

### ML-DSA certificate verification (native provider, opt-in)

`crypto::native::verify` has ML-DSA verification algorithms (`ML_DSA_44`,
`ML_DSA_65`, `ML_DSA_87`, type `MlDsaVerify`) over `browntls_crypto::mldsa`:
pure ML-DSA with the empty context (RFC 9881 §3), the public key being the
FIPS 204 encoding in the `subjectPublicKey` BIT STRING, and both identifiers
the RFC 9881 `id-ml-dsa-*` identifier with absent parameters, matched byte
for byte. A key or signature of the wrong length, and every other failure,
is an invalid signature; verification does not allocate.

They are not in the defaults: `ALL_VERIFICATION_ALGS`, `SUPPORTED_SIG_ALGS`
and `default_provider()` are unchanged, so a default configuration rejects
an ML-DSA-signed certificate or CRL as an unsupported signature algorithm
(alert `bad_certificate` from a TLS 1.3 client, since the failing signature
is inside the chain). An application opts in with
`SUPPORTED_SIG_ALGS_WITH_ML_DSA`, whose `all` list is
`ALL_VERIFICATION_ALGS_WITH_ML_DSA` (the default list, computed at compile
time, followed by `ML_DSA_VERIFICATION_ALGS`) and whose `mapping` is the
unchanged `VERIFICATION_ALG_MAPPING`. Set as a provider's
`signature_verification_algorithms`, it makes ML-DSA signatures verify
wherever the library verifies with the `all` list: certificate paths in
`WebPkiServerVerifier` and `WebPkiClientVerifier` (with or without a
revocation policy), the CRLs checked in them, OCSP response and delegated
responder signatures (stapled responses under a `RevocationPolicy` and the
initial staple of `ServerStapleResolver`, both tested; responses that
resolver installs later, live-fetched responses and those read for the
Certificate Transparency 2.0 requirements use the same list but are not
tested with ML-DSA) and the server chain `ServerStapleResolver`
validates. Certificate Transparency logs cannot have ML-DSA keys (version 1
SCTs name no ML-DSA algorithm, version 2 logs are P-256 or Ed25519).

Opting in has a cost per signature: one ML-DSA verification took about 73,
113 and 180 µs for ML-DSA-44, -65 and -87 in a measurement on one x86-64
machine (on the order of 0.1 ms), and path building stays bounded by the
existing budget of 100 signature checks per validation
(`crates/browntls-pki/src/path.rs`).

With this table the TLS side does not change. The `signature_algorithms`
lists a browntls peer sends come from the verifier's scheme mapping, which
here has no ML-DSA scheme, so they are identical with and without the
opt-in, and a `CertificateVerify` or `ServerKeyExchange` signed with an
ML-DSA scheme is refused as unadvertised. Nothing on the wire tells a peer
that ML-DSA chains are accepted, and `KEY_PROVIDER` loads no ML-DSA private
key. The opt-in is for X.509 validation through the verifiers and
`browntls_pki`: chains with ML-DSA certificates anywhere validate, including
an ML-DSA end entity certificate, but only a classical end entity key can
then authenticate a TLS handshake. TLS 1.3 authentication with ML-DSA keys
is a further, separate opt-in
([ML-DSA TLS 1.3 authentication][ml-dsa-tls13]). The RFC 9881 §5 key usage
rules for
ML-DSA keys are enforced by `browntls-pki` with or without the opt-in; a
violation is reported as `CertificateError::Other` (alert
`certificate_unknown`), like other key usage failures. The RustCrypto
provider has the same opt-in, described below; its default provider does not
verify ML-DSA either.

Whichever verifier or algorithm table names the ML-DSA signature
schemes (`mldsa44`, `mldsa65`, `mldsa87`; `draft-ietf-tls-mldsa-06`
specifies them for TLS 1.3 `CertificateVerify` and certificate signatures),
the library uses them for handshake signatures in TLS 1.3 only
(`SignatureScheme::is_ml_dsa`, crate-private, which goes by the code point).
A TLS 1.2 handshake does not list them in a CertificateRequest or pass them
to a certificate resolver or key (a TLS 1.2 ClientHello that names no other
scheme fails with `handshake_failure`), and both sides refuse them in
`ServerKeyExchange` and `CertificateVerify` whatever the cipher suite and
the verifier say (`verify_tls12_signature` and
`verify_tls12_signature_with_raw_key` also reject them before looking at
the table). A key whose signer names one of them in a TLS 1.2 handshake,
against the list it was given, fails the handshake with `internal_error`.
A ClientHello that does not offer TLS 1.3 leaves them out of
`signature_algorithms`. Delegated credentials (RFC 9345) are not issued,
loaded or accepted with an ML-DSA credential key or delegation signature,
and exported authenticators (RFC 9261) do not request, offer or accept the
schemes: no specification defines ML-DSA for either, so the combinations
are not enabled by assumption. All of this is about handshake signatures
and what `signature_algorithms` says. Certificate path signatures are
verified with the table's `all` list in every protocol version, so a chain
with ML-DSA-signed certificates and a classical end entity also validates
in TLS 1.2 under the opt-in.
`crates/browntls-core/tests/mldsa_tls13_only_rules.rs` checks these rules
with test doubles (verifiers, keys and cipher suites that name the schemes)
and with rewritten handshake messages.

`crates/browntls-core/tests/native_mldsa.rs` checks the algorithms against
the RustCrypto `ml-dsa` crate (signatures of each verified by the other, and
identical deterministic signatures), the RFC 9881 Appendix C certificates,
paths, CRLs, stapled OCSP responses and TLS 1.3 handshakes with both tables.

### ML-DSA certificate verification (RustCrypto provider, opt-in)

`crypto::rustcrypto::verify` has the same three algorithms (`ML_DSA_44`,
`ML_DSA_65`, `ML_DSA_87`, type `MlDsaVerify`) backed by the RustCrypto
`ml-dsa` crate, an optional dependency enabled by the `rustcrypto` feature
(see [Maintenance](Maintenance.md#rustcrypto-ml-dsa-dependency)): pure
ML-DSA with the empty context, the same identifiers matched byte for byte,
the raw FIPS 204 key, and every failure an invalid signature. Unlike the
native algorithms they allocate (the `ml-dsa` crate keeps the expanded
public matrix and the decoded signature on the heap) and need more stack,
because the matrix is built there first: about 64 to 80 KiB for one
ML-DSA-87 verification against under 32 KiB, measured on one x86-64 host.
The tables mirror the
native ones: `rustcrypto::SUPPORTED_SIG_ALGS` and `default_provider()` are
unchanged; `ML_DSA_VERIFICATION_ALGS`, `ALL_VERIFICATION_ALGS_WITH_ML_DSA`
(the `all` list of `SUPPORTED_SIG_ALGS`, computed at compile time with the
helper the native tables use, followed by the ML-DSA algorithms) and
`SUPPORTED_SIG_ALGS_WITH_ML_DSA` (with the unchanged `mapping`) are the
opt-in. Everything said above about where the opt-in applies and the
unchanged `signature_algorithms` lists holds for it too, and TLS 1.3
authentication with ML-DSA keys is likewise a separate opt-in
([ML-DSA TLS 1.3 authentication][ml-dsa-tls13]).

`crates/browntls-core/tests/rustcrypto_mldsa.rs` checks the RustCrypto
algorithms with signatures by `browntls_crypto::mldsa` and by the `ml-dsa`
crate, signatures with a non-empty context, the RFC 9881 Appendix C
certificates, agreement with the native algorithms on valid and mutated
inputs (including malformed hint encodings) for every parameter set, paths
and a TLS 1.3 handshake with an ML-DSA CA chain and an ECDSA end entity,
with the opt-in table and with the default provider.

### ML-DSA TLS 1.3 authentication (opt-in, experimental)

TLS 1.3 authentication with ML-DSA keys follows `draft-ietf-tls-mldsa-06`
("Use of ML-DSA in TLS 1.3"), pinned at that revision: an Internet-Draft,
not a published RFC, whose code points `mldsa44` (0x0904), `mldsa65`
(0x0905) and `mldsa87` (0x0906) are registered with "Recommended: N". A
`CertificateVerify` under one of these schemes is pure ML-DSA (FIPS 204
ML-DSA.Sign and ML-DSA.Verify) over the RFC 9846 §4.5.2 content with the
empty FIPS 204 context string, and the end-entity key must be the ML-DSA
key of the same parameter set (§3.2 of the draft). The support is
experimental and off by default: `default_provider()` neither offers nor
accepts the schemes and loads no ML-DSA private key. A later revision or
the published RFC may change the behaviour; the opt-in items are the only
entry points, so nothing else in a configuration depends on the draft.

A provider opts in through two independent fields, here for the native
provider:

- `native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13` as
  `signature_verification_algorithms`. Its `all` list is
  `ALL_VERIFICATION_ALGS_WITH_ML_DSA` (as for certificate paths above) and
  its `mapping` is `VERIFICATION_ALG_MAPPING_WITH_ML_DSA`: the default
  mapping followed, in a list computed at compile time, by
  `ML_DSA_VERIFICATION_ALG_MAPPING`, which maps each scheme to the one
  algorithm of its parameter set. A verifier built from it lists the three
  schemes, after every default scheme, in the `signature_algorithms` of
  each ClientHello that offers TLS 1.3 and of each TLS 1.3
  CertificateRequest, so the opt-in is visible on the wire, and it accepts
  a TLS 1.3 `CertificateVerify` under one of them. Because a scheme maps
  to one algorithm and algorithms are matched to the key's
  `AlgorithmIdentifier` byte for byte, a signature under `mldsa65` verifies
  only with an `id-ml-dsa-65` end-entity key. A key of another parameter
  set, a classical key or an identifier with parameters is refused as an
  unsupported signature algorithm for that key, and a signature that does
  not verify (one made with a non-empty FIPS 204 context included) as a
  bad signature, both with a `decrypt_error` alert. The browntls peers
  never send `signature_algorithms_cert`, so the one list also states
  which certificate signatures are accepted (RFC 9846 §4.3.3),
  consistently with the `all` list.
- `native::KEY_PROVIDER_WITH_ML_DSA` as `key_provider`. It loads what
  `KEY_PROVIDER` loads and, for a PKCS #8 key that fails there, an ML-DSA
  key (`sign::any_ml_dsa_type`: the RFC 9881 §6 encoding in the `seed`,
  `expandedKey` or `both` form, with the §8.2 consistency check). The key
  (`sign::MlDsaSigningKey`) offers a signer only for the scheme of its own
  parameter set and only when the peer listed it, so the scheme a peer
  signs with is fixed by its key and must have been offered by the
  verifying side; there is no fallback to another scheme. Signing is
  hedged with 32 bytes from the operating system for each signature and
  fails without them (`FailedToGetRandomBytes`, alert `internal_error`).
  HashML-DSA is not used. Signing needs about 42, 66 and 102 KiB of stack
  for ML-DSA-44, -65 and -87 on the thread driving the handshake (release
  builds on x86-64; unoptimised builds need more).

A side may set either field alone: a client that only verifies ML-DSA
servers needs the table, a server that only presents an ML-DSA certificate
needs the key provider. The role checks are those of every scheme: a
client accepts a server `CertificateVerify` only under a scheme it offered
in its ClientHello, a server accepts a client `CertificateVerify` only
under a scheme of its CertificateRequest (initial or post-handshake), and
an unoffered scheme is refused with `illegal_parameter` before the
`CertificateVerify` signature is checked. A TLS 1.3 server whose keys can
sign with none of the client's schemes fails with `handshake_failure`
(`NoSignatureSchemesInCommon`), which is what a client without the opt-in
gets from a server that has only an ML-DSA key.

An ML-DSA key reports `SignatureAlgorithm::Unknown(255)`, a value the
TLS 1.2 `SignatureAlgorithm` registry does not assign, as its key family,
so no TLS 1.2 cipher suite and no TLS 1.2 client certificate type matches
it: a server holding only an ML-DSA key completes no TLS 1.2 handshake
(`NoCipherSuitesInCommon`, alert `handshake_failure`).
Together with the rules of the previous section, ML-DSA appears in
TLS 1.3 handshakes (and so in QUIC and DTLS 1.3) only, never in TLS 1.2 or
DTLS 1.2, in delegated credentials or in exported authenticators. A peer
without the opt-in fails the handshake with an ML-DSA-only peer as with
any key type it does not support; nothing falls back to another algorithm
unless the application configures a second certified key and a resolver
that chooses by the offered schemes.

The RustCrypto provider has the same opt-in under the same names
(`rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13`,
`rustcrypto::KEY_PROVIDER_WITH_ML_DSA`, `rustcrypto::sign::any_ml_dsa_type`
and `MlDsaSigningKey`), backed by the RustCrypto `ml-dsa` crate (see
[Maintenance](Maintenance.md#rustcrypto-ml-dsa-dependency)), with the same
table order, scheme binding, hedged signing from the operating system's
random source and TLS 1.2 behaviour. It loads the same RFC 9881 private
keys: the `seed`, `expandedKey` and `both` forms (the `both` form only
when its expanded key is the one its seed derives), from a PKCS #8
structure the provider parses itself, in strict DER, to the same rules as
`browntls_crypto::mldsa`. The crate has no checked decoding of an expanded
key, so the provider checks an `expandedKey` before the crate decodes it
(`crypto/rustcrypto/sign_mldsa/expanded.rs`): the `s1` and `s2`
coefficients are in range, and `t0` and `tr` are the values that `rho`,
`s1` and `s2` determine, recomputed with the provider's own constant-time
arithmetic and the `shake` crate; a key loads only if the crate then
derives the same public key. These are the native provider's checks, and
the loaders are tested and fuzzed for agreement. It differs in two ways.
It needs more stack, above all to load a key: for ML-DSA-87 on x86-64,
about 100 to 145 KiB to sign and 260 to 430 KiB to load a key in
optimised builds, and up to about 512 KiB and 1.25 MiB in an unoptimised
one (the native provider: about 102 KiB and 20 KiB, optimised). And the
crate wipes the stored key
on drop but not the temporaries of key derivation and signing, which the
native implementation wipes (the native one, in turn, does not wipe its
SHAKE states, which the crate does).

A handshake between the two providers works
in both directions; `crates/browntls-core/tests/mldsa_tls13.rs` runs the
same cases as the native target with the RustCrypto provider, and
`tests/rustcrypto_mldsa.rs` checks that both providers load the same keys
to the same `SubjectPublicKeyInfo`, verify each other's signatures and
agree on the RFC 9881 Appendix C keys and on malformed encodings.

The transports that carry the TLS 1.3 handshake use the opt-in unchanged.
QUIC (RFC 9001) carries the larger flight in CRYPTO frames (about 10, 14
and 19 kB at the Handshake level for an ML-DSA-44, -65 and -87 server
chain of two certificates). DTLS 1.3 fragments and reassembles it (an
ML-DSA-87 mutual handshake is about 22 kB of handshake-epoch datagrams in
each direction at the default MTU, within the reassembly limits) and
retransmits lost fragments; at a small MTU a flight of more than 32
records is acknowledged in parts, which costs extra retransmissions.
DTLS 1.2 follows the TLS 1.2 rules above. The unbuffered API, the Tokio
streams and the `browntls` facade need nothing beyond the provider fields
(a Tokio worker's default 2 MiB stack is ample for either provider), and
kernel TLS offload starts after authentication, a later post-handshake
authentication being handled in user space.
`crates/browntls-core/tests/mldsa_transports.rs`,
`crates/browntls-tokio/tests/mldsa.rs` and `crates/browntls/tests/mldsa.rs`
cover these with the native provider.

Resumption needs nothing specific: a resumed handshake has no
`CertificateVerify`. As with every algorithm, a client's sessions are bound
to its verifier, so a configuration without the opt-in does not resume a
session made with it, while a server resumes a ticket its ticketer can
open whatever table its client verifier has by then. Tickets issued after
mutual authentication carry the client's chain and grow with it (two
tickets take about 35 kB after an ML-DSA-87 chain of two certificates).

`crates/browntls-core/tests/mldsa_tls13_native.rs` runs the cases of
`tests/cases/mldsa_tls13.rs` with the native provider: server, client and
mutual authentication for every parameter set with the exact scheme of
each `CertificateVerify`, mixed classical and ML-DSA chains, each opt-in
alone, peers without the scheme, keys and signers that break the rules
(another parameter set, a classical scheme for an ML-DSA key and the
reverse, an unoffered scheme, damaged signatures, a non-empty context),
a server with a classical and an ML-DSA key, HelloRetryRequest,
resumption, post-handshake authentication, certificate compression, raw
public keys, and the delegated credential and exported authenticator
refusals.

Interoperability is tested with OpenSSL 3.5 and nothing else:
`crates/browntls-core/tests/openssl_interop.rs` (`mldsa`, skipped where
the `openssl` tool lists no ML-DSA TLS scheme) and the Docker end-to-end
scenarios `tls13-mldsa*` ([end-to-end tests](../tests/e2e/README.md)), in
both roles, with client authentication, with the scheme fixed on the
OpenSSL side, and with the `seed`, `expandedKey` and `both` private key
forms OpenSSL writes (`both` by default). No other implementation has
been tried: the Go peer of the end-to-end tests implements the schemes
but its harness is limited to Encrypted Client Hello and reads only
`seed` keys, and the GnuTLS, wolfSSL, BoringSSL and pion peers there are
not built with ML-DSA authentication. The draft publishes no handshake
test vectors. Not covered by any test: Encrypted Client Hello with an
ML-DSA server, the Tokio DTLS adapter, a real kernel offload, a failing
randomness source during a handshake, and fuzzing of handshakes with
ML-DSA identities (the fuzz targets cover the key loaders only). The
support stays experimental until the draft is published and these gaps
are closed.

### Legacy RSA client authentication in TLS 1.3 (RFC 9963, opt-in)

TLS 1.3 signs handshakes with RSASSA-PSS, which some RSA keys cannot make:
keys in hardware tokens or operating system key stores that offer
RSASSA-PKCS1-v1_5 only.
[RFC 9963](https://www.rfc-editor.org/rfc/rfc9963.html) registers
`rsa_pkcs1_sha256_legacy` (0x0420), `rsa_pkcs1_sha384_legacy` (0x0520) and
`rsa_pkcs1_sha512_legacy` (0x0620), with "Recommended: N", for one use:
the signature in a TLS 1.3 client's `CertificateVerify`. browntls
implements that use, with an `rsaEncryption` certificate key, and refuses
every other. As §3 of the RFC asks, the schemes are off by default:
`default_provider()` lists none of them and its key provider loads no key
that chooses one, so a configuration that names none of the items below
behaves as before.

Each side opts in separately, here for the native provider:

- A server sets `native::SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY` as the
  `signature_verification_algorithms` of the provider its client
  certificate verifier is built with. Its `mapping` is
  `VERIFICATION_ALG_MAPPING_WITH_RSA_PKCS1_LEGACY`: the default mapping
  followed by `RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING`, which maps each
  legacy scheme to the RSASSA-PKCS1-v1_5 algorithm of its hash. Its `all`
  list is the default one, since the schemes add no certificate signature
  algorithm. The TLS 1.3 CertificateRequest of such a server, in the
  handshake and in post-handshake authentication, lists the three schemes
  after every default scheme (0x0620, 0x0520, 0x0420), so the opt-in is
  visible on the wire, and the server accepts a client `CertificateVerify`
  under one of them. `WebPkiClientVerifier` checks it with
  `crypto::verify_tls13_client_signature`, which a custom
  `ClientCertVerifier` calls for the same behaviour (there is a raw public
  key variant). `verify_tls13_signature`, which checks every other TLS 1.3
  signature, refuses the legacy schemes whatever table it is given.
- A client gives its certificate a key that chooses a legacy scheme.
  `native::sign::any_rsa_pkcs1_legacy_type` loads an `rsaEncryption`
  private key (PKCS #8 or PKCS #1, 2048 to 8192 bits) as an
  `RsaPkcs1LegacySigningKey`, which signs with RSASSA-PKCS1-v1_5 alone:
  in a TLS 1.3 CertificateRequest, `rsa_pkcs1_sha512_legacy`,
  `rsa_pkcs1_sha384_legacy` or `rsa_pkcs1_sha256_legacy`, the first of
  these, in that order, that the request lists; in TLS 1.2,
  `rsa_pkcs1_sha512`, `rsa_pkcs1_sha384` or `rsa_pkcs1_sha256`.
  It stands for a key that cannot do better. A key that lives in a token
  is used through the application's own `SigningKey`, which chooses a
  legacy scheme from the list it is offered by its own rule; browntls adds
  no token or key store interface. No key provider loads the type, so the
  choice is made per key, and the other RSA keys never choose a legacy
  scheme: a key that can make RSASSA-PSS signatures keeps making them
  when the request lists the legacy schemes too (RFC 9963 §3).

The client needs no table and the server no key. A legacy key whose
server did not opt in finds no scheme to sign with, and the client sends
an empty Certificate message, which a server that requires a certificate
answers with `certificate_required`.

The rules hold by code point, whatever a verifier, a resolver or a key
says:

- A ClientHello never lists a legacy scheme, in TLS or DTLS, even when the
  client's server verifier advertises one.
- A client refuses a server `CertificateVerify` under a legacy scheme with
  `illegal_parameter`, before a signature is checked. A TLS 1.3 server's
  key is never offered one, and a server whose key returns a legacy signer
  anyway fails with `internal_error` before it signs. Server
  authentication with an RSA key still requires RSASSA-PSS.
- A server accepts a legacy scheme only if its CertificateRequest listed
  it. A server without the opt-in answers a client that signs with one
  with `illegal_parameter`, before its verifier is called. A browntls
  client sends no such message: a key that names a legacy scheme the
  request did not list is treated as one that cannot sign.
- TLS 1.2 and DTLS 1.2 never use the schemes: no CertificateRequest lists
  them, no key is offered them, and a ServerKeyExchange or
  CertificateVerify under one is refused. Like the ML-DSA schemes they
  are TLS 1.3 only.
- Delegated credentials (RFC 9345) and exported authenticators (RFC 9261)
  never use them, in either role.

A legacy signature verifies only as RSASSA-PKCS1-v1_5 in the encoding of
RFC 8017 §8.2 with the scheme's hash, over the RFC 9846 §4.5.2 content.
The native provider builds the expected encoded message, the DER
`DigestInfo` with its NULL parameters included, and compares it in full
with the one the signature opens to; it parses nothing. With either
provider a `DigestInfo` without the NULL, with a BER length or with
another hash's identifier, a bare digest, and a signature shorter or
longer than the modulus are bad signatures (`decrypt_error`), as are an
RSASSA-PSS signature named as a legacy scheme and the reverse. The
certificate key must be an `rsaEncryption` key: with an `id-RSASSA-PSS`,
ECDSA or EdDSA key the scheme is refused as unsupported for that key.

The RustCrypto provider has the same table under the same names
(`rustcrypto::SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY` and the two
mappings), so a server using it accepts legacy clients. It has no key
type, because it does not sign with RSA; a client using it supplies its
own `SigningKey`.

The transports that carry the TLS 1.3 handshake use the opt-in unchanged:
QUIC (RFC 9001), DTLS 1.3 (which retransmits a lost client flight with
its legacy `CertificateVerify`), the unbuffered API, the Tokio streams
and the `browntls` facade need nothing beyond the provider field and the
key. Kernel TLS offload starts after authentication, and a later
post-handshake authentication with a legacy scheme is handled in user
space in either role. DTLS 1.2 follows the TLS 1.2 rules above.
Resumption needs nothing specific: a resumed handshake has no
`CertificateVerify`.
`crates/browntls-core/tests/rsa_pkcs1_legacy_transports.rs`,
`crates/browntls-tokio/tests/rsa_pkcs1_legacy.rs` and
`crates/browntls/tests/rsa_pkcs1_legacy.rs` cover these with the native
provider's key.

`crates/browntls-core/tests/rsa_pkcs1_legacy_rules.rs` drives the rules
with test doubles: verifiers that advertise the legacy schemes, keys that
claim them and handshake messages rewritten on the wire.
In the same directory, `rsa_pkcs1_legacy_native.rs` and
`rsa_pkcs1_legacy.rs` run the cases of `cases/rsa_pkcs1_legacy.rs` with
the native and the RustCrypto provider: each scheme in the handshake and
after it, the CertificateRequest with and without the opt-in, an
unchanged ClientHello, RSASSA-PSS for a capable key and for an RSA server,
the malformed encodings above, scheme and key mismatches, and TLS 1.2. In
the shared cases the client's legacy key is a double on the `rsa` crate,
so the signatures the providers verify are made by an independent RSA
implementation; the native target adds cases with its own key. The fuzz
target `tls_config` checks the key, the verification functions and a
model of client authentication over fuzz-chosen keys, schemes and
signature forms, and `tls_auth` that an exported authenticator refuses
the schemes ([fuzz targets](../fuzz/README.md)).

Interoperability is tested with rustls 0.23 and nothing else, in memory
in the same test targets. rustls does not implement the schemes, but it
sends whatever scheme a custom signer names, so it is an independent
implementation of the handshake and of the signed content: an opted-in
browntls server accepts a rustls client that signs with 0x0420, a server
without the opt-in refuses it, and browntls clients refuse a rustls
server that signs its own `CertificateVerify` with 0x0420. No
implementation of RFC 9963 itself has been tried. Of the peers of the
[end-to-end tests](../tests/e2e/README.md), the OpenSSL and Go sources
examined in November 2026 name none of the code points, and GnuTLS and
wolfSSL were not examined. BoringSSL, a peer of the delegated credential
harness only, implements `rsa_pkcs1_sha256_legacy` alone in its current
sources; the revision that harness pins was not checked, and no handshake
with it has been tried. The RFC publishes no test vectors. Not covered by
any test: a key in a real token or key store, Encrypted Client Hello with
a legacy client, and a real kernel offload.

### Post-quantum hybrid key agreement (RFC 10024)

Both the native and RustCrypto providers implement the three
[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) groups. They work
with TLS 1.3, DTLS 1.3, and TLS 1.3 over QUIC v1. The default lists include
`X25519MLKEM768`, with its position controlled by the
`prefer-post-quantum` feature. The P-256 and P-384 hybrids are opt-in
through each provider's `kx_group` module or `ALL_KX_GROUPS`.

Set `CryptoProvider::kx_groups` before constructing the client and server
configurations. A list containing only hybrid groups requires a hybrid
exchange. Include a classical group if the endpoint may negotiate one.
Buffered and unbuffered connections, QUIC, and Tokio use those same
configurations. kTLS uses the traffic keys derived by the userspace
handshake. The connection's `negotiated_key_exchange_group()` exposes the
result once the exchange completes.

The protocol concatenates the ECDHE and ML-KEM components in the order
defined for each group, then feeds the result into the existing TLS 1.3
key schedule. First-generation Kyber draft identifiers are obsolete.
When an initial DTLS ClientHello with a hybrid share would exceed the
datagram budget, the client offers the group with an empty key-share
list. The HelloRetryRequest selects the group, and the second ClientHello
can carry the share across fragments after the cookie in its first
fragment. This keeps the stateless acceptor's address-validation policy.

### Protocol version policy (RFC 9852, RFC 9851)

A configuration enables a list of protocol versions, fixed when it is built.
`ClientConfig::builder()`, `ServerConfig::builder()` and
`with_safe_default_protocol_versions()` take `DEFAULT_VERSIONS`: every
version of the build, which is TLS 1.3 and, with the `tls12` feature,
TLS 1.2. `builder_with_protocol_versions(&[..])` and
`with_protocol_versions(&[..])` take exactly the versions they are given.
The order of a list means nothing: two peers that both have TLS 1.3
negotiate it.

RFC 9852 §4 requires a new protocol that uses TLS to specify TLS 1.3 as its
default, and lets it name TLS 1.2 as an additional, non-default option. That
is a requirement on the protocol and on the application that implements it.
browntls is a general-purpose library and keeps its default list for the
deployed protocols that still meet TLS 1.2 peers: TLS 1.3 is preferred and
TLS 1.2 stays enabled where it is built. An application of a new protocol
lists TLS 1.3 itself and does not rely on the default:

```rust
use browntls::{ClientConfig, ProtocolVersion, ServerConfig, version};

let client = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
    .with_root_certificates(roots)
    .with_no_client_auth();
let server = ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
    .with_no_client_auth()
    .with_single_cert(chain, key)?;

// After the handshake, on either side:
assert_eq!(conn.protocol_version(), Some(ProtocolVersion::TLSv1_3));
```

`with_tls13_only()` on a builder and `ClientConfig::builder_tls13_only()` /
`ServerConfig::builder_tls13_only()` are that list under a name: they do
what `&[&version::TLS13]` does and nothing more. `supports_version()` on
either configuration reports whether its list holds a version, so that code
which receives a configuration can check it against a policy
(`!config.supports_version(ProtocolVersion::TLSv1_2)`). It reports the
list, not what the provider can negotiate: a version of the default list is
reported even when the provider has no cipher suite for it.

A protocol that keeps TLS 1.2 as its non-default option lists both versions
(`&[&version::TLS13, &version::TLS12]`, which needs the `tls12` feature):
TLS 1.3 is then used with every peer that has it.

The list is the policy; the `tls12` Cargo feature is not. It is a default
feature, and Cargo builds one `browntls-core` with every feature that any
crate of the application asked for, so a dependency can bring TLS 1.2 back
into the `DEFAULT_VERSIONS` of an application that turned the feature off.
Turning it off removes the TLS 1.2 code from a build that nothing else
needs it in. What a connection may negotiate is decided by the list in
either build.

With TLS 1.3 alone in the list:

- A client names `0x0304` alone in `supported_versions`, offers the
  provider's TLS 1.3 suites and no TLS 1.2 suite (the signalling value of
  RFC 5746 §3.3 is left out too; a GREASE value still leads the list when
  `enable_grease` is set), sends none of the extensions that only TLS 1.2
  reads, and does not offer a TLS 1.2 session of its resumption store.
- A client that is answered with TLS 1.2 fails with
  `PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig` and a
  `protocol_version` alert.
- A server refuses a ClientHello that does not offer TLS 1.3 with a
  `protocol_version` alert: `PeerIncompatible::Tls12NotOfferedOrEnabled`
  when `supported_versions` lists older versions only,
  `SupportedVersionsExtensionRequired` when the extension is absent and
  `legacy_version` is TLS 1.2 or higher, and `Tls12NotOffered` when it is
  absent and `legacy_version` is lower. The version is checked before
  `TLS_FALLBACK_SCSV`, so a fallback probe gets the same answer, which
  RFC 7507 §3 allows in place of `inappropriate_fallback`.
- Neither side tries again with another version. The refusal is the
  application's error to report, and a retry over TLS 1.2 could only come
  from the application building a second configuration.
- The configuration fields that concern TLS 1.2 alone
  (`allow_mac_then_encrypt`, `require_ems`, `require_secure_renegotiation`,
  `trusted_ca_keys`, client certificate URLs) have no effect on the
  handshake. `require_ems` still enters `fips()`, whatever the list.
- A provider without a TLS 1.3 suite is refused when the configuration is
  built (`no usable cipher suites configured`).

A configuration with both versions keeps the downgrade protection of
RFC 9846 §4.1.3: a client that offered TLS 1.3 and is answered with
TLS 1.2 by a server whose random carries the sentinel fails with
`PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported` and an
`illegal_parameter` alert, and a server answers `TLS_FALLBACK_SCSV` in a
hello below its highest version with `inappropriate_fallback`.

The policy belongs to the configuration, wherever it is handed over.
`server::Acceptor` and `browntls_tokio::LazyConfigAcceptor` read a
ClientHello before any configuration exists, so they apply no version
policy themselves: the configuration passed to `into_connection` or
`into_stream` accepts or refuses the hello. The buffered and unbuffered
connections, the Tokio streams and the kernel TLS handoff all run the
handshake of `browntls-core` over the same configuration types. A QUIC
connection offers and accepts TLS 1.3 alone whatever the list holds, and a
configuration without TLS 1.3 cannot be used for one (RFC 9001 §4.2).

Neither RFC covers DTLS. A DTLS endpoint speaks a DTLS version only when
its own `dtls::Versions` policy and the configuration's list both have the
matching TLS version, so a configuration that lists TLS 1.3 alone never
speaks DTLS 1.2 (see [DTLS 1.3](#dtls-13-rfc-9147)).

#### TLS 1.2 compatibility

Nothing changes for an application that uses TLS 1.2 today: the default
list still enables it wherever the `tls12` feature is built, `tls12`
remains a default feature, and a list of `&[&version::TLS12]` still makes a
TLS 1.2-only configuration. With both versions enabled, TLS 1.2 is used
only with a peer that does not have TLS 1.3.

RFC 9851 freezes TLS 1.2 in the IETF: apart from urgent security fixes,
new exporter labels and new ALPN protocol IDs, new work is specified and
registered for TLS 1.3 or later. That binds the specifications, not a
library, and browntls takes the same position for its own work: TLS 1.2
support is kept for compatibility and receives security fixes, and new
protocol features are added for TLS 1.3. Of the features here, the hybrid
post-quantum groups (RFC 10024), ML-DSA authentication, Encrypted Client
Hello, delegated credentials and certificate compression are TLS 1.3 only
by their specifications, and external PSKs are implemented for TLS 1.3
alone. An application that needs one of them, or post-quantum key
agreement at all, needs TLS 1.3 with every peer, which is what a
TLS 1.3-only list states.

### TLS 1.2 record protection

TLS 1.2 suites are either `GenericAEADCipher` or `GenericBlockCipher`
(RFC 5246 §6.2.3); `Tls12RecordProtection` names which, and the key block
(RFC 5246 §6.3) is split accordingly (`KeyBlockShape`). Stream ciphers (RC4,
RFC 7465) and the RSA and finite-field Diffie-Hellman key exchanges that
RFC 10015 prohibits in TLS 1.2 are not implemented.

For the CBC suites the client sends `encrypt_then_mac` (RFC 7366) whenever a
CBC suite is on offer, and the server acknowledges it only when it selects a
CBC suite. By default neither side uses a CBC suite without it (RFC 9325 §4.2):
a server with `allow_mac_then_encrypt` unset does not select a CBC suite for
a client that did not offer the extension, and a client with it unset refuses
a CBC suite the server selected without acknowledging it. The MAC-then-encrypt
transform is implemented, for the opt-in, in time independent of the padding
(`browntls_crypto::tls_cbc`): a fixed number of hash compressions per record
length and a constant-time padding check, the Lucky Thirteen countermeasure.
In the protocol SHA-1 exists only as the HMAC of the `*_CBC_SHA` suites; no
signature uses it (RFC 9155). Outside it, revocation checking hashes OCSP
`CertID`s with SHA-1. The explicit per-record IV comes from the operating
system.

A TLS 1.2 client also requires the server to acknowledge
`renegotiation_info` (RFC 5746) unless `require_secure_renegotiation` is
cleared (RFC 9325 §3.5), and neither side ever renegotiates. A connection
that ends with a fatal alert forgets its TLS 1.2 session on both sides
(RFC 5246 §7.2.2), and a TLS 1.2 server honours the client's curves for its
ECDSA certificate as well as for key exchange (RFC 8422 §5.3).

### TLS 1.2-only extensions of RFC 6066

RFC 6066 defines three extensions that TLS 1.3 does not have (the IANA
registry marks them "-" for TLS 1.3): `client_certificate_url` (§5),
`trusted_ca_keys` (§6) and `truncated_hmac` (§7). All three are parsed in
a ClientHello, a ServerHello and TLS 1.3 EncryptedExtensions, so a
malformed body there ends the handshake with `decode_error` whichever
protocol version is negotiated: the first and the last are empty, and
`trusted_ca_keys` holds a list (possibly empty) of `pre_agreed`,
`key_sha1_hash`, `x509_name` and `cert_sha1_hash` entries. An entry of any
other identifier type cannot be skipped, since it carries no length, and is
a `decode_error` too, and so is a list of more than 1024 entries (a local
bound on what an unauthenticated ClientHello may make the server allocate).
Earlier versions ignored these extensions whatever their bodies held, so a
peer that sends a malformed one now fails the handshake. In a TLS 1.3
ServerHello or EncryptedExtensions each of the three is
`illegal_parameter`, as for every TLS 1.2-only extension; a
HelloRetryRequest may carry none of them either, and refuses each with
`illegal_parameter` before its body is looked at.

`trusted_ca_keys`: negotiated in TLS 1.2, off by default. A client sends
the list of `ClientConfig::trusted_ca_keys` (`None` by default; an empty
list claims a set of root keys agreed by other means) only when it offers
TLS 1.2, so never over QUIC nor with an ECH offer, and again after a
HelloRetryRequest. A list of more than 1024 entries, one with an empty
`x509_name`, or one that makes the ClientHello longer than a handshake
message fails connection creation instead of sending a malformed hello.
`TrustedAuthority` builds identifiers from a CA certificate or a trust
anchor with a caller-supplied SHA-1 (`crypto::native::sha1` or
`crypto::rustcrypto::sha1`): the RSA modulus without leading zero bytes,
the `subjectPublicKey` value for ECDSA and DSA keys and, as a local choice
the RFC does not make, for other key types too; `matches_certificate`
compares one with a CA certificate. A certificate resolver reads the list
with `ClientHello::trusted_ca_keys()`, whatever version is negotiated, and
calls `ClientHello::acknowledge_trusted_ca_keys()` when the list guided its
choice; `server::ResolvesServerCertUsingTrustedCaKeys` does both, serving
a registered chain that shares an identifier with the list and signs with
one of the client's schemes, and its fallback resolver otherwise. Since a
name may be shared by several roots (a CA key rollover keeps it), a
certificate hash match wins over a key hash match, which wins over a name
or `pre_agreed` match; among equals the first chain registered wins. The
server answers with the empty extension only in a full TLS 1.2 handshake,
to a client that sent the list, after an acknowledgement: never in TLS 1.3,
never when resuming a session (no chain is sent then), and an `Accepted`
view's acknowledgement does nothing. A client accepts the answer only in
TLS 1.2 and only after sending the list (otherwise `unsupported_extension`
in TLS 1.2 and `illegal_parameter` in TLS 1.3; `decode_error` for a body),
and reports it through `trusted_ca_keys_acknowledged()` on the buffered and
unbuffered client connections. The list travels in the clear and reveals
which roots the client trusts (RFC 6066 §11.4). No peer of the end-to-end
interoperability matrix implements the extension (OpenSSL, GnuTLS and Go
ignore it), so it is tested between browntls peers only, on both
providers, with the Tokio streams and through the `browntls` facade.

`client_certificate_url`: negotiated in TLS 1.2 when both sides enable
it; see [client certificate URLs](#client-certificate-urls-rfc-6066-5)
below.

`truncated_hmac`: deliberately not implemented, and not planned.
RFC 9325 §4.6 says implementations MUST NOT use it: its use with the CBC
suites it applies to has been shown to be insecure, and it has no effect on
AEAD suites. A client never sends the extension and so refuses
a ServerHello that carries it (`unsupported_extension`); a server never
acknowledges it, which RFC 6066 §7 allows, and the connection then uses the
full HMAC.

#### Client certificate URLs (RFC 6066 §5)

A constrained TLS 1.2 client may name its certificate chain with URLs and
SHA-1 hashes in a CertificateURL message instead of sending it
(`browntls_core::certificate_url`). Both sides are off by default.

Client: `ClientConfig::enable_client_certificate_url` offers the empty
extension when TLS 1.2 is among the offered versions and the client
certificate resolver has certificates (so never on QUIC or in an ECH
inner hello, which offer TLS 1.3 only). The URLs belong to the
`CertifiedKey` (`set_certificate_url`), built with `UrlAndHash` and
`CertificateUrl` (`individual_certs`, end entity first, or `pkipath`;
`encode_pki_path` writes the DER `PkiPath ::= SEQUENCE OF Certificate`,
issuer first). The key may hold no certificate at all. A CertificateURL
message replaces the Certificate only when a TLS 1.2 server acknowledged
the extension and sent a CertificateRequest; anywhere else, TLS 1.3
included, a key without a chain sends an empty Certificate and no
CertificateVerify. A warning-level `certificate_unobtainable` is logged and
the handshake goes on (RFC 6066 §5); a fatal one ends it with
`Error::AlertReceived`.

Server: `ServerConfig::client_certificate_url` takes a
`ClientCertificateUrlPolicy` (`None` by default) with the caller's SHA-1
function, the allowed URI schemes (only `http` by default, compared
without regard to case), at most 8 URLs, 2048 bytes per URL and 64 KiB
for all fetched objects; zero limits or no valid scheme make connection
creation fail. The server acknowledges the extension only on a full TLS 1.2
handshake (not a resumption), with a policy set, a client certificate
verifier that sends a CertificateRequest, and an X.509 client certificate
(not an RFC 7250 raw public key). It then takes a CertificateURL message
in place of the Certificate, into the transcript as received. Without the
acknowledgement the message is `unexpected_message`, and in TLS 1.3 its
type stays unknown. An unknown chain type, an empty list or URL and
trailing bytes are `decode_error`; a padding byte other than 0x01 and a
`pkipath` list of other than one URL are `illegal_parameter`.

The library never opens a connection to a URL. A client-chosen URL that a
server fetches is a server-side request forgery vector (RFC 6066 §11.3), so
the application, or its fetcher, performs and authorizes every fetch.
Before anything reaches it, URLs beyond the policy's count or length, not
printable ASCII, without a scheme or with one not allowed, without a `//`
authority or with an empty one, with userinfo, a fragment or a backslash
end the handshake with `certificate_unobtainable`. Otherwise the
connection pauses, like the live OCSP pause and independently of it, with
a `ClientCertificateUrlQuery`
(`CommonState::pending_client_certificate_url`,
`IoState::client_certificate_url_pending`,
`ConnectionState::PendingClientCertificateUrl` on the unbuffered API). No
input is processed while it is outstanding: ClientKeyExchange,
CertificateVerify, ChangeCipherSpec and Finished stay buffered, and
`read_tls` returns `WouldBlock`. `resolve_client_certificate_url` answers
it with `ClientCertificateUrlResponse::Fetched` (one object per URL) or
`Unobtainable`; a wrong id is an error that changes nothing, and buffered
input is processed as after `resolve_peer_revocation`.

An unobtainable chain, a wrong number of objects or more bytes than the
limit is `certificate_unobtainable`, always, also when client
authentication is optional. RFC 6066 §5 lets a server that does not
require the certificate continue, but the client still sends a
CertificateVerify that cannot be checked without its key, and this crate
does not go on with an unverified one: a deliberate narrowing. An object
whose SHA-1 differs from the client's is `bad_certificate_hash_value`
(always fatal, also when received as a warning); a malformed `PkiPath`
(not one DER SEQUENCE of 1 to 16 SEQUENCEs with definite, minimal
lengths and nothing after it) is `bad_certificate`. The chain, in TLS
order, then goes through the very path a Certificate message takes: the
client certificate verifier, the revocation hook, then ClientKeyExchange.
Nothing about the client is reported as authenticated before its
CertificateVerify verified.

No peer of the end-to-end matrix implements the extension (OpenSSL,
GnuTLS and Go do not), so the evidence is self-interoperation on both
providers (`crates/browntls-core/tests/client_certificate_url*.rs`,
buffered and unbuffered), the Tokio fetcher tests, and codec and PkiPath
vectors checked with `openssl asn1parse` and Python `hashlib`.

### TLS 1.3 protocol rules (RFC 9846)

TLS 1.3 follows RFC 9846, which obsoletes RFC 8446; RFC 6066 supplies
`server_name` and `status_request`. The rules that RFC 9846 tightened, and
where they live:

- Extensions are checked against RFC 9846 Table 1 (`tls13::extensions`;
  extensions outside the table follow the TLS 1.3 column of the IANA
  registry, and TLS 1.2-only ones are allowed in a ClientHello alone;
  `record_size_limit` and `ticket_request` may appear in ClientHello and
  EncryptedExtensions only). A
  recognised extension in a message that may not carry it is
  `illegal_parameter`; one that answers nothing we sent is
  `unsupported_extension`. This covers ServerHello, HelloRetryRequest,
  EncryptedExtensions, CertificateRequest, CertificateEntry and
  NewSessionTicket.
- Versions: a ClientHello whose `supported_versions` offers TLS 1.3, and a
  TLS 1.3 ServerHello or HelloRetryRequest, must carry `legacy_version` 0x0303
  (`protocol_version` otherwise); a `supported_versions` value the client did
  not offer, or below TLS 1.3, is `illegal_parameter`.
- HelloRetryRequest: the server remembers the cipher suite and group it
  selected; the second ClientHello must carry exactly one key share, for that
  group, and still offer that suite (`illegal_parameter`). After a
  HelloRetryRequest the client drops a PSK whose hash differs from the
  selected suite's.
- KeyUpdate (`CommonState::key_update_to_send`, `ConnectionCore::
  maybe_send_key_update`): the answer to `update_requested` is sent once,
  after the received flight is processed and before any further application
  data, however many requests arrived; a side that asked does not ask again
  until a KeyUpdate from the peer arrives (a refresh then rotates only its own
  key); no more than 2^48-1 key updates are sent, after which a peer's request
  is ignored and the public `refresh_traffic_keys` fails. A write that reaches
  the confidentiality limit rotates the key before the write returns; when
  the key cannot be rotated yet (a server's half-RTT data before the client's
  Finished), the record layer takes no more data until it can, and plaintext
  buffered before the handshake stays buffered across the rotation. 0-RTT
  data, which cannot be rekeyed, stops short of the limit. No KeyUpdate (and
  no ticket) is sent after our own `close_notify` (§6.1). The limit is not
  enforced on received records. A peer that keeps requesting updates without
  sending non-empty application data in between is cut off after eight
  requests, a local resource bound.
- Record layer: a protected `change_cipher_spec` record, or one whose value
  is not 0x01, is `unexpected_message`.
- Rejected 0-RTT: a server that declines early data skips the client's
  undecryptable records while their plaintext totals at most
  `max_early_data_size`, or 16384 bytes when that is zero (§4.3.10); each
  record is charged its length less
  the suite's tag and content type byte, an upper bound on its plaintext,
  and at least one byte, so the budget also bounds the number of records
  tried (`RecordLayer::doing_trial_decryption`). One byte more fails with
  `bad_record_mac`. After a HelloRetryRequest no key is tried: records are
  charged their length, at least one byte, and the next one past the budget
  is read as the second ClientHello.
- Alerts: `general_error` (117) exists; `user_canceled` is ignored at either
  level in TLS 1.3 (the peer must follow it with `close_notify`), within the
  same bound as TLS 1.2 warning alerts; every other alert except
  `close_notify` ends the connection whatever its level.
- Tickets: a server sends NewSessionTicket only when the ClientHello offered
  `psk_dhe_ke`, announces a lifetime of at most seven days (one day for
  session-cache tickets, the ticketer's otherwise), sends no ticket when that
  lifetime would be zero, and does not resume a PSK older than it. A client
  discards a ticket with a zero lifetime.
- Signatures: in TLS 1.3 an ECDSA scheme binds its curve (a P-384 key
  cannot verify `ecdsa_secp256r1_sha256`); a client's CertificateVerify must
  use a scheme from the server's CertificateRequest list. A signature inside
  the certificate chain that fails, or uses an algorithm not accepted (MD5,
  SHA-1), is `bad_certificate`; `decrypt_error` is kept for handshake
  signatures.
- Server certificates: an empty Certificate message is `decode_error` when it
  arrives; a non-empty `certificate_request_context` is `illegal_parameter`;
  OCSP responses may come with any entry and are associated with the
  certificate they accompany. The revocation policy controls the check depth.
- Key shares come in `supported_groups` order, and a server that would have
  preferred a group other than the one the client's shares allowed lists its
  groups in EncryptedExtensions (RFC 9846 §4.3.7). Key shares are generated
  per connection and never reused.

Not implemented: RFC 6066 `max_fragment_length` (not "Recommended" in
RFC 9846 Table 1; `record_size_limit` and the local `max_fragment_size`
setting cover the use case).

### Client session resumption

A saved client session (TLS 1.2 session ID or ticket, TLS 1.3 ticket) is
bound to the identities of the `Arc`s that established it: the
configuration's server certificate verifier and its client certificate
resolver (`ClientConfig::client_auth_cert_resolver`). A configuration offers a
stored session only when both are the same objects, compared by address and
held weakly, so the store keeps neither alive and a later allocation cannot
reuse the address while the session exists. A session authenticated with a
delegated credential is offered only while `enable_delegated_credentials` is
set.

A `ClientSessionStore` shared between configurations, or a cloned
configuration given another verifier with
`DangerousClientConfig::set_certificate_verifier`, therefore makes a full
handshake under its own verifier rather than resuming a session another
verifier accepted, and does not reuse a TLS 1.2 session whose client identity
another resolver chose. Configurations that share the verifier and resolver
(for example clones) keep resuming each other's sessions. Equivalent but
distinct verifier objects do not match, and a verifier whose own policy
changes at run time keeps its sessions; give such configurations separate
stores.

Configurations sharing a store still share its slots: an incompatible TLS 1.3
ticket is consumed and dropped (no older ticket or TLS 1.2 session is tried
instead), and the next full handshake replaces the single TLS 1.2 session
kept per server name. This costs resumptions, never verification.

### Post-handshake client authentication (RFC 9846 §4.7.2)

A client offers `post_handshake_auth` when `ClientConfig::
enable_post_handshake_auth` is set (off by default) and its certificate
resolver has certificates. Its traffic state then keeps a copy of the
transcript through its Finished and answers every CertificateRequest at
once, in order, from the resolver: Certificate echoing the request's
context, CertificateVerify over `Transcript-Hash(handshake .. client
Finished, CertificateRequest, Certificate)` when it has a usable key (an
empty Certificate otherwise), and a Finished keyed by the current
`client_application_traffic_secret_N`. Each exchange starts from the
handshake transcript, not from earlier exchanges (§4.5). A
CertificateRequest without our offer is `unexpected_message`, one with an
empty `certificate_request_context` is `illegal_parameter` (§4.4.2); its
extensions are checked as in the handshake. Each answer costs a signature,
so a client answers at most eight requests while the server sends no
application data and then aborts with `unexpected_message`, the same local
resource bound as for KeyUpdate requests. On the client only a record with
application data in it renews either budget: a zero-length application data
record (§5.1) gives the application nothing and does not.

A server learns the offer from the ClientHello (`ServerConnection::
post_handshake_auth_offered`). `ServerConnection::request_client_auth`
needs a completed TLS 1.3 handshake, the offer, a verifier that offers
client authentication, no request still unanswered (one at a time,
which bounds the state kept per connection), and no `close_notify` in
either direction (after the client's, nothing it sends is processed, so a
request would stay unanswered). The request's
`certificate_request_context` is an 8-byte request counter followed by 24
random bytes: unique on the connection and unpredictable (§4.4.2). The
answer may come after any amount of application data or KeyUpdates, but
once its Certificate has arrived the CertificateVerify and Finished must
follow with nothing in between (`unexpected_message` otherwise). The
answer goes through the same checks as the handshake's client
authentication (context echo, `ClientCertVerifier`, scheme from our list,
signature), then a constant-time Finished check (`decrypt_error`). Only
after the Finished does `peer_certificates` change and
`post_handshake_auth_status` become `Authenticated`; an empty Certificate
is `Declined` (and `certificate_required` when the verifier makes client
authentication mandatory). A resumed handshake may be followed by
post-handshake authentication, as §4.4.2 allows.

The unbuffered connections have the same methods
(`UnbufferedServerConnection::{post_handshake_auth_offered,
request_client_auth, post_handshake_auth_status}`,
`UnbufferedClientConnection::post_handshake_auth_responses`) over the same
state and checks (`ConnectionCore::request_client_auth`). The request is
queued like any handshake message, so the next `process_tls_records`
offers it through `EncodeTlsData` before anything else, and a client's
answer leaves through `EncodeTlsData` as soon as the request is processed.

With `ServerConfig::request_client_auth_after_handshake` set, a server
leaves client authentication out of a TLS 1.3 handshake whose client
offered `post_handshake_auth`; other clients, and TLS 1.2, are asked in the
handshake as before. The handshake then completes without a client
certificate even when the verifier makes it mandatory, so the application
must request and check it. RFC 8740 forbids post-handshake authentication
over HTTP/2; the library does not tie either setting to ALPN, the
application chooses.

### Stateless HelloRetryRequest cookies (RFC 9846 §4.3.2)

`ServerConfig::hello_retry_cookies` (default `None`) holds a
`ProducesTickets` sealer, which should be a dedicated instance with its own
key (for example a separate `TicketRotator` over an AEAD ticket producer).
Creating a connection with the `ServerConfig::ticketer` instance itself as
the sealer fails; a separate sealer sharing the ticketer's key cannot be
detected, but the plaintexts stay disjoint (a ticket starts with a 0 or 1
byte, a cookie with its label), which a unit test pins.
When it is set, a HelloRetryRequest carries a cookie that seals
(`server::cookie`):

```text
"browntls hrr ck1" (domain label, 16 bytes) | issued_at u64 (seconds)
| cipher_suite u16 | named_group u16 | Hash(ClientHello1) <1 byte length>
| legacy_session_id <1 byte length> | server_name <1 byte length>
```

The connection that sent the HelloRetryRequest keeps its state and requires
the second ClientHello to echo the cookie byte for byte
(`missing_extension` if absent, `illegal_parameter` if different). A fresh
server connection, or an acceptor (`Acceptor`, `UnbufferedAcceptor`), whose
first ClientHello carries a cookie opens it instead: it must authenticate
under the sealer (a `TicketRotator` accepts its current or previous key),
carry the label, parse exactly and be at most 60 seconds old
(in either direction, for servers sharing a key); the suite and group must
still be configured, the hash length must match the suite's, and the
ClientHello must repeat the session ID and server name. Any failure is
`illegal_parameter` (RFC 9846 names no alert for a bad cookie; RFC 9147
§5.1 uses `illegal_parameter` for DTLS). The connection then rebuilds the
transcript as `message_hash(Hash(ClientHello1))` followed by the
HelloRetryRequest re-encoded from the cookie (§4.5), takes the cookie's
suite and group as the retry's choice, and continues with the usual
second-ClientHello rules. Like the stateful path, it compares the second
ClientHello with the first only through what the cookie carries (suite,
group, session ID, server name) and through `Hash(ClientHello1)` in the
transcript, which the PSK binders and Finished cover. If the clock fails
while a cookie is issued or opened, the handshake aborts with
`internal_error`. Such a connection ignores change_cipher_spec
records before that ClientHello (within the usual bound), as §4.3.2
requires; ahead of any other first ClientHello they stay
`unexpected_message`. Without a sealer no cookie is sent and one in a first
ClientHello is ignored, as before.

No cookie is sent when the first ClientHello offered 0-RTT: the client's
early data records would reach a fresh connection ahead of its second
ClientHello, so that retry stays stateful. Nor, on a server configured for
ECH (`ServerConfig::ech` or `ech_backend`), when it carried an ECH extension
(GREASE included): the HPKE context and the HelloRetryRequest's ECH extension
cannot be rebuilt from a cookie, so such a server's fresh connection refuses a
cookie whose ClientHello offers ECH (`illegal_parameter`). A server without
ECH ignores the extension and keeps the retry stateless. A cookie can be
replayed during
its lifetime by anyone who saw it; that gives no more than replaying the
second ClientHello would, since the handshake still needs the client's key
share and Finished. TLS cookies are not bound to the client's address:
that is fine over TCP, where the handshake itself proves the address. DTLS
1.3 cookies are, and carry a label of their own, so that neither kind opens
as the other (see [DTLS 1.3](#dtls-13-rfc-9147)).

### Exporters

`export_keying_material` is the RFC 9846 §7.5 exporter (RFC 5705 in TLS
1.2, where it requires the extended master secret). `ConnectionCommon::
export_early_keying_material` is the separate early exporter that §7.5
recommends, from `early_exporter_master_secret` (logged as
`EARLY_EXPORTER_SECRET`; checked against RFC 8448 §4). A client has it from
the moment it offers 0-RTT and loses it if the server rejects 0-RTT; a
server has it once it accepts 0-RTT. After a fatal error neither side
exports anything. Like 0-RTT data it is not forward
secret and replays with the ClientHello.

`tls_exporter_channel_binding` is the RFC 9266 `tls-exporter` channel
binding: 32 bytes under the label `EXPORTER-Channel-Binding` with an empty
context. RFC 9266 §2 defines it for TLS 1.3 and for earlier versions only
with the extended master secret, which the TLS 1.2 exporter requires
anyway; since browntls never renegotiates, the RFC 9266 §4.2 renegotiation
exclusion does not arise.

`UnbufferedConnectionCommon` has the same three, through the same code
(`ConnectionCore::export_keying_material` and
`ConnectionCore::export_early_keying_material`). An unbuffered client builds
its ClientHello in `new`, so its early exporter is there as soon as the
connection exists when that ClientHello offers 0-RTT.

### TLS 1.3 external PSKs

External pre-shared keys (RFC 9846 §4.3.11) live in `browntls_core::psk`. An
`ExternalPsk` carries its identity, key, hash (SHA-256 or SHA-384) and
optional restrictions: one cipher suite, one server name, one ALPN protocol.
A caller may also attach an opaque local key generation with
`with_key_generation`; each endpoint applies its own value independently, and
it is not sent in the handshake.
A client lists its keys in `ClientConfig::external_psks`; a server finds them
through a `ResolvesExternalPsk` in `ServerConfig::external_psks`
(`with_external_psks_only` builds a server without a certificate).

- Key exchange: only `psk_dhe_ke`. The `psk_ke` mode, which gives up forward
  secrecy (RFC 9257), is neither offered nor accepted; a server ignores the
  PSKs of a client that offers only `psk_ke`.
- Client: a resumption ticket comes first, then the external PSKs in
  configuration order, each with an obfuscated ticket age of zero and a
  binder over the hash of the first offered suite it is usable with, under
  the `ext binder` label (`imp binder` for imported keys, `res binder` for
  tickets). After a HelloRetryRequest only the PSKs usable with the selected
  suite are offered again. The key schedule then continues with the
  negotiated suite (which may differ from the binder's in everything but
  the hash).
- Server: the first offered external PSK usable with a suite the server
  could select narrows the suite choice to the suites it is usable with (the
  server "MUST ensure that it selects a compatible PSK (if any) and cipher
  suite"). Of the first 16 identities, the first that names a usable external
  PSK or ticket is selected and only its binder is checked, in constant time;
  a wrong binder is `decrypt_error`. An identity whose binder length is not
  that of the key's hash is passed over. Ordinary external PSK authentication
  uses the key alone. When a TLS 1.3 client offered a `psk_dhe_ke` PSK
  and none was selected, a server without a certificate fails with
  `handshake_failure`; otherwise (no PSK offered, `psk_ke` only, or TLS 1.2)
  it fails as any server without a certificate does, with `unrecognised_name`
  when the client sent a server name and `access_denied` otherwise. A client
  that offers TLS 1.3
  only and a PSK may omit `signature_algorithms` (RFC 9846 §4.3.3); it is
  then served by PSK only. Only servers configured with external PSKs defer
  the missing-certificate failure to after PSK selection.
- 0-RTT: off by default for external PSKs (RFC 9257). `with_early_data`
  enables it per key; the key needs a provisioned suite and must be the first
  offered, and the server checks suite and ALPN protocol against the
  provisioned ones (RFC 9846 §4.3.10). The server also requires a live
  per-credential cutoff and an application-supplied atomic replay policy.
  Missing or uncertain policy declines early data. Deployments sharing a
  credential share the policy's authoritative state and retain its marks
  through the last possible acceptance time. Applications still need
  replay-safe request semantics.
- Importer (RFC 9258): a key configured with `imported(context)` is used
  only through the importer. The client offers one `ImportedIdentity` per
  hash of its TLS 1.3 suites (target protocol TLS 1.3, target KDF
  `HKDF_SHA256` or `HKDF_SHA384`), with `ipskx = HKDF-Expand-Label(
  HKDF-Extract(0, epsk), "derived psk", Hash(ImportedIdentity), L)` under the
  EPSK's hash; the server parses the identity, resolves its external identity
  and requires the same context. The EPSK's hash must be that of one of the
  provider's TLS 1.3 suites. Stream TLS and QUIC use the TLS 1.3 target and
  importer label. DTLS uses the DTLS 1.3 target and `dtls13` label. The
  derivation is checked against independent HMAC computations and across
  providers. Deployments that used browntls's earlier TLS-labelled DTLS
  importer must upgrade both DTLS endpoints together.
- Certificate authentication with an external PSK ([RFC 9973],
  `tls_cert_with_extern_psk`, 0x0021) is opt-in on both sides
  (`cert_with_extern_psk`). The client prefers a fresh handshake when it has
  an eligible key. Its offer excludes resumption tickets and 0-RTT. The
  server scans the full wire-bounded list for recognizable tickets, checking
  each distinct identity once without consuming stateful tickets. A
  recognizable ticket or a bad binder for the selected external PSK triggers
  `illegal_parameter`. External key resolution
  and selection remain limited to the first 16 identities. An opaque identity
  the server cannot recognize is handled as an unknown external identity.
  The in-memory cache reads only the stored version. Custom
  `StoresServerSessions` implementations can override `session_version()`
  to avoid fetching a full value for the scan.
  The extension combines the key exchange and external PSK in the TLS key
  schedule. Server authentication still uses Certificate and CertificateVerify
  with a certificate or configured raw public key. The server can also request
  client authentication. The external PSK contributes to confidentiality.
- With ECH, the real external identity and extension are in the inner
  ClientHello. Without ECH, an observer can associate repeated uses of the
  same identity. Rotate identities as appropriate for the deployment. The
  retry must repeat the extension on the effective hello or fail. Retry cookies
  carry that decision, so an upgrade rejects old in-flight retry cookies.
- For a client that requires fresh RFC 9973 on every connection, set
  `cert_with_extern_psk`, `require_cert_with_extern_psk`, and
  `require_external_psk` to `true` and use
  `client.resumption = Resumption::disabled()`. Set
  `server.require_cert_with_extern_psk = true` to require a fresh handshake
  on the server too. Use a server config with a credential and an external
  key resolver. Strict servers issue no tickets and use the configured
  verifier for any client authentication. Both configs apply through the
  buffered, unbuffered, Tokio, QUIC and DTLS APIs.
- The server's resolver or acceptor can inspect the visible hello with
  `ClientHello::offers_cert_with_extern_psk()`. Treat this as an
  unauthenticated routing signal. On both sides
  `CommonState::negotiated_cert_with_extern_psk()` reports fresh RFC 9973
  after the handshake completes. A resumed connection can report the
  inherited external identity through `external_psk_identity()`.
- `CommonState::external_psk_identity` reports the key used, once the peer's
  Finished has verified (until then the peer has not proven it holds the
  key); such a handshake is `HandshakeKind::Full`. A peer that offers or
  accepts external PSKs may still complete a handshake without one;
  `require_external_psk` (client and server) refuses that with
  `handshake_failure`, otherwise the application must check
  `external_psk_identity` after the handshake. With it, a client offers only
  tickets from external-PSK sessions and a server passes over other tickets;
  TLS 1.2 is refused.
- Tickets: a ticket issued on a connection that used an external PSK records
  the PSK's identity, importer context and a per-ticket verifier derived from
  the raw key, optional key generation and that ticket's resumption secret
  (in the server's encrypted ticket and in the client's
  `Tls13ClientSessionValue`). Resuming it reports the same
  `external_psk_identity` (as `HandshakeKind::Resumed`) and counts for
  `require_external_psk`. The client offers such a ticket only while the PSK
  is configured, usable for the connection and still verifies; the server
  resolves the identity again and applies the same check. Changing either the
  key bytes or the optional generation therefore invalidates existing tickets;
  removing the key does too. Identity-only ticket records from older browntls
  revisions fail closed rather than resuming without a key binding.

[RFC 9973]: https://www.rfc-editor.org/rfc/rfc9973.html

RFC 9257 guidance and what browntls enforces:

- Keys shorter than 128 bits are refused (`ExternalPsk::MIN_KEY_LEN`); the
  entropy of a key cannot be measured, and a low-entropy secret such as a
  password must not be used as a PSK (it needs a PAKE).
- A PSK must be known to exactly two parties, and a node that acts as client
  and as server must use distinct PSKs for the two roles: sharing a key more
  widely lets any holder impersonate any other (including reflection of a
  connection back to its sender). browntls cannot see this; it is a
  provisioning rule for the application.
- Identities are sent in clear and can link connections of one client;
  choose identities that reveal nothing and, where linkability matters, are
  not stable. The resolver receives unauthenticated identities and should
  not leak through timing or errors which identities exist. The handshake
  itself tells them apart: a known identity with a wrong binder fails with
  `decrypt_error`, while an unknown one is passed over (a certificate
  handshake, or `handshake_failure` without one). This is inherent in
  checking binders only for identities the server knows.
- A server that holds an external PSK and a certificate authenticates with
  the PSK when one is offered; the PSK proves only possession of the key,
  not any certificate identity.

### Optional ClientHello extensions

- `record_size_limit` (RFC 8449), both sides, TLS 1.3 and 1.2, on by
  default (`ClientConfig::record_size_limit`,
  `ServerConfig::record_size_limit`, default 16385): the client announces
  the configured value, lowered to the protocol maximum (2^14 + 1 when TLS
  1.3 is offered, 2^14 otherwise); a server answers only a client that sent
  it, in EncryptedExtensions (TLS 1.3) or the ServerHello (TLS 1.2), with
  its value lowered to the negotiated version's maximum. Once negotiated,
  records we send carry at most the peer's limit of plaintext (minus one in
  TLS 1.3, whose limit counts the content type) or `max_fragment_size` less
  the header, whichever is smaller (`MessageFragmenter`); protected records
  the peer sends that exceed our limit (TLS 1.3: the whole
  `TLSInnerPlaintext`, including padding) end the connection with
  `record_overflow`. If the server acknowledges the extension, the TLS 1.3
  client checks all authenticated records carrying EncryptedExtensions.
  If the server omits it, the protocol limit applies. A peer value below
  64 is `illegal_parameter`, including when the server declines the
  extension. Higher peer values are capped at the protocol maximum.
  A configured value below 64 fails connection creation
  (`Error::BadRecordSizeLimit`). The new handshake's cap applies to its
  handshake and application keys. Stream TLS 1.3 ticket 0-RTT uses the
  server receive cap from the ticket-issuing connection. Older server
  sessions without the cap can resume without early data. External PSKs
  use the cap provisioned on both peers with
  `ExternalPsk::with_early_data_record_size_limit` (default 16385).
  DTLS 1.2 and 1.3 support the extension through opt-in
  `dtls::Settings::with_record_size_limit`. The effective send cap
  composes with the datagram MTU and CID overhead. Protected handshake
  fragments, acknowledgements and application data share the cap.
  Application sends remain one datagram. An authenticated record over
  the negotiated limit fails with `record_overflow`; DTLS 1.2 CID and
  DTLS 1.3 count the entire inner plaintext.
- `ticket_request` (RFC 9149), TLS 1.3 only: the client sends
  `ClientConfig::tls13_ticket_request` (default none) when it offers TLS
  1.3; the server sends at most `resumption_count` tickets for a resumed
  session and `new_session_count` otherwise, never more than
  `send_tls13_tickets`, and announces that number as `expected_count` in
  EncryptedExtensions. The extension in a ServerHello or HelloRetryRequest
  is `illegal_parameter` (TLS 1.3) or `unsupported_extension` (TLS 1.2).
  A client's requested counts are clamped to
  `max_tls13_tickets_per_connection` (default 8, valid 0–255). The client
  accepts the first that many valid tickets across the entire connection,
  including after kernel handoff, and ignores further valid tickets without
  deriving or storing them. Zero disables ticket storage. Invalid ticket
  messages still fail through the ordinary protocol checks.
- GREASE (RFC 8701, `msgs::grease`), client, opt-in
  (`ClientConfig::enable_grease`, default off until the GnuTLS end-to-end
  scenarios have run with it): random per-connection GREASE values first in
  the cipher suites, `supported_groups`, `key_share` (a one-byte share),
  `supported_versions`, `signature_algorithms` and `psk_key_exchange_modes`,
  plus an empty GREASE extension first and a one-byte one after every other
  extension but `padding` and `pre_shared_key`. A second ClientHello repeats
  the values, but drops the GREASE key share when the HelloRetryRequest
  named a group. The values never enter the lists the server's choices are
  checked against, so a server selecting one fails as for any value not
  offered (`illegal_parameter`, or `unsupported_extension` for an
  extension). ALPN is not GREASEd. A browntls server ignores GREASE values
  like any unknown value.
- GREASE (RFC 8701 §4.1), server, opt-in (`ServerConfig::enable_grease`,
  default off like the client's: a client that mishandles unknown values
  would fail client authentication or lose its tickets). It covers the two
  TLS 1.3 messages whose extension points a server offers. A
  CertificateRequest, in the handshake or after it (also the one an
  offloaded connection hands to kernel TLS), lists a GREASE signature scheme
  first in `signature_algorithms` and carries an empty GREASE extension
  first and a one-byte one last; a NewSessionTicket carries the same two
  extensions. The values are drawn for each message, and the two extension
  types of a message differ. The GREASE scheme is never in the list a client
  CertificateVerify is checked against, so a client signing with it fails as
  for any scheme not offered (`illegal_parameter`); a Certificate entry
  extension of a GREASE type is refused like any unknown one. Nothing goes
  into the ServerHello, HelloRetryRequest, EncryptedExtensions or
  Certificate, where a client must reject GREASE (§3.1), into TLS 1.2
  messages (§4.1 names TLS 1.3 only), or into exported authenticator
  requests (RFC 9261). A browntls client ignores a server's GREASE values
  like any unknown value: unknown extensions of both messages are skipped,
  and an unknown signature scheme is passed on with the others to
  `ResolvesClientCert::resolve` and `SigningKey::choose_scheme`. The
  built-in keys choose only schemes they implement; a custom key must not
  choose a scheme it does not know. The option needs no API of its own
  above the protocol crate: the acceptors of `browntls-tokio` (buffered and
  unbuffered) take the configuration as it is, and the facade re-exports it
  as `browntls::ServerConfig::enable_grease`.
- `padding` (RFC 7685), client: by default
  (`ClientHelloPadding::AvoidProblematicLengths`) a ClientHello handshake
  message of 256 to 511 bytes is padded to 512 bytes, or 513 to 515 bytes
  from 509 to 511 where the four-byte extension header does not fit
  (RFC 7685 §4);
  `AtLeast(n)` pads to at least `n` bytes first; `Disabled` never pads. The
  extension comes right before `pre_shared_key`, which stays last, and is
  sized with the binders in place. A server ignores its content.

### External session and identity binding (RFC 8844)

`browntls_core::external_binding` implements `external_id_hash` (55) and
`external_session_id` (56) on both sides, in TLS 1.2 and 1.3, for
protocols that signal a session out of band (SDP `tls-id`, WebRTC identity
assertions). The module documentation is the reference; in short:

- `ClientConfig::external_binding` and `ServerConfig::external_binding`
  (default `None`, feature off) hold an `ExternalBinding`: our hash and
  `tls-id` to send, the peer's to expect, and `require_peer_support`. The
  values belong to one connection, so the application clones its base
  configuration per connection. A server choosing its configuration finds
  the client's values on the `ClientHello` view of `Acceptor`,
  `UnbufferedAcceptor` and the Tokio `LazyConfigAcceptor`.
- No resumption and no 0-RTT: a connection with a binding neither offers
  nor accepts a ticket or TLS 1.2 session ID, issues no NewSessionTicket,
  ticket or cacheable session ID, and stores nothing it receives, so a
  later connection, bound or not, cannot resume it either. RFC 8844 §5
  forbids using security-sensitive information from one TLS connection in
  another, even of the same signaling session, and a resumed handshake
  would skip the verifier in which applications pin the signaled
  certificate fingerprint (which §3.2 and §4.3 require in addition). A
  bound client sends no early data even with `enable_early_data`: it
  checks the server's answer only in EncryptedExtensions, after the server
  has read the data. External PSKs, provisioned by the application rather
  than left by a connection, keep working (without early data).
- Wire rules: `external_id_hash` is 0 or 32 bytes, `external_session_id`
  20 to 255 bytes; anything else is `decode_error`, for any server, since
  the hello decoder parses both. With a binding configured, a client
  always sends `external_id_hash`, empty without an assertion of its own
  (RFC 8844 §3.2), and `external_session_id` when it has a `tls-id`. The
  server answers only what the client sent, in the TLS 1.2 ServerHello or
  the TLS 1.3 EncryptedExtensions, `external_id_hash` likewise always
  (empty without an assertion); either extension in a TLS 1.3 ServerHello
  is `illegal_parameter`, an unsolicited one in a TLS 1.2 ServerHello
  `unsupported_extension`. After a stateful HelloRetryRequest the second
  ClientHello must repeat the first's values
  (`PeerMisbehaved::ExternalBindingChangedOnRetry`); after a stateless one
  (cookies) the server starts afresh, checks the second ClientHello
  against its expectations, and the first is bound by the transcript hash
  the cookie carries.
- Checks: a mismatch is `illegal_parameter`; an absent extension is
  accepted unless `require_peer_support` is set (`missing_extension` in TLS
  1.3, `handshake_failure` in TLS 1.2). Without an expectation nothing is
  compared, and the application checks the values reported by
  `peer_external_id_hash` and `peer_external_session_id` itself. A client
  that expects the server's `tls-id` without sending its own fails
  connection creation (`Error::InconsistentExternalBinding`).
- ECH: both values go in the ClientHelloInner only. A client checks
  nothing after a rejection; a server checks the ClientHello it answers
  even when it rejects an offer (it cannot tell GREASE from a stale real
  offer), so a server that requires support refuses a stale offer's outer
  hello with `missing_extension` instead of sending retry configurations.
- Security: the extensions bind the connection to the signaling session
  but do not by themselves authenticate the signaling peer. Without
  identity assertions, `external_session_id` prevents the session splicing
  (unknown key-share) attack of RFC 8844 §4, if the signaling channel
  delivers the `tls-id` values with integrity. Session concatenation (§5)
  within one connection is prevented by identity systems (WebRTC or SIP
  identity, that is `external_id_hash` with assertions the application
  verifies), but two back-to-back connections through an attacker remain
  possible; defending against concatenation also requires that peers
  cannot claim other entities' certificate fingerprints (§6). With
  identity assertions, TLS peer identities cannot be misrepresented even
  by an attacker that modifies signaling (§6).

### Cached information (RFC 7924)

`cached_info` (module `browntls_core::cached_info`) lets a TLS 1.2 client
that kept the server's Certificate or CertificateRequest message from an
earlier handshake offer its fingerprint, and a server whose message has that
fingerprint send the fingerprint in its place. Both object types are
implemented: `cert` (1) and `cert_req` (2). TLS 1.3 never uses it: the
extension may appear in a ClientHello offering both versions, a TLS 1.3
server ignores it, and in any TLS 1.3 server message it is
`illegal_parameter` (`tls13/extensions.rs`). Both sides are off by default.

API:

- Client: `ClientConfig::cached_info: Option<Arc<dyn
  ClientCachedInfoStore>>` (default `None`). The trait has `lookup(server
  name, type)`, returning the objects to offer, most preferred first, and
  `insert(server name, object)`. `ClientCachedInfoMemoryCache::new(max
  servers, per server)` is the built-in store (`std`): it evicts the server
  name inserted longest ago, and within a name and type the object inserted
  longest ago; it holds at most `max_servers * per_server * 2` messages of
  at most 64 KiB each. `CachedObject::new(provider, type, message)` builds
  an object from a complete TLS 1.2 handshake message (header included) and
  computes its fingerprint; there is no way to supply a fingerprint, and
  the message must be exactly one well-formed message of the type (a
  Certificate with at least one certificate). Applications may provision
  objects themselves (the constrained-device case of RFC 7924 §1).
- Server: `ServerConfig::cached_info: ServerCachedInfoPolicy`, one switch
  per type (`cert`, `cert_req`), both off by default.
- Both sides and every connection type (buffered, unbuffered,
  `browntls-tokio`): `CommonState::cached_info_replaced()` reports which
  messages of this handshake travelled as fingerprints.
- `cached_info::fingerprint(provider, message)` is the SHA-256 of a complete
  handshake message (RFC 7924 §5, checked against Appendix A), taken from
  the provider's cipher suites.

Rules:

- A ClientHello that offers TLS 1.2, with a store configured, carries at
  most `MAX_OFFERED_PER_TYPE` (4) objects of each type the store returns for
  the server name (not with an ECH offer, nor on QUIC, which offer TLS 1.3
  only); a second ClientHello repeats the first one's offer, and there is no
  extension when the store has none. A TLS 1.2 server that sees an offer
  computes the fingerprint of the Certificate its resolver selected and of
  the CertificateRequest it is about to send, and replaces a message by
  `opaque hash_value<1..255>` (the 32-byte fingerprint) only when its policy
  allows the type and the client offered exactly that fingerprint; it then
  lists the type in its ServerHello. Unknown types, hashes of another length
  and stale fingerprints are skipped: the message goes in full and the type
  is not listed (RFC 7924 §4). A resumed handshake never answers.
- The client accepts in the ServerHello only types it offered objects of,
  each once (otherwise `illegal_parameter`); the extension without an offer
  is `unsupported_extension`; a malformed extension body is
  `decode_error`. In a full handshake an acknowledged Certificate or
  CertificateRequest is read only in its hash form: a full message in its
  place is `decode_error`, and a fingerprint matching no offered object of
  that type, or of another length, is `illegal_parameter`. A hash form the
  server did not acknowledge is parsed as a full message and fails as a
  malformed one (`decode_error`). An acknowledgement in a resumed handshake,
  which has neither message, is ignored; a `cert_req` acknowledgement
  without a CertificateRequest is not an error.
- Transcript: both sides hash each message as it was sent, the hash form
  when replaced (RFC 7924 §7, second paragraph), so Finished, the extended
  master secret session hash and a client CertificateVerify cover the
  fingerprint, not the restored message.
- A restored message is processed exactly as a received one: the restored
  chain is verified at the current time with the configured verifier, as a
  received chain is, becomes `peer_certificates()` and the peer
  chain of the session stored for resumption, and its leaf key verifies the
  ServerKeyExchange signature. A restored CertificateRequest drives client
  certificate selection like a received one.
- The client stores messages received in full only after the handshake
  completed (the server's Finished verified, after the chain): a failed
  handshake stores nothing, and a restored message is never stored again.

Security analysis:

- The server still proves possession of its private key. browntls has no
  TLS 1.2 RSA or static Diffie-Hellman key exchange (RFC 10015): every TLS
  1.2 suite is ECDHE with a signed ServerKeyExchange, which the client
  checks against the leaf key of the restored chain. A server that has not
  the key of the cached certificate cannot complete the handshake, whatever
  fingerprint it sends.
- Being cached never makes a chain trusted: it is verified as if received,
  so a chain that has expired or lost its trust anchor since it was cached
  fails as it would in full. Only the client's own store is consulted, and a
  fingerprint must equal one the client offered, all 32 bytes.
- A wrong, injected or replayed fingerprint can only make the handshake
  fail: it selects among the client's own offered objects (any other is
  `illegal_parameter`), and an attacker who changes the ServerHello or the
  hash form changes the transcript, so Finished fails. An attacker
  substituting one offered object for another still needs the server's
  key for the ServerKeyExchange signature.
- Cache poisoning: only messages received in full in a handshake whose
  Finished verified, after their chain verified, are inserted, so a store
  holds what an authenticated server sent. An application store may return
  anything; offering it is harmless for the same reasons, and objects of
  another type are dropped before the offer.
- Privacy: fingerprints travel in the clear in the ClientHello, so an
  observer can link the client's connections to a server and learn which
  certificate it saw (RFC 7924 §7); the extension is therefore off by
  default and not offered with ECH (a GREASE ECH extension does not
  suppress it, since it hides nothing). The memory store keeps fingerprints
  per server name only in memory.
- Resource bounds: a server compares one fingerprint per type against at
  most the 65535 bytes of the client's list, and hashes at most two of its
  own messages per handshake; the built-in store is bounded as above; a
  client offers at most eight objects.
- Interactions: TLS 1.2 OCSP stapling (CertificateStatus) and SCTs (in the
  ServerHello) are separate messages, never cached; certificate compression,
  delegated credentials and QUIC are TLS 1.3 only; renegotiation is refused;
  kernel TLS handoff happens after the handshake and sees nothing of it.

Testing limits: no other implementation the project tests against (OpenSSL,
GnuTLS, Go crypto/tls, rustls) implements RFC 7924, so there is no
third-party interoperability test, and the wire format is checked only
against the RFC text and its Appendix A vector (whose printed message
header carries a spurious `00 02`: the vector's hash is that of the
560-byte certificate under the header `0b 00 02 36 00 02 33 00 02 30`).
In-process tests on both providers (`tests/cached_info*.rs`, cases in
`tests/cases/cached_info.rs`) cover buffered and unbuffered peers, client
authentication, stale caches, verification of restored chains, the
malformed server answers above (forged by rewriting the server's flight)
and TLS 1.3; `browntls-tokio` has a test through both stream families
(`tests/cached_info.rs`); the `tls_conn` and `tls_unbuffered` fuzz targets
offer and answer the extension when the client's resumption is disabled.

### Connection APIs

Both APIs drive the same handshake state machines through
`ConnectionCore` (`conn.rs`), which deframes and processes one unit at a
time (`ConnectionCore::process_one`) over a `DeframerBuffer`:

- Buffered (`std`): `ClientConnection`/`ServerConnection` own a receive
  buffer (`DeframerVecBuffer`, at most one maximum-size record),
  queue received plaintext and outgoing records, and offer `read_tls`,
  `write_tls`, `reader()` and `writer()`. `write_tls` offers the transport
  up to 64 queued records in one vectored write, and a vectored write to
  `writer()` hands the record layer up to 64 buffers at a time (more are
  taken as consecutive writes); both gather their slices on the stack, so
  neither allocates for the call. The send buffer limit
  (`set_buffer_limit`, 64 KiB by default) caps the application data a
  write takes; control records (handshake messages, alerts, KeyUpdates)
  are queued whatever the limit, but the outgoing queue counts them apart
  (`ChunkVecBuffer::control_len`). Once the handshake is done, while more
  control bytes wait unwritten than the limit allows (capped at 64 KiB),
  `wants_read` is false and `read_tls` fails: a peer that keeps asking for
  answers (KeyUpdate `update_requested`, post-handshake CertificateRequest)
  while it reads nothing cannot grow the queue without bound. The check
  falls between reads: the records one `read_tls` took in (at most one
  maximum-size record's worth) are processed in full, so the queue may pass
  the bound by what they call for (one KeyUpdate, or one post-handshake
  authentication answer per CertificateRequest among them). Reading resumes once
  `write_tls` has taken the backlog; `complete_io` writes before it reads, so it
  never meets the bound.
- Unbuffered (`unbuffered.rs`, no `std` needed):
  `UnbufferedClientConnection`/`UnbufferedServerConnection`.
  `process_tls_records(&mut incoming)` parses records from the front of the
  caller's buffer (`DeframerSliceBuffer`), decrypts them in place and
  returns a `ConnectionState` plus the number of bytes to discard.
  Application data (and a server's accepted 0-RTT data) is returned as a
  slice of the caller's buffer, one record per call: the state machine still
  judges every record, but `CommonState::take_received_plaintext` and the
  server's early-data store only flag it instead of copying it.
  `WriteTraffic::encrypt` encrypts into a caller buffer after checking the
  whole size first (`InsufficientSize` carries the exact requirement, and
  nothing is consumed). Each data record is built in place there
  (`MessageEncrypter::encrypt_into`): the plaintext is copied once behind
  the header and sealed, without a per-record allocation for the built-in
  providers (an encrypter that keeps the provided `encrypt_into` allocates
  one record and copies it). What an encrypter reports is accepted only as
  one application data record within the buffer; otherwise, and when it
  fails, the buffer is zeroed from that record on and the write fails. A
  KeyUpdate that is due (an answer to the peer, or the RFC 9846 §5.5
  refresh) is written into the same buffer in order. Once a record has
  failed to encrypt (`encrypt_failed`), `WriteTraffic` takes no more data
  and makes no `close_notify`: the peer could not read them, and after a
  KeyUpdate that was lost the write key has moved on without the peer (a
  refresh asked for then still queues a KeyUpdate, which the peer rejects,
  before the failure is reported). So a KeyUpdate before the data
  that fails to encrypt fails the write with no data taken, one after the
  data leaves that write's records good and reported, and no `close_notify`
  follows either. (The buffered connection reports the failure at its next
  `process_new_packets` or write; records it encrypts until then are ones
  the peer cannot read and answers with an alert.) At
  the limit, data that cannot be rekeyed (TLS 1.2, 0-RTT) fails with
  `EncryptExhausted`, and a server's half-RTT data fails with the temporary
  `KeyUpdateAwaitsHandshake` until the client's Finished arrives, instead of
  being held back. Should a provider's record turn out longer than its
  `encrypted_payload_len` promised, a KeyUpdate that no longer fits stays
  queued for `EncodeTlsData`, and data records already sequenced are never
  withdrawn.
  Handshake messages, alerts and KeyUpdates produced by the state machine
  are queued as encoded records until `EncodeTlsData::encode` copies them
  out; that queue and the handshake joiner are bounded by the protocol, not
  by application data. After a fatal error the alert is offered through
  `EncodeTlsData` first, then the error is returned on every call. A client
  writes 0-RTT data through `TransmitTlsData::may_encrypt_early_data` right
  after its ClientHello. The connection-specific accessors of the buffered
  types are there too: `ech_status` on both sides, the server's
  post-handshake authentication methods and `client_delegated_credential`,
  and the client's `delegated_credential` and
  `post_handshake_auth_responses`.
- Acceptors read the first ClientHello before a `ServerConfig` is chosen:
  `Acceptor` (buffered, `std`) and `UnbufferedAcceptor` (no `std`; the
  caller's buffer and `discard`, as `process_tls_records`). Both drive one
  `ConnectionCore` parked in a state that handles nothing
  (`server/server_conn/accept.rs`): `first_handshake_message` reads
  plaintext records (only `change_cipher_spec` may come first, for a
  stateless retry), then the ClientHello checks that need no configuration
  run (`hs::process_client_hello`). `into_connection(config)` applies the
  checks and settings of a connection created with `config`
  (`ServerConfig::apply_to`), lets `config`'s ECH keys replace the
  ClientHello with the inner one, and hands it to
  `ExpectClientHello::with_certified_key`, then checks that a ClientHello
  that changed the read key ended its record (RFC 9846 §5.1, the check
  `ConnectionCore::process_one` makes for every handshake message). The same
  core (deframer, joiner, common state) goes on, so the connection behaves as
  one created with `config` that read the same bytes; an unbuffered one
  reports 0-RTT data in place, from the bytes the acceptor did not discard.
  Three differences remain. An alert record ahead of the ClientHello is
  refused by an acceptor (`InappropriateMessage`, `unexpected_message`, as in
  rustls), while a new connection ignores a warning alert there and reports
  a fatal one. With no cookie sealer, a `change_cipher_spec` ahead of the
  ClientHello is `IllegalMiddleboxChangeCipherSpec` through an acceptor and
  `InappropriateMessage` on a new connection (both `unexpected_message`).
  With ECH, the acceptor checks the outer ClientHello before decryption, so a
  defect only there (duplicate key shares or certificate compression
  algorithms, no `signature_algorithms`) is refused, where a new connection
  checks only the inner ClientHello. Every refusal fails the
  core (`ConnectionCore::fail`, which forgets a TLS 1.2 session it resumed)
  and queues a fatal alert, `internal_error` for a refused configuration;
  `AcceptedAlert::write` or `UnbufferedAcceptedAlert::encode` (the
  `EncodeTlsData` size contract) copies it out. A call after completion
  fails with an empty alert.

### Asynchronous streams (`browntls-tokio`)

`browntls-tokio` adapts the buffered API to Tokio's `AsyncRead`,
`AsyncBufRead` and `AsyncWrite`, and the unbuffered API in its `unbuffered`
module (below); it depends only on Tokio's I/O traits (no runtime; the
default `coop` feature adds Tokio's `rt` feature for the task budget, see
below, and the optional `ocsp` feature adds Tokio's `time` for staple
refresh). In the streams at the crate root, each poll pairs the connection with
the transport for its duration (`common::Stream`) and drives `read_tls` and
`write_tls` through adapters that turn the task context's `Pending` into
`WouldBlock`, the design of tokio-rustls:

- `TlsConnector`/`TlsAcceptor` return futures (`Connect`, `Accept`, and
  `into_fallible` variants that hand the transport back on error) that run
  the handshake. While it runs they give the transport (`get_ref`,
  `get_mut`) and the connection (`connection`, `connection_mut`) to a
  caller that polls them by hand; a future that has no connection (it
  could not be created, or a lazily chosen configuration refused the
  ClientHello and only an alert is left to send) gives only the transport.
  A handshake that can neither read nor write while still
  in progress (the peer's `close_notify` mid-handshake) ends with
  `UnexpectedEof` instead of polling forever, the asynchronous counterpart
  of the `complete_io` fix.
- `LazyConfigAcceptor` drives `server::Acceptor` over the transport until
  it yields the ClientHello (`StartHandshake`, which picks the
  `ServerConfig`). A refusal, from the acceptor or from
  `Accepted::into_connection`, writes and flushes the `AcceptedAlert` before
  the future fails; `take_io` returns the transport afterwards.
- With `TlsConnector::early_data(true)` and an eligible TLS 1.3 PSK,
  `Connect` can resolve before the handshake (`IoSession::skip_handshake`).
  The first read, flush, shutdown, or write beyond the allowance completes
  the handshake and flushes the last flight. Automatic resend requires a
  separate policy, a caller-supplied byte cap, and the same concrete ALPN
  as the ticket-issuing connection or provisioned external PSK. The adapter
  retains the outcome through reads and split polls. Write-side operations
  and handoff report unresent bytes until the application acknowledges them.
  A terminal failure remains visible to every later operation.
- Servers read accepted early data through `server::TlsStream::early_data`
  (`EarlyDataReader`, an `AsyncRead` over `ServerConnection::early_data`);
  ordinary reads never return it. By default `Accept` resolves after the
  client's Finished, so the data was sent by a client that completed this
  handshake. With `TlsAcceptor::early_data(true)` or
  `StartHandshake::early_data(true)`, `Accept` resolves while the handshake
  is in progress, once the connection accepted early data and the server's
  flight is written and flushed (`IoSession::returns_early`,
  `early_phase_reached`); other connections are accepted as before. The
  stream then carries an `EarlyPhase`: the reader returns buffered early
  data, else drives the handshake until more arrives, and reaches end of
  file when the handshake is complete (the core does not report
  EndOfEarlyData by itself; a client sends it with its Finished). An
  ordinary read, a flush or a shutdown completes the handshake first, and
  flushes the tickets. A write does too, since the connection would only
  hold the plaintext, unless `ServerConfig::send_half_rtt_data` lets the
  connection encrypt it at once (0.5-RTT data); a flush writes and flushes
  such data before it waits for the client. A handshake failure in this
  phase is kept and fails every later operation; the reader returns the
  early data received before it first. Every operation that drives the
  handshake in this phase registers a waker for the other direction's
  parked task as well (reads for a parked writer, as answering reads do;
  writes, flushes and shutdowns for a read waiting in the phase), and so
  does a write that goes out as 0.5-RTT data without ending the phase, so a task
  whose transport registration was taken over is still woken when the
  operation that took it is dropped; whichever operation moves the
  handshake on also wakes a read waiting in the phase. The option adds no
  acceptance rule of its own: the core accepts early data only for a
  session taken out of the session storage (single-use tickets, RFC 9846
  §8.1) or an external PSK that allows it, and bounds it by
  `max_early_data_size`. What the option gives up is the implicit wait for
  the client's Finished, which a replayed first flight cannot produce; the
  documentation of `TlsAcceptor::early_data` says so.
- `StartHandshake::into_stream_with` processes the records the acceptor read
  past the ClientHello (early data in the same flight) before it returns:
  the handshake only processes input after reading from the transport, so
  they would otherwise wait for the client's next flight. A failure there
  is answered like a refused configuration, with what the connection queued
  (`AcceptedAlert::from(ServerConnection)`: its flight, then the alert).
- Reads return plaintext through `Reader::into_first_chunk`, which lends the
  first buffered chunk for the connection's lifetime so `poll_fill_buf` can
  return it. A read whose records queue an answer (an alert, a KeyUpdate
  answer, a post-handshake authentication response) writes and flushes it
  as far as the transport takes it at once, since the peer may wait for it
  (a server awaiting client authentication before it responds); records
  that writes queued are left to them. Such a write may replace a parked
  writer's write-readiness registration in the transport (tokio-rustls's
  crate documentation gives wakeup problems of this kind as its reason for
  not writing during reads), so it registers a waker for both the reading
  and the writing task: writability wakes the writer even if the reader is
  never polled again, and nothing is woken at a mere `Pending`, which would
  spin a task that polls both directions. A write that moved bytes also
  wakes the writer at once. An answer the transport took only in part
  stays the reads' to finish. A read that fails writes and flushes the
  alert and wakes the writer, which then sees the failure. When the
  connection stops reading because the control records it owes are past
  the bound (see the buffered API above), a read writes everything queued,
  the writer's records ahead of the answers included, with the same joint
  waker, and waits for writability instead of taking more input or
  polling itself again. A write, flush or shutdown that takes the
  registration over wakes that read once it moves bytes or fails.
- A write encrypts what the send buffer takes and writes queued records
  until the transport blocks; a write that took nothing returns `Pending`
  only while records wait for the transport, so a retry cannot spin.
- `write_tls` offers the queued records as slices of one vectored write. A
  transport that reports one (`AsyncWrite::is_write_vectored`) gets them as
  they are. Tokio's default `poll_write_vectored` writes only the first
  slice, a write per record, so for any other transport (the report
  decides, not whether `poll_write_vectored` is overridden)
  `common::coalesce` copies whole records into a buffer on the stack (8 KiB,
  no allocation, nothing kept between polls) and writes them together: a
  handshake flight or a run of small records is one write. A record that
  does not fit with those before it starts the next write, and one that
  fits with no other (every full-size record) is written from the queue
  without a copy. Record order and contents do not change.
- `shutdown` queues `close_notify` once and then shuts the transport's write
  side. Writes after it fail with `BrokenPipe` without reaching the
  connection (RFC 9846 §6.1). The peer's `close_notify` is end of file;
  end of file without it is `UnexpectedEof`.
- TLS errors surface as `io::Error` of kind `InvalidData` wrapping
  `browntls_core::Error`; the alert describing a local failure is written if
  the transport takes it at once.
- With the `coop` feature the streams, the server's `EarlyDataReader`, the
  handshake futures and `LazyConfigAcceptor` take part in Tokio's
  cooperative scheduling (`tokio::task::coop`, `common::coop`). Tokio's
  resources take a unit of the task's budget per completed operation and return
  `Pending`, rescheduling the task, once it is spent. A TLS stream completes
  operations the transport never sees (reads of buffered plaintext, writes the
  connection buffers) and may run over a transport that does not count, so it
  counts itself: an operation starts only while budget is left and takes one
  unit when it completes. The unit is taken after the operation, not held across
  it as Tokio's `RestoreOnPending` would be, because a restored unit also
  gives back what the transport took meanwhile. In addition, every read
  from the transport after the first in one poll takes a unit
  (`Stream::read_io`, and the acceptor's read loop), and a spent budget
  looks like a transport that is not ready: the peer decides how many
  records, with or without plaintext, or pieces of a handshake, one poll
  would otherwise work through. A poll of a stream pairs the connection
  with the transport more than once (a read copies chunk after chunk into
  the caller's buffer; a client finishes an early-data handshake and then
  reads, and so does a server stream returned early; a server's early data
  reader drives the handshake step after step), so the stream's state
  carries "this poll has read" from one pairing to the next
  (`StreamState::read_before`, cleared when a poll begins). Writes need no such
  bound: one poll writes only what the caller handed it and what was queued. A
  read wakes its own task and returns `Pending` in two places, both after the
  control records the connection owed filled their backlog, which stops it
  reading until they are written, and the poll wrote them all: in
  `write_before_reading` (the records were queued behind a writer's, and the
  read wrote everything), and at the end of `Stream::poll_fill_buf` (the backlog
  was full when the poll began, or the poll's own reads filled it, and the
  answer the read writes in any case emptied it). In both no transport waker is
  registered, since the last read returned or none was made, and nothing
  is left to write; the next poll reads, so the wake does not repeat. The
  task returns to the scheduler and takes nothing from the budget.
- `into_split` (`split.rs`) gives a `ReadHalf` and a `WriteHalf` for two
  tasks; `reunite` gives the stream back. The connection state is one, so
  the halves do not run in parallel: they share the stream behind a lock
  held for the length of one poll and taken only with `try_lock`. A half
  that finds the stream taken leaves its waker and looks once more (the
  other poll may have ended in between), then returns `Pending`; the poll
  that has the stream unlocks it and then wakes the waiting half, also when
  it panics, after which the lock is poisoned and every operation of either
  half fails (`reunite` still returns the stream, as that poll left it).
  No half waits for the lock inside its poll, so no worker thread is parked
  behind the other half's record protection, which is what the blocking
  lock of `tokio::io::split` does; the lock around the two wakers is held
  for a few instructions. The second look is what rules out a lost wakeup,
  and it relies on `try_lock` failing only while the lock is held. Turns
  are not queued: a waiting half is woken at the end of each poll of the
  other and may find the stream taken again, and a half that is always
  ready may take it again and again until its task yields, which the
  `coop` feature makes it do. The read half is not an
  `AsyncBufRead`, since the stream's buffer cannot be lent out between two
  polls while the other half uses the stream.
- `into_kernel_handoff` (`browntls_tokio::kernel`) readies a client or
  server stream for
  [kernel TLS offload](#kernel-tls-offload-browntls_corekernel) without
  operating system support of its own. `into_inner` would drop what only the
  stream holds (an unfinished 0-RTT phase with the early data to send again, a
  read error kept for the next read), and the connection's handover then fails
  on what is still in flight. The future instead clears the connection's
  `kernel_handoff_blocker` step by step: it ends the 0-RTT phase as any other
  operation would (so `EarlyDataNotResent` is reported and the stream stays
  usable), completes a handshake still in progress, writes and flushes the
  queued records, reads exactly `bytes_to_record_boundary` bytes while a record
  is incomplete and processes them (answering a KeyUpdate received on the way),
  and moves the received plaintext, accepted 0-RTT data first, into a buffer of
  its own. That 0-RTT data can be replayed and is never returned by reads of the
  stream, so `early_data_len` tells where it ends. Every round clears the
  blocker it met, moves bytes or returns, so it cannot spin; bytes after
  the peer's `close_notify`, a whole record or part of one, fail it at once
  (the connection would never process them), as does a connection that has
  failed before, with its own error. A server's stream returned before its
  handshake completed (`TlsAcceptor::early_data`) leaves its early phase
  first, as it does in a flush: 0.5-RTT data is written and flushed, and
  the handshake is completed with the
  0-RTT data left where the stream's reader finds it, so a future given
  up while it waits returns the stream as it was, and a handshake that
  fails, then or before, is kept by the stream and fails its later
  operations too. The generic loop therefore never meets a handshake in
  progress, and refuses one as it refuses any blocker it cannot clear.
  The transport must not read ahead of
  what it is asked for: bytes it held back would never reach the kernel.
  It resolves to a `KernelHandoff` (the transport, the
  connection without a blocker, the plaintext to read first), which can
  also go on in userspace when the kernel declines. A blocker that driving
  the stream cannot clear is `Unsupported`; every failure returns the
  stream and the plaintext already taken (`KernelHandoffError`), and a
  future given up hands both back (`IntoKernelHandoff::into_stream`). The
  future takes no unit of the task's budget for resolving (`coop`): it
  resolves once, and its read towards a record boundary ends with that
  record. A 0-RTT phase or handshake it completes counts its reads as the
  stream's own operations do, every read after the first in one poll. The
  tests (`crates/browntls-tokio/tests/kernel_handoff.rs`) hand streams to
  the kernel stand-in of the `browntls-core` kernel tests, keyed with the
  extracted secrets, over a transport that cuts records short and holds
  writes back: no byte is lost or read twice in either direction with
  unread plaintext, a partial record, records not yet written, a KeyUpdate
  in flight and declined or accepted 0-RTT data; a read error kept for the
  next read, data after `close_notify` and a failed connection fail the
  handoff. `tests/kernel_handoff_early.rs` hands over a server's stream
  returned before its handshake completed: the handshake completed by the
  handoff with the unread 0-RTT data counted in front, 0.5-RTT data sent
  through a buffering transport before the wait, a future given up with
  nothing taken, and a handshake that failed before or fails under the
  handoff reported by it and by the stream afterwards.

The `unbuffered` module drives `UnbufferedClientConnection`,
`UnbufferedServerConnection` and `UnbufferedAcceptor` instead, with its own
`TlsConnector`, `TlsAcceptor`, `LazyConfigAcceptor` and one generic
`TlsStream<IO, C>`. The buffered streams copy the plaintext of a received
record out of the deframer into a chunk allocated for it, which
`poll_fill_buf` lends and `poll_read` copies again into the caller's
buffer (one allocation per record, one or two copies); these allocate
nothing per record and copy plaintext at most once:

- The stream owns the buffers (`unbuffered/buffers.rs`). `Incoming` is one
  allocation of 18 437 bytes (a TLS 1.2 record at its largest), made at the
  first read and never grown (it is larger only when
  `StartHandshake::from_parts` is given more bytes than that).
  `process_tls_records` decrypts the record at its front in place; the
  plaintext stays there, before the bytes not processed yet, until the
  caller has read it, and no TLS bytes are read or moved meanwhile.
  `poll_fill_buf` lends it, one record at a time; `poll_read` copies it
  into the caller's buffer. A partly received record moves to the front
  only when the rest of it, by its header, would not fit behind it
  (ciphertext, moved before it is decrypted). `Outgoing` holds encoded
  records the transport has not taken; it grows to what one write needs
  and is reused.
- One step function (`driver.rs`, `read_step`) maps a `ConnectionState` to
  what the poll functions do next: encode a handshake or control record
  into `Outgoing`, mark it transmitted, lend plaintext, collect early data,
  or ask for input. Write-side operations call `process_tls_records` with
  no input (`write_step`), which never decrypts a record, to reach
  `WriteTraffic` and to encode what the connection has queued (a KeyUpdate
  the application asked for through `get_mut`).
- The handshake future reads and writes until `is_handshaking` is false
  and checks that before every read, since the call that processes the
  peer's last flight already reports `WriteTraffic`. While its own flight
  waits for the transport it still takes the peer's bytes in (what a
  handshake makes the connection queue is bounded), so a peer that writes
  more before it reads does not deadlock with it. A failure encodes its
  alert, writes it and then fails; later operations fail the same way.
  Early data a server accepts is appended to a vector the stream keeps
  (`early_data`, `take_early_data`), bounded by
  the configured allowance. By default the connector completes the
  handshake before returning. On opt-in, the client adds early ciphertext
  behind ClientHello using the core transmit grant. It uses the same
  resend and acknowledgement policy as the buffered client.
- A write encrypts at most 65 536 bytes and returns that count; the next
  write first waits for `Outgoing` to drain, so it holds the records of
  one write at most, besides the bounded answers below and `close_notify`. A
  vectored write gathers small slices, up to 16 384 bytes, into one record
  through a scratch buffer that is zeroed afterwards.
- A read that encodes records for the peer (a KeyUpdate answer, a
  post-handshake authentication response, an alert) writes them at once
  with the joint waker described above, and the write side wakes a parked
  reader when it moves bytes or fails. Until the transport has taken and
  flushed them, later reads go on writing and flushing (a transport that
  buffers until flushed must not keep the answer), and the read's waker is
  kept: a write, flush or shutdown polled meanwhile registers it with the
  transport next to its own, so a write future that took the registration
  over and was then dropped (a timeout) does not strand the read. The
  stream counts the bytes of records the connection queued (application
  data aside) since the last application write; while more than 16 KiB of
  them are unwritten, reads take no input and wait for the transport.
  Application data that writes encrypted does not count, so two peers
  that both write before reading do not stop each other.
- `LazyConfigAcceptor` feeds the same `Incoming` to `UnbufferedAcceptor`;
  bytes behind the ClientHello stay in it for the connection
  `StartHandshake::into_stream` builds. A refusal encodes the
  `UnbufferedAcceptedAlert`, writes and flushes it, then fails.
  `StartHandshake::into_parts` and `from_parts` let a caller keep the
  accepted ClientHello and the received bytes across its own decision.
- `TlsStream::into_parts` returns the transport, the connection, the
  unread plaintext and the TLS bytes not processed or not written, to go
  on by hand or to hand the connection to the kernel.
- The module has no halves of its own (`tokio::io::split` works) and does
  not count against the task budget (`coop`): a poll reads from the
  transport until a record gives plaintext or the transport waits, so over
  a transport that never waits and does not count, the peer decides how
  long one poll runs. Both are open.

A TLS 1.2 server connection paused for a client certificate URL query
(RFC 6066 §5) is answered by the acceptor's
`client_certificate_url_fetcher`, an application closure that takes the
query and returns the objects (`browntls_tokio::certificate_url`, no Cargo
feature): `TlsAcceptor`, `LazyConfigAcceptor`, `StartHandshake` and the
unbuffered counterparts take one, and every place that answers
certificate status queries (handshakes, early-data paths, reads, the
unbuffered driver) answers this query first. Without a fetcher it is
answered `Unobtainable` at once. The fetch runs in the poll that met it
and is dropped with the handshake future. The fetcher authorizes every
destination; the module documentation lists what it must check.

### Kernel TLS offload (`browntls_core::kernel`)

Linux can protect the records of a TCP connection itself (kernel TLS):
`setsockopt(TCP_ULP, "tls")`, then the traffic keys with `TLS_TX` and
`TLS_RX`. The handshake stays in browntls. Afterwards a buffered or unbuffered
connection, client or server, is turned into a `KernelConnection` with
`dangerous_into_kernel_connection`, which returns the `ExtractedSecrets` to
install. The core does no system calls; `browntls-ktls` drives the socket.

The kernel decrypts application data for the application and hands every
other record over, decrypted, with its content type. Those records go to
`KernelConnection::handle_record`, which runs them through the same state
machine as in userspace: handshake messages are joined across records and a
KeyUpdate must end its record (RFC 9846 §5.1), TLS 1.3 KeyUpdate and
NewSessionTicket (stored in the client's session store), post-handshake client
authentication in both roles, alerts and `close_notify`, and the TLS 1.2
HelloRequest. Every record the connection would send (a KeyUpdate, an alert, a
post-handshake authentication message) is queued as plaintext instead of being
encrypted, one fragment per record within the negotiated fragment length.
`pop_output` returns, in order, `Record`s to send with the kernel's
`TLS_SET_RECORD_TYPE`, `TxKeys` to install after the KeyUpdate that announced
them and `RxKeys` to install before the next record is read (Linux stops
reading after a TLS 1.3 KeyUpdate until it has them).

Linux decides that a KeyUpdate arrived from the first byte of each handshake
record alone, for either version. A handshake record that starts with the
KeyUpdate type but is not exactly one whole TLS 1.3 KeyUpdate (part of one, a
fragment of another message that happens to start with that byte, any such
record in TLS 1.2) would leave the kernel waiting for keys that never come, so
`handle_record` fails it with `unexpected_message` instead. A KeyUpdate after
other messages in its record is refused too: the kernel would not pause there
and could read on under the old key. Empty handshake
records and other records between the fragments of a handshake message are
refused as the userspace deframer refuses them. Checks against application
data interleaved with a handshake message (RFC 8446 §5.1) cannot be made: the
kernel delivers that data to the application directly.

The handover is refused while something is in flight that the kernel could
not continue: unread received data or accepted 0-RTT
data, received bytes not yet processed or part of a record (the kernel must
start at a record boundary), queued records or plaintext, a KeyUpdate still
owed, or revocation evidence still pending. After our `close_notify`, a fatal
alert or an encryption failure it refuses for good (`Closed`).
`kernel_handoff_blocker` reports which without consuming the connection, so a
driver can drain it first (`dangerous_into_kernel_connection` drops the
connection when it fails);
`dangerous_extract_secrets` refuses the same things in flight. Secret extraction
must be enabled, QUIC connections and suites without a kernel form (TLS 1.2
AES-CBC, AES-128-CCM-8) are refused, and so is a configured `max_fragment_size`
below the smallest payload limit Linux takes (64 bytes, 63 for TLS 1.3).
`dangerous_extract_secrets` refuses disabled extraction and unsupported suites
with its own errors and otherwise adds the in-flight checks, which take
precedence when something is in flight and apply even after our
`close_notify`, a fatal alert, an encryption failure or a `FragmentTooSmall`
refusal, where `kernel_handoff_blocker` reports another reason first; it also
refuses a partly received handshake message, which the kernel handover instead
carries over and completes from the kernel's records.

The library's limits stay in force. The driver reports the application data
records the kernel sent (`records_sent`); at the suite's confidentiality limit
(RFC 9846 §5.5) a TLS 1.3 connection queues a key refresh and a TLS 1.2
connection `close_notify`. The peer's KeyUpdate and post-handshake
authentication requests are bounded per application data received, which the
driver reports (`application_data_received`). `max_tx_payload_len` gives the
fragment length the peer's `record_size_limit` or the configured
`max_fragment_size` asks for, which the kernel must be told
(`TLS_TX_MAX_PAYLOAD_LEN`, Linux 6.19). The kernel does not pad TLS 1.3
records or enforce the record size limit we announced on what it receives.

Tests drive a `KernelConnection` against a userspace stand-in for the kernel
that protects records with the extracted secrets as Linux does
(`crates/browntls-core/tests/cases/kernel.rs`): data in both directions,
KeyUpdate from either side, tickets after the handover, post-handshake
authentication, closure, the blockers, the limits and malformed records, for
every suite with a kernel form on both providers.

### Key logging

Client and server configurations use `NoKeyLog` by default. The non-default
`key-log` Cargo feature enables the shared RFC 9850 callbacks. It applies to
buffered and unbuffered TLS, DTLS and QUIC-TLS. Tokio uses the core config,
and a kTLS handoff logs only during the userspace handshake. Omit the Cargo
feature for production. To check whether any dependency enables it, use
`cargo tree -e features -i browntls-core` with the production build options.

With `std` and `key-log` on Linux, `KeyLogFile::try_from_path` opens an
explicit path, and `KeyLogFile::new()` reads `SSLKEYLOGFILE` at construction.
The sink requires local Unix ownership, permission, and lock semantics. It
accepts owner-only regular files under trusted directories, rejects links
and shared destination directories, and skips writes during advisory-lock
contention. File errors leave the TLS exchange usable. The file API stays
available as an inactive sink on other platforms. Custom callbacks do not
require `std`.

The log contains TLS 1.2 master secrets and TLS 1.3 traffic and exporter
secrets, and for Encrypted Client Hello the records below. Access can defeat
confidentiality and integrity for recorded and active sessions, including
applications relying on exporters. Use synthetic test traffic and enforce
access control and retention for any sink. This feature is independent of
the ordinary telemetry controlled by `logging`.

#### ECH records (RFC 9850 §2.3)

With `key-log`, a connection that uses Encrypted Client Hello also hands its
sink `ECH_SECRET`, the KEM shared secret of the HPKE context that seals the
inner ClientHello, and `ECH_CONFIG`, the serialized `ECHConfig` that context
is bound to. Both are identified by the random of the outer ClientHello. The
TLS labels keep their identifier: the inner ClientHello's random when ECH is
accepted, the outer one otherwise. Whoever reads `ECH_SECRET` can decrypt the
inner ClientHello of a capture, and so learns the server name that ECH
hides.

| Party | Writes the two records |
|---|---|
| Client | Once, when the ClientHello carrying a real offer is on its way, whatever the server answers. Never for a handshake that fails before that, never for GREASE, and not again for a second ClientHello. |
| Server, shared mode | Once, for an offer it accepts: the payload opened, the outer name matched the public name where that is checked, and the inner ClientHello decoded. The configuration is that of the key that decrypted. Nothing for a candidate that fails (another key, trial decryption, GREASE) or for a second ClientHello. |
| Client-facing server, split mode | Only after `ech::split::ClientFacing::with_key_log`, and only for a connection it forwards. It has no configuration and reads no environment variable, so without that call it logs nothing. It never holds a TLS secret of the connection. |
| Back-end server, split mode | Never. Its TLS secrets are identified by the inner ClientHello's random. |

The secret leaves the HPKE implementation only when three things hold: the
feature is compiled in (`browntls-core`'s `key-log` enables the feature of
the same name in `browntls-crypto`, without which that crate has no
interface that returns it), the sink answers `will_log("ECH_SECRET")`, and
the suite is the built-in provider's. The hook on `crypto::hpke::Hpke` is
hidden and its trait cannot be named outside the crate, so an HPKE suite of
another library cannot supply a value: such a connection logs `ECH_CONFIG`
alone. Inside the crate the capturing setup takes a `KeyLogAuthorisation`,
which only the sink's answer makes, so no code path reaches it without
asking. The value is the output of the KEM's `Encap` or `Decap`
(`shared_secret` in RFC 9180 §5.1.1), never a key, nonce or exporter secret
of the context. It is a local of the function that writes the record, in a
buffer zeroised on drop; the state kept for the connection does not hold it.

`KeyLogFile` writes `ECH_SECRET` values of 32, 48 or 64 bytes (the `Nsecret`
of the KEMs of RFC 9180) and `ECH_CONFIG` values that are one well-formed
`ECHConfig`. The integration tests read such a file back together with the
captured outer ClientHello and decrypt the inner ClientHello with an HPKE
key schedule written over independent primitives
(`crates/browntls-core/tests/ech_native/key_log_fixture.rs`), for a buffered
connection and one HPKE suite (X25519, HKDF-SHA256, AES-128-GCM). The tests
of the unbuffered, Tokio and facade entry points check the labels and the
identifier, not the values. No Wireshark run and no other implementation's
log has been compared yet.

### Linux kernel TLS (`browntls-ktls`)

`KtlsStream::new` takes a buffered `ClientConnection` or `ServerConnection`
(the sealed `Offload` trait) and a connected TCP socket. It refuses a
connection that cannot be offloaded before touching the socket, then attaches
the `tls` upper layer protocol, which fails without kernel support and
otherwise leaves the bytes alone until keys are installed. It then clears the
transient blockers: it completes the handshake with `complete_io`, writes the
queued records, moves received plaintext and accepted 0-RTT data into its own
buffer (read before anything from the kernel), and reads exactly
`bytes_to_record_boundary` bytes while a record is incomplete, so the kernel
starts at a record boundary. Until here every failure is
`HandoffError::Refused`, which returns the connection, the socket and any
plaintext already taken; the connection can go on in userspace. Then it
installs `TLS_TX`, `TLS_TX_MAX_PAYLOAD_LEN` when the peer asked for smaller
records (after `TLS_TX`, so the kernel applies the TLS 1.3 bound) and
`TLS_RX`; a failure from here on is `HandoffError::Failed`.

`CryptoInfo` builds the `tls12_crypto_info_*` option values (AES-GCM-128/256,
AES-CCM-128, ChaCha20-Poly1305) byte by byte in the kernel's layout and wipes
them on drop. Reads use `recvmsg` with room for `TLS_GET_RECORD_TYPE`:
application data goes to the caller and is reported with
`application_data_received`; any other record is collected until `MSG_EOR`
(the kernel continues a partly read record on the next call, never mixing
types) and given to `handle_record`. Each output is then carried out in order:
records with `sendmsg` and `TLS_SET_RECORD_TYPE`, new keys with `TLS_TX` or
`TLS_RX` from sequence number zero. The kernel takes a control record within
the payload limit whole or, on a full non-blocking socket, not at all
(`EAGAIN`); the stream then keeps it and the outputs after it in a backlog
that is carried out before anything else is sent, so no application data or
transmit key change overtakes it. New receive keys never wait there: they
are installed at once, and each blocked attempt looks only at the outputs
new since the last one, so the backlog is never scanned whole. Reading does
not wait for room to send while the backlog is small: `read` sends what it
can and goes on, a `write` that sent bytes reports them even if the outputs
it triggered must wait, and `flush` sends what is left (including a fatal
alert after a failure). Once the backlog costs more than 64 KiB (each
output its in-memory size plus a record's payload, the userspace cap on
unwritten control records), `read` takes in no more records and reports
`WouldBlock` until the socket takes it (`AsyncKtlsStream` waits for room),
so a peer that keeps asking for answers it does not read cannot make the
backlog grow without bound. The check falls before each record is read, so
the backlog may pass the bound by what one record calls for. The descriptor's
flags are never changed. Writes are one plain `send` each, which closes its last
record, so `n` bytes make at most `n.div_ceil(max)` records (unless the
kernel closes records early under memory pressure); that bound is reported with
`records_sent`, and a write takes at most 64 records so the confidentiality
limit is met in steps (it can be passed by fewer than 64 records). Bytes sent
on the socket directly (`splice`) must be reported with
`KtlsStream::records_sent`; a file is sent with `sendfile` (below), which
counts for itself. TCP closing without `close_notify` is
`UnexpectedEof`, as is every later call. A refused handover can be retried on
the same socket (an attached `tls` ULP is accepted), and a peer
`record_size_limit` the kernel cannot honour (before Linux 6.19) is refused
before any key is installed. A reduced negotiated receive limit keeps the
connection in userspace because Linux kTLS cannot enforce that limit.
Linux pauses reception whenever a handshake record
starts with the KeyUpdate type byte or holds only part of a KeyUpdate; browntls
then has no keys to install, so the stream fails on `EKEYEXPIRED` instead of
hanging. A close_notify followed by more data before the handover, a whole
record or part of one, is refused without waiting for the rest. On a
non-blocking socket (and, as the kernel's code reads, one with a send
timeout) the kernel may still hold part of a record after a write
returned: `KtlsStream::unsent` tells how much (see the ledger below), and the
caller waits for it to be zero before closing.

What follows the handover lives in one `Engine` (`src/engine.rs`): the
`KernelConnection`, the plaintext from before the handover, a control record
in transit and the backlog. It owns no socket; every call takes the
descriptor, and reports `WouldBlock` only for what it documents (a read when
the kernel has no record or the backlog is over its bound, a write or flush
when the socket has no room).
`KtlsStream` is that engine with a socket.

The engine also keeps a ledger (`src/ledger.rs`) of what the kernel was given
to send, because the kernel does not say when it has sent it. On a
non-blocking socket Linux reports a write as done once the record is
encrypted, even when TCP had no room for all of it (`tls_sw_sendmsg` does not
pass on the `EAGAIN` of its push), and sends the rest from a work item when
room appears; a FIN or a close before that drops what is left, and the peer
sees a truncated stream. Nothing reports that work, but two counters tell how
far it has come. The transmit record sequence number, read back with
`getsockopt(TLS_TX)`, counts the records made (exactly: the kernel may close
records earlier than the stream can predict); the buffer is wiped after the
read, since the kernel returns the key with it. TCP's count of the bytes it
has taken is `tcpi_bytes_acked` (`TCP_INFO`) plus the unacknowledged bytes it
holds (`SIOCOUTQ`); the two come from two calls, so the acknowledged count,
which only grows, is read on both sides of the other and the reading repeated
while it moved, and a reading that never settles is a lower bound. The ledger
takes TCP's count when the transmit keys are installed, adds up the plaintext
the engine hands over (application data and control records) and the records
made under each set of keys (the kernel counts from zero after a key update),
and knows what a record adds to its plaintext (22 bytes in TLS 1.3; 29 in
TLS 1.2 with AES-GCM, 21 with ChaCha20-Poly1305). The records' bytes on the
wire less what TCP has taken since the handover is what the kernel still
holds: `unsent()` on both streams, which may read high while
acknowledgements arrive and never low. When the counters cannot be read at
the handover, or bytes were sent on the socket directly
(`records_sent`), there is no ledger and `unsent()` says so
(`Unsupported`). A FIN takes a sequence number, so the count no longer fits
once the write side is shut.

`sendfile` on either stream sends part of a regular file as application data
with `sendfile(2)`, the kernel making the records from the file's pages. It
goes through the engine like a write (the outputs that wait first, at most 64
records' worth a call, the plaintext entered in the ledger), with three
differences.

The engine never asks for more than the file holds behind the offset
(`fstat`; anything but a regular file is refused). Asked for what is there or
less, the kernel closes the last record like a write. When it finds the end of
the file before the count, having sent something, it sends what it holds
without `MSG_DONTWAIT` (`tls_sw_splice_eof`), and the call waits for TCP to
take all of it, on a non-blocking socket too. A file that holds less than the
size it reports (cut short between the two calls, or on a file system that
reports sizes it does not have) can still bring that about.

The records are counted by the kernel's record sequence number, read on both
sides of the call, plus one. A call cut short (no room on a non-blocking
socket, a signal on a blocking one) leaves its last bytes in a record that a
later call closes, and the kernel may close a record early (too many pieces of
pages in it, or memory pressure), so the bytes sent do not bound the records
made. The bytes of an open record go out with whatever is sent next, are in
`unsent()` until then, and are lost if the stream is dropped first. Without the
kernel's counters the engine reports a record for every 4096 bytes on top of
those the bytes alone make.

`sendfile(2)` has no flag against `SIGPIPE`, which a peer could otherwise
bring upon a process that does not ignore the signal by resetting the
connection. Kernel TLS raises it in two places: during a `sendfile` on a
connection closed for sending, even when the call reports bytes as sent
(`tls_sw_sendmsg_locked` returns what it copied and raises the signal for the
error behind it), and when the socket is closed, where the records the kernel
still holds are sent with the flags of the calls that made them. Both are
answered with `sys::HeldSigpipe`, which blocks the signal for the calling
thread and, when dropped, takes a `SIGPIPE` that became pending meanwhile
(`sigtimedwait`) before it unblocks the signal again, if the caller had not
blocked it; one that was pending before is left alone, and one sent to the
process by something else meanwhile cannot be told from the kernel's and is
taken too. `sys::sendfile` holds it for the length of the call. A stream that
sent a file holds it while it is dropped (`src/quiet_close.rs`): the stream's
`Drop` takes the hold, and the field that keeps it is declared right behind
the socket, so that the socket, and nothing else, is dropped under the hold.
The kernel sends the held records when the last reference to the socket goes,
in whichever task drops it. A socket the stream does not own (a borrowed or
shared one), a duplicate, and a descriptor inherited by a child process (which
closes it at `exec` if it is close-on-exec, and whenever it does otherwise,
possibly after the parent dropped the stream) are closed elsewhere, and that
closer has to see to the signal itself:
nothing in userspace can discard the records.

`AsyncKtlsStream::sendfile` runs the same call when Tokio reports the socket
writable; only the socket is waited for, not the file's storage. The tests
(`tests/sendfile.rs`, `tests/tokio_zero_copy.rs`, and unit tests in
`src/sys.rs` and `src/sigpipe_tests.rs`) count the records on the wire, drive
KeyUpdates with a suite whose keys last for 100 records, fill a non-blocking
socket, and show that a count past the end of the file does not wait for a
peer that is not reading. A handler counts the `SIGPIPE`s delivered to the
test process: none from `sendfile` on plain TCP and on kernel TLS sockets of
both streams whose write side was closed, and none from dropping those
streams.

`set_tx_zerocopy_sendfile` on either stream sets `TLS_TX_ZEROCOPY_RO` (Linux
5.19; off after the handover), which lets a network device that encrypts the
records itself send the pages of a `sendfile` without a copy; the file must
then not change until its bytes are acknowledged, or a retransmission carries
a record that does not authenticate. With software encryption in the kernel
the option changes nothing. The tests (`tests/zero_copy.rs`,
`tests/tokio_zero_copy.rs`) read it back on the running kernel.

`set_rx_expect_no_pad` sets `TLS_RX_EXPECT_NO_PAD`: TLS 1.3 records are
decrypted straight into the reader's buffer on the promise that the peer does
not pad. A record that is padded after all, or is not application data, is
decrypted a second time into a buffer of the kernel's and copied out, so the
peer decides how often the work is done twice, and the option is the
application's to set. Before Linux 7.2 `tls_decrypt_sw` does not take back the
reader's position the first attempt advanced: the copy lands behind the first
attempt's output, and a peer that pads corrupts what the application reads.
The engine therefore sets the option only when `uname` reports release 7.2 or
later, and refuses it (`Unsupported`) on anything older or that it cannot
parse, including older kernels that carry the correction and the release
candidates of 7.2 (the correction came with 7.2-rc7); when `uname` itself
fails, its error is returned and the option stays off. The release is the
only evidence: a kernel built from a 7.2 pre-release source whose release
does not name a release candidate is taken for 7.2. While the option is set,
every read zeroes its buffer for up to a record's length behind the bytes it
reports (and all of that length after an error, `WouldBlock` included, before
which a padded record without content may have been decrypted there): the
first attempt writes there the plaintext of a control record that follows the
data, a padded record's padding, or the output for a record that then fails to
authenticate. `tests/zero_copy.rs` reads against a userspace peer that pads two
records of three (a wrapper around the suite's encrypter) and checks every
read's buffer; on an older kernel the tests check the refusal instead.

`AsyncKtlsStream` (feature `tokio`) is the engine with a
`tokio::net::TcpStream`, implementing `AsyncRead` and `AsyncWrite`. Each
system call runs inside `TcpStream::try_io`, so a call that finds the socket
not ready clears Tokio's readiness and the task is woken when it changes;
plaintext from before the handover, the peer's closure and a failure are
reported without the socket. `AsyncKtlsStream::from_client` and `from_server`
take a `browntls-tokio` stream over a `TcpStream`: they refuse what driving
cannot clear and attach the `tls` upper layer protocol before anything is
taken from the stream, ready it with
[`into_kernel_handoff`](#asynchronous-streams-browntls-tokio), check the
record size and install the keys. Until the keys go in, every failure returns
the stream and the plaintext taken (`StreamHandoffError::Refused`), so it can
go on in userspace. 0-RTT data a server had accepted and not read is the
front of the plaintext the stream returns first; the stream and the refusal
carry its length (`early_data_len`), because it can be replayed and a
`browntls-tokio` stream would have returned it through `early_data()` only.
`AsyncKtlsStream::new` takes a connection already at rest and its socket. A
read that owes the peer something (a KeyUpdate answer) and finds the socket
full registers for writability as well as readability.
Tokio keeps one waker per direction, and the stream may be split into halves
on two tasks, so the reader and a parked writer register a waker that wakes
both: neither can lose its wakeup to the other's registration. `poll_shutdown`
queues `close_notify` once, sends what waits, waits until the ledger shows
that TCP has taken every record, and shuts the socket's write side. While
the kernel holds records, the stream waits for the socket to have room: the
kernel schedules its work item when room appears, just before it wakes the
socket's waiters. That the socket has no room is something `poll` shows and
Tokio's cached readiness does not, so the stream asks the kernel. Once there
is room and the ledger still shows records held, the work item is under way
and nothing reports its end, so the stream looks again after a pause
(`src/drain.rs`): four times it only yields to the runtime, then a clock
thread wakes it after pauses from a quarter of a millisecond to eight
milliseconds. Yielding longer was not seen to help: on one Linux 7.0 host,
in four runs, records still held after two looks stayed held through 315 to
393 more within a millisecond and were gone after the first pause (the work
item, queued on the task's own processor, may not run until the thread
blocks or the scheduler's next tick; a reading, not shown). That thread is
one for the whole process, started with the first alarm and gone
five seconds after the last; where it cannot be started the task goes on
yielding. The pauses use no timer of the runtime, which may have none. The
wait ends with an error when the socket hangs up or has an error pending
while records are held (they will not be sent; `POLLERR` alone is not taken
for that, since the socket's error queue raises it too), when the counters
cannot be read or do not fit, and with `TimedOut` when the same records have
been held for five seconds although the socket had room and TCP had nothing
in flight whose acknowledgement would make the kernel send. Only where there
is no ledger (`Unsupported`) does the stream wait for room alone, as it did
before the ledger existed: that narrows the window without closing it. A test of
that earlier wait, which shut down straight after writing a megabyte
into 4096-byte socket buffers, failed in one of six kernel CI jobs: the
kernel end's read after its shutdown failed with `BrokenPipe`. The likely cause,
from reading the kernel and not shown by the log, is the kernel's late send
meeting the FIN (`EPIPE`, which the kernel then leaves on the socket as its
error). The wait for room (ask the kernel, stay pending without room, be woken
when room appears), the pauses and the five-second limit are tested without
kernel TLS (`src/tokio_stream.rs`, `src/drain.rs`), as is TCP's count on plain
TCP (`src/ledger.rs`). The other tests
(`crates/browntls-ktls/tests/tokio_offload.rs`) run on the running kernel
like those of `KtlsStream`: both ends offloaded for every
suite with KeyUpdates, data in flight at the handover kept in order, an
offloaded server against a userspace client (tickets, KeyUpdate, closure), a
KeyUpdate answered by a read while the socket is full (the answer seen on the
wire by a relay), split halves across key updates, a client still in its
0-RTT phase (with the server's count of accepted 0-RTT data), truncation, a
megabyte written through small socket buffers and shut down at once, a
shutdown that stays pending while the kernel holds records a peer does not
read (and the count of them), a peer that closed TCP before the handover (the
kernel attaches the upper layer protocol to an established connection only,
`ENOTCONN`; the stream goes on in userspace), and refusals that return the
stream.

`src/sys.rs` is the crate's only `unsafe` code, an exception to the workspace's
`unsafe_code = "deny"`: `setsockopt`, `getsockopt`, `poll` on one descriptor
without waiting, `ioctl(SIOCOUTQ)`, `uname`, `sendfile` (whose only pointer is
to the offset) with `fstat` and the calling thread's signal mask around it,
`sendmsg`/`recvmsg` with one control message, plain `send`, and
`clock_gettime(CLOCK_THREAD_CPUTIME_ID)` for the routing's write timing. Its
invariants are listed at its top: borrowed descriptors,
pointers only into live values with their lengths, the thread's signal mask
left as it was, control messages built and
read through the libc `CMSG_*` functions within a `cmsghdr`-aligned buffer
sized with `CMSG_SPACE`, and no value created from kernel output but plain
integers. The tests (`crates/browntls-ktls/tests/offload.rs`) run over
loopback TCP against the running kernel: both ends offloaded for every suite
with KeyUpdates from both sides (and, on these blocking sockets, the ledger
at zero to the byte after every call), an offloaded end against a userspace
peer in
each role (tickets, a KeyUpdate from the userspace end, data that arrived with
the Finished, closure, and the recorded TLS 1.2 explicit nonces, which must
never repeat), a peer's smaller `record_size_limit`, truncation, and a refused
handover. They are skipped without the `tls` module unless
`BROWNTLS_KTLS_REQUIRED=1`, which the x86-64 and aarch64 CI jobs and the
Tokio lower bound job set after `modprobe tls` (the riscv64 job does not, so
there they may be skipped).

### Delegated credentials (RFC 9345)

`browntls_core::delegated_credential` holds the `DelegatedCredential` codec,
signing (`DelegatedCredential::issue`) and validation (`validate`, the
check both sides run on a received credential, public for callers that
handle credentials below the handshake); the native provider
adds `crypto::native::delegated_credential::generate`, which creates an
ECDSA (P-256/384/521), Ed25519 or Ed448 credential key and has the
certificate's key sign the credential. A credential is issued for the side
that authenticates with it (the signed context string differs, §4) and
attached to a `CertifiedKey` for that side: `with_delegated_credential` for a
server, `with_client_delegated_credential` for a client. Pass the configured
`CryptoProvider` to either attachment method or a
`DelegatedCredentialKey` constructor. The provider verifies the issuer
signature against the exact leaf and role; the leaf must carry
`DelegationUsage` and the `digitalSignature` key usage. Key association
uses the delegated signer's SPKI or a one-time signature when the signer
cannot export it. Attachment checks that the credential expires strictly
inside its parent's validity period and accepts staged credentials.
`check_usable_at` checks activation at a caller-supplied time, and
presentation uses the connection clock. `DelegatedCredential::to_bytes`
returns a `Result` and checks the enclosing extension length. Use the
fixed-identity config builders `with_single_certified_key` and
`with_client_auth_certified_key` to install a prepared key, or return it
from a certificate resolver. A side only presents credentials attached for
it, so one `CertifiedKey` can serve both roles. Credential keys
may not be `rsaEncryption` keys (§4): the
`rsa_pss_rsae_*` schemes are never issued, attached, offered or accepted
(`rsa_pss_pss_*` is allowed). `CertifiedKey` keeps its credentials in a
private field (`delegated_credentials()` reads them), so it can no longer
be built with a struct literal; `CertifiedKey::new` remains.

- Server: when the ClientHello carries `delegated_credential` and a
  credential is unexpired, has at most seven days left and expires before
  its certificate, uses a `dc_cert_verify_algorithm` the client listed in
  both `delegated_credential` and `signature_algorithms` (which governs
  CertificateVerify) and is signed with a scheme in its
  `signature_algorithms`, the credential goes on the end-entity
  CertificateEntry and its key signs CertificateVerify. Otherwise the
  certificate key signs, as before. Never with raw public keys or TLS 1.2.
- Client: off unless `ClientConfig::enable_delegated_credentials`. The
  chain is verified as usual; then the credential is validated (offered
  schemes, not expired, at most seven days left and not beyond the
  certificate's `notAfter`, CertificateVerify scheme equal to
  `dc_cert_verify_algorithm`, `DelegationUsage` and `digitalSignature`,
  signature by the certificate key) and CertificateVerify is verified with
  its key through
  `ServerCertVerifier::verify_tls13_signature_with_delegated_key` (the
  default implementation refuses). `ClientConnection::delegated_credential`
  returns the credential used by a full handshake; it remains `None` on a
  resumed connection.
- Client credentials (§4.1.2) mirror this with the roles exchanged. A
  server asks for them only while `ServerConfig::enable_delegated_credentials`
  is set: its CertificateRequests, in the handshake and after it
  (`request_client_auth`), then carry `delegated_credential` with the client
  certificate verifier's TLS 1.3 schemes other than `rsa_pss_rsae_*`. A
  client whose resolved `CertifiedKey` has a client credential the request
  accepts (same conditions as for a server, by the client's clock) puts it
  on its end-entity CertificateEntry and signs CertificateVerify with its
  key; otherwise the certificate key signs. The credential is tried first,
  so a client whose certificate key cannot sign (kept offline) still
  authenticates when the server accepts credentials. The server verifies
  the chain as usual, validates the credential when CertificateVerify
  arrives using the real signature and delegated-credential schemes sent
  in that specific CertificateRequest, and checks the signature with the
  credential's key through
  `ClientCertVerifier::verify_tls13_signature_with_delegated_key` (the
  default implementation refuses; `WebPkiClientVerifier` implements it). It
  checks the credential's expiry again when the client's Finished arrives.
  `client_delegated_credential` on `ServerConnection`,
  `UnbufferedServerConnection` and the server's `KernelConnection` returns
  the credential of the client's current identity: that of the full
  handshake, replaced (or cleared) by each successful post-handshake
  authentication (a declined one leaves it, like `peer_certificates`);
  `None` on a resumed connection. Never with raw public keys
  or TLS 1.2. `browntls-tokio` streams reach the accessors through
  `get_ref`.
- Resumption: the client and server save the absolute expiry of the delegated
  credential that authenticated the original full handshake. A ticket is not
  offered or accepted, including for 0-RTT, when the current time is at or
  after that deadline. The client checks again after the resumed server
  Finished so a handshake that crossed the deadline cannot complete. Every
  descendant ticket carries the original deadline unchanged; the server also
  caps its advertised ticket lifetime to the remaining credential lifetime
  and sends no ticket when none remains. This is independent of an RFC 9973
  external-PSK binding; both properties are retained when both authenticated
  the session. A server keeps the deadline of a client's credential the same
  way, next to its own: a ticket is passed over at or after either deadline,
  or when the session's client used a credential and the configuration no
  longer enables them, the ticket lifetime is capped by both, and the
  resumed handshake is aborted if the deadline passes before the client's
  Finished.
- Persistence: the private client session value carries the deadline without
  changing `ClientSessionStore`. The server session encoding has a mandatory
  tagged deadline field. Because the encoding from before server credentials
  cannot distinguish sessions authenticated with a delegated credential, the
  change that added the field deliberately rejects every server session value
  written before it (TLS 1.3 and TLS 1.2); old and new members of a
  mixed-version fleet therefore cold-miss each other's cached sessions and
  tickets rather than resuming ambiguous authentication state. Client
  credentials later made the tag a bit mask (1: the server credential's
  deadline follows, 2: the client credential's). Values with that field
  written before client credentials (tag 0 or 1) still decode; a server
  from before client credentials rejects a value that carries a client
  deadline, so it never resumes a session whose client authentication it
  cannot bound.
- Alerts (§4.1.1 to §4.1.3), the same on both sides: an invalid credential
  is `illegal_parameter`; one the receiver did not ask for is
  `unexpected_message`; one on an entry other than the end entity's is
  `illegal_parameter`; a CertificateVerify that fails under the
  credential's key gets the same alert as one that fails under a
  certificate key (`decrypt_error` for a bad signature).
- Exported authenticators (RFC 9261) do not carry delegated credentials: an
  authenticator's Certificate entry with one is refused.
  No other implementation the project tests against supports delegated
  credentials, so the tests are browntls to browntls only.

### Exported authenticators (RFC 9261)

`browntls_core::exported_authenticator` adds `request_authenticator`,
`authenticator` and `validate_authenticator` to `ClientConnection` and
`ServerConnection` (with `std`) and to `UnbufferedClientConnection` and
`UnbufferedServerConnection` (also without `std`); QUIC connections do not
have them. One macro per side defines the methods, with the same signatures
and documentation, on the buffered and the unbuffered type, and their
bodies call the same code on the `ConnectionCore` both APIs drive (the
exporter, the context lists, the request digests, the verifier calls and
the clock). Without `std` the default time provider has no clock, so
validation fails with `FailedToGetCurrentTime` unless the configuration
has one. The messages are carried by the application protocol,
not the record layer. A client request is a `ClientCertificateRequest`
(type 17), a server request a TLS 1.3 `CertificateRequest`; the answer is
TLS 1.3 `Certificate`, `CertificateVerify` and `Finished` messages, or a lone
`Finished` over an empty certificate list to decline (also when no key can
sign with a requested scheme). A server may authenticate spontaneously with
a random 32-byte context.

- Keys: the exporter with the labels `EXPORTER-client authenticator
  handshake context` / `... finished key` (`server` for server
  authenticators), a zero-length context (§5.1; in TLS 1.2 its two length
  octets enter the RFC 5705 seed, in TLS 1.3 it equals no context) and the
  length of the connection's hash. TLS 1.3 and TLS 1.2 with the extended
  master secret (the TLS 1.2 exporter refuses sessions without it); for
  TLS 1.2 the HMAC comes from a TLS 1.3 suite of the provider with the
  same hash.
- Validation: the request must be one this side made and not yet answered
  (recognised by a digest of its bytes); framing is bounded by the
  handshake message limit; request type and context are checked;
  `Finished` is compared in constant time before any certificate or
  signature is verified; the CertificateVerify scheme must be one the
  request offered (for a spontaneous authenticator, one the client's
  verifier supports); then the chain and signature go through the
  configured `ServerCertVerifier` (with the connection's server name, the
  SNI; no secondary host names) or `ClientCertVerifier`. Entry extensions
  are refused.
- Local policy: contexts are 1 to 255 bytes and used once per connection
  (a reused context is `PeerMisbehaved::ReusedAuthenticatorContext`). Each
  side keeps three lists of at most 256 entries, capped separately:
  requests it made, authenticators it made, and spontaneous authenticators
  it validated. A full list makes further requests, authenticators or
  spontaneous validations fail; answers to its own requests are recorded
  on the request, so a peer cannot use up the room they need. A request's
  `signature_algorithms` is required; `certificate_authorities` may be set,
  `server_name`, `oid_filters` and `status_request` are not supported.
- Errors are returned to the caller; no alert is sent and the connection
  continues, since the messages are outside the TLS record layer.
- No other implementation the project tests against exposes exported
  authenticators, so the tests are browntls to browntls only.

### Encrypted Client Hello (RFC 9849)

`browntls_core::ech` implements ECH on top of the HPKE traits in `crypto::hpke`
(`Hpke`, `HpkeSealer`, `HpkeOpener`); the native provider implements them in
`crypto::native::hpke` for every `browntls_crypto::hpke` suite. The
RustCrypto provider has no HPKE, so the client and the servers that decrypt
need the native provider or another implementation of the traits; the
back-end server of split mode decrypts nothing and works with either
provider. Both server topologies of RFC 9849 §3.1 are implemented: shared
mode, where one server decrypts and terminates the connection, and split
mode, where a client-facing server decrypts and relays the connection to a
back-end server that terminates it.

- Client (`ClientConfig::ech_mode`): `EchConfig::new` picks the first
  configuration in an `ECHConfigList` with RFC 9849's version, no unknown
  mandatory extension, a public name that is an LDH host name not ending in a
  numeric or `0x` label, and a cipher suite the given HPKE suites cover. The
  handshake state machine builds the inner ClientHello (TLS 1.3 only, an
  `inner` ECH extension, no 0-RTT, and no TLS 1.2 session: TLS 1.2 sessions
  are not even looked up, so the `legacy_session_id` both hellos share is
  always fresh random and never one a TLS 1.2 server issued for the hidden
  name), then
  `ech::client` seals it into the outer one: a fresh random, the public name
  as SNI, no ALPN, a GREASE `pre_shared_key` mirroring the inner PSK, the
  longest run of extensions identical in both replaced by
  `ech_outer_extensions`, and the §6.1.3 padding. With RFC 8701 GREASE on,
  both hellos carry the same GREASE values; RFC 7685 `padding` goes only into
  the outer hello (the inner one is padded by §6.1.3), sized for the outer
  hello and covered by its AAD. An inner PSK, a ticket or an external PSK, is
  mirrored by a GREASE one in the outer hello. Both transcripts are kept
  until the ServerHello (or the HelloRetryRequest's ECH extension) shows
  whether the server confirmed acceptance; on rejection the handshake
  continues with the outer hello, authenticates the public name, answers a
  CertificateRequest with an empty Certificate, and after Finished sends
  `ech_required` and fails with `Error::RejectedEch`, which carries the
  retry configurations. A HelloRetryRequest that confirmed acceptance
  followed by a ServerHello that does not is `illegal_parameter`. GREASE
  (`EchMode::Grease`) sends a random `config_id`, a real `enc` and a payload
  sized like a padded inner hello, and ignores the server's ECH answers.
- Server in shared mode (`ServerConfig::ech`, `EchServerConfig`): keys are
  matched by `config_id` (several keys may share one) and trial-decrypted;
  with `EchServerConfig::with_trial_decryption` every key is tried whatever
  the identifier (§7.1, the second method, for clients that randomize it;
  §10.4 allows it only when configured, since each ClientHello that does
  not decrypt then costs one decapsulation per key and suite). With
  `EchServerConfig::with_public_name_check`, an extension that decrypts
  under a configuration whose public name differs from the outer
  `server_name` (ignoring ASCII case) is `illegal_parameter`; only the
  configuration that decrypted is compared, so keys shared between
  configurations with different public names cause no spurious failure. The
  inner
  hello is rebuilt in linear time (one cursor into the outer extensions;
  missing, repeated, out-of-order or ECH references, and non-zero padding,
  are `illegal_parameter`), must carry an `inner` ECH extension and offer
  nothing below TLS 1.3, and replaces the outer ClientHello for the rest of
  the handshake (also through either acceptor, using the configuration
  passed to `into_connection`). The ServerHello random and, after a
  HelloRetryRequest, its ECH extension carry the acceptance confirmations.
  The second ClientHello must repeat the `config_id` and cipher suite with an
  empty `enc` and decrypt with the same HPKE context (`missing_extension`,
  `illegal_parameter`, `decrypt_error`). An extension that does not decrypt
  (GREASE included) leaves the outer hello in use; EncryptedExtensions then
  carries the server's `ECHConfigList` as retry configurations, and a
  HelloRetryRequest carries 8 random bytes in place of a confirmation. An
  `ech_outer_extensions` extension, or an ECH extension of type `inner` or of
  an unknown type, in a ClientHello as received is `illegal_parameter`.
- Client-facing server of split mode (`ech::split::ClientFacing`, §7.1):
  a sans-I/O object per connection, fed the client's and the back-end
  server's bytes. It reassembles the first ClientHello (plaintext handshake
  records, at most 64 KiB, nothing else in the records) and decrypts it with
  the shared-mode code, then decides: `Forward` when ECH is accepted (the
  inner ClientHello, re-framed in records of the client's record version, is
  queued for the back-end server chosen by its `server_name`), `Local`
  otherwise (no extension, GREASE, stale keys, or input that is not a
  ClientHello or does not parse as one). A ClientHello whose framing is
  wrong (an empty handshake record, more than 64 KiB, or more handshake data
  after it in its record) is a fatal error instead, because a local server
  would decrypt and answer it before noticing; refusing empty records also
  bounds what is buffered before the decision. After `Local`, the bytes
  received so far go to an ordinary shared-mode `ServerConnection` with the
  same keys
  (`into_server_connection` or `into_received`), which decrypts again,
  reaches the same result, authenticates as the public name and sends the
  retry configurations. After `Forward`, client records are forwarded whole
  until the back-end server's first handshake message: a
  HelloRetryRequest (recognised by its random) makes the client-facing
  server decrypt the second ClientHelloOuter with the first one's HPKE
  context (§7.1.1, the same checks and alerts as shared mode) and forward
  its inner ClientHello; a ServerHello, an alert or anything else switches
  both directions to unmodified relaying (`is_relaying`). An `inner` or
  unknown ECH type, `ech_outer_extensions`, or a malformed inner
  ClientHello is a fatal error with a plaintext alert for the client
  (`take_for_client`). The client-facing server never holds traffic keys.
  It buffers one partial record per direction, one ClientHello, a copy of
  the client's bytes until the decision (for a local hand-off), and what it
  queues for each side until the caller takes it. It issues no
  HelloRetryRequest cookie (§7.1.1), so it keeps its state for the whole
  handshake.
- Back-end server of split mode (`ServerConfig::ech_backend`, §7.2): a
  ClientHello with an `inner` ECH extension (as the client-facing server
  forwards it) is confirmed in the ServerHello random and, after a
  HelloRetryRequest, in its ECH extension, with the same code as shared
  mode; the HelloRetryRequest stays stateful, as in shared mode. An `outer`
  or unknown type is `illegal_parameter` (§7), as is an inner ClientHello
  offering TLS 1.2 or below (stricter than §7.2, which only forbids
  confirming when TLS 1.2 is negotiated; a conforming client-facing server
  never forwards such a hello, §7.1); after a
  HelloRetryRequest the second ClientHello must carry `inner` again
  (`missing_extension` otherwise), and one that adds it is
  `illegal_parameter`. A ClientHello without ECH is served as usual.
  `ech_backend` and `ech` exclude each other (connection creation and the
  acceptors' `into_connection` fail).
- Client with a random identifier (`EchConfig::with_random_config_id`,
  §10.4): one random `config_id`, repeated after a HelloRetryRequest, for
  servers known to use trial decryption.
- `ech::svcb` reads the `ech` SvcParam (RFC 9848) from SVCB/HTTPS record
  data or its Base64 presentation form; the crate does no DNS lookups.

Tests: shared and split mode in-process
(`crates/browntls-core/tests/ech_native.rs`: acceptance with and without a
HelloRetryRequest, input fed byte by byte, an inner ClientHello spanning
records, resumption, rejection completed locally with retry configurations and
the retry forwarded, GREASE and non-ECH connections kept local, every error path
of the client-facing and back-end servers, trial decryption with random
identifiers, a back-end server on the RustCrypto provider), the `tls_ech` fuzz
target (split mode in fuzz-chosen pieces), and the Docker E2E matrix (`ech-*`
scenarios: browntls in every role, and Go crypto/tls 1.27 as client and
shared-mode server, also as the client of the browntls split-mode servers).

Not implemented: ECH with DTLS or QUIC, and a client-facing server that
inspects anything after the back-end server's ServerHello (by design: it
relays the encrypted handshake unmodified).

### ECH configuration files (RFC 9934)

`ech::pem::EchPem` reads an ordered ECHConfigList with an optional matching
PKCS #8 key. Use `to_public_pem` or `ech_config_list` for material shared with
clients or published in DNS. Protect private files and any copy of their
contents like the TLS server's certificate private key. The native key codec
supports X25519, X448, P-256, P-384 and P-521. It reads BER and DER and writes
DER. NIST keys with the ECDH-only PKCS #8 algorithm identifier retain that
restriction on export. Applications without the native provider may supply
a PKCS #8 codec, and public-only parsing requires only the allocator.

For a shared server, put an `EchServerConfig::from_pems` result in
`ServerConfig::ech`. A split-mode client-facing server uses the same
configuration for decryption and for its local TLS fallback. Pass decryption
bundles and advertised retry lists separately. This allows a retiring key to
continue decrypting existing client offers while the retry list advertises
only current configs. A public-only retry config may identify a key on
another instance if clients can reach it using the original deployment's
retry routing. Clients with a public file select a config using
`EchConfig::from_pem`.

Tokio's buffered and unbuffered connectors and acceptors also accept parsed
PEM inputs through `from_ech_pem`. Linux kTLS helpers prepare the userspace
connection. The existing handoff APIs still manage kernel offload and fallback
with explicit opt-in to traffic secret extraction.

### QUIC-TLS (RFC 9001)

`browntls_core::quic` is the TLS half of QUIC, shaped like `rustls::quic`: a
QUIC implementation feeds the contents of CRYPTO frames to `read_hs`, takes the
bytes to send from `write_hs`, and receives the keys of each encryption level
as a `KeyChange`. Packets, frames, transport parameters, loss recovery and
the choice of packet number space stay with the QUIC implementation; browntls
does not implement QUIC transport (RFC 9000). Only QUIC version 1 is
supported.

- Connections: `quic::ClientConnection` and `quic::ServerConnection` share
  the TLS 1.3 state machines through `CommonState::quic`. In that mode
  handshake messages are queued with the level that protects them (Initial,
  Handshake or 1-RTT) instead of being written as records; no record layer
  keys are installed, no ChangeCipherSpec is sent (§8.4), no EndOfEarlyData
  is sent or expected (§8.3) and `legacy_session_id` is empty.
- Levels: `write_hs` emits one level's bytes per call and returns the next
  level's keys once they exist; the bytes written by that call belong to the
  previous level. `read_hs` refuses bytes that continue past a message that
  changes the peer's level (§4.1.3, `KeyEpochWithPendingFragment`).
- Packet protection: each TLS 1.3 suite names a `quic::Algorithm` in its
  `quic` field: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 on both
  providers, AES-128-CCM on the native one; TLS_AES_128_CCM_8_SHA256 has none
  (§5.3) and is never offered. The RustCrypto provider computes the ChaCha20
  header protection block itself, since the `chacha20` crate refuses block
  counter 0xffffffff, which a peer can choose. Keys come from "quic key", "quic
  iv" and "quic hp" (§5.1); Initial keys from the client's Destination
  Connection ID (§5.2). Header protection masks the packet number without
  branching on its length (§9.5). Each packet key reports the §6.6
  confidentiality and integrity limits; counting packets is the QUIC
  implementation's job.
- Key update: `Secrets::next_packet_keys` derives the next phase with
  "quic ku" (§6); a TLS KeyUpdate message is `unexpected_message`.
- Other TLS extensions: `record_size_limit` is neither offered nor
  acknowledged, since QUIC has no TLS records. An external PSK can
  authenticate a QUIC handshake but never carries 0-RTT, because 0-RTT
  needs the transport parameters remembered with a ticket (RFC 9000
  §7.4.1). Encrypted Client Hello (shared mode or as a split-mode back-end
  server) is refused on QUIC connections for now:
  the outer ClientHello has no ALPN, so a QUIC server rejecting ECH could
  not complete the handshake that delivers retry configurations.
- Post-handshake client authentication (§4.4): a QUIC client never offers
  `post_handshake_auth`, and a QUIC server ignores the offer, so
  `request_client_auth_after_handshake` does not defer client
  authentication there. A post-handshake CertificateRequest is a
  PROTOCOL_VIOLATION, without an alert.
- Transport parameters: the `quic_transport_parameters` extension (0x39) is
  required in QUIC (`missing_extension`) and refused by a TLS server
  (`unsupported_extension`); the pre-RFC code point 0xffa5 is not recognised.
  A client keeps the server's parameters with its ticket for 0-RTT.
- ALPN: if either side configures protocols and none is agreed, the
  handshake fails with `no_application_protocol` (§8.1).
- 0-RTT: a server allows it only with `max_early_data_size` 0 or `u32::MAX`
  (§4.6.1), and a client refuses a ticket announcing any other early data
  size. A server exposes 0-RTT keys only when it accepted early data; a
  client drops them after a HelloRetryRequest or a refusal. Whether to
  accept 0-RTT is decided before the stored resumption data is visible, and
  needs stateful session storage, as for TLS.
- Errors: the first fatal alert is available from `alert`, and
  `crypto_error_code` maps it to CRYPTO_ERROR `0x0100 + alert` (§4.8).
  The violations RFC 9001 makes a PROTOCOL_VIOLATION (data left over at a
  level change, a ticket without the 0-RTT sentinel, a ClientHello with a
  session ID) fail without an alert, so `alert` stays `None`.
- `read_hs` takes no encryption level: apart from level changes, the QUIC
  implementation checks which level CRYPTO data may arrive at.
- Retry: `retry_integrity_tag` and `verify_retry_integrity` compute and check
  the §5.8 tag with a provider's TLS_AES_128_GCM_SHA256 suite (any other
  suite is refused).

### DTLS 1.3 (RFC 9147)

`browntls_core::dtls` runs the TLS 1.3 handshake over datagrams. It is a
low-level, sans-I/O API: `dtls::ClientConnection` and
`dtls::ServerConnection` take each received datagram with `read_datagram`
(which decrypts application data in place and returns its ranges), produce
whole datagrams with `write_datagram`, and leave the socket and the clock to
the caller, who passes a monotonic time to every call and fires
`handle_timeout` once `next_timeout` has passed. DTLS 1.3 is the default.
Explicit endpoint policy can enable DTLS 1.2 certificate handshakes and
separately configured session ID or RFC 5077 ticket resumption with the
`tls12` feature; see [DTLS 1.2](DTLS12.md) for the APIs, policy and transport
separation, protocol boundaries and outstanding qualification. The following
record and handshake details describe DTLS 1.3.

- Handshake: the TLS 1.3 state machines with the DTLS hello encoding
  (`legacy_cookie`, DTLS version numbers, an empty session ID that is never
  echoed), no ChangeCipherSpec and no EndOfEarlyData. A configuration must
  allow TLS 1.3 and hold a suite with DTLS record protection: every TLS 1.3
  suite but TLS_AES_128_CCM_8_SHA256 (§4.5.3), which is never offered.
  Tickets are kept apart from TLS ones, so a DTLS connection never resumes
  a TLS session or the reverse; resumption with a ticket works as in TLS.
- Records: unified headers with encrypted record numbers (§4.2.3), a
  replay window of 128 records per epoch, and at most four keyed receiving
  epochs kept for reordered records. Records that do not authenticate, are
  replayed or cannot be delimited are dropped silently (§4.5.2).
  Unprotected input, which anyone who knows an address can forge, counts
  for little: unprotected ACKs are ignored; unprotected alerts end the
  handshake only before the peer has authenticated, and only fatal error
  alerts (not close_notify or user_canceled); unprotected handshake
  fragments are buffered only as the peer's hello at the next expected
  message sequence, while no handshake read keys are installed, and
  otherwise only signal a retransmission, which they earn at most once per
  timeout.
  When failed decryptions in an epoch exceed the suite's integrity limit
  the connection fails (§4.5.3), and the confidentiality limit triggers a
  KeyUpdate. Connection IDs require explicit DTLS settings (below).
- Handshake messages are fragmented to the datagram size (`set_mtu`: 256 to
  65507 bytes, 1200 by default), reassembled out of order within bounded
  windows, acknowledged per §7 and retransmitted on a timer that starts at
  one second, doubles up to 60 seconds and gives up after nine
  retransmissions. The keys of a KeyUpdate are used only once it is
  acknowledged (§8), and no second KeyUpdate is sent meanwhile. Nothing
  sent after a close_notify is read (RFC 9846 §6.1). A close_notify of
  ours is sent after everything queued before it, and nothing is
  retransmitted after it, except a client's last flight: it is
  retransmitted with close_notify after it until acknowledged, or
  quietly given up after nine retransmissions, so that the server
  completes its handshake. Once the peer's close_notify arrives nothing
  more is retransmitted, but a client whose last flight is not
  completely sent yet sends it once; an ACK still owed and our own
  close_notify are sent, and application data can still be, under the
  current keys. Closing before our Finished is queued cancels the
  handshake: the peer, which ignores an unprotected close_notify, gives
  up on its own timer. A server that closes before its handshake
  completes may never complete it, with no timer left, so nothing should
  wait for the handshake after `send_close_notify`.
- Application data is never fragmented: `send` seals one record into one
  datagram and refuses data longer than `max_application_data`.
- Cookies: `ServerConnection::new` answers a ClientHello without a valid
  cookie with a HelloRetryRequest whose cookie is bound to the
  caller-provided address of the client (opaque bytes, §5.1), so that a
  spoofed address costs the server one small datagram and one connection
  object; `dtls::Acceptor` (below) keeps no state at all. The blocking UDP
  server and Tokio `UdpServer` encode a socket peer using its address family,
  IP octets, IPv6 scope ID, and port, so IPv6 peers with the same IP and port
  but different scopes have distinct cookies. Callers of the low-level
  `ServerConnection` and `Acceptor` APIs provide opaque address bytes and must
  include the scope ID when it is part of the peer identity; an IP-only value
  does not distinguish scoped IPv6 peers. The blocking adapter's former
  IPv6 encoding omitted four scope bytes, so old and new instances reject
  each other's in-flight cookies even when they share sealing keys. Keep a
  retry on an instance with the same encoding during a rolling upgrade, or
  restart the handshake. Numeric scope IDs are local to each host; shared
  keys do not make link-local retries portable across differing interface
  indices. The cookie mechanism needs
  `ServerConfig::hello_retry_cookies`; the exchange is on by default and
  `new_without_cookie_exchange` turns it off for paths whose address is
  already verified. `dtls::Acceptor` answers first ClientHellos without
  keeping any state and returns a connection only for a ClientHello that
  comes back with a valid cookie for its address. A second ClientHello
  that spans several datagrams must carry the cookie in its first
  fragment (browntls clients send it first), which is checked before
  anything is kept.
- Connection IDs: opt-in through `dtls::Settings::with_connection_ids` and
  the low-level client/server `new_with_settings` constructors.
  Servers on already verified paths can instead use
  `new_without_cookie_exchange_with_settings`.
  `ConnectionIdPolicy::new(receive_len, allow_sending)` selects a fixed
  local receiving length of 8 to 32 bytes, or zero for the empty receiving
  direction, independently of permission to send nonempty peer IDs. A server
  declines an offer that requires forbidden sending; a client fails a
  selection forbidden by its policy. Local IDs come from the configured
  provider's random source; peer IDs may have any wire length, including
  zero. A selected CID that leaves no room for handshake fragments or a
  one-record ACK at the configured MTU makes output fail explicitly until
  the MTU is raised.
  Negotiation uses ClientHello and ServerHello (RFC 9146), never
  EncryptedExtensions, stream TLS or QUIC. All protected records carry the
  selected nonempty CID in their authenticated unified header. A missing
  or wrong receiving CID discards the rest of the datagram (RFC 9147 §4).
  `Received::authenticated_records` reports only records that passed
  association, traffic-key authentication and replay checks. Path
  migration also requires an independent return-routability check.
  `local_connection_ids` supplies wrapper lookup IDs,
  including those in pending updates, after negotiation.
  Wrappers must detect collisions when registering IDs across associations;
  local generation checks uniqueness only within its own association.
  `issue_connection_ids` and `request_connection_ids` implement RFC 9147 §9
  only after the handshake. Each message type permits one outstanding
  transmission until ACK; a request also waits for a response, which may
  contain no IDs. Requests receive spare IDs, with one coalesced response
  while an earlier update awaits ACK; excess requests fail with
  `too_many_cids_requested`. At most 16 local IDs are ever issued per
  association, including its initial ID, with four generation attempts per
  ID to avoid reuse. All issued IDs remain valid until the association
  ends. Peer spare
  storage is capped at 16 and duplicates are coalesced. Immediate updates
  select the first provided ID; spare updates retain the current one.
  When the local quota is exhausted, spare responses contain no IDs and
  local immediate issuance fails. DTLS 1.2 uses the RFC 9146 type-25
  header and AEAD authentication data, without connection ID rotation.
  Both built-in providers support either CID direction for DTLS 1.2.
- Path validation: `Settings::with_return_routability_checks` opts into
  RFC 9853 with CID. A new address can become active after a fresh,
  authenticated record advances the receiving sequence and the peer
  answers a protected challenge on that address. Enhanced validation
  probes the existing path first. Candidate responses and probes share a
  three-times received-byte limit. Transport adapters keep ordinary output
  on the validated address and discard candidate application input while
  validation is pending. Blocking and Tokio clients can replace a
  connected local UDP socket while retaining the association and clock.
  A single-socket server responds to a valid probe on its preferred
  local socket independently of validation of the peer's address.
  A server handle stays bound to the originally admitted address and its
  current validated address is reported separately. See
  [Tokio DTLS](../crates/browntls-tokio/README.md#dtls-over-udp).
- DTLS currently omits 0-RTT, Encrypted Client Hello, and post-handshake
  client authentication.

With the `std` feature, `dtls::UdpClient` and `dtls::UdpServer` run these
connections over `std::net::UdpSocket` with blocking calls. While a call
blocks it retransmits and acknowledges as the connections ask, on a clock
that starts when the object is made, unless a client retains an existing
clock origin.

- `UdpClient` holds one connection over a socket connected to its server.
  `connect` returns once the handshake completes (`from_connection` pairs a
  connection configured beforehand, for example its MTU, with a socket, and
  `complete_handshake` runs the handshake). Each `send` is one datagram of
  application data and each `recv` returns one; `recv` skips empty
  datagrams and returns 0 once the server sent close_notify. `connection_mut`
  reaches the connection, for example to refresh its keys, and
  `into_parts` returns it with the socket, dropping what was received and
  not yet returned. `from_connection` starts a clock at zero and is for a
  connection not yet driven. To rewrap an in-progress connection, use
  `into_parts_with_clock` and `from_connection_with_clock`: they transfer
  the original `Instant`, so retained retransmission and acknowledgement
  deadlines include time spent outside the wrapper. Low-level I/O between
  wrappers must use durations measured as `start.elapsed()`. Neither parts
  method transfers the read timeout or buffered application data.
- `UdpServer` holds many clients on one socket and tells them apart by their
  address only. `next_event` returns the next `ServerEvent`, and only for
  clients that completed a handshake: `Connected`, `Received` (one datagram of
  application data, empty ones included), `Closed` (the client's close_notify;
  the connection is gone) or `Failed` (likewise). `send_to`, `close`
  (close_notify, then the connection is forgotten), `remove` (forgotten without
  a word) and `connection_mut` act on a connected client. A ClientHello from the
  address of an existing connection, such as a client restarted on the same
  port, is ignored until that connection is removed. Queued events precede
  further socket or timer work. If Finished, data and close_notify arrive
  together, the connection remains available through `Connected` and
  `Received`, and is removed when `Closed` is returned. Closing a retained
  connection discards its queued events. `remove` also discards queued
  events for an address whose connection has already been removed.
- Cookies: every datagram from an address without a connection goes to a
  `dtls::Acceptor`, so the server configuration needs
  `hello_retry_cookies`, and a client costs nothing but one
  HelloRetryRequest until it answers from the same address with a valid
  cookie.
- Bounds: at most 256 handshakes run at once (`set_max_handshakes`), and a
  new one replaces the oldest; lowering the limit drops nothing until the
  next handshake starts. The limit counts addresses, so one host using many
  ports can displace other hosts' handshakes. A handshake that does not
  complete within 30 seconds (`set_handshake_timeout`, from the next
  handshake on) is dropped; a timeout shorter than the gap between the
  datagrams of a client's second flight drops every handshake (a second
  ClientHello often takes two datagrams). Connected clients are not
  bounded: they stay until they close or fail, or the application closes
  or removes them. The timers of all connections share one queue, rebuilt
  from the connections once it holds more than twice as many entries
  as there are connections, plus 64.
- Read timeouts: none by default, so `connect`, `complete_handshake`,
  `recv` and `next_event` wait as long as the connection does (a handshake
  the server never answers fails once its retransmissions run out, after
  about five minutes). With `set_read_timeout` they fail with
  `io::ErrorKind::TimedOut` once it passes, but still read what arrives
  within a millisecond of each look, up to 64 datagrams: even a zero
  timeout takes a datagram that is waiting, and a stream of junk cannot
  hold the timeout off. A handshake that timed out continues with the next
  call.
- Live OCSP checks (`browntls_core::revocation`) are not supported: a
  client's handshake that would wait for one fails with
  `io::ErrorKind::Unsupported`, and a server's is dropped.

Evidence: in-memory handshakes between browntls endpoints over a simulated
network with loss, duplication, reordering, corruption and small datagrams
on both providers (`crates/browntls-core/tests/cases/dtls.rs`), unit tests
of the record, reassembly, replay and hello codecs, and the `tls_dtls` fuzz
target ([`fuzz/`](../fuzz/README.md)). The blocking API has tests over IPv4
and IPv6 loopback sockets on both providers
(`crates/browntls-core/tests/cases/dtls_udp.rs`). Shared DTLS 1.3 and 1.2
cookie cases distinguish IPv6 peers with the same address and port but
different scope IDs; Tokio has a matching serializer regression. These are
deterministic identity and cookie tests, not a multi-interface socket test.
The `tls_dtls_udp` fuzz
target drives a server and several clients over loopback through fuzz-chosen
calls and junk datagrams. Targeted blocking regressions
cover combined Finished/data/close events, explicit peer removal and a
retained overdue retransmission after client rewrapping; the IPv6 test
asserts the cookie contains the source address, scope ID and port.
Loopback neither loses nor reorders datagrams;
broader loss recovery is exercised by the simulated network of the
sans-I/O tests. The
[Docker DTLS suite](../tests/e2e/README.md#dtls-13-interoperability)
covers mutually authenticated full DTLS 1.3 handshakes against wolfSSL in
both roles, with ECDSA P-256, application data and `close_notify`.
The opt-in Pion suite checks RFC 9853 rebind after mutual authentication and
an application exchange on one association. The simulated network checks
ACK loss and ordering, timeout, epoch rollover and replay independently
of peer support for those scenarios.

### Cargo features (`browntls-core`)

| Feature | Default | Effect |
|---|---|---|
| `std` | yes | Buffered connections and I/O helpers (`Stream`, `KeyLogFile`), default session caches, system time; the unbuffered API needs only `alloc`; enables `alloc` |
| `alloc` | yes (through `std`) | Currently gates nothing: the crate always links `alloc` |
| `native` | yes | Provider backed by `browntls-crypto` |
| `rustcrypto` | no | Provider backed by RustCrypto crates (RSA verification only) |
| `tls12` | yes | TLS 1.2 support |
| `logging` | yes | `log` crate diagnostics |
| `key-log` | no | RFC 9850 key-log callbacks, including the ECH records, and, on Linux, the explicit-path file sink; enables `browntls-crypto`'s `key-log` |
| `prefer-post-quantum` | yes | X25519MLKEM768 first in the default group list |
| `zlib` | no | zlib certificate compression (RFC 8879), `miniz_oxide` |
| `brotli` | no | Brotli certificate compression (RFC 8879), `brotli`; enables `std` |
| `zstd` | no | Zstandard certificate compression (RFC 8879), `ruzstd` |
| `fuzzing` | no | Unstable entry points for the [fuzz targets](../fuzz/README.md); not a supported API |

An application sets these features on `browntls`, which has each of them
except `fuzzing` under the same name, and `tokio`, `ktls`, `coop` and `ocsp`
besides (see [Facade crate](#facade-crate-browntls)).

### Certificate compression (RFC 8879)

`browntls_core::compress` defines the `CertCompressor` and `CertDecompressor`
traits and, behind the `zlib`, `brotli` and `zstd` features, one built-in
pair per RFC 8879 algorithm (`compress::ZLIB`, `BROTLI`, `ZSTD`). Enabled
built-ins are the default compressor and decompressor lists of new client and
server configurations, in the order Brotli, zlib, Zstandard; without those
features the lists are empty and the extension is neither offered nor
accepted. Compression applies in both directions in TLS 1.3, DTLS 1.3,
and QUIC-TLS: a server
compresses its Certificate with its first compressor the ClientHello offered,
a client its own with the first one the CertificateRequest offered, and a
built-in compressor sends uncompressed a message that compression would not
make smaller (a `CertCompressor` of your own decides this itself). With
`std`, servers and clients cache compressed messages (`CompressionCache`,
`ServerConfig::cert_compression_cache`, `ClientConfig::cert_compression_cache`).

On receipt (`compress::receive_compressed_certificate`, used by both sides):

- an algorithm that was not offered is `illegal_parameter`;
- `uncompressed_length` must be non-zero and at most the configuration's
  `cert_decompression_limit`, itself capped at 65,535 bytes
  (`compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE`, the same handshake body
  limit as for an uncompressed Certificate); the codec rejects a length above
  that cap with `decode_error`, anything else over a limit is
  `bad_certificate`, in both cases before any decompression;
- the output buffer is allocated once at the declared length and the
  decompressor must fill it exactly: shorter, longer, truncated or trailing
  input is `bad_certificate` (RFC 8879 §4), as is a decompressed message that
  is not a well-formed Certificate.

A `cert_decompression_limit` of zero turns reception off: the client does
not send the extension, the server leaves it out of its CertificateRequest,
and a compressed message is then an algorithm that was not offered.

The built-in decoders use memory besides that buffer, bounded by the expected
length and the format, never by what the stream declares:

| Algorithm | Working memory besides the output buffer | Refused before decoding |
|---|---|---|
| zlib | Fixed decoder state (about 11 KiB); the output buffer is the window | |
| Brotli | A window of at most the expected length rounded up to a power of two (the decoder's byte allocator refuses larger requests, so a stream announcing more fails without the allocation), context maps up to 16 KiB, prefix code tables (at most 256 per category) | Large-window streams |
| Zstandard | At most 128 KiB of retained history and bounded block scratch, including temporary growth during a rejected block | Skippable frames, a nonzero dictionary ID, and windows or blocks outside the limits |

With `zstd` enabled, `ClientConfig::cert_zstd_decompression_limits` and
`ServerConfig::cert_zstd_decompression_limits` govern the built-in decoder
independently of the expanded body limit. The defaults accept advertised
windows up to 8 MiB and cap decoder history at 128 KiB. For a large
advertised window the decoder uses at most 128 KiB when the longest
acceptable frame output fits in that history. The decoder handles up to
64 concatenated data frames and verifies any checksum. Each declared
content size and the aggregate expanded length must match exactly.

Callers can set stricter limits with `ZstdDecompressionLimits::new`, or
pass them to `ZSTD.decompress_with_limits` for direct use. Both configs flow
through the buffered, unbuffered, Tokio, DTLS and QUIC-TLS entry points.
Stream post-handshake client authentication uses the same receiving
policy. Linux kTLS inherits the authenticated connection after the userspace
handshake. Zstandard compression uses the single level implemented by
`ruzstd`.


## Primitive backends

Each primitive has a portable, constant-time implementation that is the
reference for testing, plus accelerated backends selected at run time.

| Family | x86-64 | aarch64 | riscv64 |
|---|---|---|---|
| SHA-1 (HMAC-SHA1 for TLS 1.2 `*_CBC_SHA` suites only, never signatures) | SHA-NI | FEAT_SHA1 | Zbb scalar |
| SHA-2 | SHA-NI (SHA-256), x86-64-v3 (SHA-256 and SHA-512; no SHA512 extension backend) | FEAT_SHA256, FEAT_SHA512 | Zvknha/Zvknhb, Zknh |
| SHA-3 / SHAKE | BMI1/BMI2 (one state); AVX2, AVX-512VL (four states) | portable (one state); NEON, FEAT_SHA3 (four states) | Zbb (one state); RVV, RVV + Zvkb (four states) |
| AES-GCM | AES-NI + PCLMULQDQ, VAES + VPCLMULQDQ (YMM, and ZMM with a fused CTR+GHASH loop) | FEAT_AES + FEAT_PMULL | Zvkned + Zvkg / Zvbc, Zkne + Zbc/Zbkc |
| AES decryption (CBC) | AES-NI, VAES (YMM) | FEAT_AES | Zvkned, Zknd |
| ChaCha20-Poly1305 | AVX2, AVX-512 | NEON | RVV |
| X25519 / Ed25519 | BMI2 + ADX field arithmetic (X25519 ladder only; Ed25519 portable) | portable 64-bit | portable 64-bit |
| X448 / Ed448 | portable 64-bit (Karatsuba field multiplication, precomputed fixed-base comb) | portable 64-bit | portable 64-bit |
| P-256 / P-384 / P-521 | BMI2 + ADX field arithmetic (per-curve kernels; the same specialised reductions in portable code elsewhere) | portable 64-bit | portable 64-bit |
| RSA | BMI2 + ADX Montgomery kernel, AVX-512 IFMA exponentiation | portable 64-bit | portable 64-bit |
| FFDHE (RFC 7919) | RSA BMI2 + ADX Montgomery kernel | portable 64-bit | portable 64-bit |
| ML-KEM | AVX2 NTT | NEON NTT | RVV NTT |
| ML-DSA (FIPS 204) | portable (scalar NTT; no SIMD backend) | portable | portable |

ML-DSA (`browntls_crypto::mldsa`: ML-DSA-44, -65 and -87, key generation,
hedged and deterministic signing with a context string, verification and the
FIPS 204 key and signature encodings) has the portable scalar backend alone
and does not take part in load-aware routing. It also reads and writes the
RFC 9881 key encodings: `VerifyingKey::{from_spki_der, to_spki_der}` for the
`SubjectPublicKeyInfo` (§4), and `SigningKey::{from_pkcs8_der,
to_pkcs8_der}` for the PKCS #8 `OneAsymmetricKey` (§6) in strict DER, with
the private key in the `seed`, `expandedKey` or `both` form (a `both` key
whose expanded key is not the one its seed derives, or a `publicKey` that
is not the key's, is refused; §8.2). Comparing a loaded key's
`SubjectPublicKeyInfo` with a certificate's associates the two
(`crates/browntls-core/tests/native_mldsa_keys.rs` does so for the RFC 9881
Appendix C keys and certificates). The `crypto_mldsa` fuzz target checks
these decoders and the primitive against the RustCrypto `ml-dsa` crate
([fuzz targets](../fuzz/README.md)). The native provider uses ML-DSA for
opt-in certificate and CRL signature verification (see
[ML-DSA certificate verification][ml-dsa-verification]) and, as a separate
experimental opt-in, for TLS 1.3 handshake signatures: verification with
`SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13` and hedged signing with keys loaded
by `KEY_PROVIDER_WITH_ML_DSA` (see
[ML-DSA TLS 1.3 authentication][ml-dsa-tls13]). The default `KEY_PROVIDER`
loads no ML-DSA private key, and the RustCrypto provider does not use this
module (its own opt-in uses the RustCrypto `ml-dsa` crate). HashML-DSA is
not implemented. Its module documentation states which operations are constant
time, the stack use and the key sizes.

[ml-dsa-verification]: #ml-dsa-certificate-verification-native-provider-opt-in
[ml-dsa-tls13]: #ml-dsa-tls-13-authentication-opt-in-experimental

GHASH is also available on its own as `browntls_crypto::gcm::Ghash` (SP
800-38D section 6.4, keyed by the hash subkey `H`, the counterpart of the
RustCrypto `ghash` crate's `GHash`), in the way `chacha::Poly1305` exposes
Poly1305. It runs on the GHASH backends of the AES-GCM row, chosen when the
value is created (the one selected under the GHASH policy; differential tests
can name one, with the portable backend as the fallback), and does not take
part in load-aware routing. Input can be streamed, given as whole blocks or
zero-padded to a block boundary as GCM pads its additional data and
ciphertext; there is no length limit. The key material, the accumulator and a
buffered partial block are zeroised on drop. It is not a MAC by itself: its
values must be masked before release, as GCM does with `E_K(J0)`.

AES-CCM (TLS 1.3 `TLS_AES_128_CCM_SHA256` and `TLS_AES_128_CCM_8_SHA256`) runs
on the AES backends of this table: counter mode uses each backend's
pipelined keystream, and CBC-MAC encrypts one block at a time.

AES-CBC without padding (`browntls_crypto::cbc`, for the TLS 1.2 CBC suites
with AES-128 and AES-256) also follows the AES backend selection and
acceleration policy. Encryption is serial and encrypts one block at a time;
decryption pipelines eight blocks per iteration (AES-NI, FEAT_AES), sixteen
(VAES, also on the AVX-512 tier) or `VLEN/32` (Zvkned). The portable inverse
cipher is bitsliced like the forward one. The scalar riscv64 tier decrypts
with Zknd when present and with the portable code on Zkne-only CPUs.

`browntls_crypto::tls_cbc` implements the TLS 1.2 CBC record transform
(RFC 5246 MAC-then-encrypt and RFC 7366 encrypt-then-MAC, with HMAC-SHA1,
HMAC-SHA256 or HMAC-SHA384) over a `CbcBlockCipher` trait. For
MAC-then-encrypt, the padding check and the record MAC are constant time with
respect to the padding (the Lucky Thirteen countermeasure): the number of hash
compressions depends only on the record length.

`browntls_crypto::hpke` implements RFC 9180 Hybrid Public Key Encryption in
base mode for Encrypted Client Hello: DHKEM over X25519, X448, P-256, P-384
and P-521, HKDF-SHA256/384/512, and AES-128-GCM, AES-256-GCM,
ChaCha20-Poly1305 or export-only. It composes the crate's own primitives (and
therefore their accelerated backends), adds no `unsafe`, and stays
allocation-free: `seal`/`open` returning vectors exist only with `alloc`.
NIST public keys must be uncompressed points on the curve, X25519/X448
all-zero shared secrets are rejected, and a failed `open` leaves the sequence
number unchanged. The PSK and authenticated modes are not implemented.

`browntls_crypto::nist::{p256, p384, p521}` expose, besides keys, ECDH and
ECDSA, the curves' arithmetic for other protocols, named after the RustCrypto
`primeorder` / `elliptic-curve` 0.14 types without implementing their
traits: `FieldElement` (integers modulo `p`), `Scalar` (integers modulo the
group order `n`), `AffinePoint` (with the identity as a flag and SEC 1
encoding to and from `Sec1Point`, the identity as `00`) and
`ProjectivePoint`, which convert to and from `PublicKey`. Values stay in the
Montgomery form of the curve code, always fully reduced; decoders reject
values at or above the modulus and points off the curve
(`Scalar::from_bytes_reduced` reduces up to twice the scalar length on
request). Arithmetic, inversion (safegcd), square roots (`p = 3 mod 4`),
comparisons, the group law (the complete RCB formulas, total on every
input), scalar multiplication (`mul`: signed fixed windows over a table
built by complete additions, so any point including the identity;
`mul_by_generator`: the comb table) and normalisation are constant time; an
`Option` or `Result` reveals only whether a value was zero, a root exists or
an encoding was canonical. SEC 1 decoding is variable time, for public
encodings, and `ProjectivePoint::mul_by_generator_and_mul_add_vartime` is
the verification's variable-time double multiplication, for public inputs.
Field and point operations run on the backend the curve's policy selects at
each call (BMI2/ADX or portable) and are not routed by `accel::load`;
scalar arithmetic is the portable Montgomery code on every backend.
`Scalar` is zeroised on drop; field elements, points and `Sec1Point`
encodings (which may encode a secret point) are `Copy` and implement
`Zeroize` for callers that hold secret ones; `Debug` prints none of their
values, encodings included (`Sec1Point::as_bytes` gives the bytes).

The table states the design target; [Status](#status) records what has been
implemented and executed.

### Supported platforms

- **x86-64**: the supported baseline is x86-64-v3 (AVX2, BMI1/2, FMA, MOVBE).
  The crate still builds for the default `x86_64-unknown-linux-gnu` target:
  every accelerated function carries `#[target_feature]` and is entered only
  after run-time detection, so a v3 build (`-C target-cpu=x86-64-v3`) lets the
  compiler resolve the checks statically. AES-NI, PCLMULQDQ, SHA, SHA512,
  VAES, VPCLMULQDQ, ADX and AVX-512 are optional extensions detected with
  `CPUID`/`XGETBV`.
- **aarch64**: Advanced SIMD (NEON) is assumed; the Cryptographic Extension
  features (AES, PMULL, SHA2, SHA3, SHA512) are detected through `std`, or
  taken from compile-time target features without `std`.
- **riscv64**: RVV 1.0 and the vector cryptography extensions (Zvkned,
  Zvknha/Zvknhb, Zvkg, Zvbc, Zvbb, Zvkb) plus scalar Zbb/Zbc/Zbkb/Zbkc/Zknh/
  Zkne/Zknd are detected with the Linux `riscv_hwprobe` system call. RVV
  intrinsics are not available on stable Rust, so vector code uses inline
  assembly with `.option arch` directives and is written to be correct for any
  VLEN from 128 to 1024 bits. Processors that implement only RVV 0.7.1
  (XTheadVector), such as the T-Head TH1520, report no vector support and use
  the scalar paths. Builds may assert extensions that a kernel or emulator does
  not report with `--cfg browntls_assume_riscv="<ext>"`.

`--cfg browntls_force_soft` disables every SIMD and hardware backend.

### Acceleration policy and status

Accelerated backends use one or both kinds of hardware support:

| Kind | Instructions |
|---|---|
| SIMD | AVX2, AVX-512, NEON, RVV vector units |
| Dedicated | AES-NI, PCLMULQDQ, SHA, Armv8 AES/PMULL/SHA2/SHA512/SHA3, RISC-V Zk\*/Zvk\*/Zbc/Zbkc, and scalar multi-precision or bit-manipulation extensions (BMI1/BMI2/ADX, Zbb) |

For example AES-NI and SHA-NI are dedicated, ChaCha20 AVX2 and the ML-KEM
NTTs are SIMD, and VAES, RISC-V Zvkned/Zvkg/Zvknh\* and the x86-64-v3 SHA-2
schedule (AVX2 with BMI2) use both.

At run time, `browntls_crypto::accel` (re-exported as
`browntls_core::crypto::native::accel`) holds a process-wide `Policy` per
algorithm family (SHA-1, SHA-256, SHA-512, Keccak, four-way Keccak, AES, GHASH,
ChaCha20, Poly1305, X25519, P-256, RSA, ML-KEM, P-384, P-521) with one level
per kind:

| Level | Behaviour for that kind |
|---|---|
| `Preferred` (default) | Backends using it may be selected; the best available one wins |
| `Required` | The selected backend must use it; setting fails with `Unsupported` if no available backend qualifies |
| `None` | Backends using it are never selected |

`accel::set_policy`, `set_policy_all`, `set_kind`, `set_kind_all` and
`native::default_provider_with_acceleration` set levels; `accel::status_all`,
`accelerated` and `accelerated_by(kind)` report, per family, the policy, the
kinds the CPU offers, and the selected backend with the kinds it uses.
Keyed objects (AES-GCM, ML-KEM and RSA private keys) keep the backend chosen
when they were created or loaded. Hardware feature checks that guard `unsafe`
code are independent of the policy.

### Load-aware backend routing

The policy's choice is static: one backend per family, the *primary*.
`accel::load` (off by default, `load::enable(Config)`; needs the `std`
feature for its clock and per-thread state) can move part of a family's
work to another backend while the primary runs slower than it usually does.
The premise is that a processor's hardware for one kind of instruction is a
fixed resource, so when other work is using it, calls that depend on it take
longer, and instructions of another kind may then be the faster way to the
same result.

Work is grouped in *streams*, one per homogeneous kind of work of a family
(for example the records of an AEAD), and each stream runs this loop:

| Phase | What happens |
|---|---|
| Steady | Everything runs on the primary. Some calls are timed (about one record of at least 4096 bytes in sixteen; every key exchange, encapsulation and signature operation), giving a short-term average cost and a baseline, the cost in normal operation. The baseline follows slow drift (weight 1/1024 upwards, 1/256 downwards) but not a run of slow calls |
| Probing | The short-term cost exceeded the baseline by `threshold_percent` (default 25, at least 20) and five of the last eight timed calls were each that slow. One call in eight goes to the next permitted backend in preference order, until at least four of them and sixteen calls of the primary were timed |
| Shifting | The probed backend measured at least 5% cheaper than the congested primary. Every eight timed calls of the primary its share grows by 1/16 of the work while that holds (up to `max_shift_percent`, default 90), or shrinks by as much when the primary has recovered to within half the threshold of its baseline or the alternate is the slower one |

When no alternate is cheaper, the present cost is accepted as the baseline
(at most doubling it per episode). An episode that moved nothing, or that
ended with nothing left on the alternate while the primary was still slow,
is followed by a pause of 256 timed calls of the primary, doubled for each
such episode up to 65536; a doubling is forgotten after 4096 uneventful
timed calls. A probe or a shift that ends because the primary recovered is
followed by a quarter of that pause. `load::status_all` reports, per
stream, the phase, both backends, the shifted share and the costs;
`load::set_fixed` pins a share by hand for experiments.

Which calls are timed, probed or shifted is decided by a per-thread call
counter mixed (SplitMix64) with a per-thread random key, using separate bits
for the three choices. No state is shared between threads on that path, and
a peer cannot tell in advance where a call will run.

Properties this design keeps:

- Every backend of a family computes the same function bit for bit (the
  differential tests compare each with the portable one), so routing never
  changes an output, a negotiated parameter or a record on the wire.
- Alternates are the backends the family's `Policy` permits and the CPU can
  run, so `Acceleration::None` and `Required` bind shifted work too.
  `Config::portable` says whether the portable backend is one of them.
- Decisions use call counters, input lengths and measured durations, never
  secret values. The durations are those of code written to run in constant
  time; if a backend's time did depend on a secret, routing could make that
  dependence visible in which backend runs later, so it adds no leak of its
  own but relies on the backends as much as their direct use does.
- An alternate takes work only while its timed calls are cheaper than the
  primary's. Load that slows every backend alike moves little: it costs a
  few probes per alternate and then the growing pause. In simulations of
  such load (steady, random and periodic bursts) under 1% of the calls ran
  on an alternate, and the time lost stayed under 1% even with an
  alternate three times slower.
- A keyed object is routed only while the policy still selects the backend
  it was created for, and one created with explicit backends never is.
- An ML-KEM key and an RSA private key hold nothing that depends on the
  backend their arithmetic runs on (the ML-KEM backends share one
  representation of the key polynomials; an RSA key's Montgomery constants
  are the same for every multiplication kernel), so a routed call uses the
  key as it is: nothing is added to a key, and it does not matter when the
  key was created. An RSA signature moves only to a backend below the
  key's own; the AVX-512 IFMA backend's per-key constants are used by that
  backend alone.
- A keyed object whose key is expanded per backend (an AES-GCM key) is
  routable only if it was created while routing was enabled. It then keeps
  a copy of the AES key in a small allocation and expands it for the
  alternates when one of its records is first routed to one; until then it
  costs nothing else, and a key created earlier or with explicit backends
  never enters the routing code. Each alternate AES backend runs with the
  GHASH backend of its own instruction class (VAES with VPCLMULQDQ of the
  same width, AES-NI with PCLMULQDQ, and so on), so a moved record leaves
  the primary's instructions for both halves of the work; where the GHASH
  policy forbids that backend or the CPU lacks it, the next permitted one
  in GHASH preference order is used, and without one that AES backend is
  not an alternate. On x86-64 an expanded AES-GCM key takes 1664 bytes,
  which is the size of the key types with or without routing; each
  alternate of an expanded key adds as much on the heap (4992 bytes per key
  for the three alternates of AVX-512 VAES). The alternates are listed once,
  under the configuration and policies of that moment, and their storage is
  sized for that list before any key is expanded into it, so it is never
  moved while it holds key material. The key copy and the whole of the
  alternates' storage are zeroised on drop.

Limits:

- Costs are wall-clock times. A slowdown that hits every backend alike (too
  few cores, a descheduled virtual machine) is probed and then accepted as
  the baseline. Pauses are counted in timed calls, so a stream with little
  traffic pauses for long.
- The baseline settles somewhat below the mean of a jittery cost. Very
  noisy timings, or timed calls that alternate between two cost levels,
  cause fruitless episodes and long pauses; an alternate that is nearly as
  slow as the congested primary is given up when timings are noisy.
- Someone able to slow the primary's calls but not the alternate's moves
  work to the alternate, which may be slower than an undisturbed primary
  (by at most the factor of the slowdown). Contention for the primary's
  instructions does exactly that, which is the case routing exists for;
  doing it call by call would need the schedule, which is keyed with a
  non-cryptographic mixing function.
- Records shorter than 4096 bytes are too short to time and always run on
  the primary, unless a share was fixed by hand. A record whose additional
  data exceeds 1/64 of its length is routed but not timed.
- A key exchange or signature stream is meant to hold calls of one cost.
  Calls that do not fit are left out of the measurements and still routed:
  - a rejected signature and a ciphertext of the wrong length (a peer
    chooses how many of those it sends);
  - an ECDSA signature with another hash than the curve's TLS hash, whose
    RFC 6979 nonce derivation costs differently (P-256 with SHA-512
    measured 28% above P-256 with SHA-256 on one machine);
  - an ECDSA verification that did less work than random inputs cause.
    Verification runs in variable time on public values, and whoever
    supplies both the key and the signature can make it cost a tenth
    (measured on P-256), which would drag the stream's baseline down.
    Verifications that pass this check vary by under a tenth.

  When such calls land on a probe they yield no sample, so a stream of them
  can keep a probe from completing. What remains varies within the
  threshold but is partly in other hands: an ML-KEM public key chosen for
  it raises the cost of encapsulating to it by up to 10%, and an RSA key's
  public exponent changes its signing cost by 4% (3 against 65537) to 17%
  (the largest accepted), through the two public-exponent exponentiations
  of blinding and the fault check.
- Only the polynomial arithmetic of an ML-KEM operation moves; its Keccak
  permutations follow their own policies and are not routed.
- The cost per byte depends somewhat on the record length (about 10%
  between 4096 and 16384 bytes for ChaCha20-Poly1305 on one machine), which
  is why the threshold cannot be set below 20%.
- The controller's constants were chosen by reasoning and simulation (the
  `accel::load` unit tests drive the state machine with synthetic costs,
  including the fixed-capacity model of the premise with jitter of up to
  20%, where it stays within a few percent of the best fixed split for
  alternates that help by a fifth or more); they were not tuned on
  contended hardware.
- `load::status` exposes average durations of recent calls, including
  secret-key operations; it is diagnostic data for the operator.

Routed so far: ChaCha20-Poly1305 records (ChaCha20 backends), AES-GCM
records (AES backends, each with its GHASH companion; one stream per key
size, since 256-bit keys cost more per byte), the X25519 ladder, P-256,
P-384 and P-521 (four streams per curve: public key derivation, ECDH, ECDSA
signing and accepted ECDSA verifications), ML-KEM (nine streams: key
generation, encapsulation and decapsulation of each parameter set) and RSA
signatures, that is the private-key operation with its blinding and fault
check, of 2048-, 3072- and 4096-bit keys (one stream per size; keys of
other sizes are not routed). That includes their uses by the native TLS
provider once an application calls `load::enable`; for AES-GCM that means
keys created after the call. AES-CCM, AES-CBC, the AES block types, RSA
verification, FFDHE, X448, Ed25519, Ed448, the hash functions and the
public NIST arithmetic types (`FieldElement`, `Scalar`, `AffinePoint`,
`ProjectivePoint`) are not routed.

#### Kernel TLS at the head of the order

Linux kernel TLS is another place where the records of a connection can be
protected, but it takes whole connections and does not give them back, so it
cannot be one more backend of a record stream. `accel::load::kernel` puts it
in front of the backends instead, for the record work the kernel can take
(AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 records), and the choice is
made once per connection, when it is ready to be handed over:

| Kernel TLS | `accel::load` | Where a new connection's records are protected (`kernel::place`) |
|---|---|---|
| not active | either | In userspace, by the family's backends, routed between them record by record as above |
| active | disabled | By the kernel |
| active | enabled | By the kernel, unless the stream of that record work keeps the connection in userspace (below), where the backends take it as above |

So while kernel TLS is active the order is kernel TLS, then the family's
backends in their preference order (for AES-GCM those with dedicated AES
instructions, widest first; for ChaCha20-Poly1305 the SIMD backends; the
portable code last; a unit test pins that no backend with SIMD alone comes
before one with dedicated instructions in these families). While it is not
active, nothing differs from the order above. A driver activates it once it
knows that the running kernel takes connections
(`browntls_ktls::routing::activate`, which asks the kernel to attach the
`tls` upper layer protocol to a loopback socket).

With routing enabled, each of the three kinds of record work has one more
stream, with two channels, the kernel (the primary) and userspace (its one
alternate), run by the controller described above. Two things differ because
a connection is placed as a whole and stays where it was put:

- While the kernel is probed, the first 64 new connections all stay in
  userspace until four of its writes were timed, then one in eight. A probe
  that waited for one placement in eight would often run out first (it is
  given up after 64 timed writes of the primary), since connections can be
  rare next to writes.
- Placements end what samples do not. A probe is given up after 4096 new
  connections, whatever was timed by then, and a shift ends after 4096 new
  connections without a timed write of the kernel's (the baseline stays,
  so congestion is looked for again after the pause). The connections kept
  in userspace may make no write long enough to time, and so may the
  kernel's once those it had are done; without these bounds such a process
  would keep its new connections in userspace for good. A process with
  many connections and few long writes is in effect not routed by load:
  its connections go to the kernel.
- A shifted share is a share of the new connections. Connections the kernel
  has stay with it, and those in userspace stay there, so a shift acts as
  fast as connections come and go.

The crypto crate does not see the socket, so the driver reports the costs
(`kernel::sample`, `Sample::done`): for one write in sixteen of at least
4096 bytes (every such write of a userspace connection while the kernel is
probed, until four were timed), the bytes of application data the socket
accepted and what that took. Both places are measured alike, from the plaintext
to the bytes TCP has taken: for the kernel that is the `send` that encrypts
(`Engine::write`, so `KtlsStream` and `AsyncKtlsStream` however they were
made), for userspace the encryption by a backend and the `send`
(`UserspaceStream`, `AsyncUserspaceStream`). `browntls-ktls` measures
processor time of the calling thread (`clock_gettime` with
`CLOCK_THREAD_CPUTIME_ID`), so that waiting for the peer or for room in the
socket counts for neither place. `kernel::status` and `status_all` report
the streams in the form of the backends' reports (primary `kernel TLS`,
alternate `userspace`, costs per byte written) and `kernel::set_fixed` pins
the share of new connections kept in userspace; the backends' own reports
(`load::status_all`, `lanes`) are unchanged.

`browntls_ktls::routing::RoutedStream::new` follows the placement for a
buffered connection: it completes the handshake, asks `kernel::place` for
the negotiated suite's record work, and returns the connection as a
`KtlsStream` or, in userspace, as a `UserspaceStream` (a
`browntls_core::Stream` that reports its writes). A connection that was placed
with the kernel and that the kernel cannot take (no `tls` module, a suite
or a configuration without a kernel form, a cipher the running kernel
lacks) stays in userspace with the refusal recorded, and the application
data a refused handover had taken is read first; I/O failures and
`WouldBlock` are returned as `KtlsStream::new` returns them. A kernel
with the `tls` module can still lack a cipher (built without it, or
restricted to approved algorithms), and it says so only when it is given
keys, after the connection's secrets were extracted. So the kernel is
asked once per cipher and protocol version, with keys of zeros on a
loopback socket that carries no data, before the first such connection is
handed over. `AsyncRoutedStream::from_client` and `from_server` do the
same for `browntls-tokio` streams, whose handshake is done before they are
placed, except for a stream returned early for 0-RTT data: a server has its
suite by then and is placed by it, and a client, which has none yet,
follows the order alone. An `AsyncUserspaceStream` times a write one poll
at a time, and not before the handshake is complete. A suite whose records
have no stream (TLS 1.3 AES-128-CCM) follows the order alone.

Limits, beyond those of the routing as a whole:

- Only new connections move. A process with a few long-lived connections
  is never rebalanced.
- Userspace is measured by the connections that are there: those kept back
  to measure it and those the kernel refused. If none of them makes a
  write long enough to time while the kernel is probed, the probe ends
  without a comparison and the kernel's present cost is accepted as its
  baseline.
- Only writes are timed; a connection is placed for both directions by what
  sending costs.
- The costs include the kernel's network stack for both places. Load on it
  slows both alike, which the controller probes and then accepts.
- Processor time of the calling thread does not include encryption that the
  kernel hands to another context (asynchronous crypto drivers, a network
  device that encrypts); such a kernel measures cheap and keeps its
  connections, which is the intended outcome but not a measured one.
- What only the kernel can do (`sendfile` without a copy to userspace) is
  no part of a cost per byte written. An application that depends on it
  hands its connections over with `KtlsStream::new` and does not ask the
  routing.
- 0-RTT data that a server accepted and had not read when it asked the
  routing is delivered differently by place on the synchronous path: with
  the kernel it is the first data the stream returns, not told from the
  rest (as with `KtlsStream::new`), in userspace it stays in the
  connection's `early_data()`. Such a server reads it before it asks. The
  Tokio streams report how much of what they return first is 0-RTT data
  (`early_data_len`).
- A kernel refusal that comes after the handover took application data out
  of the connection (a peer's `record_size_limit` on a kernel before 6.19)
  is covered by unit tests of the streams' reads only; no test provokes it
  through a kernel.
- A userspace write that found no room in a non-blocking socket (a
  `UserspaceStream` on such a socket, a poll of an `AsyncUserspaceStream`)
  encrypts without sending all of it and is reported cheaper than it is;
  the time between two polls is not counted.
- The placement was exercised with synthetic costs
  (`crates/browntls-crypto/tests/accel_load_kernel.rs`) and with fixed
  shares on real sockets (`crates/browntls-ktls/tests/routing.rs`,
  `tests/tokio_routing.rs`); no test drives the automatic controller
  through real timings, and whether a shift away from the kernel ever pays
  on real hardware is not measured.

Where a connection's records are protected changes no byte on the wire.
The placement is a function of call counters, lengths of writes and
measured durations; the kernel holds the traffic keys of the connections
placed with it, as with any kernel TLS handover.

### Operating-system interface

On Linux x86-64, aarch64 and riscv64, `browntls-crypto` issues `getrandom(2)`
and `riscv_hwprobe(2)` without libc through a single naked, C-variadic
`syscall(nr, ...)` trampoline (stable since Rust 1.99). Other targets obtain
entropy from the optional `getrandom` crate feature.

## Toolchain and dependency policy

- Rust 1.100.0 is pinned in `rust-toolchain.toml` and is the MSRV
  (`rust-version`). Toolchain upgrades are explicit changes.
- `Cargo.lock` is committed and CI builds with `--locked`.
- Runtime dependencies: none for `browntls-pki`; `getrandom` (optional,
  only with the `getrandom` feature) for `browntls-crypto`; `log`
  (optional), the RustCrypto crates (only with `rustcrypto`) and the
  pure-Rust compression crates `miniz_oxide`, `brotli` and `ruzstd` (only
  with `zlib`, `brotli`, `zstd`) for `browntls-core`; `tokio` (I/O traits,
  plus `rt` with the default `coop` feature and `time` with `ocsp`) for
  `browntls-tokio`; `libc` (Linux only) for `browntls-ktls`, plus
  `tokio` with `net` (adding `mio` and `socket2`) and `browntls-tokio` with
  its `tokio` feature; none of its own for `browntls`, whose dependencies
  are the three crates it re-exports. Independent implementations (RustCrypto,
  rustls with ring, tokio-rustls, rcgen) are dev-dependencies used as test
  oracles.
- `deny.toml` defines advisory, license, ban and source policy, enforced with
  a checksum-pinned cargo-deny in CI.

## Testing strategy

| Layer | Evidence |
|---|---|
| Primitives | RFC/NIST known-answer tests, Wycheproof vectors, differential tests against RustCrypto, and every available backend compared with the portable one |
| Platforms | Native x86-64 and aarch64 on GitHub-hosted Ubuntu 26.04 runners (each with dispatch and portable-only builds; the Arm runner implements every Armv8 extension the backends use) and riscv64 on the RISE runner, plus QEMU user-mode profiles for the x86-64 SHA-NI/VAES tier and every RISC-V tier (static musl binaries, since the Ubuntu 26.04 riscv64 glibc requires RVA23) (scalar, Zk, RVV with VLEN 128 with and without vector crypto, and VLEN 256 and 1024 with vector crypto) |
| PKI | Run-time generated certificate chains, curated public test certificates, malformed-input robustness |
| TLS | Codec round trips and rejection tests, in-memory handshakes across suites, groups, signature schemes and versions (Encrypted Client Hello: accepted, after a HelloRetryRequest, with resumption, rejected with retry configurations, GREASE, and tampered second ClientHellos, `crates/browntls-core/tests/ech_native.rs`), DTLS 1.3 handshakes between browntls endpoints over a simulated lossy, reordering and corrupting network (`crates/browntls-core/tests/cases/dtls.rs` and the Docker wolfSSL peer), interoperability with rustls in both directions (TLS and QUIC-TLS; asynchronous streams against tokio-rustls over loopback TCP, `crates/browntls-tokio/tests/interop.rs`), RFC 9001 Appendix A packet protection vectors, and with the OpenSSL 3 command-line tool over loopback TCP in both directions, with and without client authentication, plus `s_client` answering post-handshake authentication and following a stateless HelloRetryRequest onto a fresh connection (`crates/browntls-core/tests/openssl_interop.rs`, required in the native x86-64 and aarch64 CI jobs) |
| Entropy | Millions of samples per public generator (OS entropy and both providers' `secure_random`, every key-generation function, HPKE, key-exchange groups, ticket keys and nonces, and full TLS 1.3 and 1.2 handshakes for randoms, session IDs, key shares and traffic secrets), each checked for duplicates, bit and byte bias with per-byte min-entropy and Shannon floors, window collision entropy, repeated blocks and serial correlation at a 10^-9 false-alarm level, on x86-64, and at smoke size on aarch64 and riscv64 ([`crates/browntls-entropy/`](../crates/browntls-entropy/README.md)); detects visible low entropy only, not a well-hashed small seed |
| Fuzzing | cargo-fuzz targets for the message codecs, deframer, certificate decompression, PKI parsers and path validation, both connection state machines, and API-sequence targets grouped by topic that together reach every public function of `browntls-crypto`, `browntls-pki`, `browntls-core` and `browntls-tokio` (`browntls-ktls` is not fuzzed; `browntls` defines no function of its own) ([`fuzz/`](../fuzz/README.md)); CI runs generated seeds on the stable toolchain, checks public API coverage, and fuzzes the targets as a GitHub Actions matrix on one x86-64 runner on pull requests and weekly |
| Facade | `browntls` adds paths and features, no behaviour: a handshake through each of its three paths (the root, `browntls::tokio`, and `browntls::ktls` against the running kernel), probes that the forwarded features reach the crates behind it, the feature sets an application picks in their own CI job, and a manifest check of the feature tables (`crates/browntls/tests/`, `tests/scripts/check_facade_features.py`; see [Facade crate](#facade-tests)) |
| End-to-end | Release builds of the `browntls-e2e` client and server (built on the `browntls` facade alone) in containers on a Docker network against OpenSSL 3.5 (Alpine and Ubuntu 26.04, the latter not on native riscv64), OpenSSL 3.0 (Ubuntu 24.04), GnuTLS 3.8, Go `crypto/tls` (Encrypted Client Hello scenarios only) and browntls itself, for x86-64-v3, aarch64, native riscv64 and riscv64 with vector crypto under QEMU: TLS 1.3 and 1.2 suites and groups including X25519MLKEM768, HelloRetryRequest, client authentication, resumption, Encrypt-then-MAC required by default (`tests/e2e/`, [Docker end-to-end tests](../tests/e2e/README.md)) |

Test certificates and keys are generated at run time; no private keys are
committed. Successful CI is evidence for the tested configurations only and
is not a security assessment.

The [RFC hardening integration report](RFC-Hardening-Integration.md) maps
the Phase 0–5 requirements to public APIs, the tested provider and feature
configurations, and native Linux peer and Service runs.

## Status

The first implementation milestone establishes the crates, the provider mount
point, primitive backends and the TLS state machines. Measured throughput
against OpenSSL is recorded in [Performance](Performance.md). Coverage, gaps and
deferred features are listed in the [roadmap](Roadmap.md).
