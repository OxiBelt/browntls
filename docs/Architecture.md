# Architecture

This document describes the design of browntls: a TLS 1.2 / TLS 1.3 library,
with DTLS 1.3 over datagrams, written from scratch in Rust, targeting the
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
| Signature schemes | ECDSA, Ed25519, RSA-PSS (rsae), RSA PKCS #1 v1.5 | Ed448, then `rsa_pss_pss_sha512/384/256` (RSASSA-PSS public keys) | |

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
  suite"). Of the first 16 identities (a local bound on lookups and ticket
  decryption; later ones are ignored), the first that names a usable external
  PSK or ticket is selected and only its binder is checked, in constant time;
  a wrong binder is `decrypt_error`. An identity whose binder length is not
  that of the key's hash is passed over. A handshake that selects an external
  PSK sends no certificate. When a TLS 1.3 client offered a `psk_dhe_ke` PSK
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
  provisioned ones (RFC 9846 §4.3.10). There is no anti-replay protection
  for external PSKs: such early data can be replayed.
- Importer (RFC 9258): a key configured with `imported(context)` is used
  only through the importer. The client offers one `ImportedIdentity` per
  hash of its TLS 1.3 suites (target protocol TLS 1.3, target KDF
  `HKDF_SHA256` or `HKDF_SHA384`), with `ipskx = HKDF-Expand-Label(
  HKDF-Extract(0, epsk), "derived psk", Hash(ImportedIdentity), L)` under the
  EPSK's hash; the server parses the identity, resolves its external identity
  and requires the same context. The EPSK's hash must be that of one of the
  provider's TLS 1.3 suites. No published test vectors exist; the derivation
  is checked against an independent HMAC computation and across providers.
- Certificate authentication with an external PSK (RFC 8773,
  `tls_cert_with_extern_psk`, 0x0021): opt-in on both sides
  (`cert_with_extern_psk`). A client sends the extension only when it offers
  an external PSK, and then no 0-RTT under one; a server echoes it in its
  ServerHello only when it selected an external PSK and has a certificate,
  and then authenticates with Certificate and CertificateVerify (and may
  request client authentication) on top of the PSK and (EC)DHE. A client
  rejects the extension without an external PSK (`illegal_parameter`) and,
  with `require_cert_with_extern_psk`, a server that does not negotiate it.
  A client that sends the extension offers no resumption ticket alongside,
  so the server cannot skip the requested certificate by resuming instead (a
  conservative choice, not an RFC 8773 requirement).
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
  `TLSInnerPlaintext`, padding included, derived from the ciphertext length
  less the suite's expansion) end the connection with `record_overflow`
  (`RecordLayer::set_inbound_record_size_limit`). A peer value below 64 is
  `illegal_parameter`; a value above the protocol maximum is lowered, not
  refused; a configured value below 64 fails connection creation
  (`Error::BadRecordSizeLimit`). 0-RTT data, sent before the client could
  see the server's limit, is exempt, and a TLS 1.3 client applies its own
  limit from the record after EncryptedExtensions (the server's handshake
  records already respect it).
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
- GREASE (RFC 8701, `msgs::grease`), client only, opt-in
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
  like any unknown value and sends none itself (RFC 8701 §4 is optional).
- `padding` (RFC 7685), client: by default
  (`ClientHelloPadding::AvoidProblematicLengths`) a ClientHello handshake
  message of 256 to 511 bytes is padded to 512 bytes, or 513 to 515 bytes
  from 509 to 511 where the four-byte extension header does not fit
  (RFC 7685 §4);
  `AtLeast(n)` pads to at least `n` bytes first; `Disabled` never pads. The
  extension comes right before `pre_shared_key`, which stays last, and is
  sized with the binders in place. A server ignores its content.

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
  post-handshake authentication methods, and the client's
  `delegated_credential` and `post_handshake_auth_responses`.
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
- With `TlsConnector::early_data(true)` and a resumable session that
  allows 0-RTT, `Connect` resolves before the handshake
  (`IoSession::skip_handshake`). Writes go to `ClientConnection::early_data`
  and are kept; the first read, flush or shutdown, or a write the allowance
  cannot take, completes the handshake and flushes our last flight
  (EndOfEarlyData, Finished). Declined early data is resent as 1-RTT data
  only when the same ALPN protocol is certain (none offered, or one offered
  and selected; RFC 9846 §4.2.10); otherwise that operation fails once with
  `EarlyDataNotResent`. A handshake failure in this phase is kept and fails
  every later operation. Whichever operation ends the phase wakes a read
  waiting in it, whose transport registration it may have replaced.
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
  `ServerConfig::max_early_data_size`. The connector does not send early
  data.
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
before any key is installed. Linux pauses reception whenever a handshake record
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
signing (`DelegatedCredential::issue`) and validation; the native provider
adds `crypto::native::delegated_credential::generate`, which creates an
ECDSA (P-256/384/521), Ed25519 or Ed448 credential key and has the
certificate's key sign the credential. A credential is attached to a
`CertifiedKey` with `with_delegated_credential`, which checks that the
certificate carries the `DelegationUsage` extension
(1.3.6.1.4.1.44363.44, parsed by `browntls-pki`) and the
`digitalSignature` key usage, and, when the key exposes its public key, that
it matches the credential's public key. Credential keys may not be
`rsaEncryption` keys (§4): the
`rsa_pss_rsae_*` schemes are never issued, attached, offered or accepted
(`rsa_pss_pss_*` is allowed). `CertifiedKey` keeps its credentials in a
private field (`delegated_credentials()` reads them), so it can no longer
be built with a struct literal; `CertifiedKey::new` remains.

- Server: when the ClientHello carries `delegated_credential` and a
  credential is unexpired, has at most seven days left, uses a
  `dc_cert_verify_algorithm` the client listed and is signed with a scheme
  in its `signature_algorithms`, the credential goes on the end-entity
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
- Resumption: the client and server save the absolute expiry of the delegated
  credential that authenticated the original full handshake. A ticket is not
  offered or accepted, including for 0-RTT, when the current time is at or
  after that deadline. The client checks again after the resumed server
  Finished so a handshake that crossed the deadline cannot complete. Every
  descendant ticket carries the original deadline unchanged; the server also
  caps its advertised ticket lifetime to the remaining credential lifetime
  and sends no ticket when none remains. This is independent of an RFC 8773
  external-PSK binding; both properties are retained when both authenticated
  the session.
- Persistence: the private client session value carries the deadline without
  changing `ClientSessionStore`. The server session encoding has a mandatory
  tagged deadline field. Because the old encoding cannot distinguish sessions
  authenticated with a delegated credential, an upgrade deliberately rejects
  every pre-change server session value (TLS 1.3 and TLS 1.2); old and new
  members of a mixed-version fleet therefore cold-miss each other's cached
  sessions and tickets rather than resuming ambiguous authentication state.
- Alerts (§4.1.3): an invalid credential is `illegal_parameter`; one the
  client did not ask for is `unexpected_message`; one on an entry other than
  the end entity's is `illegal_parameter`; a CertificateVerify that fails
  under the credential's key gets the same alert as one that fails under a
  certificate key (`decrypt_error` for a bad signature).
- Not implemented: client credentials (the extension is parsed in
  CertificateRequest but never sent, and a client never presents one; a
  server answers a client Certificate entry carrying one with
  `unsupported_extension`, like other unsolicited entry extensions).
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
`handle_timeout` once `next_timeout` has passed. Only DTLS 1.3 is
implemented; there is no DTLS 1.2.

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
  KeyUpdate. Records with a connection ID are refused, since none is
  negotiated.
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
  object; `dtls::Acceptor` (below) keeps no state at all. It needs
  `ServerConfig::hello_retry_cookies`; the exchange is on by default and
  `new_without_cookie_exchange` turns it off for paths whose address is
  already verified. `dtls::Acceptor` answers first ClientHellos without
  keeping any state and returns a connection only for a ClientHello that
  comes back with a valid cookie for its address. A second ClientHello
  that spans several datagrams must carry the cookie in its first
  fragment (browntls clients send it first), which is checked before
  anything is kept.
- Not supported over DTLS: 0-RTT (a server rejects an offer), Encrypted
  Client Hello (configurations with it are refused), post-handshake client
  authentication (not offered; a request is refused), connection IDs
  (RFC 9146) and the return routability check (RFC 9853). There is no
  Tokio API for DTLS yet.

With the `std` feature, `dtls::UdpClient` and `dtls::UdpServer` run these
connections over `std::net::UdpSocket` with blocking calls. While a call
blocks it retransmits and acknowledges as the connections ask, on a clock
that starts when the object is made.

- `UdpClient` holds one connection over a socket connected to its server.
  `connect` returns once the handshake completes (`from_connection` pairs a
  connection configured beforehand, for example its MTU, with a socket, and
  `complete_handshake` runs the handshake). Each `send` is one datagram of
  application data and each `recv` returns one; `recv` returns 0 once the
  server sent close_notify, and also for an empty datagram
  (`connection().peer_has_closed()` tells them apart). `connection_mut`
  reaches the connection, for example to refresh its keys, and
  `into_parts` returns it with the socket, dropping what was received and
  not yet returned.
- `UdpServer` holds many clients on one socket and tells them apart by
  their address only. `next_event` returns the next `ServerEvent`, and only
  for clients that completed a handshake: `Connected`, `Received` (one
  datagram of application data), `Closed` (the client's close_notify; the
  connection is gone) or `Failed` (likewise). `send_to`, `close`
  (close_notify, then the connection is forgotten), `remove` (forgotten
  without a word) and `connection_mut` act on a connected client. A
  ClientHello from the address of an existing connection, such as a client
  restarted on the same port, is ignored until that connection is removed.
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
  `io::ErrorKind::TimedOut` once it passes, but still read what has already
  arrived, up to 64 datagrams: even a zero timeout takes a datagram that is
  waiting, and a stream of junk cannot hold the timeout off. A handshake
  that timed out continues with the next call.
- Live OCSP checks (`browntls_core::revocation`) are not supported: a
  client's handshake that would wait for one fails with
  `io::ErrorKind::Unsupported`, and a server's is dropped.

Evidence: in-memory handshakes between browntls endpoints over a simulated
network with loss, duplication, reordering, corruption and small datagrams
on both providers (`crates/browntls-core/tests/cases/dtls.rs`), unit tests
of the record, reassembly, replay and hello codecs, and the `tls_dtls` fuzz
target ([`fuzz/`](../fuzz/README.md)). The blocking API is tested over
loopback sockets on both providers
(`crates/browntls-core/tests/cases/dtls_udp.rs`) and by the `tls_dtls_udp`
fuzz target, which drives a server and several clients over loopback
through fuzz-chosen calls and junk datagrams; loopback neither loses nor
reorders datagrams, so its retransmissions are exercised only by the
simulated network of the sans-I/O tests. No other DTLS implementation has
been tested against.

### Cargo features (`browntls-core`)

| Feature | Default | Effect |
|---|---|---|
| `std` | yes | Buffered connections and I/O helpers (`Stream`, `KeyLogFile`), default session caches, system time; the unbuffered API needs only `alloc`; enables `alloc` |
| `alloc` | yes (through `std`) | Currently gates nothing: the crate always links `alloc` |
| `native` | yes | Provider backed by `browntls-crypto` |
| `rustcrypto` | no | Provider backed by RustCrypto crates (RSA verification only) |
| `tls12` | yes | TLS 1.2 support |
| `logging` | yes | `log` crate diagnostics |
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
accepted. Compression applies to TLS 1.3 only, in both directions: a server
compresses its Certificate with its first compressor the ClientHello offered,
a client its own with the first one the CertificateRequest offered, and a
built-in compressor sends uncompressed a message that compression would not
make smaller (a `CertCompressor` of your own decides this itself). With
`std`, servers and clients cache compressed messages (`CompressionCache`,
`ServerConfig::cert_compression_cache`, `ClientConfig::cert_compression_cache`).

On receipt (`compress::receive_compressed_certificate`, used by both sides):

- an algorithm that was not offered is `illegal_parameter`;
- `uncompressed_length` must be non-zero and at most the configuration's
  `cert_decompression_limit`, itself capped at 64 KiB
  (`compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE`, the limit for an
  uncompressed Certificate message); the codec already rejects a length above
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
| Zstandard | The declared window, at most 128 KiB, plus one block (128 KiB) and entropy tables | Skippable frames, dictionaries, a declared content size other than the expected length, a window above 128 KiB |

The Zstandard window limit is below the 8 MiB that RFC 8878 §3.1.1.1.2
recommends decoders accept. One-shot encoders, which know the size of a
Certificate message, write single-segment frames whose window is the content
size, and the built-in encoder declares 128 KiB; a frame from a streaming
encoder that was not told the size (libzstd then declares at least 512 KiB)
is refused. `tests/cert_compression_memory.rs` checks, on Linux, that
refusing streams of at most about 52 KB (a few hundred bytes for Brotli and
Zstandard) which announce 8 to 16 MiB does not raise the process's peak
resident memory by more than 1 MiB. Zstandard
compression uses the single level `ruzstd` implements.

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
| TLS | Codec round trips and rejection tests, in-memory handshakes across suites, groups, signature schemes and versions (Encrypted Client Hello: accepted, after a HelloRetryRequest, with resumption, rejected with retry configurations, GREASE, and tampered second ClientHellos, `crates/browntls-core/tests/ech_native.rs`), DTLS 1.3 handshakes between browntls endpoints over a simulated lossy, reordering and corrupting network (`crates/browntls-core/tests/cases/dtls.rs`; no DTLS interoperability test yet), interoperability with rustls in both directions (TLS and QUIC-TLS; asynchronous streams against tokio-rustls over loopback TCP, `crates/browntls-tokio/tests/interop.rs`), RFC 9001 Appendix A packet protection vectors, and with the OpenSSL 3 command-line tool over loopback TCP in both directions, with and without client authentication, plus `s_client` answering post-handshake authentication and following a stateless HelloRetryRequest onto a fresh connection (`crates/browntls-core/tests/openssl_interop.rs`, required in the native x86-64 and aarch64 CI jobs) |
| Entropy | Millions of samples per public generator (OS entropy and both providers' `secure_random`, every key-generation function, HPKE, key-exchange groups, ticket keys and nonces, and full TLS 1.3 and 1.2 handshakes for randoms, session IDs, key shares and traffic secrets), each checked for duplicates, bit and byte bias with per-byte min-entropy and Shannon floors, window collision entropy, repeated blocks and serial correlation at a 10^-9 false-alarm level, on x86-64, and at smoke size on aarch64 and riscv64 ([`crates/browntls-entropy/`](../crates/browntls-entropy/README.md)); detects visible low entropy only, not a well-hashed small seed |
| Fuzzing | cargo-fuzz targets for the message codecs, deframer, certificate decompression, PKI parsers and path validation, both connection state machines, and API-sequence targets grouped by topic that together reach every public function of `browntls-crypto`, `browntls-pki`, `browntls-core` and `browntls-tokio` (`browntls-ktls` is not fuzzed; `browntls` defines no function of its own) ([`fuzz/`](../fuzz/README.md)); CI runs generated seeds on the stable toolchain, checks public API coverage, and fuzzes the targets as a GitHub Actions matrix on one x86-64 runner on pull requests and weekly |
| Facade | `browntls` adds paths and features, no behaviour: a handshake through each of its three paths (the root, `browntls::tokio`, and `browntls::ktls` against the running kernel), probes that the forwarded features reach the crates behind it, the feature sets an application picks in their own CI job, and a manifest check of the feature tables (`crates/browntls/tests/`, `tests/scripts/check_facade_features.py`; see [Facade crate](#facade-tests)) |
| End-to-end | Release builds of the `browntls-e2e` client and server (built on the `browntls` facade alone) in containers on a Docker network against OpenSSL 3.5 (Alpine and Ubuntu 26.04, the latter not on native riscv64), OpenSSL 3.0 (Ubuntu 24.04), GnuTLS 3.8, Go `crypto/tls` (Encrypted Client Hello scenarios only) and browntls itself, for x86-64-v3, aarch64, native riscv64 and riscv64 with vector crypto under QEMU: TLS 1.3 and 1.2 suites and groups including X25519MLKEM768, HelloRetryRequest, client authentication, resumption, Encrypt-then-MAC required by default (`tests/e2e/`, [Docker end-to-end tests](../tests/e2e/README.md)) |

Test certificates and keys are generated at run time; no private keys are
committed. Successful CI is evidence for the tested configurations only and
is not a security assessment.

## Status

The first implementation milestone establishes the crates, the provider mount
point, primitive backends and the TLS state machines. Measured throughput
against OpenSSL is recorded in [Performance](Performance.md). Coverage, gaps and
deferred features are listed in the [roadmap](Roadmap.md).
