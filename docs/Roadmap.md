# Roadmap

Phases are ordered by dependency. A feature counts as supported only when its
phase exit criteria pass in CI; until then it is experimental and may be absent
from the public API. Status values: `done`, `in progress`, `planned`.

## Phase 0: foundations — in progress

- Cargo workspace, pinned toolchain, MSRV, lint policy (`forbid(unsafe_code)`,
  Clippy pedantic subset), committed lockfile, and Cargo CI gates (fmt, Clippy,
  tests, rustdoc, MSRV).
- Exit: CI runs every Cargo gate on every push.

## Phase 1: wire format and primitives interface — in progress

- Bounds-checked codec, IANA registries, error and alert model.
- Handshake message and extension codecs for TLS 1.2 and TLS 1.3.
- Record deframer, fragmenter, handshake joiner, and record protection with
  sequence-number and confidentiality limits.
- In-house primitives in `browntls-crypto`: SHA-256/384/512, HMAC, HKDF,
  AES-128/256-GCM, ChaCha20-Poly1305, X25519, Ed25519, P-256, P-384, ECDSA,
  RSA-PSS and RSA PKCS#1 v1.5, ML-KEM-768/1024, each with a portable
  constant-time path and SIMD/hardware-accelerated backends where available.
- `CryptoProvider` traits, the native provider over `browntls-crypto`, and a
  RustCrypto-based fallback provider selectable by Cargo feature.
- TLS 1.3 and TLS 1.2 key schedules.
- Exit: round-trip and malformed-input tests for every codec; RFC 8448,
  RFC 5869, RFC 8439, NIST CAVP and Wycheproof vectors pass on both portable
  and accelerated backends; differential tests against RustCrypto pass.

## Phase 2: TLS 1.3 handshake

- Client and server 1-RTT handshake, HelloRetryRequest, certificate and
  CertificateVerify, Finished, KeyUpdate, alerts, `close_notify`.
- Buffered connection API and `std` stream adaptors.
- Temporary test verifier pinned to a fixed trust anchor; no Web PKI claims.
- Exit: loopback tests for every suite and group; interop with OpenSSL.

## Phase 3: TLS 1.2 handshake

- ECDHE_ECDSA and ECDHE_RSA with AES-GCM and ChaCha20-Poly1305, extended
  master secret (required by default), `renegotiation_info`, RFC 8446 downgrade
  sentinels, version negotiation between 1.2 and 1.3.
- Exit: loopback and OpenSSL interop for every TLS 1.2 suite.

## Phase 4: certificate verification (`browntls-pki`)

- DER/X.509 parsing, path building with bounded search, validity periods,
  basic constraints, key usage, extended key usage, name constraints,
  SAN DNS/IP matching (RFC 6125/9525), CRL checking, and signature algorithms
  matching the provider.
- Client certificate verification for servers.
- Exit: path-validation test suites and fuzzing of the DER parser.

## Phase 5: resumption and early data

- TLS 1.2 session IDs and RFC 5077 tickets; TLS 1.3 PSK resumption with
  `psk_dhe_ke`, binders, ticket age obfuscation, and bounded client caches.
- Rotating AEAD ticket encrypter; server-side stateful session storage.
- TLS 1.3 0-RTT with replay-window guidance and limits.
- Exit: resumption loopback tests across versions; interop with OpenSSL.

## Phase 6: extensions and features at rustls parity

- ALPN (RFC 7301), SNI and server certificate resolution (RFC 6066), client
  authentication, OCSP stapling, exporters (RFC 5705, RFC 8446 §7.5), key log
  output, raw public keys (RFC 7250), certificate compression (RFC 8879),
  configurable fragment size, vectored output.
- Post-quantum hybrid key exchange X25519MLKEM768 and SecP256r1MLKEM768
  (RFC 10024).
- Client-side Encrypted Client Hello (RFC 9849) with HPKE (RFC 9180).
- QUIC TLS interface (RFC 9001) and the unbuffered API.
- Exit: per-feature loopback and interop tests.

## Phase 7: kernel TLS offload (`browntls-ktls`)

- Export of traffic secrets and sequence numbers after the handshake, Linux
  `TLS_TX`/`TLS_RX` socket configuration, and key update handling with
  documented unsafe/syscall boundaries and independent review.
- Exit: kernel integration tests on supported Linux versions.

## Phase 8: assurance

- BoGo conformance runner with a tracked expectation list, fuzzing in CI,
  `cargo deny`/`cargo audit`/`cargo vet` gates, benchmarks, and an external
  security review before any release.

## Specification matrix

| Specification | Scope | Phase |
| --- | --- | --- |
| RFC 9846 (TLS 1.3, obsoletes RFC 8446) | Full protocol except post-handshake client auth | 2, 5 |
| RFC 5246 (TLS 1.2) | ECDHE AEAD suites only | 3 |
| RFC 5288, RFC 5289, RFC 7905 | TLS 1.2 AEAD suites | 3 |
| RFC 7627 | Extended master secret | 3 |
| RFC 5746 | Signalling only; renegotiation refused | 3 |
| RFC 8422 | ECC groups and point formats for TLS 1.2 | 3 |
| RFC 6066 | SNI, `status_request` | 2, 6 |
| RFC 7301 | ALPN | 6 |
| RFC 5077 | TLS 1.2 tickets | 5 |
| RFC 5705 | Exporters | 6 |
| RFC 7250 | Raw public keys (TLS 1.3) | 6 |
| RFC 8879 | Certificate compression | 6 |
| RFC 10024 | Hybrid ML-KEM key agreement | 6 |
| RFC 9849, RFC 9180 | ECH (client), HPKE | 6 |
| RFC 9001 | QUIC TLS | 6 |
| RFC 5280, RFC 9525 | Certificate path and identity validation | 4 |
| RFC 8448 | TLS 1.3 test vectors | 1, 2 |
