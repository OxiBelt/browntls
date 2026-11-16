# Roadmap

Implementation status of browntls against its target of rustls 0.23-level
features. See [Architecture](Architecture.md) for the design. Status values:
**done** (implemented and tested in CI configurations), **in progress**, and
**planned**. This file is updated with each milestone; it reports evidence, not
intent.

## Milestone 1: foundations

| Area | Status | Notes |
|---|---|---|
| Workspace, toolchain pin (1.100.0), lockfile, CI matrix | done | Native x86-64, aarch64 and riscv64 jobs plus QEMU profiles |
| CPU feature detection (x86-64, aarch64, riscv64) | done | `riscv_hwprobe` via the libc-free system-call trampoline |
| OS entropy without libc (Linux) | done | `getrandom(2)` |
| Portable SHA-2, SHA-3/SHAKE, HMAC, HKDF, TLS 1.2 PRF | done | Known-answer tests |
| Accelerated SHA-2 / Keccak backends | done | SHA-NI, x86-64-v3, FEAT_SHA256/512, Zvknha/b, Zknh; four-way Keccak (AVX2, AVX-512VL, NEON/SHA3, RVV). No x86 SHA512 extension |
| AES-GCM (portable, AES-NI/VAES, Armv8, Zvkned/Zvkg) | done | Bitsliced portable AES and constant-time GHASH; AES-NI+PCLMULQDQ, VAES (YMM) with VPCLMULQDQ (YMM) GHASH, AVX-512 VAES+VPCLMULQDQ with a fused CTR+GHASH loop, FEAT_AES+PMULL, Zvkned+Zvkg/Zvbc, Zkne+Zbc. The ZMM and VPCLMULQDQ backends are tested only on native hardware (QEMU 8.2 cannot execute them); elsewhere CTR and GHASH are separate passes |
| ChaCha20-Poly1305 (portable, AVX2/AVX-512, NEON, RVV) | done | Poly1305 scalar, BMI2 and four-way AVX2 |
| X25519 / Ed25519 | done | BMI2/ADX ladder on x86-64; small-order Ed25519 public keys rejected |
| X448 / Ed448 (optional, non-preferred) | done | Portable 8x56-bit field with Karatsuba multiplication, fixed-base comb for Ed448 signing and X448 public keys; X448 group in TLS 1.3 and TLS 1.2 ECDHE, Ed448 certificates and handshake signatures; cofactored Ed448 verification, small-order Ed448 public keys rejected; OpenSSL 3 interop suite (TLS 1.3 and 1.2) |
| P-256 / P-384 / P-521 ECDH and ECDSA | done | RCB complete formulas for secret-scalar additions, Jacobian doubling in the ladder and variable-time Jacobian verification, RFC 6979 with hedging; specialised BMI2/ADX and portable field arithmetic and safegcd inversion for all three curves; width-6 fixed-base comb for P-256 |
| RSA PKCS #1 v1.5 / PSS | done | 2048-8192-bit verification, CRT signing with blinding and fault check, key generation; safegcd unblinding; fused BMI2/ADX and portable Montgomery kernels; AVX-512 IFMA CRT and public-exponent exponentiation; signing stack 24-52 KiB by key size (IFMA); RSASSA-PSS (`id-RSASSA-PSS`) keys without parameters or restricted to SHA-256/384/512 (in every encoding RFC 4055 treats as equal, with any minimum salt length up to the digest length), signing and verifying only `rsa_pss_pss_*` (TLS 1.3 and 1.2), matched through one canonical form in path validation and handshake verification, in the OpenSSL 3 interop suite |
| ML-KEM-512/768/1024 | done | AVX2, NEON and RVV arithmetic; four-way SHAKE sampling |
| HPKE (RFC 9180), base mode | done | DHKEM(X25519, X448, P-256, P-384, P-521), HKDF-SHA256/384/512, AES-GCM, ChaCha20-Poly1305 and export-only; all RFC 9180 base-mode vectors for the supported suites (none exist for P-384 or HKDF-SHA384) and differential tests against the `hpke` crate for every X25519/NIST suite; PSK and authenticated modes left out |
| FFDHE (RFC 7919 groups, TLS 1.3 only) | done | ffdhe2048-8192 with RFC 7919 short exponents over the RSA constant-time Montgomery exponentiation; non-preferred groups of the native provider, ffdhe2048-4096 in the defaults and ffdhe6144/8192 opt-in (server cost); OpenSSL 3 interop suite |
| PKI types and PEM | done | |
| X.509 path validation, name checks, CRLs | done | DFS path building with webpki-style budgets, RFC 6125 names, DNS/IP name constraints, v2 CRLs; directoryName/URI constraints fail closed; deviations from webpki documented in the crate |
| TLS record layer and handshake (1.2, 1.3) | done | TLS 1.3 to RFC 9846 (HRR, PSK resumption, client auth, KeyUpdate, downgrade sentinels; the RFC 9846 rules on extensions per message, versions, HelloRetryRequest, KeyUpdate, alerts, tickets and ECDSA curves, see [Architecture](Architecture.md#tls-13-protocol-rules-rfc-9846)) and TLS 1.2 (ECDHE AEAD and AES-CBC suites, Encrypt-then-MAC (RFC 7366) negotiated and required by default, constant-time MAC-then-encrypt as an opt-in, EMS, session ID and ticket resumption, client auth, renegotiation refused and `renegotiation_info` required of servers (RFC 9325 §3.5)); RSA and finite-field DH key exchange left out (RFC 10015); interoperability tested against rustls 0.23 in both directions |
| Crypto provider mount point, RustCrypto provider | done | rustls 0.23-shaped traits; RustCrypto provider verifies RSA but does not sign with it (advisory) |
| Native provider (`browntls-crypto`) | done | All suites, X25519/NIST/ML-KEM and hybrid groups, ECDSA/Ed25519/RSA signing and verification, AEAD tickets; the RFC 9846 optional algorithms (AES-CCM, X448, FFDHE, Ed448, `rsa_pss_pss_*`) as a non-preferred tier (see [Architecture](Architecture.md#algorithm-tiers-native-provider)); byte-identical records to the RustCrypto provider. All handshake, API and rustls interop suites run on both providers; native adds RSA, ML-KEM-1024 and mixed-provider handshakes |

## Later milestones

| Area | Status |
|---|---|
| 0-RTT early data (stateful resumption), hybrid post-quantum groups, kTLS secret export | done |
| RFC 9846 optional AES-CCM suites (non-preferred tier): `TLS_AES_128_CCM_SHA256` then `TLS_AES_128_CCM_8_SHA256` in the defaults after every AES-GCM and ChaCha20-Poly1305 suite; RFC 9147 Appendix B limits, kTLS export for CCM only | done |
| Raw public keys (RFC 7250), certificate compression framework (RFC 8879), OCSP/SCT passthrough, `max_fragment_size`, `Acceptor` | done |
| `record_size_limit` (RFC 8449, both sides, TLS 1.3 and 1.2, on by default), `ticket_request` (RFC 9149), client GREASE (RFC 8701, opt-in) and ClientHello padding (RFC 7685, on by default for 256 to 511-byte hellos): in-memory suites on both providers, rustls 0.23 and OpenSSL 3 interop with all four on; Docker E2E scenarios added, GnuTLS not yet run (see [Architecture](Architecture.md#optional-clienthello-extensions)) | done |
| TLS 1.3 post-handshake client authentication (RFC 9846 §4.7.2, opt-in on both sides), stateless HelloRetryRequest cookies (RFC 9846 §4.3.2, server opt-in, continued by a fresh `ServerConnection` or `Acceptor`), early exporter (RFC 9846 §7.5, RFC 8448 vector), RFC 9266 `tls-exporter` channel binding; both providers, plus OpenSSL 3 `s_client` interop for post-handshake authentication and the stateless retry | done |
| Delegated credentials (RFC 9345), server side in TLS 1.3: issuing with the native provider, `DelegationUsage` parsing, client validation with the RFC 9345 alerts, and client/server resumption bounded by the original credential expiry (descendant tickets, 0-RTT and RFC 8773 included); tests on both providers (`crates/browntls/tests/delegated_credentials*.rs`), browntls to browntls only. Client credentials not implemented | done |
| Exported authenticators (RFC 9261) for TLS 1.3 and TLS 1.2 with EMS: requests, authenticators, spontaneous server authenticators, the empty authenticator, validation through the configured verifiers; tests on both providers (`crates/browntls/tests/exported_authenticators*.rs`), browntls to browntls only | done |
| TLS 1.3 external PSKs (RFC 9846 §4.3.11, `psk_dhe_ke` only), the PSK importer (RFC 9258) and certificate authentication with an external PSK (RFC 8773, opt-in); `require_external_psk` on both sides; tickets of external-PSK sessions keep the PSK identity and are resumed only while the PSK is configured; 0-RTT with external PSKs opt-in per key; both providers, cross-provider handshakes, OpenSSL 3 interop for direct external PSKs in both directions (see [Architecture](Architecture.md#tls-13-external-psks)) | done |
| Built-in certificate compressors (zlib, brotli, zstd) | done: optional features `zlib` (`miniz_oxide`), `brotli` (`brotli`) and `zstd` (`ruzstd`, single compression level), default lists when enabled; both directions in TLS 1.3 (client certificates included); declared length bounded by a 64 KiB cap and a configurable limit and enforced exactly; unit and handshake tests on both providers and across them. zlib and Brotli interoperate with rustls 0.23 (zlib-rs, brotli) in both roles and both directions; Zstandard has no second implementation in the test suite and accepts frames with a window of at most 128 KiB (below the RFC 8878 recommendation; see [Architecture](Architecture.md#certificate-compression-rfc-8879)), and nothing is tested against OpenSSL (the OpenSSL 3.0 command-line tool of the interop suite has no certificate compression; OpenSSL 3.2 and later do) |
| Unbuffered API (`browntls::unbuffered`, `UnbufferedClientConnection`, `UnbufferedServerConnection`; also without `std`): TLS 1.2 and 1.3, both sides, in-place decryption in the caller's buffer, encryption into the caller's buffer with exact size errors, resumption, 0-RTT, KeyUpdate including the confidentiality-limit refresh, `close_notify`; tested against buffered browntls peers, itself and rustls 0.23 on both providers, with whole and byte-by-byte input (`tests/cases/unbuffered.rs`) | done |
| Encrypted Client Hello (RFC 9849): client (real offers, GREASE, random configuration identifiers), shared-mode server, split mode (client-facing server `ech::split::ClientFacing` and back-end server `ServerConfig::ech_backend`), trial decryption and the public name check as server options, retry configurations, SVCB/HTTPS `ech` parameter parsing (RFC 9848); in-process tests, the `tls_ech` fuzz target, and Docker E2E scenarios for both topologies against browntls and Go crypto/tls; see [Architecture](Architecture.md#encrypted-client-hello-rfc-9849) | done |
| Load-aware backend routing (`accel::load`, opt-in): per-stream cost tracking, congestion detection against a baseline, probing and a shifted share that follows the measurements, on a keyed per-thread schedule; fixed shares for experiments; see [Architecture](Architecture.md#load-aware-backend-routing) | done: the controller (unit-tested with synthetic costs, including the fixed-capacity model it is built for), ChaCha20-Poly1305 records, AES-GCM records (keys created while routing is enabled expand their key for each alternate AES backend, paired with a GHASH backend of the same instruction class, when a record is first routed to one), the X25519 ladder, P-256, P-384 and P-521 (public key derivation, ECDH, ECDSA signing and verification), ML-KEM (key generation, encapsulation, decapsulation) and RSA signatures of 2048-, 3072- and 4096-bit keys (so also the native provider's uses of them once an application enables routing), with tests that fixed shares of 0, 1, 50 and 100% on every alternate give identical results, also while shares change under concurrent use, and that failed operations are not timed. AES-CCM, AES-CBC, RSA verification, FFDHE, X448, Ed25519, Ed448 and the hash functions are not routed, the automatic controller is not exercised through real timings in any test. TLS handshakes and records of the native provider are tested with every stream pinned on each alternate, between native peers and against the RustCrypto provider (`crates/browntls/tests/native_load_routing.rs`). Measured on one machine ([Performance](Performance.md#load-aware-backend-routing)): enabling it costs about 20 ns per long record and 0.1 to 0.2 µs per key exchange or signature, and no alternate was ever faster there, so no shift happened; no measurement exists on hardware where the premise holds, and the benefit is unverified |
| QUIC | planned |
| Fuzzing targets for codecs, PKI and handshake state | done: eight cargo-fuzz targets in `fuzz/` (handshake messages, deframer, certificate decompression, X.509 path validation, PEM, CRLs, client and server connections with a genuine in-process peer and identity TLS 1.3 record protection); built and run over generated seeds in CI on the stable toolchain. The first manual campaign ran each target for 60 seconds from the generated seeds when the targets were added (nightly 1.102, libFuzzer with AddressSanitizer, x86-64; between 3.5 thousand executions for the connection targets and 4.5 million for `pki_crl`) and found no crash, which is evidence of little beyond the harnesses working |
| Fuzzing the public API | done: fifteen API-sequence targets grouped by topic (hashes, ciphers, ECC, RSA, KEMs, HPKE, crypto utilities, PKI, configuration, buffered and unbuffered connections, ECH, PSK, delegated credentials and exported authenticators, codec types), checked against RustCrypto oracles, models and every backend; CI requires them to reach every public function of the three library crates (four `PlainMessage` methods are not reachable from outside the crate and are exempt). The Fuzz workflow runs all twenty-three targets as a GitHub Actions matrix: on one x86-64 runner, on pull requests for the targets whose sources changed and daily with cached corpora |
| Kernel integration design | planned |

## Governance gaps

These requirements from [Maintenance](Maintenance.md) are not yet met:

- `cargo vet` admission with real audits for every dependency.
- Continuous fuzzing beyond the daily CI runs. There is no dedicated fuzzing
  service (such as OSS-Fuzz); each target gets twenty minutes a day per
  architecture, findings from CI are reported only as a target name and an
  input hash, and the riscv64 runners build without AddressSanitizer. The
  connection targets do not reach states behind a Finished or
  CertificateVerify they would have to forge, or TLS 1.2 after
  ChangeCipherSpec, except through the genuine in-process peers of the API
  targets.
- `cargo vet` audits are also missing for the optional compression crates
  (`miniz_oxide`, `brotli`, `ruzstd` and their dependencies), which parse
  peer data when their features are enabled; `ruzstd` contains `unsafe`.
- Named, non-author review of `unsafe` code, constant-time properties and
  cryptographic correctness, with Miri or sanitizer evidence where applicable.
- `deny.toml` ignores RUSTSEC-2023-0071 (`rsa` 0.9, Marvin) for public-key
  verification uses until 2027-01-31; it needs a named owner and tracking
  issue, and should be removed once tests verify RSA through
  `browntls-crypto`.
- RISC-V vector and scalar crypto backends assume data-independent
  instruction latency; detection does not yet require Zkt/Zvkt. Several
  internal accelerated entry points (`nist` P-256 BMI2/ADX, ML-KEM SIMD) rely
  on a selection invariant rather than an unforgeable capability token.
  Both were reported by the first independent `unsafe`/assembly review, which
  found no memory-safety defects in the asm operand constraints.
- Load-aware backend routing (`accel::load`) decides from wall-clock
  durations. It reads no secret values, but it would turn a
  secret-dependent duration of a backend, if one existed, into a
  secret-dependent choice of backend for later calls; the constant-time
  properties it relies on are verified only as far as the other items of
  this list say. Its schedule is keyed with a non-cryptographic mixing
  function, so it resists prediction by peers, not analysis by someone who
  can observe many routing decisions exactly. Its constants were chosen by
  reasoning and simulation and have not been evaluated on contended
  hardware, and its statistics are updated without locks, so concurrent
  samples can be lost (by design; a multi-threaded stress test checks
  ranges, with no loom or sanitizer evidence). Two independent reviews
  covered the controller and its claims; the simulations they and the
  final revision rest on are not part of the test suite, apart from the
  cases the unit tests reproduce.
- Accelerated backends for extensions without available hardware or emulation
  (for example the x86 SHA512 extension) remain unimplemented until they can
  be executed in tests. Backends that only native hardware can execute (the
  AVX-512 AES-GCM and RSA IFMA paths) are covered by the development machine
  and by CI runners whose CPUs offer them, not by a fixed CI profile.
- The performance work of November 2026 (AVX-512 AES-GCM, P-256 kernels and
  safegcd inversion, RSA IFMA and safegcd unblinding) had one independent
  review per area; constant time was checked by inspecting generated code,
  not by statistical timing tests. The RSA BMI2/ADX kernel uses `rbp` as a
  general register, which breaks frame-pointer unwinding inside the block and
  would need attention for kernel builds (objtool). Secret-derived values may
  remain in vector registers after AVX-512 code returns.
- The RFC 9846 optional algorithms (AES-CCM, X448/Ed448, FFDHE, RSASSA-PSS
  keys) are portable code; their constant-time properties rest on
  construction and review, not on timing tests. They exist only in the native
  provider.
- RSASSA-PSS `AlgorithmIdentifier`s are matched through a canonical form
  (`browntls_pki::alg_id::canonical_public_key_alg_id`), which accepts NULL
  or absent hash parameters, key salt lengths up to the digest and an
  explicit trailer field 1. Still rejected, fail closed: SHA-1 and SHA-224
  parameters and MGF1 with SHA-1 (although RFC 4055 §3 says validators MUST
  support SHA-1; no TLS scheme uses them); certificate signatures whose salt
  is not the digest length (allowed by RFC 4055 §3.3, described by no TLS
  scheme); an explicitly written `saltLength` 20, which is not DER. The
  certificate/key consistency check compares `SubjectPublicKeyInfo` bytes,
  so a key file and a certificate that write equivalent parameters
  differently are reported as mismatched; and `tbsCertificate.signature` is
  compared with `signatureAlgorithm` byte for byte (RFC 5280 §4.1.1.2).
- The AES-NI and VAES backends leave a copy of round key 0 (the AES key
  itself) in dead stack memory after each call; the portable backend and the
  CCM, X448, Ed448 and FFDHE code wipe their secret intermediates.
- The TLS 1.2 CBC record transform (`browntls_crypto::tls_cbc`), AES-CBC and
  SHA-1 were written by one engineer each and had no independent review yet.
  The constant-time MAC-then-encrypt path (the Lucky Thirteen countermeasure,
  only used when a configuration allows MAC-then-encrypt) rests on
  construction and source review, not on statistical timing tests or
  generated-code inspection. The CBC suites exist only in the native
  provider.
- Known deviations from RFC 5246 in the TLS 1.2 implementation, all shared
  with TLS 1.3 and deliberate: a received `close_notify` is not answered with
  one (the application decides when to close); a fatal alert is sent on its
  own, not coalesced with pending records; handshake messages are capped at
  64 KiB (RFC 5246 allows 2^24 - 1); resumption without
  `extended_master_secret` is accepted, as RFC 7627 §5.3 allows, instead of
  being refused; and renegotiation is never performed (a HelloRequest after
  the handshake is answered with `no_renegotiation`, RFC 5746 §4.2).
- Known deviations from RFC 9846 in the TLS 1.3 implementation, deliberate:
  a peer that sends more than eight `update_requested` KeyUpdates without
  application data in between is cut off with `unexpected_message` (a local
  resource bound); `user_canceled` counts towards the same bound as TLS 1.2
  warning alerts; the RFC 6066 `max_fragment_length` extension is not
  offered or accepted; a server keeps at most one post-handshake
  CertificateRequest outstanding (RFC 9846 §4.7.2 allows several), and its
  answer may be a CompressedCertificate with an algorithm the request
  offered, as in the handshake (RFC 8879 §4); a client answers at most
  eight post-handshake CertificateRequests without application data from
  the server in between and then aborts with `unexpected_message` (a local
  resource bound: each answer costs a signature); a HelloRetryRequest cookie
  expires after 60 seconds, is not bound to the client's address, and none
  is sent when the first ClientHello offered 0-RTT.
- Post-handshake client authentication, stateless HelloRetryRequest
  cookies, the early exporter and the RFC 9266 channel binding have had one
  code review (its findings are addressed) and no security audit. The
  client side of post-handshake authentication is exercised against the
  browntls server and against records forged with the server's extracted
  keys (an unsolicited CertificateRequest, an empty context, the request
  bound); no test sends a server messages interleaved within an answer,
  which needs a misbehaving client. The server side is also tested against
  `openssl s_client -enable_pha`.
- RFC 8449 `record_size_limit`: a peer value above the protocol maximum is
  lowered rather than refused (RFC 8449 §4 lets a client abort); 0-RTT
  records are not checked against the server's limit, and a TLS 1.3 client
  checks its own limit only from the record after EncryptedExtensions. The
  client's GREASE (RFC 8701) is off by default until the Docker E2E GnuTLS
  scenarios have passed with it; server-side GREASE (RFC 8701 §4) is not
  implemented.
- Delegated credentials (RFC 9345) have no interoperability evidence: no
  implementation the project tests against (OpenSSL 3, rustls) supports
  them. A server does not check a credential's signature when it is
  attached, so a credential issued for another certificate is only rejected
  by the peer. Verifiers that do not override
  `verify_tls13_signature_with_delegated_key` refuse credentials.
  `CertifiedKey` gained a private field, so struct-literal construction no
  longer compiles (use `CertifiedKey::new`).
- Exported authenticators (RFC 9261) have no interoperability evidence and
  were written from the RFC alone; the exporter labels, the CertificateVerify
  context string and the message layout have not been checked against
  another implementation or published test vectors. Secondary host names
  (the `server_name` request extension) are not supported: a client
  validates server authenticators against the connection's SNI only.
- External PSKs: the `psk_ke` mode is not implemented (RFC 9257 recommends
  (EC)DHE); a server examines only the first 16 `pre_shared_key`
  identities; 0-RTT under an external PSK has no anti-replay protection
  (it is off by default). The RFC 9258 importer has no interoperability
  test (OpenSSL 3 does not implement it) and no published test vectors;
  RFC 8773 has no interoperability test either; a client that sends
  `tls_cert_with_extern_psk` offers no resumption ticket alongside.
