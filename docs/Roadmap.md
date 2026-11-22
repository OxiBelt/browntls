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
| AES-GCM (portable, AES-NI/VAES, Armv8, Zvkned/Zvkg) | done | Bitsliced portable AES and constant-time GHASH; AES-NI+PCLMULQDQ, VAES (YMM) with VPCLMULQDQ (YMM) GHASH, AVX-512 VAES+VPCLMULQDQ with a fused CTR+GHASH loop, FEAT_AES+PMULL, Zvkned+Zvkg/Zvbc, Zkne+Zbc. The ZMM and VPCLMULQDQ backends are tested only on native hardware (QEMU 8.2 cannot execute them); elsewhere CTR and GHASH are separate passes. GHASH is also public on its own (`gcm::Ghash`, not routed), tested against the RFC 8452 and GCM-specification GHASH values, a bit-serial reference and the AES-GCM tag relation on every backend |
| ChaCha20-Poly1305 (portable, AVX2/AVX-512, NEON, RVV) | done | Poly1305 scalar, BMI2 and four-way AVX2 |
| X25519 / Ed25519 | done | BMI2/ADX ladder on x86-64; small-order Ed25519 public keys rejected |
| X448 / Ed448 (optional, non-preferred) | done | Portable 8x56-bit field with Karatsuba multiplication, fixed-base comb for Ed448 signing and X448 public keys; X448 group in TLS 1.3 and TLS 1.2 ECDHE, Ed448 certificates and handshake signatures; cofactored Ed448 verification, small-order Ed448 public keys rejected; OpenSSL 3 interop suite (TLS 1.3 and 1.2) |
| P-256 / P-384 / P-521 ECDH and ECDSA | done | RCB complete formulas for secret-scalar additions, Jacobian doubling in the ladder and variable-time Jacobian verification, RFC 6979 with hedging; specialised BMI2/ADX and portable field arithmetic and safegcd inversion for all three curves; width-6 fixed-base comb for P-256. Public field, scalar and point arithmetic (`FieldElement`, `Scalar`, `AffinePoint`, `ProjectivePoint`, SEC 1 with the identity; constant time except the documented `vartime` double multiplication and SEC 1 decoding, canonical decoding, scalars zeroised on drop) tested against num-bigint and the RustCrypto scalars and points on both backends and reached by the `crypto_ecc` fuzz target |
| RSA PKCS #1 v1.5 / PSS | done | 2048-8192-bit verification, CRT signing with blinding and fault check, key generation; safegcd unblinding; fused BMI2/ADX and portable Montgomery kernels; AVX-512 IFMA CRT and public-exponent exponentiation; signing stack 24-52 KiB by key size (IFMA); RSASSA-PSS (`id-RSASSA-PSS`) keys without parameters or restricted to SHA-256/384/512 (in every encoding RFC 4055 treats as equal, with any minimum salt length up to the digest length), signing and verifying only `rsa_pss_pss_*` (TLS 1.3 and 1.2), matched through one canonical form in path validation and handshake verification, in the OpenSSL 3 interop suite |
| ML-KEM-512/768/1024 | done | AVX2, NEON and RVV arithmetic; four-way SHAKE sampling |
| HPKE (RFC 9180), base mode | done | DHKEM(X25519, X448, P-256, P-384, P-521), HKDF-SHA256/384/512, AES-GCM, ChaCha20-Poly1305 and export-only; all RFC 9180 base-mode vectors for the supported suites (none exist for P-384 or HKDF-SHA384) and differential tests against the `hpke` crate for every X25519/NIST suite; PSK and authenticated modes left out |
| FFDHE (RFC 7919 groups, TLS 1.3 only) | done | ffdhe2048-8192 with RFC 7919 short exponents over the RSA constant-time Montgomery exponentiation; non-preferred groups of the native provider, ffdhe2048-4096 in the defaults and ffdhe6144/8192 opt-in (server cost); OpenSSL 3 interop suite |
| PKI types and PEM | done | |
| X.509 path validation, name checks, CRLs | done | DFS path building with webpki-style budgets, RFC 9525 DNS/IP/URI/SRV identities and corresponding name constraints, v2 CRLs; directoryName constraints fail closed; deviations from webpki documented in the crate |
| X.509 inspection API | done | `Cert` (any v3 certificate, with the parser path validation uses; `EndEntityCert` dereferences to it): every extension, typed basic constraints, key usage, EKU, key identifiers, SANs (`GeneralName`, every RFC 5280 choice), name constraints and CRL distribution points; X.501 `Name` parsing with strict DER (SET OF order included); `SignedData` verification of certificates, CRLs, CSRs and raw triples with the path-validation algorithm matching. Policy extensions and other extensions are only available undecoded; `authorityInfoAccess`, the TLS Feature extension and `id-pkix-ocsp-nocheck` are decoded by functions in `browntls_pki::ocsp` (see [Architecture](Architecture.md#certificate-inspection)) |
| TLS record layer and handshake (1.2, 1.3) | done | TLS 1.3 to RFC 9846 (HRR, PSK resumption, client auth, KeyUpdate, downgrade sentinels; the RFC 9846 rules on extensions per message, versions, HelloRetryRequest, KeyUpdate, alerts, tickets and ECDSA curves, see [Architecture](Architecture.md#tls-13-protocol-rules-rfc-9846)) and TLS 1.2 (ECDHE AEAD and AES-CBC suites, Encrypt-then-MAC (RFC 7366) negotiated and required by default, constant-time MAC-then-encrypt as an opt-in, EMS, session ID and ticket resumption, client auth, renegotiation refused and `renegotiation_info` required of servers (RFC 9325 §3.5)); RSA and finite-field DH key exchange left out (RFC 10015); interoperability tested against rustls 0.23 in both directions |
| RFC 10024 hybrid key agreement | done | Native and RustCrypto support X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 for TLS 1.3, DTLS 1.3 and QUIC v1. The NIST hybrids are explicit provider choices. Covers the low-level exchanges, Tokio adapters and kTLS handoff. See [Architecture](Architecture.md#post-quantum-hybrid-key-agreement-rfc-10024). |
| Crypto provider mount point, RustCrypto provider | done | rustls 0.23-shaped traits; RustCrypto provider verifies RSA but does not sign with it (advisory) |
| Native provider (`browntls-crypto`) | done | All suites, X25519/NIST/ML-KEM and hybrid groups, ECDSA/Ed25519/RSA signing and verification, AEAD tickets; the RFC 9846 optional algorithms (AES-CCM, X448, FFDHE, Ed448, `rsa_pss_pss_*`) as a non-preferred tier (see [Architecture](Architecture.md#algorithm-tiers-native-provider)); byte-identical records to the RustCrypto provider. All handshake, API and rustls interop suites run on both providers; native adds RSA, ML-KEM-1024 and mixed-provider handshakes |

## Later milestones

| Area | Status |
|---|---|
| 0-RTT early data (stateful resumption), hybrid post-quantum groups, kTLS secret export | done |
| RFC 9846 optional AES-CCM suites (non-preferred tier): `TLS_AES_128_CCM_SHA256` then `TLS_AES_128_CCM_8_SHA256` in the defaults after every AES-GCM and ChaCha20-Poly1305 suite; RFC 9147 Appendix B limits, kTLS export for CCM only | done |
| Raw public keys (RFC 7250), certificate compression framework (RFC 8879), OCSP/SCT passthrough, `max_fragment_size`, `Acceptor` | done |
| Client certificate URLs (RFC 6066 §5), TLS 1.2 only, both sides, off by default: the server pauses and the application (or the `browntls-tokio` fetcher) performs and authorizes every fetch; strict URL policy, hash and PkiPath checks; tests on both providers, browntls to browntls only (no peer of the end-to-end matrix implements it); see [Architecture](Architecture.md#client-certificate-urls-rfc-6066-5) | done |
| OCSP, Must-Staple, and Mozilla CRLite for server and client certificate authentication, with opt-in live queries and Tokio server staple refresh | done: see [certificate revocation](Architecture.md#certificate-revocation) |
| Certificate Transparency 2.0 (RFC 9162) in `browntls-pki` (`transparency`): `TransItem` and `TransItemList` parsing and encoding, Merkle inclusion and consistency proof verification, SCT v2 and signed tree head verification (ECDSA P-256, Ed25519), inclusion evidence across the certificate extension, OCSP `singleExtensions` and the TLS extension body, all without `std` ; the `transparency_info` TLS extension (RFC 9162 §6.5) in `browntls-core`: server lists in the TLS 1.2 ServerHello and TLS 1.3 CertificateEntry, client offer, raw items and a WebPKI verifier policy over the certificate, stapled OCSP and TLS sources, on buffered, unbuffered and Tokio connections | done, browntls to browntls only (both providers, TLS 1.2 and 1.3, resumption, compressed certificates). Tested only for self-consistency against encoders and a reference Merkle tree written from the RFC text; no public CT 2.0 log, second implementation or RFC test vector was available (see [Architecture](Architecture.md#certificate-transparency-20-rfc-9162)) |
| `record_size_limit` (RFC 8449, both sides, TLS 1.3 and 1.2, on by default), `ticket_request` (RFC 9149), client GREASE (RFC 8701, opt-in) and ClientHello padding (RFC 7685, on by default for 256 to 511-byte hellos): in-memory suites on both providers, rustls 0.23 and OpenSSL 3 interop with all four on; Docker E2E scenarios with all four on, run against OpenSSL, GnuTLS and browntls (see [Architecture](Architecture.md#optional-clienthello-extensions)) | done |
| Cached information (RFC 7924 `cached_info`), TLS 1.2 only, both sides, both object types (`cert`, `cert_req`), off by default: client store trait with a bounded in-memory store, server policy per type, `cached_info_replaced()` on every connection type; in-process tests on both providers with buffered and unbuffered peers and forged server answers, a `browntls-tokio` test, coverage in the `tls_conn` and `tls_unbuffered` fuzz targets; no interoperability test, since no implementation the project tests against supports it (see [Architecture](Architecture.md#cached-information-rfc-7924)) | done |
| `trusted_ca_keys` (RFC 6066 §6, TLS 1.2 only, opt-in on both sides): client list with identifiers built from CA certificates or trust anchors, server acknowledgement in full TLS 1.2 handshakes only, ready-made resolver (`ResolvesServerCertUsingTrustedCaKeys`); tests on both providers, buffered, unbuffered and Tokio streams; browntls to browntls only, no interoperability peer implements it (see [Architecture](Architecture.md#tls-12-only-extensions-of-rfc-6066)) | done |
| Server GREASE (RFC 8701 §4.1, opt-in `ServerConfig::enable_grease`): a GREASE signature scheme and two GREASE extensions in TLS 1.3 CertificateRequest messages (handshake, post-handshake, and through the kernel handoff) and two GREASE extensions in NewSessionTicket messages, on buffered, unbuffered and QUIC connections; the messages are read as sent over QUIC and at the kernel handoff, a CertificateVerify signed with the GREASE scheme is refused, on both providers; rustls 0.23 and OpenSSL 3 clients authenticate and resume against it; through `browntls-tokio` (browntls and tokio-rustls clients against a `TlsAcceptor`, post-handshake authentication, the unbuffered acceptor) and the facade; Docker E2E scenarios with a browntls server sending GREASE tickets, and in `tls13-optional-extensions-client-auth` a GREASE CertificateRequest, to OpenSSL, GnuTLS and browntls clients (see [Architecture](Architecture.md#optional-clienthello-extensions)) | done |
| TLS 1.3 post-handshake client authentication (RFC 9846 §4.7.2, opt-in on both sides), stateless HelloRetryRequest cookies (RFC 9846 §4.3.2, server opt-in, continued by a fresh `ServerConnection`, `UnbufferedServerConnection`, `Acceptor` or `UnbufferedAcceptor`), early exporter (RFC 9846 §7.5, RFC 8448 vector), RFC 9266 `tls-exporter` channel binding; both providers, plus OpenSSL 3 `s_client` interop for post-handshake authentication and the stateless retry | done |
| Delegated credentials (RFC 9345) in TLS 1.3, for server authentication (§4.1.1) and client authentication (§4.1.2, in the handshake and post-handshake; a server opts in with `ServerConfig::enable_delegated_credentials`): issuing with the native provider, `DelegationUsage` parsing, validation with the RFC 9345 alerts on both sides, and client/server resumption bounded by the original credential expiry (descendant tickets, 0-RTT and RFC 9973 included); buffered, unbuffered and `browntls-tokio` connections; tests on both providers (`crates/browntls-core/tests/delegated_credentials*.rs`, `crates/browntls-tokio/tests/delegated_credentials.rs`), browntls to browntls only | done |
| Exported authenticators (RFC 9261) for TLS 1.3 and TLS 1.2 with EMS: requests, authenticators, spontaneous server authenticators, the empty authenticator, validation through the configured verifiers; on buffered and unbuffered connections (the unbuffered ones also without `std`; not QUIC), one implementation for both; tests on both providers (`crates/browntls-core/tests/exported_authenticators*.rs`, every buffered/unbuffered pairing) and a unit test built without `std`, browntls to browntls only | done |
| TLS 1.3 external PSKs (RFC 9846 §4.3.11, `psk_dhe_ke` only), the PSK importer (RFC 9258) and certificate authentication with an external PSK (RFC 9973, opt-in, with strict server policy and offer/negotiation inspection); `require_external_psk` on both sides; tickets of external-PSK sessions bind the key bytes and optional caller generation so rotation invalidates old tickets; 0-RTT with external PSKs opt-in per key; both providers, cross-provider handshakes, OpenSSL 3 interop for direct external PSKs in both directions (see [Architecture](Architecture.md#tls-13-external-psks)) | done |
| External session and identity binding (RFC 8844, `external_id_hash` and `external_session_id`), both sides, TLS 1.3 and 1.2, opt-in per connection: buffered and unbuffered connections, the `ClientHello` view of both acceptors, `browntls-tokio`, ECH (inner ClientHello only) and HelloRetryRequest; no resumption or 0-RTT on a bound connection (RFC 8844 §5), external PSKs still usable; tests on both providers (`crates/browntls-core/tests/external_binding*.rs`, `crates/browntls-tokio/tests/external_binding.rs`) and the `tls_binding` fuzz target, browntls to browntls only (see [Architecture](Architecture.md#external-session-and-identity-binding-rfc-8844)) | done |
| Built-in certificate compressors (zlib, brotli, zstd) | done: optional features `zlib` (`miniz_oxide`), `brotli` (`brotli`) and `zstd` (`ruzstd`, single compression level), default lists when enabled; both directions in TLS 1.3 (client certificates included); declared length bounded by a 64 KiB cap and a configurable limit and enforced exactly; unit and handshake tests on both providers and across them. zlib and Brotli interoperate with rustls 0.23 (zlib-rs, brotli) in both roles and both directions; Zstandard has no second implementation in the test suite and accepts frames with a window of at most 128 KiB (below the RFC 8878 recommendation; see [Architecture](Architecture.md#certificate-compression-rfc-8879)), and nothing is tested against OpenSSL (the OpenSSL 3.0 command-line tool of the interop suite has no certificate compression; OpenSSL 3.2 and later do) |
| Unbuffered API (`browntls_core::unbuffered`, `UnbufferedClientConnection`, `UnbufferedServerConnection`, `UnbufferedAcceptor`; also without `std`): TLS 1.2 and 1.3, both sides, in-place decryption in the caller's buffer, encryption into the caller's buffer with exact size errors, resumption, 0-RTT, KeyUpdate including the confidentiality-limit refresh, `close_notify`, Encrypted Client Hello status, the client's delegated credential, TLS 1.3 post-handshake client authentication started by an unbuffered server or answered by an unbuffered client, the early exporter and the RFC 9266 `tls-exporter` channel binding, the server configuration chosen from the ClientHello (`UnbufferedAcceptor`, sharing the buffered `Acceptor`'s checks; stateless retry cookies and ECH included); tested against buffered browntls peers, itself and rustls 0.23 on both providers, with whole and byte-by-byte input (`tests/cases/unbuffered.rs`; the ECH, delegated credential, post-handshake authentication and exporter cases browntls to browntls only) | done |
| Encrypted Client Hello (RFC 9849): client (real offers, GREASE, random configuration identifiers), shared-mode server, split mode (client-facing server `ech::split::ClientFacing` and back-end server `ServerConfig::ech_backend`), trial decryption and the public name check as server options, retry configurations, SVCB/HTTPS `ech` parameter parsing (RFC 9848); in-process tests, the `tls_ech` fuzz target, and Docker E2E scenarios for both topologies against browntls and Go crypto/tls; see [Architecture](Architecture.md#encrypted-client-hello-rfc-9849) | done |
| ECH PEM configuration files (RFC 9934): BER and DER PKCS #8 import and DER export for all five native DHKEMs, public-only files, ordered retry selection, and core, Tokio and Linux kTLS configuration APIs. See [Architecture](Architecture.md#ech-configuration-files-rfc-9934). | done |
| Load-aware backend routing (`accel::load`, opt-in): per-stream cost tracking, congestion detection against a baseline, probing and a shifted share that follows the measurements, on a keyed per-thread schedule; fixed shares for experiments; see [Architecture](Architecture.md#load-aware-backend-routing) | done: the controller (unit-tested with synthetic costs, including the fixed-capacity model it is built for), ChaCha20-Poly1305 records, AES-GCM records (keys created while routing is enabled expand their key for each alternate AES backend, paired with a GHASH backend of the same instruction class, when a record is first routed to one), the X25519 ladder, P-256, P-384 and P-521 (public key derivation, ECDH, ECDSA signing and verification), ML-KEM (key generation, encapsulation, decapsulation) and RSA signatures of 2048-, 3072- and 4096-bit keys (so also the native provider's uses of them once an application enables routing), with tests that fixed shares of 0, 1, 50 and 100% on every alternate give identical results, also while shares change under concurrent use, and that failed operations are not timed. AES-CCM, AES-CBC, RSA verification, FFDHE, X448, Ed25519, Ed448 and the hash functions are not routed, the automatic controller is not exercised through real timings in any test. TLS handshakes and records of the native provider are tested with every stream pinned on each alternate, between native peers and against the RustCrypto provider (`crates/browntls-core/tests/native_load_routing.rs`). Measured on one machine ([Performance](Performance.md#load-aware-backend-routing)): enabling it costs about 20 ns per long record and 0.1 to 0.2 µs per key exchange or signature, and no alternate was ever faster there, so no shift happened; no measurement exists on hardware where the premise holds, and the benefit is unverified |
| QUIC-TLS (RFC 9001): `browntls_core::quic` handshake API shaped like `rustls::quic`, Initial/Handshake/0-RTT/1-RTT keys, AES and ChaCha20 header protection, AES-GCM, ChaCha20-Poly1305 and AES-128-CCM packet protection on both providers (CCM native only), key update, Retry integrity tag, RFC 9001 Appendix A vectors, rustls interop in both directions (see [Architecture](Architecture.md#quic-tls-rfc-9001)) | done |
| QUIC transport (RFC 9000) | out of scope |
| DTLS 1.3 (RFC 9147): `browntls_core::dtls` sans-I/O `ClientConnection` and `ServerConnection` (whole datagrams in and out, timers on the caller's clock) over the TLS 1.3 handshake; unified headers with encrypted record numbers, a 128-record replay window per epoch, the integrity limit enforced, fragmentation to the datagram size (256 to 65507 bytes, 1200 by default), reassembly, ACKs and retransmission, KeyUpdate held until acknowledged, resumption with tickets kept apart from TLS ones; the cookie exchange on by default with cookies bound to the caller-provided client address, and a stateless `dtls::Acceptor`; application data never fragmented; every TLS 1.3 suite but CCM_8, on both providers. Tests between browntls endpoints over a simulated lossy network (`crates/browntls-core/tests/cases/dtls.rs`) and the `tls_dtls` fuzz target and [wolfSSL Docker interoperability](../tests/e2e/README.md#dtls-13-interoperability) (see [Architecture](Architecture.md#dtls-13-rfc-9147)) | done |
| DTLS 1.2 (RFC 6347) | full opt-in certificate handshakes with ECDHE AEAD, EMS and address-bound cookies. Tested on both providers and in both roles against OpenSSL. Opt-in session ID and RFC 5077 ticket resumption exercised on both providers. See [DTLS 1.2](DTLS12.md) |
| DTLS connection ID negotiation and record protection (RFC 9146 and RFC 9147 §9), bounded DTLS 1.3 updates, and checked receive metadata | exercised on both providers, with paths pinned |
| DTLS path validation and connection migration (RFC 9853) | both versions, basic and enhanced selection, blocking and Tokio UDP, retained sessions, and minikube UDP Service rebind checks |
| 0-RTT, Encrypted Client Hello and post-handshake client authentication over DTLS 1.3 | planned |
| Blocking `std` API for DTLS 1.3: `dtls::UdpClient` (one server) and `dtls::UdpServer` (many clients on one socket) over `std::net::UdpSocket`; stateless cookies through the `dtls::Acceptor`, at most 256 handshakes at once with the oldest replaced, a handshake timeout, read timeouts that still take what has arrived, `ServerEvent`s for connected clients only, clients told apart by address only, no live OCSP. Loopback tests (`crates/browntls-core/tests/cases/dtls_udp.rs`) and the `tls_dtls_udp` fuzz target and [wolfSSL Docker interoperability](../tests/e2e/README.md#dtls-13-interoperability) (see [Architecture](Architecture.md#dtls-13-rfc-9147)) | done |
| Tokio API for DTLS | client, event server, and bounded, independently owned session handles |
| Fuzzing targets for codecs, PKI and handshake state | done: eight cargo-fuzz targets in `fuzz/` (handshake messages, deframer, certificate decompression, X.509 path validation, PEM, CRLs, client and server connections with a genuine in-process peer and identity TLS 1.3 record protection); built and run over generated seeds in CI on the stable toolchain. The first manual campaign ran each target for 60 seconds from the generated seeds when the targets were added (nightly 1.102, libFuzzer with AddressSanitizer, x86-64; between 3.5 thousand executions for the connection targets and 4.5 million for `pki_crl`) and found no crash, which is evidence of little beyond the harnesses working |
| Fuzzing the public API | done: twenty-three API-sequence targets grouped by topic (hashes, ciphers, ECC, RSA, KEMs, HPKE, crypto utilities, PKI including revocation, configuration, buffered and unbuffered connections, the Tokio streams over either, kernel TLS offload, ECH, PSK, RFC 8844 binding, QUIC-TLS, DTLS 1.3 and its blocking UDP API, delegated credentials and exported authenticators, codec types), checked against RustCrypto oracles, models and every backend; CI requires them to reach every public function of the four library crates other than `browntls-ktls` (four `PlainMessage` methods are not reachable from outside the crate and are exempt). The Fuzz workflow runs all thirty-one targets as a GitHub Actions matrix: on one x86-64 runner, on pull requests for the targets whose sources changed and weekly with cached corpora |
| Asynchronous Tokio streams (`browntls-tokio`): `TlsConnector`, `TlsAcceptor`, client and server streams with `AsyncRead`/`AsyncBufRead`/`AsyncWrite`, `close_notify` on `shutdown`, `LazyConfigAcceptor` (configuration chosen per ClientHello), read and write halves (`into_split`), client 0-RTT early data with explicit bounded resend authorization, server 0-RTT early data read before the handshake completes (opt-in `TlsAcceptor::early_data`, with 0.5-RTT answers), interoperability with tokio-rustls, `into_kernel_handoff` (a stream readied for kernel TLS offload: nothing in flight, received plaintext set aside); the same connector, acceptor and lazy acceptor over the unbuffered API (`browntls_tokio::unbuffered`), reading records in place with at most one copy (no client 0-RTT there, and no server stream returned before the handshake completes) | done |
| Kernel TLS offload, core (`browntls_core::kernel`): handover of buffered and unbuffered connections with blockers instead of data loss, post-handover records (KeyUpdate in both directions, NewSessionTicket, post-handshake client authentication, alerts) through the state machine, confidentiality limit and request budgets kept; tested against a userspace stand-in for Linux kernel TLS (see [Architecture](Architecture.md#kernel-tls-offload-browntls_corekernel)) | done |
| Linux kernel TLS (`browntls-ktls`): `KtlsStream` hands buffered client and server connections to the kernel after draining them to a record boundary (refusals return the connection), installs keys for TLS 1.2 and 1.3 AES-GCM, ChaCha20-Poly1305 and TLS 1.3 AES-CCM, handles control records and key updates through `browntls_core::kernel`, honours a peer's `record_size_limit` (Linux 6.19); tested against the running kernel over loopback TCP; `AsyncKtlsStream` (feature `tokio`) does the same on Tokio TCP sockets and takes `browntls-tokio` client and server streams, and its `shutdown` sends the FIN only when the kernel's counters show every record with TCP (`unsent`); the kernel's zero-copy options on both streams (`set_tx_zerocopy_sendfile`; `set_rx_expect_no_pad` on Linux 7.2 or later, where a padded record is no longer misplaced in the reader's buffer) and `sendfile`, which sends a file's pages without a pass through userspace and keeps the record count and `unsent` (see [Architecture](Architecture.md#linux-kernel-tls-browntls-ktls)) | done |
| Kernel TLS in the load-aware routing order (`accel::load::kernel`, `browntls_ktls::routing`): while a driver has activated it, kernel TLS is the first place for the records of a new connection, ahead of the backends in their usual order (dedicated instructions before SIMD alone); with `accel::load` enabled, a stream per kind of record work (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) compares what writes cost with the kernel and in userspace and keeps a share of the new connections in userspace while the kernel is slower than its baseline and userspace measures cheaper; see [Architecture](Architecture.md#kernel-tls-at-the-head-of-the-order) | done: placement, cost reports, status and fixed shares in `browntls-crypto` (tested with synthetic costs: shift to userspace and back, a slower userspace, fixed shares, disabling, deactivating); `RoutedStream` and `AsyncRoutedStream` in `browntls-ktls` place buffered connections and `browntls-tokio` streams, fall back to userspace when the kernel cannot take a connection, and time writes in both places in processor time of the calling thread (tested over loopback with fixed shares, on kernels with and without the `tls` module). Only new connections move, only writes are timed, and unbuffered connections are not placed. The automatic controller is not exercised through real timings, and no measurement shows a shift away from the kernel paying on real hardware: the benefit is unverified |
| Facade crate (`browntls`): the one dependency of an application. Its root is `browntls-core`, the `tokio` feature adds `browntls-tokio` as `browntls::tokio` and the `ktls` feature adds `browntls-ktls` as `browntls::ktls`; every feature of the three exists under the same name, except `fuzzing`; the protocol crate was renamed to `browntls-core` for it; see [Architecture](Architecture.md#facade-crate-browntls) | done: no code of its own (re-exports only, so the items are the ones the crates behind it define); a handshake through each of the three paths (`browntls::ktls` against the running kernel), probes of the forwarded features, Clippy with the default set, each optional crate alone, `std` and `native` only, the other provider and without `std`, a CI job for the feature sets an application picks, and a manifest check of the feature tables (`tests/scripts/check_facade_features.py`); the Docker E2E peer depends on it alone. Not published, like the rest of the workspace; the gaps are listed [below](#governance-gaps) |
| Kernel integration design | in progress: Linux kernel TLS offload (above); other kernel mechanisms not started |

## Governance gaps

These requirements from [Maintenance](Maintenance.md) are not yet met:

- `cargo vet` admission with real audits for every dependency.
- Continuous fuzzing beyond the weekly CI runs. There is no dedicated fuzzing
  service (such as OSS-Fuzz); each target gets twenty minutes a week on one
  x86-64 runner, and findings from CI are reported only as a target name and
  an input hash. The
  connection targets do not reach states behind a Finished or
  CertificateVerify they would have to forge, or TLS 1.2 after
  ChangeCipherSpec, except through the genuine in-process peers of the API
  targets.
- `cargo vet` audits are also missing for the optional compression crates
  (`miniz_oxide`, `brotli`, `ruzstd` and their dependencies), which parse
  peer data when their features are enabled; `ruzstd` contains `unsafe`.
- Named, non-author review of `unsafe` code, constant-time properties and
  cryptographic correctness, with Miri or sanitizer evidence where applicable.
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
- The RFC 6066 `truncated_hmac` extension is recognised but never offered or
  acknowledged, on purpose (RFC 9325 §4.6 forbids its use); see
  [Architecture](Architecture.md#tls-12-only-extensions-of-rfc-6066).
- Known deviations from RFC 9846 in the TLS 1.3 implementation, deliberate:
  a peer that sends more than eight `update_requested` KeyUpdates without
  non-empty application data in between is cut off with `unexpected_message`
  (a local resource bound); `user_canceled` counts towards the same bound as
  TLS 1.2 warning alerts; the RFC 6066 `max_fragment_length` extension is not
  offered or accepted; a server keeps at most one post-handshake
  CertificateRequest outstanding (RFC 9846 §4.7.2 allows several), and its
  answer may be a CompressedCertificate with an algorithm the request
  offered, as in the handshake (RFC 8879 §4); a client answers at most
  eight post-handshake CertificateRequests without (non-empty) application
  data from the server in between and then aborts with `unexpected_message`
  (a local resource bound: each answer costs a signature); a
  HelloRetryRequest cookie expires after 60 seconds, is not bound to the
  client's address over TLS (it is over DTLS 1.3), and none is sent when the
  first ClientHello offered 0-RTT.
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
  scenarios have passed with it. Server-side GREASE (RFC 8701 §4.1,
  `ServerConfig::enable_grease`) is off by default as well; with it on, the
  values go into TLS 1.3 CertificateRequest and NewSessionTicket messages
  only, not into TLS 1.2 messages or exported authenticator requests.
- RFC 7924 `cached_info` has no interoperability evidence (OpenSSL, GnuTLS,
  Go crypto/tls and rustls do not implement it) and was written from the RFC
  alone; its Appendix A vector is checked with the message header corrected
  (the printed header has a spurious `00 02`). TLS 1.3 handshakes do not use
  it (RFC 7924 predates TLS 1.3 and defines no TLS 1.3 behaviour).
- Delegated credentials (RFC 9345) have no interoperability evidence: no
  implementation the project tests against (OpenSSL 3, rustls) supports
  them. Neither side checks a credential's signature when it is
  attached, so a credential issued for another certificate, or for the
  other side, is only rejected by the peer. Verifiers that do not override
  `verify_tls13_signature_with_delegated_key` refuse credentials. The Docker
  end-to-end matrix does not exercise delegated credentials.
  `CertifiedKey` gained a private field, so struct-literal construction no
  longer compiles (use `CertifiedKey::new`).
- Exported authenticators (RFC 9261) have no interoperability evidence and
  were written from the RFC alone; the exporter labels, the CertificateVerify
  context string and the message layout have not been checked against
  another implementation or published test vectors. Secondary host names
  (the `server_name` request extension) are not supported: a client
  validates server authenticators against the connection's SNI only.
- DTLS 1.3 interoperability covers full handshakes against wolfSSL as
  both client and server in Docker. Resumption and loss recovery are tested
  between browntls endpoints. The opt-in
  [DTLS 1.2 certificate handshake layer](DTLS12.md) is tested on both
  providers and against OpenSSL in Docker. DTLS 1.2 session ID and RFC 5077
  ticket resumption are opt-in and exercised between browntls peers.
  CID and return routability checks are opt-in. Deferred DTLS features include
  0-RTT, Encrypted Client Hello or post-handshake client authentication,
  through the low-level, blocking or Tokio APIs. A cookie is bound to
  whatever address bytes the caller
  passes; `UdpServer` passes the client's socket address and tells clients
  apart by it alone, and supports no live OCSP checks. Unprotected hellos
  can be forged by anyone who knows the addresses: a forged one that wins
  the race against the real one can stall a handshake until it times out.
- The facade crate `browntls` and the crates behind it are unpublished
  (`publish = false`), so `browntls = "..."` from a registry does not exist
  yet; an application depends on the Git repository or a path. The manifests
  of `browntls`, `browntls-tokio` and `browntls-ktls` carry the metadata a
  crates.io release needs; those of `browntls-core`, `browntls-crypto` and
  `browntls-pki`, which the facade cannot be published without, do not
  (no `readme`, `documentation`, `keywords`, `categories`, `include` list or
  licence file in the crate directory, and no crate README).
  `browntls::tokio` shares its name with the external `tokio` crate, so
  `use browntls::*;` or `use browntls::tokio;` makes `#[tokio::main]` and
  `tokio::` paths meant for the external crate fail to compile in that
  scope (see [Architecture](Architecture.md#the-name-browntlstokio)). The facade
  without `std` is linted on the x86-64 host target only: no CI job builds
  it, or `browntls-core`, for a target without an operating system. Its
  tests are not run against the Tokio lower bound (that job compiles it with
  `tokio` through the end-to-end peer and runs the tests of `browntls-tokio`
  and `browntls-ktls`). The Docker E2E matrix does not reach
  `browntls::ktls`. The fuzz project, the entropy checks and the Kubernetes
  revocation test depend on the crates behind the facade directly (the fuzz
  project needs `fuzzing`, which the facade does not offer).
- External session and identity binding (RFC 8844) has no
  interoperability evidence (none of the implementations the project tests
  against supports it); it was reviewed by a separate agent, with no human
  review. A connection with a binding never resumes, is never resumed and
  sends no early data (RFC 8844 §5). An unsolicited answer in
  TLS 1.3 EncryptedExtensions is refused by the existing extension checks
  but is not tested on the wire. Under ECH, a server that requires peer
  support refuses a stale real offer instead of sending retry
  configurations, and an `Acceptor` sees only the outer ClientHello's
  (absent) values.
- External PSKs: the `psk_ke` mode is not implemented (RFC 9257 recommends
  asymmetric key establishment). External PSK selection considers the first
  16 identities. On RFC 9973 offers the server checks the entire
  wire-bounded list for recognizable tickets. The extension forbids
  resumption identities and early data. Ordinary external-PSK 0-RTT is
  off by default. Acceptance requires a credential cutoff and an atomic
  application-supplied replay policy shared by servers using the credential.
  Imported PSKs are
  checked with independent derivation vectors and across browntls
  providers. The [wolfSSL RFC 9973 suite](../tests/e2e/README.md)
  covers direct external PSKs in both roles over TLS and DTLS on amd64.
  The [minikube suite](../tests/kubernetes/README.md)
  exercises the Tokio TCP and UDP paths.
