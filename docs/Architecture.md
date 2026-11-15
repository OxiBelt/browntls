# Architecture

This document describes the design of browntls: a TLS 1.2 / TLS 1.3 library
written from scratch in Rust, targeting the feature level of rustls 0.23, with
its own cryptographic primitives behind a pluggable provider interface.
Implementation status is tracked in [Status](#status); the
[contributor guide](../CONTRIBUTING.md) and [security policy](../SECURITY.md)
govern how changes land.

## Crates

```text
browntls-crypto   primitives; no_std, no alloc; arch backends; no dependencies
       ^
       | (feature "native", default)
browntls ----------> browntls-pki   PKI types, PEM, X.509 path validation;
  crypto::*  (mount point)           no_std + alloc; no cryptography
  crypto::native     (default provider, browntls-crypto)
  crypto::rustcrypto (optional provider, RustCrypto crates)
```

| Crate | Role | `unsafe` |
|---|---|---|
| `browntls-crypto` | Hashes, MACs, KDFs, AEADs, key exchange, signatures, KEM, CPU detection, OS entropy | Denied crate-wide; allowed only in architecture backend modules, CPU detection, zeroisation and the system-call trampoline |
| `browntls-pki` | Certificate/key/name/time types, PEM, X.509 path building, name and revocation checks | Forbidden |
| `browntls` | Record layer, handshake state machines, configuration, provider traits and providers | Forbidden |

`browntls-pki` performs no cryptography: signatures are checked through the
`SignatureVerificationAlgorithm` trait supplied by the active provider. This
keeps certificate policy independent of any particular primitive library.
An algorithm is selected by its key and signature `AlgorithmIdentifier`s,
compared byte for byte except for `id-RSASSA-PSS`, whose equivalent
parameter encodings (RFC 4055) are first mapped to one canonical constant
(`AlgorithmIdentifier::matches_public_key` and `matches_signature`, used by
path validation and by handshake signature verification alike).

## Crypto provider mount point

`browntls::crypto` defines the provider interface, modelled on rustls 0.23 so
that existing provider designs map onto it:

- `CryptoProvider`: cipher suites, key-exchange groups, signature
  verification algorithms, secure random source and private-key loader. A
  process default can be installed; configurations can also be built with an
  explicit provider.
- Traits for each capability: hashing, HMAC, HKDF (TLS 1.3), PRF (TLS 1.2),
  record protection (`Tls13AeadAlgorithm`, `Tls12AeadAlgorithm`,
  `MessageEncrypter`, `MessageDecrypter`), key exchange (`SupportedKxGroup`,
  `ActiveKeyExchange`, including hybrid post-quantum groups), signing
  (`SigningKey`, `Signer`), randomness and key loading, plus hooks that export
  traffic secrets for kernel TLS offload.

Providers shipped in the `browntls` crate:

| Provider | Feature | Backing |
|---|---|---|
| `crypto::native` | `native` (default) | `browntls-crypto` |
| `crypto::rustcrypto` | `rustcrypto` | RustCrypto crates |

A provider is plain data (static trait objects), so applications can build a
mixed provider, for example native AEADs with RustCrypto signatures, or supply
their own implementation of any trait; `crates/browntls/tests/native_mixed.rs`
shows the pattern. When exactly one provider feature is enabled it becomes the
implicit default; with both enabled, the application installs one explicitly.

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
within each tier it follows the client's order (or its own with
`ignore_client_order`), but it picks a non-preferred suite or group only when
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
SHA-1 exists only as the HMAC of the `*_CBC_SHA` suites; no signature uses it
(RFC 9155). The explicit per-record IV comes from the operating system.

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
  registry, and TLS 1.2-only ones are allowed in a ClientHello alone). A
  recognised extension in a message that may not carry it is
  `illegal_parameter`; one that answers nothing we sent is
  `unsupported_extension`. This covers ServerHello, HelloRetryRequest,
  EncryptedExtensions, CertificateRequest, CertificateEntry and
  NewSessionTicket.
- Versions: a ClientHello with `supported_versions` and a TLS 1.3
  ServerHello or HelloRetryRequest must carry `legacy_version` 0x0303
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
  sending application data in between is cut off after eight requests, a
  local resource bound.
- Record layer: a protected `change_cipher_spec` record, or one whose value
  is not 0x01, is `unexpected_message`.
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
  OCSP responses may come with any entry (only the end entity's is used).
- Key shares come in `supported_groups` order, and a server that would have
  preferred a group other than the one the client's shares allowed lists its
  groups in EncryptedExtensions (RFC 9846 §4.3.7). Key shares are generated
  per connection and never reused.

Not implemented: post-handshake client authentication, the early exporter,
stateless HelloRetryRequest cookies, and RFC 6066 `max_fragment_length`
(not "Recommended" in RFC 9846 Table 1; `record_size_limit` and the local
`max_fragment_size` setting cover the use case).

### Delegated credentials (RFC 9345)

`browntls::delegated_credential` holds the `DelegatedCredential` codec,
signing (`DelegatedCredential::issue`) and validation; the native provider
adds `crypto::native::delegated_credential::generate`, which creates an
ECDSA (P-256/384/521), Ed25519 or Ed448 credential key and has the
certificate's key sign the credential. A credential is attached to a
`CertifiedKey` with `with_delegated_credential`, which checks that the
certificate carries the `DelegationUsage` extension
(1.3.6.1.4.1.44363.44, parsed by `browntls-pki`) and the
`digitalSignature` key usage, and that the key matches the credential's
public key.

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
  returns the credential used.
- Alerts (§4.1.3): an invalid credential is `illegal_parameter`; one the
  client did not ask for is `unexpected_message`; one on an entry other than
  the end entity's is `illegal_parameter`; a CertificateVerify that fails
  under the credential's key gets the same alert as one that fails under a
  certificate key (`decrypt_error` for a bad signature).
- Not implemented: client credentials (the extension is parsed in
  CertificateRequest but never sent, and a client never presents one).
  No other implementation the project tests against supports delegated
  credentials, so the tests are browntls to browntls only.

### Exported authenticators (RFC 9261)

`browntls::exported_authenticator` adds `request_authenticator`,
`authenticator` and `validate_authenticator` to `ClientConnection` and
`ServerConnection`. The messages are carried by the application protocol,
not the record layer. A client request is a `ClientCertificateRequest`
(type 17), a server request a TLS 1.3 `CertificateRequest`; the answer is
TLS 1.3 `Certificate`, `CertificateVerify` and `Finished` messages, or a lone
`Finished` over an empty certificate list to decline (also when no key can
sign with a requested scheme). A server may authenticate spontaneously with
a random 32-byte context.

- Keys: the exporter with the labels `EXPORTER-client authenticator
  handshake context` / `... finished key` (`server` for server
  authenticators), no context, the length of the connection's hash. TLS 1.3
  and TLS 1.2 with the extended master secret (the TLS 1.2 exporter refuses
  sessions without it); for TLS 1.2 the HMAC comes from a TLS 1.3 suite of
  the provider with the same hash.
- Validation: framing bounded by the handshake message limit, request type
  and context checked, `Finished` compared in constant time before any
  certificate or signature is verified, the CertificateVerify scheme must be
  one the request offered (for a spontaneous authenticator, one the client's
  verifier supports), then the chain and signature go through the configured
  `ServerCertVerifier` (with the connection's server name) or
  `ClientCertVerifier`. Entry extensions are refused.
- Local policy: contexts are 1 to 255 bytes and used once per connection
  (a reused context is `PeerMisbehaved::ReusedAuthenticatorContext`); each
  side remembers at most 256 contexts, after which requests and
  authenticators fail. A request's `signature_algorithms` is required;
  `certificate_authorities` may be set, `server_name`, `oid_filters` and
  `status_request` are not supported.
- Errors are returned to the caller; no alert is sent and the connection
  continues, since the messages are outside the TLS record layer.
- No other implementation the project tests against exposes exported
  authenticators, so the tests are browntls to browntls only.

### Cargo features (`browntls`)

| Feature | Default | Effect |
|---|---|---|
| `std` | yes | I/O helpers (`Stream`, `KeyLogFile`), default session caches, system time |
| `native` | yes | Provider backed by `browntls-crypto` |
| `rustcrypto` | no | Provider backed by RustCrypto crates (RSA verification only) |
| `tls12` | yes | TLS 1.2 support |
| `logging` | yes | `log` crate diagnostics |
| `prefer-post-quantum` | yes | X25519MLKEM768 first in the default group list |

## Primitive backends

Each primitive has a portable, constant-time implementation that is the
reference for testing, plus accelerated backends selected at run time.

| Family | x86-64 | aarch64 | riscv64 |
|---|---|---|---|
| SHA-1 (HMAC-SHA1 for TLS 1.2 `*_CBC_SHA` suites only, never signatures) | SHA-NI | FEAT_SHA1 | Zbb scalar |
| SHA-2 | SHA-NI | FEAT_SHA256, FEAT_SHA512 | Zvknha/Zvknhb, Zknh |
| SHA-3 / SHAKE | AVX2 multi-lane | NEON, FEAT_SHA3 | RVV |
| AES-GCM | AES-NI + PCLMULQDQ, VAES + VPCLMULQDQ (YMM, and ZMM with a fused CTR+GHASH loop) | FEAT_AES + FEAT_PMULL | Zvkned + Zvkg / Zvbc, Zkne + Zbc/Zbkc |
| AES decryption (CBC) | AES-NI, VAES (YMM) | FEAT_AES | Zvkned, Zknd |
| ChaCha20-Poly1305 | AVX2, AVX-512 | NEON | RVV |
| X25519 / Ed25519 | BMI2 + ADX field arithmetic | portable 64-bit | portable 64-bit |
| X448 / Ed448 | portable 64-bit | portable 64-bit | portable 64-bit |
| P-256 / P-384 / P-521 | BMI2 + ADX field arithmetic (P-256; specialised portable P-256 arithmetic elsewhere) | portable 64-bit | portable 64-bit |
| RSA | BMI2 + ADX Montgomery kernel, AVX-512 IFMA exponentiation | portable 64-bit | portable 64-bit |
| FFDHE (RFC 7919) | RSA BMI2 + ADX Montgomery kernel | portable 64-bit | portable 64-bit |
| ML-KEM | AVX2 NTT | NEON NTT | RVV NTT |

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
`browntls::crypto::native::accel`) holds a process-wide `Policy` per
algorithm family (SHA-1, SHA-256, SHA-512, Keccak, four-way Keccak, AES, GHASH,
ChaCha20, Poly1305, X25519, P-256, RSA, ML-KEM) with one level per kind:

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
when they were created or loaded. Hardware feature checks that guard `unsafe` code are
independent of the policy.

### Operating-system interface

On Linux x86-64, aarch64 and riscv64, `browntls-crypto` issues `getrandom(2)`
and `riscv_hwprobe(2)` without libc through a single naked, C-variadic
`syscall(nr, ...)` trampoline (stable since Rust 1.99). Other targets obtain
entropy from the optional `getrandom` crate feature.

## Toolchain and dependency policy

- Rust 1.99.1 is pinned in `rust-toolchain.toml` and is the MSRV
  (`rust-version`). Toolchain upgrades are explicit changes.
- `Cargo.lock` is committed and CI builds with `--locked`.
- Runtime dependencies: none for `browntls-crypto` and `browntls-pki`; `log`
  (optional) and the RustCrypto crates (only with `rustcrypto`) for
  `browntls`. Independent implementations (RustCrypto, rustls with ring,
  rcgen) are dev-dependencies used as test oracles.
- `deny.toml` defines advisory, license, ban and source policy, enforced with
  a checksum-pinned cargo-deny in CI.

## Testing strategy

| Layer | Evidence |
|---|---|
| Primitives | RFC/NIST known-answer tests, Wycheproof vectors, differential tests against RustCrypto, and every available backend compared with the portable one |
| Platforms | Native x86-64 and aarch64 on GitHub-hosted Ubuntu 26.04 runners (each with dispatch and portable-only builds; the Arm runner implements every Armv8 extension the backends use) and riscv64 on the RISE runner, plus QEMU user-mode profiles for the x86-64 SHA-NI/VAES tier and every RISC-V tier (static musl binaries, since the Ubuntu 26.04 riscv64 glibc requires RVA23) (scalar, Zk, RVV with VLEN 128/256/1024 with and without vector crypto) |
| PKI | Run-time generated certificate chains, curated public test certificates, malformed-input robustness |
| TLS | Codec round trips and rejection tests, in-memory handshakes across suites, groups, signature schemes and versions, interoperability with rustls in both directions, and with the OpenSSL 3 command-line tool over loopback TCP in both directions, with and without client authentication (`crates/browntls/tests/openssl_interop.rs`, required in the x86-64 CI jobs) |
| End-to-end | Release builds of the `browntls-e2e` client and server in containers on a Docker network against OpenSSL 3.5 (Alpine), OpenSSL 3.0 (Ubuntu 24.04), GnuTLS 3.8 and browntls itself, for x86-64-v3, aarch64, native riscv64 and riscv64 with vector crypto under QEMU: TLS 1.3 and 1.2 suites and groups including X25519MLKEM768, HelloRetryRequest, client authentication, resumption, Encrypt-then-MAC required by default (`tests/e2e/`, [Docker end-to-end tests](../tests/e2e/README.md)) |

Test certificates and keys are generated at run time; no private keys are
committed. Successful CI is evidence for the tested configurations only and
is not a security assessment.

## Status

The first implementation milestone establishes the crates, the provider mount
point, primitive backends and the TLS state machines. Measured throughput
against OpenSSL is recorded in [Performance](Performance.md). Coverage, gaps and
deferred features are listed in the [roadmap](Roadmap.md).
