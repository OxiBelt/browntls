# Architecture

This document records the intended design of browntls. It is a design target,
not a description of shipped behavior: the [roadmap](Roadmap.md) states which
parts exist and which conformance claims are currently backed by tests.

## Goals

- A TLS 1.2 and TLS 1.3 client and server library whose feature level and
  specification conformance match the scope of mature Rust TLS libraries such
  as rustls. rustls is a reference for *scope*, not a code source: browntls is
  written independently from the RFCs.
- Memory-safe first-party code: `#![forbid(unsafe_code)]` in every crate except
  narrowly scoped, separately reviewed kernel/FFI crates.
- Sans-I/O protocol core usable without `std` (with `alloc`), so the same state
  machine can drive sockets, async runtimes, QUIC, and kernel TLS offload.
- Pluggable cryptography. The protocol crate contains no cryptographic primitive
  implementations; it consumes a `CryptoProvider`. The default provider is built
  on browntls's own primitives (`browntls-crypto`), with portable constant-time
  code plus SIMD and hardware-accelerated backends. A RustCrypto-based provider
  remains selectable through Cargo features as a fallback.
- Secure defaults that cannot be weakened silently. Every relaxation is an
  explicit, named configuration call and is documented.

## Non-goals

These are excluded deliberately and will not be added:

- SSL 2/3, TLS 1.0, TLS 1.1, and automatic version fallback.
- Static RSA and static (EC)DH key exchange; any suite without forward secrecy.
- CBC, MAC-then-encrypt, RC4, 3DES, EXPORT, NULL, and anonymous suites.
- TLS 1.2 renegotiation (secure renegotiation is signalled only so that it can be
  refused) and TLS-level compression.
- TLS 1.3 post-handshake client authentication, DTLS, and arbitrary
  application-defined extensions.

## Crate layout

| Crate | Purpose | `unsafe` |
| --- | --- | --- |
| `browntls` | Protocol core: codecs, record layer, key schedules, handshake state machines, configuration, connection API. | forbidden |
| `browntls-crypto` | In-house primitives: SHA-2, HMAC, HKDF, AES, GHASH, AES-GCM, ChaCha20, Poly1305, X25519, Ed25519, P-256, P-384, ECDSA, RSA, ML-KEM. Portable constant-time code plus x86_64 (AES-NI, PCLMULQDQ, SHA-NI, AVX2) and AArch64 (AES, PMULL, SHA2, NEON) backends selected at runtime. | denied; allowed only in `x86_64`/`aarch64` intrinsic modules |
| `browntls-rustcrypto` (planned) | Alternative provider on RustCrypto crates, selected by Cargo feature; also used for differential testing. | forbidden |
| `browntls-pki` (planned) | X.509 parsing, path building, and Web PKI server/client certificate verification. | forbidden |
| `browntls-ktls` (planned) | Linux kernel TLS offload using secrets exported by the core. | narrow, reviewed exception |

Crates are added only when they contain working code.

## Layering

```text
 application bytes                         network bytes
        |                                         ^
        v                                         |
 +--------------------- Connection ----------------------+
 |  plaintext buffers   <->   record layer   <->  tls buffers
 |                               ^   |                   |
 |                               |   v                   |
 |              handshake joiner / message decoder       |
 |                               |                       |
 |                    state machine (client | server)   |
 |                               |                       |
 |      key schedule  -  transcript hash  -  verifiers   |
 +--------------------------- | -------------------------+
                              v
                       CryptoProvider
```

### Codec (`codec`)

A bounds-checked `Reader` over a byte slice and append-only encoding helpers.
All TLS vectors are length-prefixed by u8, u16, or u24; decoding a vector yields
a sub-reader that must be consumed exactly. Every decode returns
`Result<_, InvalidMessage>`; malformed input never panics. Encoders reserve the
length prefix and back-patch it so that nested structures are encoded once.

### Protocol registries (`enums`)

IANA registries (content types, handshake types, versions, cipher suites, named
groups, signature schemes, extension types, alerts, and so on) are represented
as open newtypes over the wire integer with named constants. Unknown values are
preserved so that unknown extensions and suites can be ignored as required by
the RFCs, and GREASE values (RFC 8701) pass through without special cases.

### Messages (`msgs`)

Typed representations of every handshake message and extension browntls
negotiates. Parsing is strict: duplicated extensions, trailing bytes, empty
vectors where the RFC requires content, and extensions illegal in a given
message are rejected with the alert the RFC prescribes. Unknown extensions are
retained as opaque bytes only where the RFC allows them.

### Record layer (`record`)

- Deframing of TLS records from an input buffer, with the RFC limits enforced:
  2^14 plaintext, 2^14 + 256 ciphertext for TLS 1.3, 2^14 + 2048 for TLS 1.2.
- Record protection through provider-supplied `MessageEncrypter` and
  `MessageDecrypter` objects. Nonce construction follows RFC 8446 §5.3 for
  TLS 1.3 and RFC 5288 / RFC 7905 for TLS 1.2.
- Sequence number tracking with mandatory key update (TLS 1.3) or connection
  close (TLS 1.2) before exhaustion, and per-suite confidentiality limits.
- Fragmentation of outgoing messages to a configurable maximum fragment size.
- Joining of handshake messages fragmented across records, with a configurable
  maximum handshake message size; interleaving handshake and other content
  types inside a fragmented message is rejected.

### Key schedules (`tls13`, `tls12`)

- TLS 1.3: HKDF-Extract/Expand-Label key schedule (RFC 8446 §7), secret
  derivation for early, handshake, application, exporter and resumption secrets,
  traffic key update, and Finished computation. Verified against RFC 8448 traces.
- TLS 1.2: the RFC 5246 PRF with extended master secret (RFC 7627) and
  RFC 5705 exporters.
- Secrets are wrapped in types that zeroize on drop and redact `Debug`.

### Handshake state machines (`client`, `server`)

Each side is an `enum` of states with one variant per point at which the
handshake waits for a peer message. A state consumes `self` and the next message
and returns the following state, so impossible transitions are type errors
rather than runtime flags. Shared logic (alerts, key updates, closing) lives in a
common layer. TLS 1.2 and TLS 1.3 flows are separate modules that share
negotiation helpers.

### Connection API

- `ClientConnection` / `ServerConnection` over a shared `ConnectionCore`:
  `read_tls`, `process_new_packets`, `write_tls`, `reader`, `writer`,
  `send_close_notify`, handshake status, negotiated parameters, exporters.
- A `std` feature adds `Stream`/`StreamOwned` adaptors over `Read + Write`.
- A lower-level unbuffered API for embedded, QUIC, and kernel offload callers.
- Buffer growth is bounded by configuration; a peer cannot make browntls buffer
  unbounded plaintext or handshake data.

### Cryptography provider (`crypto`)

`CryptoProvider` bundles:

- cipher suites (each referring to its hash, HKDF/PRF, and AEAD),
- key exchange groups (`SupportedKxGroup` -> `ActiveKeyExchange`), including
  KEM-style hybrids such as X25519MLKEM768,
- signature verification algorithms keyed by `SignatureScheme`,
- a private key loader producing `SigningKey` objects,
- a secure random source and a time source.

The core only orders and selects what the provider offers. FIPS-style policy
restrictions are expressed by the provider, not hard-coded in the core.

Providers expose raw primitives (hash, HMAC, AEAD seal/open with an explicit
nonce, key exchange, signatures, randomness). Nonce construction, additional
data, HKDF labels, and the TLS 1.2 PRF are implemented once in the core so that
each provider does not re-implement protocol logic.

### In-house primitives (`browntls-crypto`)

- Every algorithm has a portable implementation in safe Rust with no
  secret-dependent branches or table lookups (bitsliced AES, constant-time
  GHASH multiplication, fixed-window scalar multiplication with constant-time
  table selection, constant-time Montgomery exponentiation for RSA).
- Accelerated backends live in `x86_64`/`aarch64` submodules and are selected
  at object construction from runtime CPU detection. Each backend is tested
  against the portable path and against reference implementations.
- `unsafe` is confined to those intrinsic modules, requires a `SAFETY:` comment
  per block, and is reachable only after feature detection succeeds.
- Randomness comes directly from the operating system CSPRNG.
- Known-answer tests use RFC, NIST CAVP, and Wycheproof vectors; differential
  tests compare against RustCrypto crates (development dependencies only).

### Certificate verification (`verify`)

`ServerCertVerifier` and `ClientCertVerifier` traits separate path validation
from handshake signature verification. The default verifiers live in
`browntls-pki`. Disabling verification requires an API whose name contains
`dangerous`, gated behind a crate feature.

## Security invariants

1. No peer input can cause a panic, unbounded allocation, or unbounded CPU work.
2. Every protocol error becomes a typed `Error` and, where applicable, the fatal
   alert the RFC mandates; the connection then refuses further use.
3. Handshake messages are processed only in the states that allow them; a
   message received at a key change boundary that is not record-aligned is a
   fatal error (RFC 8446 §5.1).
4. Downgrade protection (RFC 8446 §4.1.3) is enforced by TLS 1.3-capable
   clients, and TLS 1.2 requires secure-renegotiation signalling.
5. Secrets never appear in `Debug` output, errors, or logs; key logging is an
   explicit opt-in.
6. Timing-sensitive comparisons (Finished, PSK binders, tickets) use
   constant-time equality supplied by the crypto layer.

## Validation strategy

- Unit tests per module, including RFC 8448 and RFC 5869 test vectors.
- Loopback client/server tests across every suite, group, version and feature.
- Interoperability tests against OpenSSL `s_client`/`s_server` in CI.
- BoringSSL's BoGo conformance runner through a shim binary.
- `cargo-fuzz` targets for the deframer, message decoders, and both state
  machines before any of them is declared supported.
- Clippy, rustfmt, rustdoc, MSRV, `cargo deny`, `cargo audit`, and `cargo vet`
  gates as required by [maintenance](Maintenance.md).
