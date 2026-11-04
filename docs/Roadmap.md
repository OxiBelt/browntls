# Roadmap

Implementation status of browntls against its target of rustls 0.23-level
features. See [Architecture](Architecture.md) for the design. Status values:
**done** (implemented and tested in CI configurations), **in progress**, and
**planned**. This file is updated with each milestone; it reports evidence, not
intent.

## Milestone 1: foundations

| Area | Status | Notes |
|---|---|---|
| Workspace, toolchain pin (1.99.1), lockfile, CI matrix | done | Native x86-64, aarch64 and riscv64 jobs plus QEMU profiles |
| CPU feature detection (x86-64, aarch64, riscv64) | done | `riscv_hwprobe` via the libc-free system-call trampoline |
| OS entropy without libc (Linux) | done | `getrandom(2)` |
| Portable SHA-2, SHA-3/SHAKE, HMAC, HKDF, TLS 1.2 PRF | done | Known-answer tests |
| Accelerated SHA-2 / Keccak backends | done | SHA-NI, x86-64-v3, FEAT_SHA256/512, Zvknha/b, Zknh; four-way Keccak (AVX2, AVX-512VL, NEON/SHA3, RVV). No x86 SHA512 extension |
| AES-GCM (portable, AES-NI/VAES, Armv8, Zvkned/Zvkg) | done | Bitsliced portable AES and constant-time GHASH; AES-NI+PCLMULQDQ, VAES (YMM) with VPCLMULQDQ (YMM) GHASH, AVX-512 VAES+VPCLMULQDQ with a fused CTR+GHASH loop, FEAT_AES+PMULL, Zvkned+Zvkg/Zvbc, Zkne+Zbc. The ZMM and VPCLMULQDQ backends are tested only on native hardware (QEMU 8.2 cannot execute them); elsewhere CTR and GHASH are separate passes |
| ChaCha20-Poly1305 (portable, AVX2/AVX-512, NEON, RVV) | done | Poly1305 scalar, BMI2 and four-way AVX2 |
| X25519 / Ed25519 | done | BMI2/ADX ladder on x86-64; small-order Ed25519 public keys rejected |
| X448 / Ed448 (optional, non-preferred) | done | Portable 8x56-bit field; X448 group in TLS 1.3 and TLS 1.2 ECDHE, Ed448 certificates and handshake signatures; cofactored Ed448 verification, small-order Ed448 public keys rejected; OpenSSL 3 interop suite (TLS 1.3 and 1.2) |
| P-256 / P-384 / P-521 ECDH and ECDSA | done | RCB complete formulas for secret-scalar additions, Jacobian doubling in the ladder and variable-time Jacobian verification, RFC 6979 with hedging; P-256: specialised BMI2/ADX and portable field arithmetic, safegcd inversion, width-6 fixed-base comb; P-384/P-521: generic CIOS reduction and Fermat inversion (performance headroom) |
| RSA PKCS #1 v1.5 / PSS | done | 2048-8192-bit verification, CRT signing with blinding and fault check, key generation; safegcd unblinding; fused BMI2/ADX and portable Montgomery kernels; AVX-512 IFMA CRT and public-exponent exponentiation; signing stack 24-52 KiB by key size (IFMA); RSASSA-PSS (`id-RSASSA-PSS`) keys without parameters or restricted to SHA-256/384/512, signing and verifying only `rsa_pss_pss_*` (TLS 1.3 and 1.2), in the OpenSSL 3 interop suite |
| ML-KEM-512/768/1024 | done | AVX2, NEON and RVV arithmetic; four-way SHAKE sampling |
| FFDHE (RFC 7919 groups, TLS 1.3 only) | done | ffdhe2048-8192 with RFC 7919 short exponents over the RSA constant-time Montgomery exponentiation; non-preferred groups of the native provider, ffdhe2048-4096 in the defaults and ffdhe6144/8192 opt-in (server cost); OpenSSL 3 interop suite |
| PKI types and PEM | done | |
| X.509 path validation, name checks, CRLs | done | DFS path building with webpki-style budgets, RFC 6125 names, DNS/IP name constraints, v2 CRLs; directoryName/URI constraints fail closed; deviations from webpki documented in the crate |
| TLS record layer and handshake (1.2, 1.3) | done | TLS 1.3 (HRR, PSK resumption, client auth, KeyUpdate, downgrade sentinels) and TLS 1.2 (ECDHE suites, EMS, session ID and ticket resumption, client auth, renegotiation refused); interoperability tested against rustls 0.23 in both directions |
| Crypto provider mount point, RustCrypto provider | done | rustls 0.23-shaped traits; RustCrypto provider verifies RSA but does not sign with it (advisory) |
| Native provider (`browntls-crypto`) | done | All suites, X25519/NIST/ML-KEM and hybrid groups, ECDSA/Ed25519/RSA signing and verification, AEAD tickets; the RFC 9846 optional algorithms (AES-CCM, X448, FFDHE, Ed448, `rsa_pss_pss_*`) as a non-preferred tier (see [Architecture](Architecture.md#algorithm-tiers-native-provider)); byte-identical records to the RustCrypto provider. All handshake, API and rustls interop suites run on both providers; native adds RSA, ML-KEM-1024 and mixed-provider handshakes |

## Later milestones

| Area | Status |
|---|---|
| 0-RTT early data (stateful resumption), hybrid post-quantum groups, kTLS secret export | done |
| RFC 9846 optional AES-CCM suites (non-preferred tier): `TLS_AES_128_CCM_SHA256` in the defaults after every AES-GCM and ChaCha20-Poly1305 suite, `TLS_AES_128_CCM_8_SHA256` opt-in only; RFC 9147 Appendix B limits, kTLS export for CCM only | done |
| Raw public keys (RFC 7250), certificate compression framework (RFC 8879), OCSP/SCT passthrough, `max_fragment_size`, `Acceptor` | done |
| Built-in certificate compressors (zlib, brotli, zstd) | planned |
| Unbuffered API, QUIC, Encrypted Client Hello | planned |
| Fuzzing targets for codecs, PKI and handshake state | planned |
| Kernel integration design | planned |

## Governance gaps

These requirements from [Maintenance](Maintenance.md) are not yet met:

- `cargo vet` admission with real audits for every dependency.
- Fuzzing of DER, PEM, X.509 and TLS message parsers and of protocol state.
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
- RSASSA-PSS key and signature `AlgorithmIdentifier`s are matched byte for
  byte, so hash identifiers with absent instead of NULL parameters (which
  RFC 4055 §2.1 says verifiers must accept), key salt lengths shorter than
  the digest and explicit default trailer fields are rejected.
- The AES-NI and VAES backends leave a copy of round key 0 (the AES key
  itself) in dead stack memory after each call; the portable backend and the
  CCM, X448, Ed448 and FFDHE code wipe their secret intermediates.
- A TLS 1.2 server does not take the client's supported groups into account
  when it chooses an ECDSA certificate (RFC 8422 §5.1.1); OpenSSL clients
  then abort with an illegal-parameter alert.
