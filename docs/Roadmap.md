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
| AES-GCM (portable, AES-NI/VAES, Armv8, Zvkned/Zvkg) | done | Bitsliced portable AES and constant-time GHASH; AES-NI+PCLMULQDQ, VAES (YMM), FEAT_AES+PMULL, Zvkned+Zvkg/Zvbc, Zkne+Zbc. No VPCLMULQDQ or AVX-512 (not executable here); CTR and GHASH are separate passes |
| ChaCha20-Poly1305 (portable, AVX2/AVX-512, NEON, RVV) | done | Poly1305 scalar, BMI2 and four-way AVX2 |
| X25519 / Ed25519 | done | BMI2/ADX ladder on x86-64; small-order Ed25519 public keys rejected |
| P-256 / P-384 / P-521 ECDH and ECDSA | done | RCB complete formulas, RFC 6979 with hedging, BMI2/ADX P-256 kernel; generic CIOS reduction and Fermat inversion (performance headroom) |
| RSA PKCS #1 v1.5 / PSS | done | 2048-8192-bit verification, CRT signing with blinding and fault check, key generation; BMI2/ADX Montgomery step; no AVX-512 IFMA; signing stack about 24 KiB |
| ML-KEM-512/768/1024 | done | AVX2, NEON and RVV arithmetic; four-way SHAKE sampling |
| PKI types and PEM | done | |
| X.509 path validation, name checks, CRLs | done | DFS path building with webpki-style budgets, RFC 6125 names, DNS/IP name constraints, v2 CRLs; directoryName/URI constraints fail closed; deviations from webpki documented in the crate |
| TLS record layer and handshake (1.2, 1.3) | in progress | |
| Crypto provider mount point, RustCrypto provider | in progress | |
| Native provider (`browntls-crypto`) | planned | After primitives land |

## Later milestones

| Area | Status |
|---|---|
| 0-RTT, hybrid post-quantum groups, kTLS secret export | planned |
| Raw public keys, certificate compression, OCSP/SCT passthrough | planned |
| Unbuffered API, QUIC, Encrypted Client Hello | planned |
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
  (for example x86 SHA512 and AVX-512 VAES) remain unimplemented until they can
  be executed in tests.
