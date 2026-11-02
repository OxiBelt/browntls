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
their own implementation of any trait.

## Primitive backends

Each primitive has a portable, constant-time implementation that is the
reference for testing, plus accelerated backends selected at run time.

| Family | x86-64 | aarch64 | riscv64 |
|---|---|---|---|
| SHA-2 | SHA-NI | FEAT_SHA256, FEAT_SHA512 | Zvknha/Zvknhb, Zknh |
| SHA-3 / SHAKE | AVX2 multi-lane | NEON, FEAT_SHA3 | RVV |
| AES-GCM | AES-NI + PCLMULQDQ, VAES + VPCLMULQDQ | FEAT_AES + FEAT_PMULL | Zvkned + Zvkg / Zvbc, Zkne + Zbkc |
| ChaCha20-Poly1305 | AVX2, AVX-512 | NEON | RVV |
| X25519 / Ed25519 | BMI2 + ADX field arithmetic | portable 64-bit | portable 64-bit |
| P-256 / P-384 / P-521 | BMI2 + ADX field arithmetic | portable 64-bit | portable 64-bit |
| RSA | BMI2 + ADX Montgomery kernel | portable 64-bit | portable 64-bit |
| ML-KEM | AVX2 NTT | NEON NTT | RVV NTT |

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
| Platforms | Native x86-64, aarch64 (GitHub Arm runner) and riscv64 (RISE runner), plus QEMU user-mode profiles for each backend tier (x86-64 SHA-NI/VAES, Armv8 crypto, RVV with VLEN 128/256/1024 and vector crypto, scalar Zk) |
| PKI | Run-time generated certificate chains, curated public test certificates, malformed-input robustness |
| TLS | Codec round trips and rejection tests, in-memory handshakes across suites, groups, signature schemes and versions, and interoperability with rustls in both directions |

Test certificates and keys are generated at run time; no private keys are
committed. Successful CI is evidence for the tested configurations only and
is not a security assessment.

## Status

The first implementation milestone establishes the crates, the provider mount
point, primitive backends and the TLS state machines. Coverage, gaps and
deferred features are listed in the [roadmap](Roadmap.md).
