//! Cryptographic primitives for browntls.
//!
//! Every algorithm has a portable, constant-time Rust implementation and, where
//! profitable, SIMD and hardware-accelerated backends selected at run time
//! through [`cpu::features`]:
//!
//! | Family | x86-64 (baseline x86-64-v3) | aarch64 | riscv64 |
//! |---|---|---|---|
//! | SHA-2 | SHA-NI, AVX2+BMI2 | SHA2, SHA512 | Zvknha/Zvknhb, Zknh |
//! | SHA-3 / SHAKE | BMI; AVX2, AVX-512VL 4-way | SHA3 (EOR3/RAX1/XAR/BCAX), NEON 4-way | Zbb; RVV 4-way |
//! | AES / GHASH | AES-NI+PCLMULQDQ, VAES | AES+PMULL | Zvkned+Zvkg/Zvbc, Zkne+Zbc/Zbkc |
//! | ChaCha20 / Poly1305 | AVX2, AVX-512 | NEON | RVV |
//! | X25519 / Ed25519 | 64-bit, BMI2/ADX | 64-bit | 64-bit |
//! | P-256 / P-384 / P-521 | 64-bit Montgomery, BMI2/ADX (P-256) | 64-bit Montgomery | 64-bit Montgomery |
//! | RSA | 64-bit Montgomery, BMI2/ADX | 64-bit Montgomery | 64-bit Montgomery |
//! | ML-KEM | AVX2 NTT | NEON NTT | RVV NTT |
//!
//! The crate is `no_std` and allocation-free by default; `std` adds runtime
//! feature detection on aarch64. Unsafe code is denied crate-wide and allowed
//! only in architecture backend modules, CPU detection and the system-call
//! trampoline, each with documented safety invariants.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

pub mod accel;
pub mod cpu;
pub mod ct;
mod error;
pub mod rand;
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
mod sys;
pub mod zeroize;

pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod tls12_prf;

pub mod der;

pub mod aead;
pub mod aes;
pub mod chacha;
pub mod gcm;

pub mod curve25519;
pub mod mlkem;
pub mod nist;
pub mod rsa;

pub use error::Error;
