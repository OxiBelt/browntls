//! In-house cryptographic primitives for browntls.
//!
//! Every algorithm has a portable, constant-time implementation written in
//! safe Rust. Where the target supports it, accelerated backends using SIMD and
//! dedicated instructions (AES-NI, PCLMULQDQ, SHA extensions, AVX2, ARMv8
//! Cryptography Extensions, NEON) are selected at runtime through [`cpu`].
//!
//! # `unsafe` policy
//!
//! `unsafe` is denied crate-wide. The only exceptions are modules named
//! `x86_64` or `aarch64` that wrap `core::arch` intrinsics; each `unsafe` block
//! carries a `SAFETY:` comment and is reachable only after [`cpu`] has
//! confirmed the required CPU features.
//!
//! # Side channels
//!
//! Code operating on secret data must not branch on, or index memory with,
//! secret values. Helpers for this live in [`ct`].
#![no_std]
#![allow(clippy::indexing_slicing)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod cpu;
pub mod ct;
pub mod rand;

pub mod aead;

pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod sha3;

pub mod aes;
pub mod aes_gcm;
pub mod ghash;

pub mod chacha20;
pub mod chacha20poly1305;
pub mod poly1305;

pub mod curve25519;

pub mod nist;

pub mod bignum;
pub mod rsa;

pub mod mlkem;
