//! Curve448: X448 key agreement (RFC 7748) and Ed448 signatures
//! (RFC 8032 §5.2).
//!
//! Layout:
//!
//! * `field` — GF(2^448 - 2^224 - 1), portable eight 56-bit limbs with
//!   64x64->128-bit products (constant time; limb bounds documented there).
//! * `scalar` — arithmetic modulo the group order `L` (Montgomery form,
//!   `R = 2^448`).
//! * `edwards` — the edwards448 group in projective coordinates with the
//!   complete formulas of RFC 8032 §5.2.4: constant-time fixed-window scalar
//!   multiplication and variable-time double-scalar multiplication for
//!   verification.
//! * [`x448`] and [`ed448`] — the public APIs.
//!
//! There is one portable implementation and no architecture backend; X448
//! and Ed448 are optional, non-preferred algorithms in browntls.

mod edwards;
mod field;
mod scalar;

pub mod ed448;
pub mod x448;
