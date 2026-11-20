//! HPKE key generation and sender setup (RFC 9180) through the native
//! provider's `Hpke` suites, as Encrypted Client Hello uses them.
//!
//! Per KEM, three streams:
//!
//! * the serialized private key of `generate_key_pair` (X25519 and X448
//!   keys are serialized clamped, so the clamped bits are excluded);
//! * `enc`, the sender's ephemeral public key from `setup_sealer`;
//! * one sealed all-zero block (ciphertext and tag), which is uniform only
//!   if the key schedule received a high-entropy shared secret.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_core::crypto::hpke::{Hpke, HpkeKem};
use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use browntls_entropy::{Stream, check, err, sample_count};

/// The first native suite using `kem`.
fn suite(kem: u16) -> &'static dyn Hpke {
    *ALL_SUPPORTED_SUITES
        .iter()
        .find(|s| s.suite().kem == HpkeKem(kem))
        .expect("suite for KEM")
}

/// A NIST public key `0x04 || x || y` with `top` free bits in the first
/// byte of each coordinate.
fn nist_point(name: &str, field: usize, top: u8) -> Stream {
    Stream::new(name, 1 + 2 * field)
        .only(0, 0)
        .only(1, top)
        .only(1 + field, top)
}

fn hpke(title: &str, kem: u16, private: Stream, enc: Stream, divisor: usize) {
    let suite = suite(kem);
    let sealed = Stream::new(format!("{title} sealed zero block"), 32);
    check(
        title,
        sample_count(divisor, 1 << 12),
        &[private, enc, sealed],
        |out| {
            let (pk, sk) = suite.generate_key_pair().map_err(err)?;
            out[0].copy_from_slice(sk.secret_bytes());
            let (enc, mut sealer) = suite.setup_sealer(b"browntls entropy", &pk).map_err(err)?;
            out[1].copy_from_slice(&enc.0);
            let ct = sealer.seal(b"", &[0u8; 16]).map_err(err)?;
            out[2].copy_from_slice(&ct);
            Ok(())
        },
    );
}

#[test]
fn dhkem_x25519() {
    hpke(
        "HPKE DHKEM(X25519)",
        0x0020,
        // RFC 7748 clamping: the low 3 bits and the top 2 bits are fixed.
        Stream::new("HPKE X25519 private key", 32)
            .fixed(0, 0x07)
            .fixed(31, 0xc0),
        Stream::new("HPKE X25519 enc", 32).fixed(31, 0x80),
        1,
    );
}

#[test]
fn dhkem_x448() {
    hpke(
        "HPKE DHKEM(X448)",
        0x0021,
        // RFC 7748 clamping: the low 2 bits and the top bit are fixed.
        Stream::new("HPKE X448 private key", 56)
            .fixed(0, 0x03)
            .fixed(55, 0x80),
        Stream::new("HPKE X448 enc", 56),
        4,
    );
}

#[test]
fn dhkem_p256() {
    hpke(
        "HPKE DHKEM(P-256)",
        0x0010,
        Stream::new("HPKE P-256 private key", 32),
        nist_point("HPKE P-256 enc", 32, 0xff),
        1,
    );
}

#[test]
fn dhkem_p384() {
    hpke(
        "HPKE DHKEM(P-384)",
        0x0011,
        Stream::new("HPKE P-384 private key", 48),
        nist_point("HPKE P-384 enc", 48, 0xff),
        4,
    );
}

#[test]
fn dhkem_p521() {
    hpke(
        "HPKE DHKEM(P-521)",
        0x0012,
        Stream::new("HPKE P-521 private key", 66).only(0, 0x01),
        nist_point("HPKE P-521 enc", 66, 0x01),
        8,
    );
}
