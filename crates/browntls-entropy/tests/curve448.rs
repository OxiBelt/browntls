//! X448 and Ed448 key generation (`browntls-crypto`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::curve448::{ed448, x448};
use browntls_crypto::rand::OsRng;
use browntls_entropy::{Stream, check, err, sample_count};

#[test]
fn x448_keys() {
    check(
        "X448 key generation",
        sample_count(2, 1 << 12),
        &[
            // Stored unclamped (RFC 7748 clamps on use).
            Stream::new("X448 private key", 56),
            Stream::new("X448 public key", 56),
        ],
        |out| {
            let sk = x448::PrivateKey::generate(&OsRng).map_err(err)?;
            out[0].copy_from_slice(sk.as_bytes());
            out[1].copy_from_slice(&sk.public_key());
            Ok(())
        },
    );
}

#[test]
fn ed448_keys() {
    check(
        "Ed448 key generation",
        sample_count(2, 1 << 12),
        &[
            Stream::new("Ed448 seed", 57),
            // RFC 8032 §5.2.2: y in 56 bytes, then a byte holding only the
            // sign of x in its top bit.
            Stream::new("Ed448 public key", 57).only(56, 0x80),
        ],
        |out| {
            let sk = ed448::SigningKey::generate(&OsRng).map_err(err)?;
            out[0].copy_from_slice(sk.seed());
            out[1].copy_from_slice(sk.verifying_key().as_bytes());
            Ok(())
        },
    );
}
