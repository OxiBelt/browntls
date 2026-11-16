//! X25519 and Ed25519 key generation (`browntls-crypto`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::curve25519::{ed25519, x25519};
use browntls_crypto::rand::OsRng;
use browntls_entropy::{Stream, check, err, sample_count};

#[test]
fn x25519_keys() {
    check(
        "X25519 key generation",
        sample_count(1, 1 << 12),
        &[
            // Stored unclamped (RFC 7748 clamps on use): all 256 bits free.
            Stream::new("X25519 private key", 32),
            // A u-coordinate below 2^255 - 19: the top bit is always 0.
            Stream::new("X25519 public key", 32).fixed(31, 0x80),
        ],
        |out| {
            let sk = x25519::PrivateKey::generate(&OsRng).map_err(err)?;
            out[0].copy_from_slice(sk.as_bytes());
            out[1].copy_from_slice(&sk.public_key());
            Ok(())
        },
    );
}

#[test]
fn ed25519_keys() {
    check(
        "Ed25519 key generation",
        sample_count(1, 1 << 12),
        &[
            Stream::new("Ed25519 seed", 32),
            // y (255 bits) and the sign of x: all bits free.
            Stream::new("Ed25519 public key", 32),
        ],
        |out| {
            let sk = ed25519::SigningKey::generate(&OsRng).map_err(err)?;
            out[0].copy_from_slice(sk.seed());
            out[1].copy_from_slice(sk.verifying_key().as_bytes());
            Ok(())
        },
    );
}
