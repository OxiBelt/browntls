//! NIST P-256, P-384 and P-521 key generation (`browntls-crypto`).
//!
//! Scalars are drawn uniformly from `[1, n - 1]` by rejection sampling, so
//! every bit below the order's bit length is free: the order is within
//! 2^-32 of a power of two for each curve. Public coordinates are reduced
//! modulo a prime just as close to a power of two.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::nist::{p256, p384, p521};
use browntls_crypto::rand::OsRng;
use browntls_entropy::{Stream, check, err, sample_count};

macro_rules! curve_test {
    ($test:ident, $title:literal, $curve:ident, $divisor:expr, $top:expr) => {
        #[test]
        fn $test() {
            const F: usize = $curve::FIELD_LEN;
            check(
                concat!($title, " key generation"),
                sample_count($divisor, 1 << 12),
                &[
                    Stream::new(concat!($title, " private scalar"), F).only(0, $top),
                    Stream::new(concat!($title, " public x || y"), 2 * F)
                        .only(0, $top)
                        .only(F, $top),
                ],
                |out| {
                    let sk = $curve::SecretKey::generate(&OsRng).map_err(err)?;
                    out[0].copy_from_slice(&sk.to_bytes()[..]);
                    // Uncompressed SEC1: 0x04 || x || y.
                    out[1].copy_from_slice(&sk.public_key().to_uncompressed()[1..]);
                    Ok(())
                },
            );
        }
    };
}

curve_test!(p256_keys, "P-256", p256, 1, 0xff);
curve_test!(p384_keys, "P-384", p384, 2, 0xff);
// 521 bits in 66 bytes: only the low bit of the first byte is used.
curve_test!(p521_keys, "P-521", p521, 4, 0x01);
