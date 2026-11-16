//! FFDHE (RFC 7919) exponent generation (`browntls-crypto`).
//!
//! The exponent cannot be exported, so its entropy is examined through the
//! public value `g^x mod p`: a low-entropy exponent repeats public values.
//! `p` is within 2^-64 of a power of two, so every bit of the public value
//! is free. One modular exponentiation per sample makes this topic costly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::ffdhe::{Group, PrivateKey};
use browntls_crypto::rand::OsRng;
use browntls_entropy::{Stream, check, err, sample_count};

fn ffdhe(title: &str, group: Group, divisor: usize) {
    check(
        title,
        sample_count(divisor, 1 << 10),
        &[Stream::new(
            format!("{title} public value"),
            group.element_len(),
        )],
        |out| {
            let sk = PrivateKey::generate(group, &OsRng).map_err(err)?;
            sk.public_key(out[0]).map_err(err)
        },
    );
}

#[test]
fn ffdhe2048() {
    ffdhe("ffdhe2048", Group::Ffdhe2048, 4);
}

#[test]
fn ffdhe3072() {
    ffdhe("ffdhe3072", Group::Ffdhe3072, 16);
}
