//! Operating-system entropy as every browntls layer obtains it.
//!
//! `browntls-crypto` issues `getrandom(2)` itself on Linux x86-64, aarch64
//! and riscv64 (one inline-assembly system call per architecture), so this
//! topic also runs natively on each of them in CI.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::rand::{OsRng, SecureRandom as _};
use browntls_entropy::{Stream, check, err, sample_count};

#[test]
fn os_rng_fills() {
    check(
        "browntls-crypto OsRng",
        sample_count(1, 1 << 12),
        &[
            Stream::new("OsRng 32-byte fill", 32),
            Stream::new("OsRng 32 one-byte fills", 32),
            Stream::new("OsRng 57-byte fill (odd length)", 57),
        ],
        |out| {
            OsRng.fill(out[0]).map_err(err)?;
            for b in out[1].chunks_mut(1) {
                OsRng.fill(b).map_err(err)?;
            }
            OsRng.fill(out[2]).map_err(err)
        },
    );
}

#[test]
fn os_rng_large_fills() {
    // Both ends of a 64 KiB fill: a short read that is not retried, or a
    // loop that stops early, leaves the tail unfilled.
    const LEN: usize = 64 * 1024;
    check(
        "browntls-crypto OsRng, 64 KiB fills",
        sample_count(64, 1 << 11),
        &[Stream::new(
            "OsRng 64 KiB fill: first and last 16 bytes",
            32,
        )],
        |out| {
            let mut buf = vec![0u8; LEN];
            OsRng.fill(&mut buf).map_err(err)?;
            out[0][..16].copy_from_slice(&buf[..16]);
            out[0][16..].copy_from_slice(&buf[LEN - 16..]);
            Ok(())
        },
    );
}

#[test]
fn provider_secure_random() {
    let native = browntls::crypto::native::default_provider().secure_random;
    let rustcrypto = browntls::crypto::rustcrypto::default_provider().secure_random;
    check(
        "CryptoProvider::secure_random",
        sample_count(1, 1 << 12),
        &[
            Stream::new("native provider secure_random", 32),
            Stream::new("RustCrypto provider secure_random", 32),
        ],
        |out| {
            native.fill(out[0]).map_err(err)?;
            rustcrypto.fill(out[1]).map_err(err)
        },
    );
}
