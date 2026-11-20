//! Starting inputs for each target, generated rather than committed: they
//! contain certificates and handshake flights made at run time.
//!
//! `cargo test` runs every harness over its seeds on the stable toolchain;
//! `cargo run --example seed_corpus` writes them to `corpus/<target>/` for
//! `cargo fuzz`.

use std::sync::Arc;

use browntls_core::compress::{CertCompressor, CompressionLevel};
use browntls_core::pki_types::ServerName;
use browntls_core::{ClientConfig, ClientConnection, RootCertStore};

use crate::connection::Identity;

/// A target name, its harness and its seeds.
pub type Target = (&'static str, fn(&[u8]), fn() -> Vec<Vec<u8>>);

/// Every fuzz target.
pub const TARGETS: &[Target] = &[
    (
        "handshake_message",
        crate::handshake_message,
        handshake_message,
    ),
    ("deframer", crate::deframer, deframer),
    ("client", crate::client, connection),
    ("server", crate::server, connection),
    ("pki_cert", crate::pki_cert, pki_cert),
    ("pki_pem", crate::pki_pem, pki_pem),
    ("pki_crl", crate::pki_crl, pki_crl),
    ("cert_decompress", crate::cert_decompress, cert_decompress),
    (
        "crypto_hash",
        crate::crypto_hash::run,
        crate::crypto_hash::seeds,
    ),
    (
        "crypto_cipher",
        crate::crypto_cipher::run,
        crate::crypto_cipher::seeds,
    ),
    (
        "crypto_ecc",
        crate::crypto_ecc::run,
        crate::crypto_ecc::seeds,
    ),
    (
        "crypto_rsa",
        crate::crypto_rsa::run,
        crate::crypto_rsa::seeds,
    ),
    (
        "crypto_kem",
        crate::crypto_kem::run,
        crate::crypto_kem::seeds,
    ),
    (
        "crypto_hpke",
        crate::crypto_hpke::run,
        crate::crypto_hpke::seeds,
    ),
    (
        "crypto_util",
        crate::crypto_util::run,
        crate::crypto_util::seeds,
    ),
    ("pki_api", crate::pki_api::run, crate::pki_api::seeds),
    (
        "pki_revocation",
        crate::pki_revocation::run,
        crate::pki_revocation::seeds,
    ),
    (
        "tls_config",
        crate::tls_config::run,
        crate::tls_config::seeds,
    ),
    ("tls_conn", crate::tls_conn::run, crate::tls_conn::seeds),
    (
        "tls_unbuffered",
        crate::tls_unbuffered::run,
        crate::tls_unbuffered::seeds,
    ),
    ("tls_ech", crate::tls_ech::run, crate::tls_ech::seeds),
    (
        "tls_kernel",
        crate::tls_kernel::run,
        crate::tls_kernel::seeds,
    ),
    ("tls_psk", crate::tls_psk::run, crate::tls_psk::seeds),
    (
        "tls_binding",
        crate::tls_binding::run,
        crate::tls_binding::seeds,
    ),
    ("tls_quic", crate::tls_quic::run, crate::tls_quic::seeds),
    ("tls_auth", crate::tls_auth::run, crate::tls_auth::seeds),
    ("tls_codec", crate::tls_codec::run, crate::tls_codec::seeds),
    ("tls_tokio", crate::tls_tokio::run, crate::tls_tokio::seeds),
    (
        "tls_tokio_unbuffered",
        crate::tls_tokio_unbuffered::run,
        crate::tls_tokio_unbuffered::seeds,
    ),
];

fn identity() -> Identity {
    Identity::generate("localhost", rcgen::ExtendedKeyUsagePurpose::ServerAuth)
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The first flight of a real client: one ClientHello record.
fn client_hello_record() -> Vec<u8> {
    crate::init();
    let config = ClientConfig::builder()
        .with_root_certificates(Arc::new(RootCertStore::empty()))
        .with_no_client_auth();
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(Arc::new(config), name).expect("client");
    let mut out = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut out).expect("write");
    }
    out
}

fn handshake_message() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // every message type, both versions, empty and one-byte bodies
    for selector in 0..19u8 {
        for tls13 in 0..2u8 {
            seeds.push(vec![2 | tls13, selector]);
            seeds.push(vec![2 | tls13, selector, 0]);
        }
    }
    // a real ClientHello, with its header and as a bare body
    let record = client_hello_record();
    let message = &record[5..];
    for tls13 in 0..2u8 {
        seeds.push([&[tls13][..], message].concat());
        seeds.push([&[2 | tls13, 1][..], &message[4..]].concat());
    }
    seeds
}

fn deframer() -> Vec<Vec<u8>> {
    let record = client_hello_record();
    let mut seeds = vec![[&[0u8][..], &record].concat()];
    // the same message fragmented across two records
    let (head, tail) = record[5..].split_at(20);
    let mut split = vec![0u8];
    for part in [head, tail] {
        split.extend_from_slice(&[0x16, 3, 3]);
        split.extend_from_slice(&(part.len() as u16).to_be_bytes());
        split.extend_from_slice(part);
    }
    seeds.push(split);
    // single payloads: alert, change_cipher_spec, handshake, application data
    seeds.push(vec![1, 2, 40]);
    seeds.push(vec![1 | 1 << 2, 1]);
    seeds.push([&[1 | 2 << 2][..], &record[5..]].concat());
    seeds.push(vec![1 | 3 << 2, b'x']);
    seeds
}

/// The client and server targets share an input format.
fn connection() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // a protected KeyUpdate, a protected alert and an unprotected alert
    let mut framed = Vec::new();
    field(&mut framed, &[0x80, 0x18, 0, 0, 1, 0]);
    field(&mut framed, &[0x81, 1, 0]);
    field(&mut framed, &[0x01, 2, 40]);
    for mode in 0..8u8 {
        for flights in 0..4u8 {
            for cut in 0..3u8 {
                seeds.push(vec![mode | flights << 4, cut]);
                seeds.push([&[mode | 8 | flights << 4, cut][..], &framed].concat());
            }
        }
    }
    seeds.push([&[0u8, 0][..], &client_hello_record()].concat());
    seeds
}

fn pki_cert() -> Vec<Vec<u8>> {
    let identity = identity();
    let mut seeds = Vec::new();
    for flags in [0u8, 1, 2, 3, 4, 8, 16, 16 | 32, 16 | 64, 16 | 128] {
        let mut seed = vec![flags];
        field(&mut seed, identity.chain[0].as_ref());
        field(&mut seed, identity.ca.as_ref());
        field(&mut seed, &[]);
        field(&mut seed, identity.ca.as_ref());
        field(&mut seed, &identity.crl);
        field(&mut seed, b"localhost");
        seed.extend_from_slice(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        seeds.push(seed);
    }
    seeds
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(3).enumerate() {
        if i != 0 && i % 16 == 0 {
            out.push('\n');
        }
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
        for j in 0..4 {
            if j <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * j)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn pki_pem() -> Vec<Vec<u8>> {
    let identity = identity();
    let section = |label: &str, der: &[u8]| {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            base64(der)
        )
    };
    let certificate = section("CERTIFICATE", identity.chain[0].as_ref());
    let crl = section("X509 CRL", &identity.crl);
    vec![
        certificate.clone().into_bytes(),
        format!("{certificate}text between sections\n{crl}").into_bytes(),
        section("UNKNOWN", b"abc").into_bytes(),
        section("PRIVATE KEY", &[0x30, 0x00]).into_bytes(),
    ]
}

fn pki_crl() -> Vec<Vec<u8>> {
    let identity = identity();
    [0u8, 1]
        .into_iter()
        .map(|flags| {
            let mut seed = vec![flags];
            field(&mut seed, &[0x7b, 4, 5, 6]);
            field(&mut seed, &[]);
            seed.extend_from_slice(&identity.crl);
            seed
        })
        .collect()
}

fn cert_decompress() -> Vec<Vec<u8>> {
    // a TLS 1.3 Certificate message body: empty context, the certificate
    // twice, so that every compressor shrinks it whatever random key the
    // certificate has (a compressor that cannot shrink its input fails)
    let identity = identity();
    let cert = identity.chain[0].as_ref();
    let mut message = vec![0u8];
    let entry_len = cert.len() + 5;
    message.extend_from_slice(&(2 * entry_len as u32).to_be_bytes()[1..]);
    for _ in 0..2 {
        message.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(cert);
        message.extend_from_slice(&[0, 0]);
    }

    let compressors: [&dyn CertCompressor; 3] = [
        &browntls_core::compress::ZLIB,
        &browntls_core::compress::BROTLI,
        &browntls_core::compress::ZSTD,
    ];
    let mut seeds = Vec::new();
    for compressor in compressors {
        let compressed = compressor
            .compress(message.clone(), CompressionLevel::Interactive)
            .expect("compressible");
        for limit in 0..4u8 {
            let mut seed = vec![limit];
            seed.extend_from_slice(&u16::from(compressor.algorithm()).to_be_bytes());
            seed.extend_from_slice(&(message.len() as u32).to_be_bytes()[1..]);
            seed.extend_from_slice(&(compressed.len() as u32).to_be_bytes()[1..]);
            seed.extend_from_slice(&compressed);
            seeds.push(seed);
        }
    }
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64*: deterministic, so failures reproduce.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    /// Every harness accepts its seeds, their truncations and a few
    /// mutations of each without panicking.
    #[test]
    fn harnesses_run_over_their_seeds() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for (name, harness, seeds) in TARGETS {
            let seeds = seeds();
            assert!(!seeds.is_empty(), "{name}");
            harness(&[]);
            for seed in &seeds {
                harness(seed);
                for _ in 0..8 {
                    let mut mutated = seed.clone();
                    if mutated.is_empty() {
                        continue;
                    }
                    let at = rng.next() as usize % mutated.len();
                    match rng.next() % 3 {
                        0 => mutated[at] ^= 1 << (rng.next() % 8),
                        1 => mutated.truncate(at),
                        _ => mutated.insert(at, rng.next() as u8),
                    }
                    harness(&mutated);
                }
            }
        }
    }

    /// The seeds reach what they are meant to reach: a genuine handshake
    /// completes inside the connection harnesses' configurations.
    #[test]
    fn genuine_peers_complete_a_handshake() {
        assert_eq!(crate::connection::self_test(), 8);
    }
}
