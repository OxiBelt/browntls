//! `browntls-core` configuration and provider APIs (`fuzz_targets/tls_config.rs`).
//!
//! Reaches the configuration builders (`builder.rs`, `client/builder.rs`,
//! `server/builder.rs`), cipher suites (`suites.rs`, `tls12/`, `tls13/`),
//! both providers' public items under `crypto/` (hashes, HMAC, HKDF, PRF,
//! key exchange, record protection, signing keys, ticket producers), the
//! WebPKI root store and verifiers (`webpki/`, `verify.rs`), `ticketer.rs`,
//! `compress.rs`, `key_log_file.rs`, the session caches and SNI resolver
//! (`server/handy.rs`, `client/handy.rs`) and `CipherSuite` helpers.
//!
//! Input: up to 64 operations, each an operation byte followed by that
//! operation's arguments (bytes, 16-bit length-prefixed fields, 8-bit
//! length-prefixed short fields), until the input or a cost budget runs
//! out. Checked properties include:
//!
//! * hashes, HMAC, HKDF and the TLS 1.2 PRF agree with the RustCrypto
//!   crates, incremental with one-shot;
//! * both sides of every key exchange group derive the same secret, across
//!   providers, hybrids through their classical component too;
//! * TLS 1.2 and 1.3 record protection round trips, rejects tampering and
//!   produces the same records in both providers and with the portable
//!   backend;
//! * a signature from either provider's signing key verifies with every
//!   provider supporting its scheme (raw key and certificate) and fails once
//!   tampered; scheme selection is exactly the key's schemes among those
//!   offered; Ed25519 signatures are identical across providers;
//! * `with_protocol_versions`, `CertifiedKey::from_der`, the client
//!   authentication and certificate builders succeed exactly for consistent
//!   inputs; connections refuse exactly the invalid fragment and record
//!   sizes;
//! * WebPKI verification against a model of the fixture chains (roots,
//!   intermediates, CRLs, names), and corrupted end entities never verify;
//! * ticket rotation against a model of its key schedule, tampered tickets
//!   rejected; session caches against a model of their eviction;
//! * a handshake between compatible configurations completes, with the two
//!   sides agreeing on the suite, version and ALPN protocol, and again on a
//!   second connection.
//!
//! Keys and certificates come from [`fixtures`], generated once per process.

use std::sync::{Arc, OnceLock};

use browntls_core::SignatureScheme;
use browntls_core::crypto::{CryptoProvider, native, rustcrypto};
use browntls_core::pki_types::UnixTime;

use crate::input::{Input, put_field, put_short_field};

mod config;
mod crypto;
pub(crate) mod fixtures;
mod misc;
pub(crate) mod sign;
pub(crate) mod verifiers;

/// 2026-11-15 00:00:00 UTC: inside every fixture's validity and the CRLs'
/// update window.
pub(crate) const NOW: UnixTime =
    UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_794_700_800));

/// Every signature scheme the library names (except ML-DSA).
const KNOWN_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PKCS1_SHA1,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::ED448,
    SignatureScheme::RSA_PSS_PSS_SHA256,
    SignatureScheme::RSA_PSS_PSS_SHA384,
    SignatureScheme::RSA_PSS_PSS_SHA512,
];

/// The default provider `p`: 0 native, 1 rustcrypto.
fn provider(p: usize) -> Arc<CryptoProvider> {
    static PROVIDERS: OnceLock<[Arc<CryptoProvider>; 2]> = OnceLock::new();
    PROVIDERS.get_or_init(|| {
        [
            Arc::new(native::default_provider()),
            Arc::new(rustcrypto::default_provider()),
        ]
    })[p]
        .clone()
}

/// A name for messages.
fn provider_name(provider: &CryptoProvider) -> &'static str {
    if format!("{:?}", provider.key_provider).contains("Native") {
        "native"
    } else {
        "rustcrypto"
    }
}

/// An operation: its harness and its cost against the per-input budget, in
/// units of about 100 µs of release-build time (the slowest seed).
type Op = (fn(&mut Input<'_>), u32);

const OPS: &[Op] = &[
    (crypto::suite_props, 1),
    (crypto::hash_op, 1),
    (crypto::hmac_op, 1),
    (crypto::hkdf_op, 2),
    (crypto::prf_op, 6),
    (crypto::kx_op, 24),
    (crypto::aead13_op, 1),
    (crypto::aead12_op, 1),
    (crypto::helpers, 1),
    (crypto::provider_op, 1),
    (sign::sign_op, 60),
    (sign::fuzzed_key, 4),
    (sign::spki_op, 1),
    (sign::certified_op, 17),
    (verifiers::root_store_op, 1),
    (verifiers::server_verifier_op, 13),
    (verifiers::client_verifier_op, 7),
    (config::client_config_op, 8),
    (config::server_config_op, 19),
    (config::handshake_op, 55),
    (misc::ticket_op, 1),
    (misc::server_cache_op, 1),
    (misc::client_cache_op, 1),
    (misc::sni_op, 5),
    (misc::compress_op, 7),
    (misc::keylog_enum_op, 1),
];

/// Operation numbers, as the seeds write them.
mod op {
    pub(super) const SUITE: u8 = 0;
    pub(super) const HASH: u8 = 1;
    pub(super) const HMAC: u8 = 2;
    pub(super) const HKDF: u8 = 3;
    pub(super) const PRF: u8 = 4;
    pub(super) const KX: u8 = 5;
    pub(super) const AEAD13: u8 = 6;
    pub(super) const AEAD12: u8 = 7;
    pub(super) const HELPERS: u8 = 8;
    pub(super) const PROVIDER: u8 = 9;
    pub(super) const SIGN: u8 = 10;
    pub(super) const FUZZED_KEY: u8 = 11;
    pub(super) const SPKI: u8 = 12;
    pub(super) const CERTIFIED: u8 = 13;
    pub(super) const ROOTS: u8 = 14;
    pub(super) const SERVER_VERIFIER: u8 = 15;
    pub(super) const CLIENT_VERIFIER: u8 = 16;
    pub(super) const CLIENT_CONFIG: u8 = 17;
    pub(super) const SERVER_CONFIG: u8 = 18;
    pub(super) const HANDSHAKE: u8 = 19;
    pub(super) const TICKET: u8 = 20;
    pub(super) const SERVER_CACHE: u8 = 21;
    pub(super) const CLIENT_CACHE: u8 = 22;
    pub(super) const SNI: u8 = 23;
    pub(super) const COMPRESS: u8 = 24;
    pub(super) const KEYLOG: u8 = 25;
}

/// The `tls_config` fuzz target.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    // About 6 ms per input.
    let mut budget = 60u32;
    for _ in 0..64 {
        if input.is_empty() {
            break;
        }
        let (op, cost) = OPS[input.choose(OPS.len())];
        if cost > budget {
            break;
        }
        budget -= cost;
        op(&mut input);
    }
}

fn field(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_field(&mut out, bytes);
    out
}

fn short(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_short_field(&mut out, bytes);
    out
}

/// Starting inputs for `tls_config`: every operation with arguments that
/// take its successful paths, over every provider, suite, group and key.
/// Kept small: the unoptimised test build signs slowly.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    let mut add = |op: u8, parts: &[&[u8]]| {
        let mut seed = vec![op];
        for part in parts {
            seed.extend_from_slice(part);
        }
        seeds.push(seed);
    };
    let text = b"the quick brown fox jumps over the lazy dog";
    let keys = fixtures::KEY_COUNT as u8;

    // Suites, hashes, HKDF, PRF, record protection, key exchange, providers.
    for p in 0..2u8 {
        for s in 0..crypto::suites(usize::from(p)).len() as u8 {
            // TLS 1.2: offered ECDSA P-256, RSA-PSS-SHA256, Ed25519.
            add(op::SUITE, &[&[p, s, 3, 3, 3, 8, 11]]);
            add(op::HASH, &[&[p, s], &field(text), &[4, 1, 9, 0, 200]]);
        }
        for s in 0..5u8 {
            add(
                op::HKDF,
                &[
                    &[p, s, 1],
                    &short(b"salt"),
                    &short(b"ikm"),
                    &[2],
                    &short(b"a"),
                    &short(b"b"),
                    &[0, 77],
                ],
            );
            add(op::HKDF, &[&[p, s, 0], &short(b""), &[0, 0xff, 0xff]]);
            add(
                op::AEAD13,
                &[
                    &[p, s],
                    &[7; 32],
                    &[9; 12],
                    &[s % 3],
                    &[0; 8],
                    &field(text),
                    &[0, 5, 0, 3, 1, 0],
                ],
            );
        }
        for s in (p..13u8).step_by(2) {
            add(
                op::PRF,
                &[
                    &[p, s],
                    &short(b"secret"),
                    &short(b"master secret"),
                    &short(b"seed"),
                    &[40, s],
                ],
            );
            add(
                op::AEAD12,
                &[
                    &[p, s],
                    &[5; 128],
                    &[s & 1, 2],
                    &[0, 0, 0, 0, 0, 0, 0, 9],
                    &field(text),
                    &[0, 3, 2, 5],
                ],
            );
        }
        add(op::PROVIDER, &[&[p, 16]]);
        add(op::PROVIDER, &[&[2, p, 2 - p, 8]]);
    }
    // An empty record of a type that must not be empty.
    add(
        op::AEAD13,
        &[
            &[0, 0],
            &[1; 32],
            &[2; 12],
            &[0],
            &[1; 8],
            &field(b""),
            &[0, 0, 0, 7, 2, 0],
        ],
    );
    for g in 0..15u8 {
        let p = g & 1;
        add(
            op::KX,
            &[
                &[p, g, 1 - p, g >> 1 & 1],
                &field(&[4, 1, 2, 3]),
                &short(b"raw"),
            ],
        );
    }
    for h in 0..3u8 {
        add(
            op::HMAC,
            &[
                &[h],
                &field(b"key"),
                &[3],
                &short(b"a"),
                &short(b""),
                &short(text),
            ],
        );
        add(op::HMAC, &[&[h], &field(&[0x5c; 200]), &[1], &short(text)]);
    }
    add(
        op::HELPERS,
        &[&[
            0x12, 0x34, 1, 2, 3, 4, 5, 6, 7, 8, 0x16, 3, 3, 5, 1, 2, 3, 4, 5, 20,
        ]],
    );

    // Keys: every key with one provider (the other where only one loads),
    // offering the key's own schemes; then two known schemes and Ed25519 as
    // a raw code point.
    for k in 0..keys {
        let p = k & 1;
        // Verification path `k % 3`.
        add(op::SIGN, &[&[k, p, 0, 1], &field(text), &[k % 3, 0, 3, 2]]);
        // Corrupt one byte of the key.
        add(op::FUZZED_KEY, &[&[1, k, 0, 10, 0x40, k % 3]]);
    }
    for k in [0u8, 1, 2, 3, 7, 5] {
        // A genuine delegated credential (Ed25519 key) on the key's own
        // chain (P-256's for keys without one).
        add(
            op::CERTIFIED,
            &[&[k, k, k & 1, 1, 0, 2, 1, 0, 0, 0x10, 0, k & 1]],
        );
    }
    add(
        op::SIGN,
        &[&[2, 1, 3, 0, 1, 0x80, 0x08, 0x07, 1], &field(b"")],
    );
    add(op::SIGN, &[&[0, 1, 1, 3, 0], &field(text), &[0, 1, 3]]);
    // Mismatched pairs and a fuzzed credential.
    add(op::CERTIFIED, &[&[9, 0, 0, 0, 1, 1, 0, 0, 0, 0x10, 0, 0]]);
    add(
        op::CERTIFIED,
        &[
            &[0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x07],
            &short(b"\x30\x00"),
            &[1],
        ],
    );
    add(
        op::FUZZED_KEY,
        &[&[0], &field(&[0x30, 0x03, 0x02, 0x01, 0x00]), &[2]],
    );
    for alg in 0..7u8 {
        add(
            op::SPKI,
            &[
                &[alg],
                &field(&[4; 65]),
                &[0x04, 0x03],
                &field(&[0x30, 6, 2, 1, 1, 2, 1, 1]),
                &field(&[0x30, 0]),
            ],
        );
    }
    add(op::SPKI, &[&[0], &field(&[0xab; 300])]);
    add(op::ROOTS, &[&[4, 0, 1, 2, 1, 3]]);
    add(op::ROOTS, &[&[3, 3], &field(b"junk"), &[0, 2, 2]]);

    // Verifiers: roots, provider, CRL, options, chain (key, without the
    // intermediate, corrupted), name, time, OCSP.
    for (i, roots) in [1u8, 3, 5, 0].into_iter().enumerate() {
        for crl in 0..3u8 {
            let p = (i as u8 + crl) % 3;
            let k = (roots + crl) % 3;
            add(
                op::SERVER_VERIFIER,
                &[&[roots, p, crl, 2 * (k & 1), k, 0, 0, k, 0, 0]],
            );
            add(
                op::CLIENT_VERIFIER,
                &[&[roots, p, 16 * (k & 1), crl, k, 0, 0, 0]],
            );
        }
    }
    add(op::SERVER_VERIFIER, &[&[1, 0, 0, 0, 1, 1, 0, 2, 0, 0]]);
    add(
        op::SERVER_VERIFIER,
        &[&[1, 0, 0, 7, 3, 0, 1, 0, 9, 0x10, 3, 0]],
    );
    add(
        op::SERVER_VERIFIER,
        &[&[9], &field(b"bad root"), &[1, 3], &field(b"bad crl")],
    );
    add(
        op::SERVER_VERIFIER,
        &[&[
            1, 1, 1, 4, 1, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]],
    );
    add(
        op::CLIENT_VERIFIER,
        &[&[1, 1, 3, 2], &short(b"\x30\x00"), &short(b"x"), &[1]],
    );
    add(op::CLIENT_VERIFIER, &[&[1, 0, 0x3d, 2, 1, 1, 0, 0]]);

    // Configurations: provider (base, mode, masks), versions, verifier,
    // then the rest.
    for p in 0..2u8 {
        for mode in 0..4u8 {
            let provider: &[u8] = if mode >= 2 {
                &[p, mode, 0xff, 0x0f, 0xf0, 0xff, 0x00, 0x3f]
            } else {
                &[p, mode]
            };
            for versions in [(2 * mode + p) % 5, (2 * mode + p + 3) % 5] {
                let verifier = (versions + mode) % 3;
                add(
                    op::CLIENT_CONFIG,
                    &[
                        provider,
                        &[versions, verifier, 0, 1, 0x40, 0x00, 0, 2, 1, 0, 0, 3, 1, 0],
                    ],
                );
                let verifier = (versions + mode) % 4;
                add(
                    op::SERVER_CONFIG,
                    &[provider, &[versions, verifier, 1, 0, 0, 0, 0, 0, 1, 0, 2]],
                );
            }
        }
        // Certificate and key pairs, matching and not.
        for (k, j) in [(0u8, 0u8), (3, 4), (7, 9), (9, 0), (6, 0)] {
            let k = k + p * u8::from(k == 0);
            add(op::CLIENT_CONFIG, &[&[p, 0, 0, 0, 1, k, j, 0, 0]]);
            add(op::SERVER_CONFIG, &[&[p, 0, 0, 0, k, j, 0, 0, 0]]);
        }
        add(
            op::SERVER_CONFIG,
            &[&[p, 0, 0, 1, 2, 2, 1], &short(b"ocsp")],
        );
        add(
            op::CLIENT_CONFIG,
            &[&[p, 0, 0, 2, 2, 2, 3, 1, 0x30, 1, 0x40, 0, 1, 1, 1]],
        );
        add(
            op::SERVER_CONFIG,
            &[&[p, 0, 0, 3, 1, 1, 0, 2, 1, 0x30, 0, 0, 1, 1]],
        );
        add(op::SERVER_CONFIG, &[&[p, 0, 0, 0, 3, 0, 3, 2, 0, 0]]);
        add(
            op::SERVER_CONFIG,
            &[
                &[p, 0, 0, 0, 0, 0, 4],
                &short(b"identity"),
                &field(&[1; 32]),
                &[1],
            ],
        );
        add(
            op::SERVER_CONFIG,
            &[
                &[p, 0, 0, 0, 0, 0, 4],
                &short(b""),
                &field(&[1; 4]),
                &[0, 9],
            ],
        );
        // Invalid fragment and record sizes.
        add(op::CLIENT_CONFIG, &[&[p, 0, 0, 0, 0, 3, 0, 2, 3]]);
        add(op::SERVER_CONFIG, &[&[p, 0, 0, 0, 0, 0, 0, 3, 1, 2, 1]]);
    }

    // Handshakes: providers, versions (client, server), server key, SNI
    // resolver, client authentication, ALPN (client, server), name,
    // tickets, client certificate.
    add(op::HANDSHAKE, &[&[0, 1, 0, 0, 0, 0, 0, 1, 2, 0, 1, 0]]);
    add(op::HANDSHAKE, &[&[1, 0, 2, 2, 3, 1, 1, 1, 3, 0, 2, 1]]);
    add(op::HANDSHAKE, &[&[1, 1, 1, 0, 2, 0, 2, 0, 0, 2, 0, 1]]);
    add(op::HANDSHAKE, &[&[0, 0, 0, 2, 4, 1, 0, 0, 0, 1, 2, 0]]);

    for p in 0..2u8 {
        // Producer, plaintext, tampering (flip byte 3 bit 1), a foreign
        // ticket, rotator start, lifetime and generator, then operations.
        let mut ticket = vec![p];
        ticket.extend_from_slice(&field(b"session state"));
        ticket.extend_from_slice(&[0, 0, 3, 1]);
        ticket.extend_from_slice(&field(b"junk"));
        ticket.extend_from_slice(&[0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 100, p, 10]);
        for step in [1u8, 2, 0, 2, 1, 0, 2, 0, 2, 3] {
            ticket.push(step);
            match step {
                0 => ticket.extend_from_slice(&[0, 0, 0, 60]),
                1 => ticket.extend_from_slice(&short(b"t")),
                2 => ticket.extend_from_slice(&[0, 1, 0, 1]),
                _ => ticket.extend_from_slice(&field(b"x")),
            }
        }
        add(op::TICKET, &[&ticket]);
    }
    add(
        op::SERVER_CACHE,
        &[&[
            2, 12, 0, 1, 2, 3, 0, 1, 1, 1, 1, 1, 2, 0, 2, 0, 4, 1, 2, 1, 0, 1, 1, 2, 2, 1,
        ]],
    );
    add(
        op::CLIENT_CACHE,
        &[&[
            9, 10, 0, 0, 0, 0x1d, 1, 0, 1, 2, 0, 2, 0, 3, 0, 1, 3, 0, 1, 1, 9, 0, 0, 0, 1, 1, 9,
        ]],
    );
    add(
        op::SNI,
        &[&[3, 0, 0, 0, 0, 5, 1, 0, 1, 2, 1, 1], &short(b"LOCALHOST")],
    );
    for c in 0..3u8 {
        add(
            op::COMPRESS,
            &[&field(text), &[1, c, c, 0, 10], &field(b"bad")],
        );
        add(op::COMPRESS, &[&field(&[0; 300]), &[0, c, c]]);
    }
    add(
        op::KEYLOG,
        &[
            &short(b"CLIENT_RANDOM"),
            &short(&[1; 32]),
            &short(&[2; 48]),
            &[0x13, 0x04],
        ],
    );
    add(op::KEYLOG, &[&[0, 0, 0, 0xc0, 0x23]]);
    add(op::KEYLOG, &[&[0, 0, 0, 0x13, 0x01]]);
    // A program of several operations.
    let program: Vec<u8> = [op::SUITE, op::KEYLOG, op::HASH, op::HELPERS]
        .iter()
        .flat_map(|o| [*o, 0, 1, 2, 3])
        .collect();
    add(op::HELPERS, &[&program]);
    seeds
}
