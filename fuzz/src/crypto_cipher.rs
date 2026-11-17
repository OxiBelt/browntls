//! Symmetric ciphers and AEADs of `browntls-crypto`
//! (`fuzz_targets/crypto_cipher.rs`).
//!
//! Reaches every public function of `aes`, `gcm` (AES-GCM and standalone
//! GHASH), `ccm`, `chacha` (ChaCha20, Poly1305 and the ChaCha20-Poly1305
//! AEAD), `aead`, `cbc` and `tls_cbc`, and checks:
//!
//! - AES blocks and CTR keystreams, AES-GCM, AES-CCM (every SP 800-38C
//!   parameter set), ChaCha20-Poly1305 and AES-CBC against the RustCrypto
//!   `aes`, `aes-gcm`, `ccm`, `chacha20poly1305` and `cbc` crates;
//!   ChaCha20 against a reference block function in this harness, Poly1305
//!   against a big-integer reference, and GHASH against a bit-serial
//!   reference (for a fuzzed hash subkey) and, through the AES-GCM tag
//!   relation, against the RustCrypto `aes` and `aes-gcm` crates;
//! - every backend this CPU has (each AES, GHASH, ChaCha20 and Poly1305
//!   backend, selected explicitly) against the oracle and therefore against
//!   the portable one; constructors for unavailable backends fail with
//!   `Unsupported` (or, for `Poly1305` and `Ghash`, fall back to the
//!   portable backend);
//! - standalone GHASH fed in every documented way (whole padded fields,
//!   streamed chunks, whole blocks, a padded last chunk, a plain stream)
//!   gives the same value;
//! - seal/open round trips; a flipped ciphertext, tag or AAD bit, and any
//!   fuzzed ciphertext the oracle rejects, fails to open and wipes the
//!   buffer; fuzzed ciphertexts the oracle accepts open to its plaintext;
//! - ChaCha20-Poly1305 and AES-GCM keys pass the same checks with
//!   load-aware routing (`accel::load`) enabled and a fuzzed share of their
//!   records fixed on a fuzzed alternate ChaCha20 or AES backend (for
//!   AES-GCM with a key created under that share, which holds the key
//!   expanded for the alternates, and with one created before it, which
//!   does not): routing never changes a record;
//! - TLS 1.2 CBC records (MAC-then-encrypt and encrypt-then-MAC, every MAC):
//!   sealed records equal an independent construction, records with extra
//!   padding open, and tampered bits, sequence numbers, padding or MACs are
//!   rejected; arbitrary fragments never panic and wipe the buffer on
//!   failure;
//! - wrong key, nonce, tag and buffer lengths give the documented errors.
//!
//! Input: a sequence of at most [`MAX_OPS`] operations, each an op selector
//! byte followed by its arguments (see [`run`]). Lengths are bounded so that
//! one input runs in milliseconds.

mod aes_aead;
mod aes_block;
mod chacha;
mod ghash;
mod tls_cbc;

use browntls_crypto::Error;
use browntls_crypto::aead::{Aead, NONCE_LEN, TAG_LEN};

use self::aes_aead::{op_ccm, op_ccm_tls, op_gcm};
use self::aes_block::{op_aes, op_cbc};
use self::chacha::{op_chacha, op_chacha_poly, op_poly1305};
use self::ghash::op_ghash;
use self::tls_cbc::op_tls_cbc;
use crate::input::{Input, put_field, put_short_field};

/// Most operations one input runs.
pub const MAX_OPS: usize = 64;
/// Number of operations.
const OPS: u8 = 10;

const OP_AES: u8 = 0;
const OP_GCM: u8 = 1;
const OP_CCM: u8 = 2;
const OP_CCM_TLS: u8 = 3;
const OP_CHACHA: u8 = 4;
const OP_POLY1305: u8 = 5;
const OP_CHACHA_POLY: u8 = 6;
const OP_CBC: u8 = 7;
const OP_TLS_CBC: u8 = 8;
const OP_GHASH: u8 = 9;

/// The `crypto_cipher` fuzz target.
///
/// Each operation is a selector byte (taken modulo the number of operations)
/// and then:
///
/// - 0 AES: width, key (32 bytes), blocks (field), counter block (16),
///   counter-word override, CTR data (message);
/// - 1 AES-GCM: width, key (32), nonce (12), AAD (8-bit field), plaintext
///   (message), tamper (u16), wrong key length, fuzzed ciphertext (field)
///   and tag (16), routing alternate and share (one byte each);
/// - 2 AES-CCM: key length, key (32), nonce length, nonce (13), tag length,
///   AAD, plaintext, tamper, fuzzed ciphertext and tag (8-bit field);
/// - 3 AES-128-CCM / CCM_8: variant, key (16), nonce (12), AAD, plaintext,
///   tamper, wrong key length, fuzzed ciphertext and tag (16);
/// - 4 ChaCha20: key (32), counter (u32), nonce (12), data (message);
/// - 5 Poly1305: key (32), message, chunk plan, flip position (u16);
/// - 6 ChaCha20-Poly1305: key (32), nonce, AAD, plaintext, tamper, wrong key
///   length, fuzzed ciphertext and tag, routing alternate and share (one
///   byte each);
/// - 7 AES-CBC: key length, key (32), IV (16), buffer (message), fuzzed
///   ciphertext (field);
/// - 8 TLS 1.2 CBC: MAC, order, width, backend, AES key (32), MAC key flag
///   and key, sequence number (u64), type, version (2), IV (16), plaintext
///   (message), buffer slack, extra padding, tamper (u16), fuzzed fragment;
/// - 9 GHASH: hash subkey (16), AAD (8-bit field), ciphertext (message),
///   chunk plan (8-bit field), width, AES key (32), nonce (12).
///
/// A message is a 16-bit length-prefixed field followed by an extension byte
/// that appends `17 * n` pattern bytes.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.byte() % OPS {
            OP_AES => op_aes(&mut input),
            OP_GCM => op_gcm(&mut input),
            OP_CCM => op_ccm(&mut input),
            OP_CCM_TLS => op_ccm_tls(&mut input),
            OP_CHACHA => op_chacha(&mut input),
            OP_POLY1305 => op_poly1305(&mut input),
            OP_CHACHA_POLY => op_chacha_poly(&mut input),
            OP_CBC => op_cbc(&mut input),
            OP_TLS_CBC => op_tls_cbc(&mut input),
            _ => op_ghash(&mut input),
        }
    }
}

/// The AES key length selected by `wide`.
fn aes_key(key: &[u8; 32], wide: bool) -> &[u8] {
    if wide { &key[..] } else { &key[..16] }
}

/// A key length below 32 that is not `good`, from one byte.
fn bad_len(b: u8, good: usize) -> usize {
    let n = usize::from(b % 31);
    if n == good { n + 1 } else { n }
}

/// Flips bit `bit` (taken modulo the total) of the concatenation of `parts`.
fn flip(parts: &mut [&mut Vec<u8>], bit: u16) {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    if total == 0 {
        return;
    }
    let mut i = usize::from(bit) % (8 * total);
    for p in parts.iter_mut() {
        if i < 8 * p.len() {
            p[i / 8] ^= 1 << (i % 8);
            return;
        }
        i -= 8 * p.len();
    }
}

/// A fuzzed ciphertext and tag, and the plaintext the oracle opens them to
/// (`None` when it rejects them).
type Fuzzed<'a> = Option<(&'a [u8], &'a [u8], Option<Vec<u8>>)>;

/// Asserts that a failed open reported `DecryptFailed` and wiped `buf`.
fn assert_rejected(r: Result<(), Error>, buf: &[u8], what: &str) {
    assert_eq!(r, Err(Error::DecryptFailed), "{what}");
    assert!(buf.iter().all(|&b| b == 0), "{what}: buffer not wiped");
}

/// Seal and open of one detached-tag AEAD instance: the ciphertext and tag
/// equal the oracle's, they open to the plaintext, a flipped bit of
/// ciphertext, tag or AAD is rejected, and a fuzzed ciphertext opens exactly
/// when the oracle accepts it (`fuzzed`: ciphertext, tag, oracle plaintext).
#[allow(clippy::too_many_arguments)]
fn check_aead(
    what: &str,
    seal: impl Fn(&[u8], &mut [u8]) -> Result<Vec<u8>, Error>,
    open: impl Fn(&[u8], &mut [u8], &[u8]) -> Result<(), Error>,
    aad: &[u8],
    pt: &[u8],
    want_ct: &[u8],
    want_tag: &[u8],
    tamper: u16,
    fuzzed: Fuzzed<'_>,
) {
    let mut buf = pt.to_vec();
    let tag = match seal(aad, &mut buf) {
        Ok(tag) => tag,
        Err(e) => panic!("{what}: seal failed with {e:?}"),
    };
    assert_eq!(buf, want_ct, "{what}: ciphertext");
    assert_eq!(tag, want_tag, "{what}: tag");
    let mut opened = buf.clone();
    assert_eq!(open(aad, &mut opened, &tag), Ok(()), "{what}: open");
    assert_eq!(opened, pt, "{what}: round trip");

    let (mut bad_ct, mut bad_tag, mut bad_aad) = (buf, tag, aad.to_vec());
    flip(&mut [&mut bad_ct, &mut bad_tag, &mut bad_aad], tamper);
    let r = open(&bad_aad, &mut bad_ct, &bad_tag);
    assert_rejected(r, &bad_ct, &format!("{what}: tampered record"));

    if let Some((ct, tag, want)) = fuzzed {
        let mut buf = ct.to_vec();
        let r = open(aad, &mut buf, tag);
        match want {
            Some(pt) => {
                assert_eq!(r, Ok(()), "{what}: fuzzed record the oracle accepts");
                assert_eq!(buf, pt);
            }
            None => assert_rejected(r, &buf, &format!("{what}: fuzzed record")),
        }
    }
}

/// Seal/open closures for an [`Aead`] instance with a fixed nonce.
fn aead_seal<A: Aead>(
    a: &A,
    nonce: &[u8; NONCE_LEN],
) -> impl Fn(&[u8], &mut [u8]) -> Result<Vec<u8>, Error> {
    move |aad, buf| a.seal_in_place(nonce, aad, buf).map(|t| t.to_vec())
}

fn aead_open<A: Aead>(
    a: &A,
    nonce: &[u8; NONCE_LEN],
) -> impl Fn(&[u8], &mut [u8], &[u8]) -> Result<(), Error> {
    move |aad, buf, tag| {
        let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| Error::DecryptFailed)?;
        a.open_in_place(nonce, aad, buf, tag)
    }
}

/// Every check of [`check_aead`] for an [`Aead`] instance.
#[allow(clippy::too_many_arguments)]
fn check_typed<A: Aead>(
    what: &str,
    a: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
    want_ct: &[u8],
    want_tag: &[u8],
    tamper: u16,
    fuzzed: Fuzzed<'_>,
) {
    check_aead(
        what,
        aead_seal(a, nonce),
        aead_open(a, nonce),
        aad,
        pt,
        want_ct,
        want_tag,
        tamper,
        fuzzed,
    );
}

// ---------------------------------------------------------------- seeds

/// Starting inputs for `crypto_cipher`: every operation with each key
/// size, variant, MAC and MAC order; valid round trips, wrong lengths and
/// the documented error cases.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let bytes: Vec<u8> = (0..200u8).map(|i| i.wrapping_mul(29) ^ 0x17).collect();
    let key = &bytes[..32];
    let mut seeds = Vec::new();
    for wide in 0..2u8 {
        // AES blocks and CTR across the counter wrap.
        let mut s = vec![OP_AES, wide];
        s.extend_from_slice(key);
        put_field(&mut s, &bytes[..48]);
        s.extend_from_slice(&bytes[40..56]);
        s.push(0x81);
        put_field(&mut s, &bytes[..37]);
        s.push(1);
        seeds.push(s);

        // AES-GCM, with a fuzzed record: routing shares of none, all and
        // some of the records on each alternate AES backend; the last
        // plaintext is long enough for its records to be timed.
        for (alternate, percent, ext) in [
            (0u8, 0u8, 0u8),
            (0, 100, 0),
            (1, 100, 0),
            (2, 100, 0),
            (1, 50, 0),
            (0, 100, 255),
        ] {
            let mut s = vec![OP_GCM, wide];
            s.extend_from_slice(key);
            s.extend_from_slice(&bytes[50..62]);
            put_short_field(&mut s, &bytes[..13]);
            put_field(&mut s, &bytes[..40]);
            s.push(ext);
            s.extend_from_slice(&[1, 7, 24]);
            put_field(&mut s, &bytes[..5]);
            s.extend_from_slice(&bytes[..16]);
            s.extend_from_slice(&[alternate, percent]);
            seeds.push(s);
        }
    }
    // AES-CCM: valid sets, an invalid tag length, an invalid key length.
    for (key_sel, nonce_len, tag_len) in [
        (0u8, 7u8, 4u8),
        (2, 13, 16),
        (1, 12, 8),
        (2, 9, 10),
        (0, 11, 14),
        (0, 8, 6),
        (2, 10, 12),
        (0, 12, 5),
        (7, 12, 16),
    ] {
        let mut s = vec![OP_CCM, key_sel];
        s.extend_from_slice(key);
        s.push(nonce_len);
        s.extend_from_slice(&bytes[60..73]);
        s.push(tag_len);
        put_short_field(&mut s, &bytes[..usize::from(nonce_len) * 3]);
        put_field(&mut s, &bytes[..usize::from(tag_len) * 5]);
        s.push(0);
        s.extend_from_slice(&[0, 3]);
        put_field(&mut s, &bytes[..16]);
        put_short_field(&mut s, &bytes[..usize::from(tag_len)]);
        seeds.push(s);
    }
    // AES-128-CCM and CCM_8.
    for short_tag in 0..2u8 {
        let mut s = vec![OP_CCM_TLS, short_tag];
        s.extend_from_slice(&key[..16]);
        s.extend_from_slice(&bytes[70..82]);
        put_short_field(&mut s, &bytes[..13]);
        put_field(&mut s, &bytes[..33]);
        s.push(0);
        s.extend_from_slice(&[0, 200, 3]);
        put_field(&mut s, &bytes[..10]);
        s.extend_from_slice(&bytes[..16]);
        seeds.push(s);
    }
    // ChaCha20 across the counter wrap.
    let mut s = vec![OP_CHACHA];
    s.extend_from_slice(key);
    s.extend_from_slice(&(u32::MAX - 1).to_be_bytes());
    s.extend_from_slice(&bytes[..12]);
    put_field(&mut s, &bytes[..100]);
    s.push(5);
    seeds.push(s);
    // Poly1305 with irregular chunks.
    let mut s = vec![OP_POLY1305];
    s.extend_from_slice(key);
    put_field(&mut s, &bytes[..70]);
    s.push(2);
    put_short_field(&mut s, &[3, 0x82, 17]);
    s.extend_from_slice(&[0, 77]);
    seeds.push(s);
    // ChaCha20-Poly1305: routing shares of none, all and some of the records
    // on each alternate backend; the last plaintext is long enough for its
    // records to be timed.
    for (alternate, percent, ext) in [
        (0u8, 0u8, 0u8),
        (0, 100, 0),
        (1, 100, 0),
        (2, 50, 0),
        (1, 100, 255),
    ] {
        let mut s = vec![OP_CHACHA_POLY];
        s.extend_from_slice(key);
        s.extend_from_slice(&bytes[..12]);
        put_short_field(&mut s, &bytes[..12]);
        put_field(&mut s, &bytes[..65]);
        s.push(ext);
        s.extend_from_slice(&[2, 0, 16]);
        put_field(&mut s, &bytes[..7]);
        s.extend_from_slice(&bytes[..16]);
        s.extend_from_slice(&[alternate, percent]);
        seeds.push(s);
    }
    // AES-CBC: both key sizes, an unaligned buffer, a bad key length.
    for (key_sel, len) in [(0u8, 48usize), (2, 64), (0, 20), (3, 32)] {
        let mut s = vec![OP_CBC, key_sel];
        s.extend_from_slice(key);
        s.extend_from_slice(&bytes[..16]);
        put_field(&mut s, &bytes[..len]);
        s.push(0);
        put_field(&mut s, &bytes[..32]);
        seeds.push(s);
    }
    // TLS 1.2 CBC: every MAC and order, both key sizes, extra padding, a
    // short buffer, a wrong MAC key length, an oversized plaintext.
    for (i, (mac, etm, wide, slack, extra)) in [
        (0u8, 0u8, 0u8, 0u8, 0u8),
        (1, 0, 1, 5, 3),
        (2, 0, 0, 0, 200),
        (0, 1, 1, 0, 2),
        (1, 1, 0, 0x81, 0),
        (2, 1, 1, 7, 15),
    ]
    .into_iter()
    .enumerate()
    {
        let mut s = vec![OP_TLS_CBC, mac, etm, wide, u8::try_from(i).unwrap_or(0)];
        s.extend_from_slice(key);
        s.push(0);
        put_short_field(&mut s, &[]);
        s.extend_from_slice(&(i as u64 * 1000 + 1).to_be_bytes());
        s.extend_from_slice(&[23, 3, 3]);
        s.extend_from_slice(&bytes[100..116]);
        put_field(&mut s, &bytes[..i * 13]);
        s.push(0);
        s.extend_from_slice(&[slack, extra, 0, 99]);
        put_field(&mut s, &bytes[..48]);
        seeds.push(s);
    }
    let mut s = vec![OP_TLS_CBC, 1, 0, 0, 0];
    s.extend_from_slice(key);
    s.push(1);
    put_short_field(&mut s, &bytes[..31]);
    seeds.push(s);
    let mut s = vec![OP_TLS_CBC, 0, 1, 0, 0];
    s.extend_from_slice(key);
    s.push(0);
    put_short_field(&mut s, &[]);
    s.extend_from_slice(&[0; 12]);
    s.extend_from_slice(&bytes[..16]);
    put_field(&mut s, &bytes[..200]);
    s.push(255);
    seeds.push(s);
    // GHASH: irregular chunks, whole blocks only, the zero subkey and a
    // ciphertext long enough for every backend's widest grouping.
    for (h, aad, msg, ext, plan, wide) in [
        (
            &bytes[100..116],
            13usize,
            40usize,
            0u8,
            &[3u8, 0x82, 17][..],
            0u8,
        ),
        (&bytes[120..136], 32, 64, 0, &[16, 1][..], 1),
        (&[0u8; 16][..], 0, 7, 0, &[][..], 0),
        (&bytes[140..156], 20, 60, 255, &[5, 0x85, 0x90][..], 1),
    ] {
        let mut s = vec![OP_GHASH];
        s.extend_from_slice(h);
        put_short_field(&mut s, &bytes[..aad]);
        put_field(&mut s, &bytes[..msg]);
        s.push(ext);
        put_short_field(&mut s, plan);
        s.push(wide);
        s.extend_from_slice(key);
        s.extend_from_slice(&bytes[60..72]);
        seeds.push(s);
    }
    seeds
}
