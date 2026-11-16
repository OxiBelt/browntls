//! Symmetric ciphers and AEADs of `browntls-crypto`
//! (`fuzz_targets/crypto_cipher.rs`).
//!
//! Reaches every public function of `aes`, `gcm`, `ccm`, `chacha` (ChaCha20,
//! Poly1305 and the ChaCha20-Poly1305 AEAD), `aead`, `cbc` and `tls_cbc`,
//! and checks:
//!
//! - AES blocks and CTR keystreams, AES-GCM, AES-CCM (every SP 800-38C
//!   parameter set), ChaCha20-Poly1305 and AES-CBC against the RustCrypto
//!   `aes`, `aes-gcm`, `ccm`, `chacha20poly1305` and `cbc` crates;
//!   ChaCha20 against a reference block function in this file and Poly1305
//!   against a big-integer reference;
//! - every backend this CPU has (each AES, GHASH, ChaCha20 and Poly1305
//!   backend, selected explicitly) against the oracle and therefore against
//!   the portable one; constructors for unavailable backends fail with
//!   `Unsupported`;
//! - seal/open round trips; a flipped ciphertext, tag or AAD bit, and any
//!   fuzzed ciphertext the oracle rejects, fails to open and wipes the
//!   buffer; fuzzed ciphertexts the oracle accepts open to its plaintext;
//! - ChaCha20-Poly1305 keys pass the same checks with load-aware routing
//!   (`accel::load`) enabled and a fuzzed share of their records fixed on a
//!   fuzzed alternate ChaCha20 backend: routing never changes a record;
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

use ::aes::cipher::{BlockCipherEncrypt as _, BlockModeDecrypt as _, BlockModeEncrypt as _};
use ::aes::cipher::{KeyInit as _, KeyIvInit as _};
use aes_gcm::AeadInOut as _;
use browntls_crypto::Error;
use browntls_crypto::accel::Algorithm;
use browntls_crypto::aead::{Aead, NONCE_LEN, TAG_LEN};
use browntls_crypto::aes::{self, Aes128, Aes256, BLOCK_LEN};
use browntls_crypto::cbc::AesCbcKey;
use browntls_crypto::ccm::{
    Aes128Ccm, Aes128Ccm8, AesCcm, CCM8_TAG_LEN, MAX_NONCE_LEN, MIN_NONCE_LEN,
};
use browntls_crypto::chacha::{
    self, ChaCha20Poly1305, POLY1305_KEY_LEN, POLY1305_TAG_LEN, Poly1305, PolyBackend,
};
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm, GhashBackend};
use browntls_crypto::tls_cbc::{
    IV_LEN, MAX_FRAGMENT_LEN, MAX_PLAINTEXT_LEN, MacAlgorithm, MacOrder, RecordKey,
};
use ccm::aead::consts::{U4, U6, U7, U8, U9, U10, U11, U12, U13, U14, U16};
use hmac::Mac as _;
use num_bigint::BigUint;

use crate::crypto_hash::{across_policies, chunks, message, with_fixed_share};
use crate::input::{Input, put_field, put_short_field};

/// Most operations one input runs.
pub const MAX_OPS: usize = 64;
/// Number of operations.
const OPS: u8 = 9;

const OP_AES: u8 = 0;
const OP_GCM: u8 = 1;
const OP_CCM: u8 = 2;
const OP_CCM_TLS: u8 = 3;
const OP_CHACHA: u8 = 4;
const OP_POLY1305: u8 = 5;
const OP_CHACHA_POLY: u8 = 6;
const OP_CBC: u8 = 7;
const OP_TLS_CBC: u8 = 8;

/// The `crypto_cipher` fuzz target.
///
/// Each operation is a selector byte (taken modulo the number of operations)
/// and then:
///
/// - 0 AES: width, key (32 bytes), blocks (field), counter block (16),
///   counter-word override, CTR data (message);
/// - 1 AES-GCM: width, key (32), nonce (12), AAD (8-bit field), plaintext
///   (message), tamper (u16), wrong key length, fuzzed ciphertext (field)
///   and tag (16);
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
///   (message), buffer slack, extra padding, tamper (u16), fuzzed fragment.
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
            _ => op_tls_cbc(&mut input),
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

// ------------------------------------------------------------------ AES

/// Encrypts `blocks` with the RustCrypto `aes` crate.
fn aes_ref(key: &[u8], blocks: &mut [[u8; BLOCK_LEN]]) {
    macro_rules! go {
        ($c:ty) => {{
            let c = <$c>::new_from_slice(key).expect("16- or 32-byte key");
            for block in blocks.iter_mut() {
                c.encrypt_block(block.into());
            }
        }};
    }
    match key.len() {
        16 => go!(::aes::Aes128),
        _ => go!(::aes::Aes256),
    }
}

/// CTR mode with a 32-bit big-endian counter in the last word (GCM `inc32`).
fn ctr_ref(key: &[u8], counter: &[u8; BLOCK_LEN], data: &mut [u8]) {
    let mut ctr = *counter;
    for chunk in data.chunks_mut(BLOCK_LEN) {
        let mut ks = [ctr];
        aes_ref(key, &mut ks);
        for (d, k) in chunk.iter_mut().zip(ks[0]) {
            *d ^= k;
        }
        let n = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]).wrapping_add(1);
        ctr[12..].copy_from_slice(&n.to_be_bytes());
    }
}

/// The selected AES backend is available.
fn check_aes_select() {
    let selected = aes::Backend::select();
    assert!(
        selected.is_available(),
        "{selected:?} selected but unavailable"
    );
}

macro_rules! aes_op {
    ($ty:ty, $len:literal, $key:expr, $blocks:expr, $ctr:expr, $data:expr) => {{
        let key: &[u8; $len] = $key[..$len].try_into().expect("fixed length");
        let mut want = $blocks.clone();
        aes_ref(key, &mut want);
        let mut want_ctr = $data.clone();
        ctr_ref(key, $ctr, &mut want_ctr);
        let check = |aes: &$ty, what: &str| {
            let mut blocks = $blocks.clone();
            aes.encrypt_blocks(&mut blocks);
            assert_eq!(blocks, want, "{what}: encrypt_blocks");
            if let (Some(first), Some(w)) = ($blocks.first(), want.first()) {
                let mut b = *first;
                aes.encrypt_block(&mut b);
                assert_eq!(&b, w, "{what}: encrypt_block");
            }
            let mut data = $data.clone();
            aes.ctr32_xor($ctr, &mut data);
            assert_eq!(data, want_ctr, "{what}: ctr32_xor");
        };
        let default = <$ty>::new(key);
        assert_eq!(default.backend(), aes::Backend::select());
        check(&default, "default backend");
        // The portable backend under a portable-only policy.
        let soft = across_policies(Algorithm::Aes, || {
            let aes = <$ty>::new(key);
            let mut blocks = $blocks.clone();
            aes.encrypt_blocks(&mut blocks);
            blocks
        });
        assert_eq!(soft, want);
        for backend in aes::Backend::ALL {
            match <$ty>::with_backend(key, backend) {
                Ok(aes) => {
                    assert!(backend.is_available(), "{backend:?}");
                    assert_eq!(aes.backend(), backend);
                    check(&aes, &format!("{backend:?}"));
                }
                Err(e) => {
                    assert!(!backend.is_available(), "{backend:?}");
                    assert_eq!(e, Error::Unsupported);
                }
            }
        }
    }};
}

fn op_aes(input: &mut Input<'_>) {
    let wide = input.bool();
    let key: [u8; 32] = input.array();
    let block_bytes = input.field();
    let blocks: Vec<[u8; BLOCK_LEN]> = block_bytes.as_chunks::<BLOCK_LEN>().0.to_vec();
    let mut ctr: [u8; BLOCK_LEN] = input.array();
    // Optionally start the counter just below the 32-bit wrap.
    let near = input.byte();
    if near & 0x80 != 0 {
        let low = u32::MAX - u32::from(near & 0x7f);
        ctr[12..].copy_from_slice(&low.to_be_bytes());
    }
    let data = message(input);
    check_aes_select();
    if wide {
        aes_op!(Aes256, 32, key, blocks, &ctr, data);
    } else {
        aes_op!(Aes128, 16, key, blocks, &ctr, data);
    }
}

// -------------------------------------------------------------- AES-GCM

fn gcm_ref_seal(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Vec<u8> {
    let nonce = (*nonce).into();
    let tag = if key.len() == 16 {
        aes_gcm::Aes128Gcm::new_from_slice(key)
            .expect("16-byte key")
            .encrypt_inout_detached(&nonce, aad, buf.into())
    } else {
        aes_gcm::Aes256Gcm::new_from_slice(key)
            .expect("32-byte key")
            .encrypt_inout_detached(&nonce, aad, buf.into())
    };
    tag.expect("short message").to_vec()
}

fn gcm_ref_open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
) -> Option<Vec<u8>> {
    let nonce = (*nonce).into();
    let tag = (*tag).into();
    let mut buf = ct.to_vec();
    let r = if key.len() == 16 {
        aes_gcm::Aes128Gcm::new_from_slice(key)
            .expect("16-byte key")
            .decrypt_inout_detached(&nonce, aad, (&mut buf[..]).into(), &tag)
    } else {
        aes_gcm::Aes256Gcm::new_from_slice(key)
            .expect("32-byte key")
            .decrypt_inout_detached(&nonce, aad, (&mut buf[..]).into(), &tag)
    };
    r.ok().map(|()| buf)
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

macro_rules! gcm_op {
    ($ty:ty, $len:literal, $key:expr, $nonce:expr, $aad:expr, $pt:expr, $tamper:expr,
     $bad:expr, $fct:expr, $ftag:expr) => {{
        let key: &[u8; $len] = $key[..$len].try_into().expect("fixed length");
        let mut want_ct = $pt.to_vec();
        let want_tag = gcm_ref_seal(key, $nonce, $aad, &mut want_ct);
        let fuzz_want = gcm_ref_open(key, $nonce, $aad, $fct, $ftag);
        let fuzzed = || Some((&$fct[..], &$ftag[..], fuzz_want.clone()));
        let default = <$ty as Aead>::new(key).expect("valid key length");
        assert_eq!(
            default.backends(),
            (aes::Backend::select(), GhashBackend::select())
        );
        check_typed(
            "AES-GCM",
            &default,
            $nonce,
            $aad,
            $pt,
            &want_ct,
            &want_tag,
            $tamper,
            fuzzed(),
        );
        assert_eq!(
            <$ty as Aead>::new(&$key[..bad_len($bad, $len)]).err(),
            Some(Error::InvalidKey)
        );
        for ab in aes::Backend::ALL {
            for gb in GhashBackend::ALL {
                match <$ty>::with_backends(key, ab, gb) {
                    Ok(gcm) => {
                        assert!(ab.is_available() && gb.is_available(), "{ab:?}/{gb:?}");
                        assert_eq!(gcm.backends(), (ab, gb));
                        let what = format!("AES-GCM {ab:?}/{gb:?}");
                        check_typed(
                            &what,
                            &gcm,
                            $nonce,
                            $aad,
                            $pt,
                            &want_ct,
                            &want_tag,
                            $tamper,
                            fuzzed(),
                        );
                    }
                    Err(e) => {
                        assert!(!(ab.is_available() && gb.is_available()), "{ab:?}/{gb:?}");
                        assert_eq!(e, Error::Unsupported);
                    }
                }
            }
        }
    }};
}

fn op_gcm(input: &mut Input<'_>) {
    let wide = input.bool();
    let key: [u8; 32] = input.array();
    let nonce: [u8; NONCE_LEN] = input.array();
    let aad = input.short_field();
    let pt = message(input);
    let tamper = input.u16();
    let bad = input.byte();
    let fct = input.field();
    let ftag: [u8; TAG_LEN] = input.array();
    assert!(GhashBackend::select().is_available());
    if wide {
        gcm_op!(
            Aes256Gcm, 32, key, &nonce, aad, &pt, tamper, bad, fct, &ftag
        );
    } else {
        gcm_op!(
            Aes128Gcm, 16, key, &nonce, aad, &pt, tamper, bad, fct, &ftag
        );
    }
}

// -------------------------------------------------------------- AES-CCM

/// Seals (`tag` empty: returns the tag) or opens (returns the plaintext)
/// with the RustCrypto `ccm` crate for any SP 800-38C parameter set.
/// `None` when the crate rejects the operation.
fn ccm_ref(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &[u8],
    tag_len: usize,
    tag: Option<&[u8]>,
) -> Option<Vec<u8>> {
    macro_rules! go {
        ($c:ty, $m:ty, $n:ty) => {{
            let c = ccm::Ccm::<$c, $m, $n>::new_from_slice(key).expect("valid key length");
            let nonce = ccm::Nonce::<$n>::try_from(nonce).expect("valid nonce length");
            let mut buf = buf.to_vec();
            match tag {
                None => c
                    .encrypt_inout_detached(&nonce, aad, (&mut buf[..]).into())
                    .ok()
                    .map(|t| [&buf[..], &t[..]].concat()),
                Some(tag) => {
                    let tag = ccm::Tag::<$m>::try_from(tag).ok()?;
                    c.decrypt_inout_detached(&nonce, aad, (&mut buf[..]).into(), &tag)
                        .ok()
                        .map(|()| buf)
                }
            }
        }};
    }
    macro_rules! by_nonce {
        ($c:ty, $m:ty) => {
            match nonce.len() {
                7 => go!($c, $m, U7),
                8 => go!($c, $m, U8),
                9 => go!($c, $m, U9),
                10 => go!($c, $m, U10),
                11 => go!($c, $m, U11),
                12 => go!($c, $m, U12),
                _ => go!($c, $m, U13),
            }
        };
    }
    macro_rules! by_tag {
        ($c:ty) => {
            match tag_len {
                4 => by_nonce!($c, U4),
                6 => by_nonce!($c, U6),
                8 => by_nonce!($c, U8),
                10 => by_nonce!($c, U10),
                12 => by_nonce!($c, U12),
                14 => by_nonce!($c, U14),
                _ => by_nonce!($c, U16),
            }
        };
    }
    if key.len() == 16 {
        by_tag!(::aes::Aes128)
    } else {
        by_tag!(::aes::Aes256)
    }
}

/// The longest CCM message for a nonce of `nonce_len` bytes, capped as the
/// library documents (2^32 - 1 blocks).
fn ccm_max_len(nonce_len: usize) -> u64 {
    let q = 15 - nonce_len;
    (u64::MAX >> (64 - 8 * q)).min(((1 << 32) - 1) * 16)
}

fn op_ccm(input: &mut Input<'_>) {
    let key_sel = input.byte();
    let key: [u8; 32] = input.array();
    let nonce_len = input.byte() % 16;
    let nonce: [u8; MAX_NONCE_LEN] = input.array();
    let tag_len = usize::from(input.byte() % 18);
    let aad = input.short_field();
    let pt = message(input);
    let tamper = input.u16();
    let fct = input.field();
    let ftag = input.short_field();

    let key = match key_sel % 4 {
        0 | 1 => &key[..16],
        2 => &key[..],
        _ => &key[..bad_len(key_sel >> 2, 16)],
    };
    let key_ok = key.len() == 16 || key.len() == 32;
    match AesCcm::new(key) {
        Ok(c) => {
            assert!(key_ok);
            assert_eq!(c.backend(), aes::Backend::select());
        }
        Err(e) => {
            assert!(!key_ok);
            assert_eq!(e, Error::InvalidKey);
        }
    }
    let nonce = &nonce[..usize::from(nonce_len).min(MAX_NONCE_LEN)];
    let params_ok = (MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&nonce.len())
        && (4..=16).contains(&tag_len)
        && tag_len % 2 == 0;
    let len_ok = params_ok && pt.len() as u64 <= ccm_max_len(nonce.len());
    let sealed = (key_ok && len_ok).then(|| ccm_ref(key, nonce, aad, &pt, tag_len, None));
    let fuzz_want = (key_ok && params_ok && ftag.len() == tag_len)
        .then(|| ccm_ref(key, nonce, aad, fct, tag_len, Some(ftag)))
        .flatten();

    for backend in aes::Backend::ALL {
        let c = match AesCcm::with_backend(key, backend) {
            Ok(c) => {
                assert!(key_ok && backend.is_available(), "{backend:?}");
                c
            }
            Err(_) => {
                assert!(!key_ok || !backend.is_available(), "{backend:?}");
                continue;
            }
        };
        assert_eq!(c.backend(), backend);
        let seal = |aad: &[u8], buf: &mut [u8]| {
            let mut tag = vec![0u8; tag_len];
            c.seal_in_place(nonce, aad, buf, &mut tag).map(|()| tag)
        };
        let open = |aad: &[u8], buf: &mut [u8], tag: &[u8]| c.open_in_place(nonce, aad, buf, tag);
        let Some(sealed) = &sealed else {
            // Unsupported nonce or tag length, or a message too long.
            let mut buf = pt.clone();
            assert_eq!(seal(aad, &mut buf).err(), Some(Error::InvalidLength));
            let tag = vec![0u8; tag_len];
            assert_eq!(open(aad, &mut buf, &tag), Err(Error::InvalidLength));
            continue;
        };
        let sealed = sealed
            .as_ref()
            .expect("the ccm crate seals valid parameters");
        let (want_ct, want_tag) = sealed.split_at(pt.len());
        let fuzzed = (ftag.len() == tag_len).then(|| (fct, ftag, fuzz_want.clone()));
        let what = format!("AES-CCM {backend:?} n={} t={tag_len}", nonce.len());
        check_aead(
            &what, seal, open, aad, &pt, want_ct, want_tag, tamper, fuzzed,
        );
        // A tag of the wrong length is rejected.
        let mut buf = want_ct.to_vec();
        let short = &want_tag[..tag_len - 2];
        assert!(c.open_in_place(nonce, aad, &mut buf, short).is_err());
    }
}

macro_rules! ccm_tls_variant {
    ($ty:ty, $tag_len:expr, $m:ty, $key:expr, $nonce:expr, $aad:expr, $pt:expr,
     $tamper:expr, $fct:expr, $ftag:expr, $new:expr, $check:ident) => {{
        let mut want_ct = $pt.to_vec();
        let c = ccm::Ccm::<::aes::Aes128, $m, U12>::new_from_slice($key).expect("16-byte key");
        let want_tag = c
            .encrypt_inout_detached(&(*$nonce).into(), $aad, (&mut want_ct[..]).into())
            .expect("short message")
            .to_vec();
        let ftag = &$ftag[..$tag_len];
        let fuzz_want = {
            let mut buf = $fct.to_vec();
            let tag = ccm::Tag::<$m>::try_from(ftag).expect("fixed length");
            c.decrypt_inout_detached(&(*$nonce).into(), $aad, (&mut buf[..]).into(), &tag)
                .ok()
                .map(|()| buf)
        };
        let fuzzed = || Some((&$fct[..], ftag, fuzz_want.clone()));
        let default: $ty = $new;
        assert_eq!(default.backend(), aes::Backend::select());
        $check(
            "AES-128-CCM",
            &default,
            $nonce,
            $aad,
            $pt,
            &want_ct,
            &want_tag,
            $tamper,
            fuzzed(),
        );
        for backend in aes::Backend::ALL {
            match <$ty>::with_backend($key, backend) {
                Ok(c) => {
                    assert!(backend.is_available(), "{backend:?}");
                    assert_eq!(c.backend(), backend);
                    let what = format!("AES-128-CCM {backend:?}");
                    $check(
                        &what,
                        &c,
                        $nonce,
                        $aad,
                        $pt,
                        &want_ct,
                        &want_tag,
                        $tamper,
                        fuzzed(),
                    );
                }
                Err(e) => {
                    assert!(!backend.is_available(), "{backend:?}");
                    assert_eq!(e, Error::Unsupported);
                }
            }
        }
        // The run-time parameterised type agrees.
        let generic = AesCcm::new($key).expect("16-byte key");
        let mut buf = $pt.to_vec();
        let mut tag = vec![0u8; $tag_len];
        assert_eq!(
            generic.seal_in_place($nonce, $aad, &mut buf, &mut tag),
            Ok(())
        );
        assert_eq!((buf, tag), (want_ct, want_tag));
    }};
}

/// Every check of [`check_aead`] for [`Aes128Ccm8`].
#[allow(clippy::too_many_arguments)]
fn check_ccm8(
    what: &str,
    c: &Aes128Ccm8,
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
        |aad, buf| c.seal_in_place(nonce, aad, buf).map(|t| t.to_vec()),
        |aad, buf, tag| {
            let tag: &[u8; CCM8_TAG_LEN] = tag.try_into().map_err(|_| Error::DecryptFailed)?;
            c.open_in_place(nonce, aad, buf, tag)
        },
        aad,
        pt,
        want_ct,
        want_tag,
        tamper,
        fuzzed,
    );
}

fn op_ccm_tls(input: &mut Input<'_>) {
    let short_tag = input.bool();
    let key: [u8; 16] = input.array();
    let nonce: [u8; NONCE_LEN] = input.array();
    let aad = input.short_field();
    let pt = message(input);
    let tamper = input.u16();
    let bad = input.byte();
    let fct = input.field();
    let ftag: [u8; TAG_LEN] = input.array();
    let long_key = [key, key].concat();
    let bad_key = &long_key[..bad_len(bad, 16)];
    if short_tag {
        assert_eq!(Aes128Ccm8::KEY_LEN, 16);
        assert_eq!(Aes128Ccm8::TAG_LEN, CCM8_TAG_LEN);
        assert_eq!(Aes128Ccm8::new(bad_key).err(), Some(Error::InvalidKey));
        ccm_tls_variant!(
            Aes128Ccm8,
            CCM8_TAG_LEN,
            U8,
            &key,
            &nonce,
            aad,
            &pt,
            tamper,
            fct,
            ftag,
            Aes128Ccm8::new(&key).expect("16-byte key"),
            check_ccm8
        );
    } else {
        assert_eq!(
            <Aes128Ccm as Aead>::new(bad_key).err(),
            Some(Error::InvalidKey)
        );
        ccm_tls_variant!(
            Aes128Ccm,
            TAG_LEN,
            U16,
            &key,
            &nonce,
            aad,
            &pt,
            tamper,
            fct,
            ftag,
            <Aes128Ccm as Aead>::new(&key).expect("16-byte key"),
            check_typed
        );
    }
}

// ------------------------------------------------------------- ChaCha20

/// Reference ChaCha20 block function (RFC 8439, section 2.3).
fn chacha_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    }
    let word = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        init[4 + i] = word(&key[4 * i..]);
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = word(&nonce[4 * i..]);
    }
    let mut s = init;
    for _ in 0..10 {
        qr(&mut s, 0, 4, 8, 12);
        qr(&mut s, 1, 5, 9, 13);
        qr(&mut s, 2, 6, 10, 14);
        qr(&mut s, 3, 7, 11, 15);
        qr(&mut s, 0, 5, 10, 15);
        qr(&mut s, 1, 6, 11, 12);
        qr(&mut s, 2, 7, 8, 13);
        qr(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for (i, chunk) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *chunk = s[i].wrapping_add(init[i]).to_le_bytes();
    }
    out
}

/// Reference ChaCha20 encryption; the block counter wraps modulo 2^32 as
/// the library documents.
fn chacha_ref(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let ks = chacha_block(key, ctr, nonce);
        for (d, k) in chunk.iter_mut().zip(ks) {
            *d ^= k;
        }
        ctr = ctr.wrapping_add(1);
    }
}

fn op_chacha(input: &mut Input<'_>) {
    let key: [u8; chacha::KEY_LEN] = input.array();
    let counter = input.u32();
    let nonce: [u8; chacha::NONCE_LEN] = input.array();
    let data = message(input);
    let mut want = data.clone();
    chacha_ref(&key, counter, &nonce, &mut want);
    assert!(chacha::Backend::best().is_available());
    let got = across_policies(Algorithm::ChaCha20, || {
        let mut buf = data.clone();
        chacha::chacha20_xor(&key, counter, &nonce, &mut buf);
        buf
    });
    assert_eq!(got, want, "chacha20_xor");
    for backend in chacha::Backend::ALL {
        let mut buf = data.clone();
        match chacha::chacha20_xor_with(backend, &key, counter, &nonce, &mut buf) {
            Ok(()) => {
                assert!(backend.is_available(), "{backend:?}");
                assert_eq!(buf, want, "chacha20_xor_with {backend:?}");
                // The keystream is an involution.
                chacha::chacha20_xor_with(backend, &key, counter, &nonce, &mut buf)
                    .expect("available backend");
                assert_eq!(buf, data);
            }
            Err(e) => {
                assert!(!backend.is_available(), "{backend:?}");
                assert_eq!(e, Error::Unsupported);
                assert_eq!(buf, data, "unsupported backend touched the data");
            }
        }
    }
}

// ------------------------------------------------------------- Poly1305

/// Reference Poly1305 (RFC 8439, section 2.5) with big integers.
fn poly1305_ref(key: &[u8; POLY1305_KEY_LEN], msg: &[u8]) -> [u8; POLY1305_TAG_LEN] {
    let mut r = [0u8; 16];
    r.copy_from_slice(&key[..16]);
    for i in [3, 7, 11, 15] {
        r[i] &= 15;
    }
    for i in [4, 8, 12] {
        r[i] &= 252;
    }
    let r = BigUint::from_bytes_le(&r);
    let s = BigUint::from_bytes_le(&key[16..]);
    let p = (BigUint::from(1u32) << 130u32) - BigUint::from(5u32);
    let mut acc = BigUint::from(0u32);
    for block in msg.chunks(16) {
        let mut n = block.to_vec();
        n.push(1);
        acc = ((acc + BigUint::from_bytes_le(&n)) * &r) % &p;
    }
    let tag = (acc + s).to_bytes_le();
    let mut out = [0u8; 16];
    for (o, t) in out.iter_mut().zip(tag) {
        *o = t;
    }
    out
}

fn op_poly1305(input: &mut Input<'_>) {
    let key: [u8; POLY1305_KEY_LEN] = input.array();
    let msg = message(input);
    let plan = input.short_field();
    let bit = input.u16();
    let want = poly1305_ref(&key, &msg);
    assert!(PolyBackend::best().is_available());
    let parts = chunks(&msg, plan);
    let got = across_policies(Algorithm::Poly1305, || {
        let mut mac = Poly1305::new(&key);
        for part in &parts {
            mac.update(part);
        }
        mac.finalize()
    });
    assert_eq!(got, want, "Poly1305");
    let mut bad = want;
    bad[usize::from(bit / 8) % POLY1305_TAG_LEN] ^= 1 << (bit % 8);
    for backend in PolyBackend::ALL {
        let _ = backend.is_available();
        // An unavailable backend falls back to the portable code.
        let mut mac = Poly1305::with_backend(&key, backend);
        mac.update(&msg);
        assert_eq!(mac.finalize(), want, "Poly1305 {backend:?}");
        let mut mac = Poly1305::with_backend(&key, backend);
        for part in &parts {
            mac.update(part);
        }
        assert_eq!(mac.verify(&want), Ok(()), "Poly1305 verify {backend:?}");
        let mut mac = Poly1305::with_backend(&key, backend);
        mac.update(&msg);
        assert_eq!(mac.verify(&bad), Err(Error::InvalidSignature));
    }
}

// ---------------------------------------------------- ChaCha20-Poly1305

fn chacha_poly_ref_seal(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Vec<u8> {
    use chacha20poly1305::KeyInit as _;
    chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .encrypt_inout_detached(&(*nonce).into(), aad, buf.into())
        .expect("short message")
        .to_vec()
}

fn chacha_poly_ref_open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
) -> Option<Vec<u8>> {
    use chacha20poly1305::KeyInit as _;
    let mut buf = ct.to_vec();
    chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .decrypt_inout_detached(&(*nonce).into(), aad, (&mut buf[..]).into(), &(*tag).into())
        .ok()
        .map(|()| buf)
}

/// The AEAD composed from the public ChaCha20 and Poly1305 functions
/// (RFC 8439, section 2.8).
fn chacha_poly_compose(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut otk = [0u8; 32];
    chacha::chacha20_xor(key, 0, nonce, &mut otk);
    let mut ct = pt.to_vec();
    chacha::chacha20_xor(key, 1, nonce, &mut ct);
    let pad = |n: usize| vec![0u8; (16 - n % 16) % 16];
    let mut mac = Poly1305::new(&otk);
    mac.update(aad);
    mac.update(&pad(aad.len()));
    mac.update(&ct);
    mac.update(&pad(ct.len()));
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ct.len() as u64).to_le_bytes());
    ct.extend_from_slice(&mac.finalize());
    ct
}

fn op_chacha_poly(input: &mut Input<'_>) {
    let key: [u8; 32] = input.array();
    let nonce: [u8; NONCE_LEN] = input.array();
    let aad = input.short_field();
    let pt = message(input);
    let tamper = input.u16();
    let bad = input.byte();
    let fct = input.field();
    let ftag: [u8; TAG_LEN] = input.array();
    let (alternate, percent) = (input.byte(), input.byte());

    let mut want_ct = pt.clone();
    let want_tag = chacha_poly_ref_seal(&key, &nonce, aad, &mut want_ct);
    assert_eq!(
        chacha_poly_compose(&key, &nonce, aad, &pt),
        [&want_ct[..], &want_tag[..]].concat(),
        "ChaCha20-Poly1305 composed from its parts"
    );
    let fuzz_want = chacha_poly_ref_open(&key, &nonce, aad, fct, &ftag);
    let fuzzed = || Some((fct, &ftag[..], fuzz_want.clone()));

    let default = <ChaCha20Poly1305 as Aead>::new(&key).expect("32-byte key");
    assert_eq!(
        default.backends(),
        (chacha::Backend::best(), PolyBackend::best())
    );
    let what = "ChaCha20-Poly1305";
    check_typed(
        what,
        &default,
        &nonce,
        aad,
        &pt,
        &want_ct,
        &want_tag,
        tamper,
        fuzzed(),
    );
    // Load-aware routing moves records to another ChaCha20 backend and never
    // changes them: with a share fixed on an alternate, the key made above
    // and one made now give the records made above without routing
    // (`want_ct`, `want_tag`), open them and reject what was rejected.
    with_fixed_share(Algorithm::ChaCha20, alternate, percent, || {
        let fresh = <ChaCha20Poly1305 as Aead>::new(&key).expect("32-byte key");
        for (what, aead) in [
            ("ChaCha20-Poly1305 routed", &default),
            ("ChaCha20-Poly1305 routed, new key", &fresh),
        ] {
            check_typed(
                what,
                aead,
                &nonce,
                aad,
                &pt,
                &want_ct,
                &want_tag,
                tamper,
                fuzzed(),
            );
        }
    });
    let long_key = [key, key].concat();
    let bad_key = &long_key[..bad_len(bad, 32)];
    assert_eq!(
        <ChaCha20Poly1305 as Aead>::new(bad_key).err(),
        Some(Error::InvalidKey)
    );
    assert_eq!(
        ChaCha20Poly1305::with_backends(bad_key, chacha::Backend::Soft, PolyBackend::Soft).err(),
        Some(Error::InvalidKey)
    );
    for cb in chacha::Backend::ALL {
        for pb in PolyBackend::ALL {
            match ChaCha20Poly1305::with_backends(&key, cb, pb) {
                Ok(c) => {
                    assert!(cb.is_available() && pb.is_available(), "{cb:?}/{pb:?}");
                    assert_eq!(c.backends(), (cb, pb));
                    let what = format!("ChaCha20-Poly1305 {cb:?}/{pb:?}");
                    check_typed(
                        &what,
                        &c,
                        &nonce,
                        aad,
                        &pt,
                        &want_ct,
                        &want_tag,
                        tamper,
                        fuzzed(),
                    );
                }
                Err(e) => {
                    assert!(!(cb.is_available() && pb.is_available()), "{cb:?}/{pb:?}");
                    assert_eq!(e, Error::Unsupported);
                }
            }
        }
    }
}

// -------------------------------------------------------------- AES-CBC

/// CBC with the RustCrypto `cbc` crate (`buf` a whole number of blocks).
fn cbc_ref(key: &[u8], iv: &[u8; 16], buf: &mut [u8], encrypt: bool) {
    macro_rules! go {
        ($c:ty) => {{
            if encrypt {
                let mut e = cbc::Encryptor::<$c>::new_from_slices(key, iv).expect("valid lengths");
                for block in buf.as_chunks_mut::<16>().0 {
                    e.encrypt_block(block.into());
                }
            } else {
                let mut d = cbc::Decryptor::<$c>::new_from_slices(key, iv).expect("valid lengths");
                for block in buf.as_chunks_mut::<16>().0 {
                    d.decrypt_block(block.into());
                }
            }
        }};
    }
    if key.len() == 16 {
        go!(::aes::Aes128);
    } else {
        go!(::aes::Aes256);
    }
}

fn op_cbc(input: &mut Input<'_>) {
    let key_sel = input.byte();
    let key: [u8; 32] = input.array();
    let iv: [u8; 16] = input.array();
    let buf = message(input);
    let fct = input.field();
    let key = match key_sel % 4 {
        0 | 1 => &key[..16],
        2 => &key[..],
        _ => &key[..bad_len(key_sel >> 2, 16)],
    };
    let key_ok = key.len() == 16 || key.len() == 32;
    match AesCbcKey::new(key) {
        Ok(c) => {
            assert!(key_ok);
            assert_eq!(c.backend(), aes::Backend::select());
        }
        Err(e) => {
            assert!(!key_ok);
            assert_eq!(e, Error::InvalidKey);
            return;
        }
    }
    let aligned = buf.len().is_multiple_of(16);
    let mut want = buf.clone();
    if aligned {
        cbc_ref(key, &iv, &mut want, true);
    }
    let fct = &fct[..fct.len() / 16 * 16];
    let mut want_fuzz = fct.to_vec();
    cbc_ref(key, &iv, &mut want_fuzz, false);
    for backend in aes::Backend::ALL {
        let c = match AesCbcKey::with_backend(key, backend) {
            Ok(c) => c,
            Err(e) => {
                assert!(!backend.is_available(), "{backend:?}");
                assert_eq!(e, Error::Unsupported);
                continue;
            }
        };
        assert!(backend.is_available(), "{backend:?}");
        assert_eq!(c.backend(), backend);
        let mut b = buf.clone();
        if !aligned {
            assert_eq!(c.encrypt(&iv, &mut b), Err(Error::InvalidLength));
            assert_eq!(c.decrypt(&iv, &mut b), Err(Error::InvalidLength));
            assert_eq!(b, buf, "a rejected buffer was modified");
            continue;
        }
        assert_eq!(c.encrypt(&iv, &mut b), Ok(()));
        assert_eq!(b, want, "AES-CBC encrypt {backend:?}");
        assert_eq!(c.decrypt(&iv, &mut b), Ok(()));
        assert_eq!(b, buf, "AES-CBC round trip {backend:?}");
        let mut f = fct.to_vec();
        assert_eq!(c.decrypt(&iv, &mut f), Ok(()));
        assert_eq!(f, want_fuzz, "AES-CBC decrypt {backend:?}");
    }
}

// ----------------------------------------------------------- TLS 1.2 CBC

const MACS: [MacAlgorithm; 3] = [
    MacAlgorithm::HmacSha1,
    MacAlgorithm::HmacSha256,
    MacAlgorithm::HmacSha384,
];

/// The record MAC with the RustCrypto `hmac` crate.
fn tls_mac_ref(alg: MacAlgorithm, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    macro_rules! go {
        ($h:ty) => {{
            let mut m = hmac::Hmac::<$h>::new_from_slice(key).expect("any key length");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        MacAlgorithm::HmacSha1 => go!(sha1::Sha1),
        MacAlgorithm::HmacSha256 => go!(sha2::Sha256),
        MacAlgorithm::HmacSha384 => go!(sha2::Sha384),
    }
}

/// The parameters of one TLS 1.2 CBC record.
struct Record<'a> {
    alg: MacAlgorithm,
    order: MacOrder,
    aes_key: &'a [u8],
    mac_key: &'a [u8],
    seq: u64,
    content_type: u8,
    version: [u8; 2],
    iv: [u8; 16],
}

impl Record<'_> {
    fn header(&self, len: usize) -> Vec<u8> {
        let mut h = self.seq.to_be_bytes().to_vec();
        h.push(self.content_type);
        h.extend_from_slice(&self.version);
        h.extend_from_slice(&u16::try_from(len).expect("record length").to_be_bytes());
        h
    }

    /// The protected fragment built independently (RFC 5246 section
    /// 6.2.3.2, RFC 7366 section 3) with `pad` bytes of padding including
    /// the length byte. `corrupt` changes padding byte `corrupt % (pad - 1)`
    /// (the length byte stays intact) when `pad > 1`.
    fn seal(&self, pt: &[u8], pad: usize, corrupt: Option<usize>) -> Vec<u8> {
        let value = u8::try_from(pad - 1).expect("at most 256 bytes of padding");
        let mut padding = vec![value; pad];
        if let Some(i) = corrupt
            && pad > 1
        {
            padding[i % (pad - 1)] ^= 0x40;
        }
        let mut out = self.iv.to_vec();
        match self.order {
            MacOrder::MacThenEncrypt => {
                let mac = tls_mac_ref(self.alg, self.mac_key, &[&self.header(pt.len()), pt]);
                let mut body = [pt, &mac[..], &padding[..]].concat();
                cbc_ref(self.aes_key, &self.iv, &mut body, true);
                out.extend_from_slice(&body);
            }
            MacOrder::EncryptThenMac => {
                let mut body = [pt, &padding[..]].concat();
                cbc_ref(self.aes_key, &self.iv, &mut body, true);
                out.extend_from_slice(&body);
                let mac = tls_mac_ref(self.alg, self.mac_key, &[&self.header(out.len()), &out]);
                out.extend_from_slice(&mac);
            }
        }
        out
    }
}

/// Opens `frag` and asserts the documented failure: `DecryptFailed` and a
/// wiped buffer.
fn assert_record_rejected<C: browntls_crypto::tls_cbc::CbcBlockCipher>(
    key: &RecordKey<C>,
    r: &Record<'_>,
    seq: u64,
    mut frag: Vec<u8>,
    what: &str,
) {
    let res = key.open(seq, r.content_type, r.version, &mut frag);
    assert_eq!(res, Err(Error::DecryptFailed), "{what}");
    assert!(frag.iter().all(|&b| b == 0), "{what}: buffer not wiped");
}

fn op_tls_cbc(input: &mut Input<'_>) {
    let alg = *input.pick(&MACS);
    let order = if input.bool() {
        MacOrder::EncryptThenMac
    } else {
        MacOrder::MacThenEncrypt
    };
    let wide = input.bool();
    let backend_sel = input.byte();
    let aes_key_bytes: [u8; 32] = input.array();
    let own_mac_key = input.bool();
    let mac_key_field = input.short_field();
    let seq = input.u64();
    let content_type = input.byte();
    let version: [u8; 2] = input.array();
    let iv: [u8; 16] = input.array();
    // Plaintexts up to a little beyond the 2^14-byte limit.
    let mut pt = input.field().to_vec();
    let ext = usize::from(input.byte()) * 67;
    pt.extend((0..ext).map(|i| (i % 249) as u8));
    let slack = input.byte();
    let extra = input.byte();
    let tamper = input.u16();
    let fuzzed = input.field();

    let h = alg.mac_len();
    let mac_key_pattern: Vec<u8> = (0..h).map(|i| (i as u8) ^ 0x3c).collect();
    let mac_key = if own_mac_key {
        mac_key_field
    } else {
        &mac_key_pattern
    };
    let aes_key = aes_key(&aes_key_bytes, wide);
    let available: Vec<aes::Backend> = aes::Backend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect();
    let backend = available[usize::from(backend_sel) % available.len()];
    let cipher = AesCbcKey::with_backend(aes_key, backend).expect("available backend");
    let key = match RecordKey::new(cipher, alg, mac_key, order) {
        Ok(key) => {
            assert_eq!(mac_key.len(), h);
            key
        }
        Err(e) => {
            assert_ne!(mac_key.len(), h);
            assert_eq!(e, Error::InvalidKey);
            return;
        }
    };
    assert_eq!(key.mac_algorithm(), alg);
    assert_eq!(key.mac_order(), order);
    assert_eq!(key.mac_len(), h);
    assert_eq!(h, tls_mac_ref(alg, b"", &[]).len());
    let r = Record {
        alg,
        order,
        aes_key,
        mac_key,
        seq,
        content_type,
        version,
        iv,
    };

    // Arbitrary fragments: never a panic; a failure wipes the buffer.
    let mut frag = fuzzed.to_vec();
    match key.open(seq, content_type, version, &mut frag) {
        Ok(range) => {
            assert!(range.start >= IV_LEN && range.end <= frag.len());
            assert!(range.len() <= MAX_PLAINTEXT_LEN);
        }
        Err(e) => {
            assert_eq!(e, Error::DecryptFailed);
            assert!(frag.iter().all(|&b| b == 0), "fuzzed fragment not wiped");
        }
    }

    pt.truncate(MAX_PLAINTEXT_LEN + 64);
    let n = pt.len();
    let round_up = |x: usize| x.div_ceil(16) * 16;
    let sealed_len = match order {
        MacOrder::MacThenEncrypt => IV_LEN + round_up(n + h + 1),
        MacOrder::EncryptThenMac => IV_LEN + round_up(n + 1) + h,
    };
    assert_eq!(key.sealed_len(n), sealed_len);
    let buf_len = if slack & 0x80 != 0 {
        sealed_len - (usize::from(slack & 0x0f) + 1)
    } else {
        sealed_len + usize::from(slack & 0x3f)
    };
    let mut buf = vec![0u8; buf_len.max(IV_LEN + n)];
    buf[IV_LEN..IV_LEN + n].copy_from_slice(&pt);
    let res = key.seal(seq, content_type, version, &iv, &mut buf, n);
    if n > MAX_PLAINTEXT_LEN || buf_len < sealed_len {
        assert_eq!(res, Err(Error::InvalidLength));
        return;
    }
    assert_eq!(res, Ok(sealed_len));
    let minimal = sealed_len - IV_LEN - n - h;
    let want = r.seal(&pt, minimal, None);
    assert_eq!(&buf[..sealed_len], &want[..], "sealed record");

    let mut rec = want.clone();
    let range = key.open(seq, content_type, version, &mut rec);
    assert_eq!(range, Ok(IV_LEN..IV_LEN + n), "open");
    assert_eq!(&rec[IV_LEN..IV_LEN + n], &pt[..]);

    // Extra padding blocks (up to 256 bytes of padding in all).
    let pad = minimal + 16 * (usize::from(extra) % ((256 - minimal) / 16 + 1));
    let padded = r.seal(&pt, pad, None);
    if padded.len() <= MAX_FRAGMENT_LEN {
        let mut rec = padded.clone();
        let range = key.open(seq, content_type, version, &mut rec);
        assert_eq!(
            range,
            Ok(IV_LEN..IV_LEN + n),
            "open with {pad} bytes of padding"
        );
        assert_eq!(&rec[IV_LEN..IV_LEN + n], &pt[..]);
        if pad > 1 {
            let bad = r.seal(&pt, pad, Some(usize::from(tamper)));
            assert_record_rejected(&key, &r, seq, bad, "bad padding");
        }
    }

    // A flipped bit anywhere, or another sequence number, is rejected.
    let mut bad = want.clone();
    flip(&mut [&mut bad], tamper);
    assert_record_rejected(&key, &r, seq, bad, "tampered record");
    assert_record_rejected(
        &key,
        &r,
        seq ^ (1 << (tamper % 64)),
        want.clone(),
        "wrong sequence number",
    );
    // A record whose MAC was computed under another key is rejected.
    let mut other_key = mac_key.to_vec();
    other_key[usize::from(tamper) % h] ^= 1;
    let other = Record {
        mac_key: &other_key,
        ..r
    };
    let forged = other.seal(&pt, minimal, None);
    assert_record_rejected(&key, &other, seq, forged, "MAC under another key");
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

        // AES-GCM, with a fuzzed record.
        let mut s = vec![OP_GCM, wide];
        s.extend_from_slice(key);
        s.extend_from_slice(&bytes[50..62]);
        put_short_field(&mut s, &bytes[..13]);
        put_field(&mut s, &bytes[..40]);
        s.push(0);
        s.extend_from_slice(&[1, 7, 24]);
        put_field(&mut s, &bytes[..5]);
        s.extend_from_slice(&bytes[..16]);
        seeds.push(s);
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
    seeds
}
