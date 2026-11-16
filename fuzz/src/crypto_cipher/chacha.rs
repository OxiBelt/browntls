//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (`chacha`) of the
//! `crypto_cipher` target, checked against a reference block function, a
//! big-integer Poly1305 and the RustCrypto `chacha20poly1305` crate.

use aes_gcm::AeadInOut as _;
use browntls_crypto::Error;
use browntls_crypto::accel::Algorithm;
use browntls_crypto::aead::{Aead, NONCE_LEN, TAG_LEN};
use browntls_crypto::chacha::{
    self, ChaCha20Poly1305, POLY1305_KEY_LEN, POLY1305_TAG_LEN, Poly1305, PolyBackend,
};
use num_bigint::BigUint;

use super::{bad_len, check_typed};
use crate::crypto_hash::{across_policies, chunks, message, with_fixed_share};
use crate::input::Input;

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

pub(super) fn op_chacha(input: &mut Input<'_>) {
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

pub(super) fn op_poly1305(input: &mut Input<'_>) {
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

pub(super) fn op_chacha_poly(input: &mut Input<'_>) {
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
