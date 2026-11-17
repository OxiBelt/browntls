//! Standalone GHASH (`gcm::Ghash`) of the `crypto_cipher` target, checked
//! against a bit-serial reference (SP 800-38D, Algorithms 1 and 2) for a
//! fuzzed hash subkey, and through the AES-GCM tag relation
//! `tag = GHASH_H(A, C) xor E_K(J0)` against the RustCrypto `aes` and
//! `aes-gcm` crates.

use ::aes::cipher::{BlockCipherEncrypt as _, KeyInit as _};
use aes_gcm::AeadInOut as _;
use browntls_crypto::accel::Algorithm;
use browntls_crypto::gcm::{GHASH_BLOCK_LEN, Ghash, GhashBackend};

use crate::crypto_hash::{across_policies, chunks, message};
use crate::input::Input;

type Block = [u8; GHASH_BLOCK_LEN];

/// Multiplication in GF(2^128), bit by bit (SP 800-38D, Algorithm 1).
fn gf_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe1 << 120;
    let mut z = 0;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    z
}

/// `GHASH_H` of `data` zero-padded to whole blocks (SP 800-38D,
/// Algorithm 2).
fn reference(h: &Block, data: &[u8]) -> Block {
    let hk = u128::from_be_bytes(*h);
    let mut y = 0u128;
    for chunk in data.chunks(GHASH_BLOCK_LEN) {
        let mut b = [0u8; GHASH_BLOCK_LEN];
        b[..chunk.len()].copy_from_slice(chunk);
        y = gf_mul(y ^ u128::from_be_bytes(b), hk);
    }
    y.to_be_bytes()
}

/// `x` zero-padded to whole blocks.
fn padded(x: &[u8]) -> Vec<u8> {
    let mut v = x.to_vec();
    v.resize(x.len().next_multiple_of(GHASH_BLOCK_LEN), 0);
    v
}

/// GCM's length block: the bit lengths of `a` and `c`, big-endian.
fn lengths(a: &[u8], c: &[u8]) -> Block {
    let mut l = [0u8; GHASH_BLOCK_LEN];
    l[..8].copy_from_slice(&(8 * a.len() as u64).to_be_bytes());
    l[8..].copy_from_slice(&(8 * c.len() as u64).to_be_bytes());
    l
}

/// `GHASH_H(A, C)` as GCM computes it, with `g`.
fn ghash_gcm(mut g: Ghash, a: &[u8], c: &[u8]) -> Block {
    g.update_padded(a);
    g.update_padded(c);
    g.update_blocks(&[lengths(a, c)]);
    g.finalize()
}

/// The ways of feeding GCM's GHASH input to one backend agree with `want`:
/// whole padded fields; each field streamed in the planned chunks and
/// ended by an empty `update_padded`; the whole blocks of the ciphertext
/// as blocks; the last chunk of each field padded by `update_padded`. A
/// plain stream of both fields equals the reference of their
/// concatenation.
fn check_backend(h: &Block, backend: GhashBackend, a: &[u8], c: &[u8], plan: &[u8], want: &Block) {
    let g = Ghash::with_backend(h, backend);
    // An unavailable backend falls back to the portable code.
    let used = if backend.is_available() {
        backend
    } else {
        GhashBackend::Soft
    };
    assert_eq!(g.backend(), used, "GHASH {backend:?}");
    assert_eq!(
        format!("{g:?}"),
        format!("Ghash {{ backend: {used:?}, .. }}")
    );
    assert_eq!(
        &ghash_gcm(g, a, c),
        want,
        "GHASH {backend:?}: padded fields"
    );

    let mut g = Ghash::with_backend(h, backend);
    for field in [a, c] {
        for part in chunks(field, plan) {
            g.update(part);
        }
        g.update_padded(&[]);
    }
    g.update(&lengths(a, c));
    assert_eq!(&g.finalize(), want, "GHASH {backend:?}: streamed");

    let mut g = Ghash::with_backend(h, backend);
    g.update_padded(a);
    let (blocks, rest) = c.as_chunks::<GHASH_BLOCK_LEN>();
    g.update_blocks(blocks);
    g.update_padded(rest);
    g.update_blocks(&[lengths(a, c)]);
    assert_eq!(&g.finalize(), want, "GHASH {backend:?}: blocks");

    let mut g = Ghash::with_backend(h, backend);
    for field in [a, c] {
        let parts = chunks(field, plan);
        let (last, init) = parts.split_last().expect("at least one chunk");
        for part in init {
            g.update(part);
        }
        g.update_padded(last);
    }
    g.update_blocks(&[lengths(a, c)]);
    assert_eq!(&g.finalize(), want, "GHASH {backend:?}: padded last chunk");

    let mut g = Ghash::with_backend(h, backend);
    let mut both = a.to_vec();
    both.extend_from_slice(c);
    for part in chunks(&both, plan) {
        g.update(part);
    }
    assert_eq!(
        g.finalize(),
        reference(h, &both),
        "GHASH {backend:?}: stream"
    );
}

/// `H = E_K(0^128)` and `E_K(J0)` for `J0 = nonce || 0^31 || 1`, from the
/// RustCrypto `aes` crate.
fn aes_h_and_mask(key: &[u8], nonce: &[u8; 12]) -> (Block, Block) {
    let mut h = [0u8; GHASH_BLOCK_LEN];
    let mut mask = [0u8; GHASH_BLOCK_LEN];
    mask[..12].copy_from_slice(nonce);
    mask[15] = 1;
    macro_rules! go {
        ($c:ty) => {{
            let aes = <$c>::new_from_slice(key).expect("16- or 32-byte key");
            aes.encrypt_block((&mut h).into());
            aes.encrypt_block((&mut mask).into());
        }};
    }
    if key.len() == 16 {
        go!(::aes::Aes128);
    } else {
        go!(::aes::Aes256);
    }
    (h, mask)
}

/// The AES-GCM tag of the RustCrypto `aes-gcm` crate for `aad` and `pt`,
/// and the ciphertext.
fn aes_gcm_tag(key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> (Vec<u8>, Block) {
    let mut ct = pt.to_vec();
    let nonce = (*nonce).into();
    let tag = if key.len() == 16 {
        aes_gcm::Aes128Gcm::new_from_slice(key)
            .expect("16-byte key")
            .encrypt_inout_detached(&nonce, aad, (&mut ct[..]).into())
    } else {
        aes_gcm::Aes256Gcm::new_from_slice(key)
            .expect("32-byte key")
            .encrypt_inout_detached(&nonce, aad, (&mut ct[..]).into())
    }
    .expect("short message");
    (ct, tag.into())
}

/// GHASH: hash subkey (16), AAD (8-bit field), ciphertext (message), chunk
/// plan (8-bit field), width, AES key (32), nonce (12).
pub(super) fn op_ghash(input: &mut Input<'_>) {
    let h: Block = input.array();
    let aad = input.short_field();
    let msg = message(input);
    let plan = input.short_field();
    let wide = input.bool();
    let key: [u8; 32] = input.array();
    let nonce: [u8; 12] = input.array();

    let mut x = padded(aad);
    x.extend(padded(&msg));
    x.extend(lengths(aad, &msg));
    let want = reference(&h, &x);
    assert!(GhashBackend::select().is_available());
    let got = across_policies(Algorithm::Ghash, || {
        let g = Ghash::new(&h);
        assert!(g.backend().is_available());
        ghash_gcm(g, aad, &msg)
    });
    assert_eq!(got, want, "GHASH");
    for backend in GhashBackend::ALL {
        check_backend(&h, backend, aad, &msg, plan, &want);
    }

    // The AES-GCM relation, with `msg` as the plaintext.
    let key = if wide { &key[..] } else { &key[..16] };
    let (hk, mask) = aes_h_and_mask(key, &nonce);
    let (ct, tag) = aes_gcm_tag(key, &nonce, aad, &msg);
    let mut s = ghash_gcm(Ghash::new(&hk), aad, &ct);
    for (s, m) in s.iter_mut().zip(mask) {
        *s ^= m;
    }
    assert_eq!(s, tag, "GHASH: AES-GCM tag relation");
}
