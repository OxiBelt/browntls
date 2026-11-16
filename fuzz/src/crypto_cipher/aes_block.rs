//! AES blocks and CTR keystreams (`aes`) and AES-CBC (`cbc`) of the
//! `crypto_cipher` target, checked against the RustCrypto `aes` and `cbc`
//! crates on every AES backend.

use ::aes::cipher::{BlockCipherEncrypt as _, BlockModeDecrypt as _, BlockModeEncrypt as _};
use ::aes::cipher::{KeyInit as _, KeyIvInit as _};
use browntls_crypto::Error;
use browntls_crypto::accel::Algorithm;
use browntls_crypto::aes::{self, Aes128, Aes256, BLOCK_LEN};
use browntls_crypto::cbc::AesCbcKey;

use super::bad_len;
use crate::crypto_hash::{across_policies, message};
use crate::input::Input;

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

pub(super) fn op_aes(input: &mut Input<'_>) {
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

// -------------------------------------------------------------- AES-CBC

/// CBC with the RustCrypto `cbc` crate (`buf` a whole number of blocks).
pub(super) fn cbc_ref(key: &[u8], iv: &[u8; 16], buf: &mut [u8], encrypt: bool) {
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

pub(super) fn op_cbc(input: &mut Input<'_>) {
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
