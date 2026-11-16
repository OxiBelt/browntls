//! AES-GCM (`gcm`) and AES-CCM (`ccm`: every SP 800-38C parameter set, and
//! the AES-128-CCM and CCM_8 types of TLS) of the `crypto_cipher` target,
//! checked against the RustCrypto `aes-gcm` and `ccm` crates.

use ::aes::cipher::KeyInit as _;
use aes_gcm::AeadInOut as _;
use browntls_crypto::Error;
use browntls_crypto::accel::Algorithm;
use browntls_crypto::aead::{Aead, NONCE_LEN, TAG_LEN};
use browntls_crypto::aes;
use browntls_crypto::ccm::{
    Aes128Ccm, Aes128Ccm8, AesCcm, CCM8_TAG_LEN, MAX_NONCE_LEN, MIN_NONCE_LEN,
};
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm, GhashBackend};
use ccm::aead::consts::{U4, U6, U7, U8, U9, U10, U11, U12, U13, U14, U16};

use super::{Fuzzed, bad_len, check_aead, check_typed};
use crate::crypto_hash::{message, with_fixed_share};
use crate::input::Input;

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

macro_rules! gcm_op {
    ($ty:ty, $len:literal, $key:expr, $nonce:expr, $aad:expr, $pt:expr, $tamper:expr,
     $bad:expr, $fct:expr, $ftag:expr, $alternate:expr, $percent:expr) => {{
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
        // Load-aware routing moves records to another AES backend, with the
        // GHASH backend that goes with it, and never changes them. A key
        // holds its key expanded for the alternates only if it was created
        // while routing was enabled: with a share fixed on an alternate, a
        // key made now and the one made above give the records made above
        // without routing (`want_ct`, `want_tag`), open them and reject
        // what was rejected; so does the new key once routing is off again.
        let routed = with_fixed_share(Algorithm::Aes, $alternate, $percent, || {
            let routed = <$ty as Aead>::new(key).expect("valid key length");
            assert_eq!(routed.backends(), default.backends());
            for (what, aead) in [
                ("AES-GCM routed", &routed),
                ("AES-GCM routed, earlier key", &default),
            ] {
                check_typed(
                    what,
                    aead,
                    $nonce,
                    $aad,
                    $pt,
                    &want_ct,
                    &want_tag,
                    $tamper,
                    fuzzed(),
                );
            }
            routed
        });
        check_typed(
            "AES-GCM, routing off again",
            &routed,
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

pub(super) fn op_gcm(input: &mut Input<'_>) {
    let wide = input.bool();
    let key: [u8; 32] = input.array();
    let nonce: [u8; NONCE_LEN] = input.array();
    let aad = input.short_field();
    let pt = message(input);
    let tamper = input.u16();
    let bad = input.byte();
    let fct = input.field();
    let ftag: [u8; TAG_LEN] = input.array();
    let (alternate, percent) = (input.byte(), input.byte());
    assert!(GhashBackend::select().is_available());
    if wide {
        gcm_op!(
            Aes256Gcm, 32, key, &nonce, aad, &pt, tamper, bad, fct, &ftag, alternate, percent
        );
    } else {
        gcm_op!(
            Aes128Gcm, 16, key, &nonce, aad, &pt, tamper, bad, fct, &ftag, alternate, percent
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

pub(super) fn op_ccm(input: &mut Input<'_>) {
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

pub(super) fn op_ccm_tls(input: &mut Input<'_>) {
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
