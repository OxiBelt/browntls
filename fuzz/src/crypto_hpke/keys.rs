//! Identifier and key operations of the `crypto_hpke` target: KEM, KDF,
//! AEAD and mode lookups, and key derivation, (de)serialization and
//! generation against the `hpke` oracle.

use browntls_core::crypto::hpke::{HpkeAead, HpkeKdf, HpkeKem};
use browntls_crypto::Error;
use browntls_crypto::hpke::{
    Aead, Kdf, Kem, MAX_ENC_LEN, MAX_PKCS8_DER_LEN, MAX_PRIVATE_KEY_LEN, MAX_PUBLIC_KEY_LEN,
    MIN_PSK_LEN, Mode, NONCE_LEN, PrivateKey, PublicKey, Suite, TAG_LEN,
};
use browntls_crypto::rand::{FixedRng, OsRng};
use browntls_crypto::zeroize::Zeroizing;
use hpke::{Deserializable as _, Serializable as _};

use super::{exact, mutate};
use crate::input::Input;

/// A fuzzed identifier: mostly near the assigned ranges.
fn id(input: &mut Input<'_>) -> u16 {
    match input.choose(4) {
        0 => input.u16(),
        1 => 0xff00 | u16::from(input.byte()),
        _ => u16::from(input.byte() % 0x24),
    }
}

/// Identifier lookups and length accessors.
pub(super) fn ids(input: &mut Input<'_>) {
    let (k, f, a) = (id(input), id(input), id(input));
    let kem = Kem::from_id(k);
    let kdf = Kdf::from_id(f);
    let aead = Aead::from_id(a);
    assert_eq!(kem, Kem::ALL.into_iter().find(|x| x.id() == k));
    assert_eq!(kdf, Kdf::ALL.into_iter().find(|x| x.id() == f));
    assert_eq!(aead, Aead::ALL.into_iter().find(|x| x.id() == a));
    let suite = Suite::from_ids(k, f, a);
    match (kem, kdf, aead) {
        (Some(kem), Some(kdf), Some(aead)) => {
            assert_eq!(suite, Some(Suite::new(kem, kdf, aead)));
        }
        _ => assert_eq!(suite, None),
    }
    // A mode identifier (RFC 9180 Table 1): bit 0 is the PSK, bit 1 the
    // sender key.
    let m = input.byte();
    let mode = Mode::from_id(m);
    assert_eq!(mode, Mode::ALL.into_iter().find(|x| x.id() == m));
    assert_eq!(mode.map(Mode::id), (m <= 3).then_some(m));
    assert_eq!(mode.map(Mode::uses_psk), (m <= 3).then_some(m & 1 != 0));
    assert_eq!(
        mode.map(Mode::uses_sender_key),
        (m <= 3).then_some(m & 2 != 0)
    );
    for (mode, id) in Mode::ALL.into_iter().zip(0u8..) {
        assert_eq!(mode.id(), id);
        assert_eq!(Mode::from_id(id), Some(mode));
        assert_eq!(mode.uses_psk(), matches!(mode, Mode::Psk | Mode::AuthPsk));
        assert_eq!(
            mode.uses_sender_key(),
            matches!(mode, Mode::Auth | Mode::AuthPsk)
        );
    }
    assert_eq!(Mode::ALL.len(), 4);
    assert_eq!(MIN_PSK_LEN, 32);
    // The TLS-side identifier types.
    let tag_len = HpkeAead(a).tag_len();
    assert_eq!(
        tag_len,
        aead.filter(|x| *x != Aead::ExportOnly).map(Aead::tag_len)
    );
    assert_eq!(
        tag_len.is_some(),
        HpkeAead(a) != HpkeAead::EXPORT_ONLY && aead.is_some()
    );

    for kem in Kem::ALL {
        assert_eq!(Kem::from_id(kem.id()), Some(kem));
        assert_eq!(kem.enc_len(), kem.public_key_len());
        assert!(kem.public_key_len() <= MAX_PUBLIC_KEY_LEN);
        assert!(kem.enc_len() <= MAX_ENC_LEN);
        assert!(kem.private_key_len() <= MAX_PRIVATE_KEY_LEN);
        assert_eq!(kem.shared_secret_len(), kem.kdf().output_len());
        assert_eq!(Kdf::from_id(kem.kdf().id()), Some(kem.kdf()));
    }
    for (kem, tls) in Kem::ALL.into_iter().zip([
        HpkeKem::DHKEM_P256_HKDF_SHA256,
        HpkeKem::DHKEM_P384_HKDF_SHA384,
        HpkeKem::DHKEM_P521_HKDF_SHA512,
        HpkeKem::DHKEM_X25519_HKDF_SHA256,
        HpkeKem::DHKEM_X448_HKDF_SHA512,
    ]) {
        assert_eq!(kem.id(), tls.0);
    }
    for (kdf, tls) in Kdf::ALL.into_iter().zip([
        HpkeKdf::HKDF_SHA256,
        HpkeKdf::HKDF_SHA384,
        HpkeKdf::HKDF_SHA512,
    ]) {
        assert_eq!(kdf.id(), tls.0);
        assert!(kdf.output_len() <= 64);
    }
    for (aead, tls) in Aead::ALL.into_iter().zip([
        HpkeAead::AES_128_GCM,
        HpkeAead::AES_256_GCM,
        HpkeAead::CHACHA20_POLY_1305,
        HpkeAead::EXPORT_ONLY,
    ]) {
        assert_eq!(aead.id(), tls.0);
        if aead == Aead::ExportOnly {
            assert_eq!(
                (aead.key_len(), aead.nonce_len(), aead.tag_len()),
                (0, 0, 0)
            );
            assert_eq!(tls.tag_len(), None);
        } else {
            assert_eq!((aead.nonce_len(), aead.tag_len()), (NONCE_LEN, TAG_LEN));
            assert!(aead.key_len() == 16 || aead.key_len() == 32);
            assert_eq!(tls.tag_len(), Some(TAG_LEN));
        }
    }
}

/// RFC 7748 clamping, as RFC 9180 §7.1.2 serializes X25519 keys.
fn clamp_x25519(k: &mut [u8]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// The `hpke` crate's view of one KEM.
trait KemOracle {
    /// `DeriveKeyPair(ikm)`: serialized private and public keys.
    fn derive(&self, ikm: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// The public key of a private key, if the private key is valid.
    fn private_key(&self, sk: &[u8]) -> Option<Vec<u8>>;
    /// Whether a public key is valid.
    fn public_key(&self, pk: &[u8]) -> bool;
}

struct KemO<K>(core::marker::PhantomData<K>);

impl<K: hpke::Kem> KemOracle for KemO<K> {
    fn derive(&self, ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = K::derive_keypair(ikm);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
    }

    fn private_key(&self, sk: &[u8]) -> Option<Vec<u8>> {
        let sk = K::PrivateKey::from_bytes(sk).ok()?;
        Some(K::sk_to_pk(&sk).to_bytes().to_vec())
    }

    fn public_key(&self, pk: &[u8]) -> bool {
        K::PublicKey::from_bytes(pk).is_ok()
    }
}

fn kem_oracle(kem: Kem) -> Option<Box<dyn KemOracle>> {
    fn o<K: hpke::Kem + 'static>() -> Option<Box<dyn KemOracle>> {
        Some(Box::new(KemO::<K>(core::marker::PhantomData)))
    }
    match kem {
        Kem::DhP256HkdfSha256 => o::<hpke::kem::DhP256HkdfSha256>(),
        Kem::DhP384HkdfSha384 => o::<hpke::kem::DhP384HkdfSha384>(),
        Kem::DhP521HkdfSha512 => o::<hpke::kem::DhP521HkdfSha512>(),
        Kem::DhX25519HkdfSha256 => o::<hpke::kem::X25519HkdfSha256>(),
        // The oracle has no X448.
        _ => None,
    }
}

/// Our private key serialization, `Nsk` bytes.
pub(super) fn private_bytes(sk: &PrivateKey) -> Vec<u8> {
    let mut out = vec![0u8; sk.kem().private_key_len()];
    let n = sk.write_bytes(&mut out).expect("Nsk bytes");
    assert_eq!(n, out.len());
    out
}

/// Key derivation, (de)serialization and generation.
pub(super) fn keys(input: &mut Input<'_>) {
    let kem = *input.pick(&Kem::ALL);
    let nsk = kem.private_key_len();
    let oracle = kem_oracle(kem);
    match input.choose(5) {
        0 => {
            let ikm = input.short_field();
            let sk = match kem.derive_key_pair(ikm) {
                Ok(sk) => sk,
                Err(e) => {
                    assert_eq!(e, Error::InvalidLength);
                    assert!(ikm.len() < nsk);
                    return;
                }
            };
            assert!(ikm.len() >= nsk);
            assert_eq!(sk.kem(), kem);
            assert_eq!(sk.public_key().kem(), kem);
            assert_eq!(sk.public_key().as_bytes().len(), kem.public_key_len());
            let bytes = private_bytes(&sk);
            if let Some(oracle) = oracle {
                // `hpke` 0.15 serializes X25519 private keys clamped, as
                // RFC 9180 §7.1.2 does, so the encodings compare directly.
                let (their_sk, their_pk) = oracle.derive(ikm);
                assert_eq!(sk.public_key().as_bytes(), their_pk, "{kem:?} pk");
                assert_eq!(bytes, their_sk, "{kem:?} sk");
            }
            // Serialization round trip, and short output buffers.
            let again = PrivateKey::from_bytes(kem, &bytes).expect("own encoding");
            assert_eq!(again.public_key(), sk.public_key());
            assert_eq!(private_bytes(&again), bytes);
            let mut der = Zeroizing([0; MAX_PKCS8_DER_LEN]);
            let restricted = again.with_pkcs8_ecdh_oid();
            let len = restricted.to_pkcs8_der(&mut der[..]).expect("own PKCS #8");
            let decoded = PrivateKey::from_pkcs8_der_or_ber(&der[..len]).expect("own DER");
            assert_eq!(decoded.kem(), kem);
            assert_eq!(
                decoded.pkcs8_uses_ecdh_oid(),
                restricted.pkcs8_uses_ecdh_oid()
            );
            assert_eq!(decoded.public_key(), sk.public_key());
            assert_eq!(private_bytes(&decoded), bytes);
            let mut short = vec![0u8; input.choose(nsk)];
            assert_eq!(sk.write_bytes(&mut short), Err(Error::InvalidLength));
            let mut long = vec![0xa5u8; nsk + 1 + input.choose(8)];
            assert_eq!(sk.write_bytes(&mut long), Ok(nsk));
            assert_eq!(&long[..nsk], bytes.as_slice());
            assert!(long[nsk..].iter().all(|&b| b == 0xa5));
        }
        1 => {
            let mut bytes = exact(input, nsk);
            mutate(input, &mut bytes);
            if input.bool() && bytes.len() == nsk {
                // All zeros or all ones: out of range for the NIST curves.
                let fill = if input.bool() { 0 } else { 0xff };
                bytes.fill(fill);
            }
            let result = PrivateKey::from_bytes(kem, &bytes);
            if bytes.len() != nsk {
                assert_eq!(result.err(), Some(Error::InvalidKey));
                return;
            }
            let their_pk = oracle.as_ref().map(|o| o.private_key(&bytes));
            let sk = match result {
                Ok(sk) => sk,
                Err(e) => {
                    assert_eq!(e, Error::InvalidKey);
                    if let Some(their) = their_pk {
                        assert_eq!(their, None, "{kem:?}: oracle accepts a rejected key");
                    }
                    return;
                }
            };
            assert_eq!(sk.kem(), kem);
            if let Some(their) = their_pk {
                assert_eq!(
                    their.as_deref(),
                    Some(sk.public_key().as_bytes()),
                    "{kem:?} pk"
                );
            }
            let mut expected = bytes.clone();
            if kem == Kem::DhX25519HkdfSha256 {
                clamp_x25519(&mut expected);
            } else if kem == Kem::DhX448HkdfSha512 {
                expected[0] &= 252;
                expected[55] |= 128;
            }
            assert_eq!(private_bytes(&sk), expected);
        }
        2 => {
            let mut bytes = if input.bool() {
                let ikm = exact(input, nsk);
                kem.derive_key_pair(&ikm)
                    .expect("Nsk bytes")
                    .public_key()
                    .as_bytes()
                    .to_vec()
            } else {
                exact(input, kem.public_key_len())
            };
            mutate(input, &mut bytes);
            let result = PublicKey::from_bytes(kem, &bytes);
            if bytes.len() != kem.public_key_len() {
                assert_eq!(result, Err(Error::InvalidKey));
                return;
            }
            if let Some(oracle) = &oracle {
                assert_eq!(
                    result.is_ok(),
                    oracle.public_key(&bytes),
                    "{kem:?}: public key validity differs from the oracle"
                );
            }
            match result {
                Ok(pk) => {
                    assert_eq!(pk.kem(), kem);
                    assert_eq!(pk.as_bytes(), bytes.as_slice());
                }
                Err(e) => assert_eq!(e, Error::InvalidKey),
            }
        }
        3 => {
            // GenerateKeyPair draws exactly Nsk bytes and derives from them.
            let rng_bytes = input.short_field();
            match kem.generate_key_pair(&FixedRng::new(rng_bytes)) {
                Ok(sk) => {
                    assert!(rng_bytes.len() >= nsk);
                    let derived = kem.derive_key_pair(&rng_bytes[..nsk]).expect("Nsk bytes");
                    assert_eq!(sk.public_key(), derived.public_key());
                    assert_eq!(private_bytes(&sk), private_bytes(&derived));
                }
                Err(e) => {
                    assert_eq!(e, Error::RandomFailure);
                    assert!(rng_bytes.len() < nsk);
                }
            }
            let sk = kem.generate_key_pair(&OsRng).expect("OS randomness");
            assert_eq!(sk.kem(), kem);
        }
        _ => {
            // Keys of another KEM are refused by both setups.
            let other = *input.pick(&Kem::ALL);
            let ikm = exact(input, MAX_PRIVATE_KEY_LEN);
            let sk = other.derive_key_pair(&ikm).expect("long enough");
            let suite = Suite::new(kem, *input.pick(&Kdf::ALL), *input.pick(&Aead::ALL));
            let sender = suite.setup_sender(sk.public_key(), b"", &OsRng);
            let enc = exact(input, kem.enc_len());
            let recipient = suite.setup_recipient(&enc, &sk, b"");
            if other != kem {
                assert_eq!(sender.err(), Some(Error::InvalidKey));
                assert_eq!(recipient.err(), Some(Error::InvalidKey));
            } else {
                let (enc, s) = sender.expect("valid key");
                let r = suite
                    .setup_recipient(enc.as_bytes(), &sk, b"")
                    .expect("genuine enc");
                let (mut a, mut b) = ([0u8; 32], [1u8; 32]);
                s.export(b"x", &mut a).expect("short export");
                r.export(b"x", &mut b).expect("short export");
                assert_eq!(a, b);
            }
        }
    }
}
