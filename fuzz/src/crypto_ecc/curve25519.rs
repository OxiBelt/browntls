//! X25519 and Ed25519 operations of the `crypto_ecc` target, checked
//! against `x25519-dalek` and `ed25519-dalek`.

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::curve25519::ed25519::{self, SigningKey, VerifyingKey};
use browntls_crypto::curve25519::x25519::{self, Backend, PrivateKey};
use browntls_crypto::rand::FixedRng;
use ed25519_dalek::{Signer as _, Verifier as _};

use super::{edit, flip_bit, message};
use crate::input::Input;

/// Op: the X25519 function on a fuzzed scalar and u-coordinate.
pub fn x25519_function(input: &mut Input<'_>) {
    let k: [u8; 32] = input.array();
    let u: [u8; 32] = input.array();
    let want = x25519_dalek::x25519(k, u);
    assert_eq!(x25519::x25519(&k, &u), want, "X25519");
    for backend in Backend::ALL {
        match x25519::x25519_with_backend(backend, &k, &u) {
            Some(out) => {
                assert!(backend.is_available());
                assert_eq!(out, want, "X25519 backend {backend:?}");
            }
            None => assert!(!backend.is_available()),
        }
    }
    // The fixed-base comb agrees with the ladder on the base point.
    assert_eq!(
        x25519::x25519_base(&k),
        x25519::x25519(&k, &x25519::BASEPOINT)
    );
    // `best` follows the acceleration policy.
    assert!(Backend::best().is_available());
    if input.bool() {
        accel::set_policy(Algorithm::X25519, Policy::NONE).expect("policy");
        let portable = Backend::best();
        accel::set_policy(Algorithm::X25519, Policy::PREFERRED).expect("policy");
        assert_eq!(portable, Backend::Portable);
    }
}

/// Op: an X25519 private key (from bytes, a slice or a byte source),
/// agreement with a second key and with a fuzzed peer value.
pub fn x25519_keys(input: &mut Input<'_>) {
    let key = match input.choose(3) {
        0 => PrivateKey::from_bytes(&input.array()),
        1 => {
            let raw = input.short_field();
            match PrivateKey::from_slice(raw) {
                Ok(key) => {
                    assert_eq!(raw.len(), 32);
                    assert_eq!(&key.as_bytes()[..], raw);
                    key
                }
                Err(e) => {
                    assert_eq!(e, Error::InvalidKey);
                    assert_ne!(raw.len(), 32);
                    return;
                }
            }
        }
        _ => {
            let raw = input.short_field();
            match PrivateKey::generate(&FixedRng::new(raw)) {
                Ok(key) => {
                    assert_eq!(&key.as_bytes()[..], &raw[..32]);
                    key
                }
                Err(e) => {
                    assert_eq!(e, Error::RandomFailure);
                    assert!(raw.len() < 32);
                    return;
                }
            }
        }
    };
    let sk = *key.as_bytes();
    let theirs = x25519_dalek::StaticSecret::from(sk);
    let public = key.public_key();
    assert_eq!(&public, x25519_dalek::PublicKey::from(&theirs).as_bytes());
    // Agreement with another key is symmetric and matches the oracle.
    let peer = PrivateKey::from_bytes(&input.array());
    let ab = key.diffie_hellman(&peer.public_key());
    let ba = peer.diffie_hellman(&public);
    assert_eq!(ab, ba, "X25519 agreement is not symmetric");
    let their_shared = theirs.diffie_hellman(&x25519_dalek::PublicKey::from(peer.public_key()));
    assert_eq!(ab, Ok(*their_shared.as_bytes()));
    // A fuzzed peer value: an all-zero result is rejected.
    let u: [u8; 32] = input.array();
    let want = x25519_dalek::x25519(sk, u);
    match key.diffie_hellman(&u) {
        Ok(shared) => {
            assert_eq!(shared, want);
            assert_ne!(shared, [0; 32]);
        }
        Err(e) => {
            assert_eq!(e, Error::KeyAgreementFailed);
            assert_eq!(want, [0; 32]);
        }
    }
}

/// An Ed25519 key from a fuzzed seed or from `generate` over fuzzed bytes.
fn ed25519_key(input: &mut Input<'_>) -> Option<SigningKey> {
    if input.bool() {
        return Some(SigningKey::from_seed(&input.array()));
    }
    let raw = input.short_field();
    match SigningKey::generate(&FixedRng::new(raw)) {
        Ok(key) => {
            assert_eq!(&key.seed()[..], &raw[..32]);
            Some(key)
        }
        Err(e) => {
            assert_eq!(e, Error::RandomFailure);
            assert!(raw.len() < 32);
            None
        }
    }
}

/// Op: Ed25519 key derivation, signing and verification round trip.
pub fn ed25519_sign(input: &mut Input<'_>) {
    let Some(key) = ed25519_key(input) else {
        return;
    };
    let msg = message(input);
    let seed = *key.seed();
    let theirs = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = key.verifying_key();
    assert_eq!(vk.as_bytes(), theirs.verifying_key().as_bytes());
    assert_eq!(VerifyingKey::from_bytes(vk.as_bytes()), Ok(vk));
    assert_eq!(VerifyingKey::from_slice(vk.as_bytes()), Ok(vk));
    let sig = key.sign(msg);
    assert_eq!(sig, theirs.sign(msg).to_bytes(), "Ed25519 signature");
    assert_eq!(vk.verify(msg, &sig), Ok(()));
    // A flipped bit or another message fails, here and in the oracle.
    let bad: [u8; 64] = flip_bit(&sig, input).try_into().expect("64 bytes");
    assert_eq!(vk.verify(msg, &bad), Err(Error::InvalidSignature));
    let dvk = theirs.verifying_key();
    assert!(
        dvk.verify(msg, &ed25519_dalek::Signature::from_bytes(&bad))
            .is_err()
    );
    let mut other = msg.to_vec();
    edit(&mut other, input);
    if other != msg {
        assert!(vk.verify(&other, &sig).is_err());
    }
    // PKCS #8 round trip.
    let der = key.to_pkcs8_der();
    let back = SigningKey::from_pkcs8_der(&der[..]).expect("own PKCS #8");
    assert_eq!(back.seed(), &seed);
    assert_eq!(back.verifying_key(), vk);
}

/// Op: verification of fuzzed keys and signatures, against
/// `ed25519-dalek`.
pub fn ed25519_verify(input: &mut Input<'_>) {
    let msg = message(input);
    let (pk, sig): ([u8; 32], [u8; 64]) = match input.choose(3) {
        0 => (input.array(), input.array()),
        mode => {
            let key = SigningKey::from_seed(&input.array());
            let mut pk = *key.verifying_key().as_bytes();
            let mut sig = key.sign(msg);
            let mask: [u8; 4] = input.array();
            let at = input.byte();
            if mode == 1 {
                for (i, m) in mask.iter().enumerate() {
                    sig[(usize::from(at) + i) % 64] ^= m;
                }
            } else {
                pk[usize::from(at) % 32] ^= mask[0];
            }
            (pk, sig)
        }
    };
    let ours = VerifyingKey::from_bytes(&pk);
    assert_eq!(VerifyingKey::from_slice(&pk), ours);
    let len = input.choose(70);
    if len != 32 {
        let mut other = pk.to_vec();
        other.resize(len, 0);
        assert_eq!(VerifyingKey::from_slice(&other), Err(Error::InvalidKey));
    }
    // Accepted keys: canonical encodings of points that are not of small
    // order.
    let theirs = ed25519_dalek::VerifyingKey::from_bytes(&pk).ok();
    let expected = theirs
        .as_ref()
        .is_some_and(|t| !t.is_weak() && t.to_edwards().compress().as_bytes() == &pk);
    assert_eq!(ours.is_ok(), expected, "Ed25519 key acceptance");
    let (Ok(vk), Some(dvk)) = (ours, theirs) else {
        return;
    };
    assert_eq!(vk.as_bytes(), &pk);
    let dsig = ed25519_dalek::Signature::from_bytes(&sig);
    let ok = vk.verify(msg, &sig);
    assert!(matches!(ok, Ok(()) | Err(Error::InvalidSignature)));
    // The same cofactorless equation as dalek's `verify`; strict
    // verification additionally rejects small-order R.
    assert_eq!(
        ok.is_ok(),
        dvk.verify(msg, &dsig).is_ok(),
        "Ed25519 verdict"
    );
    if dvk.verify_strict(msg, &dsig).is_ok() {
        assert!(ok.is_ok());
    }
}

/// A PKCS #8 v2 (`OneAsymmetricKey`) Ed25519 key with its public key.
fn ed25519_pkcs8_v2(seed: &[u8; 32], public: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![
        0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    v.extend_from_slice(seed);
    v.extend_from_slice(&[0x81, 0x21, 0x00]);
    v.extend_from_slice(public);
    v
}

/// Op: Ed25519 PKCS #8 parsing.
pub fn ed25519_pkcs8(input: &mut Input<'_>) {
    let (bytes, unedited) = if input.bool() {
        (input.short_field().to_vec(), false)
    } else {
        let key = SigningKey::from_seed(&input.array());
        let mut v = if input.bool() {
            key.to_pkcs8_der().to_vec()
        } else {
            ed25519_pkcs8_v2(key.seed(), key.verifying_key().as_bytes())
        };
        let changed = edit(&mut v, input);
        (v, !changed)
    };
    match SigningKey::from_pkcs8_der(&bytes) {
        Ok(key) => {
            let again = SigningKey::from_pkcs8_der(&key.to_pkcs8_der()[..]).expect("own PKCS #8");
            assert_eq!(again.seed(), key.seed());
            let fresh = SigningKey::from_seed(key.seed());
            assert_eq!(fresh.verifying_key(), key.verifying_key());
            assert_eq!(key.to_pkcs8_der().len(), ed25519::PKCS8_V1_LEN);
        }
        Err(e) => {
            assert!(!unedited, "own encoding rejected: {e:?}");
            assert!(
                matches!(e, Error::InvalidEncoding | Error::InvalidKey),
                "{e:?}"
            );
        }
    }
}
