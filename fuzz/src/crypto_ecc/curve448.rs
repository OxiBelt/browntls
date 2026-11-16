//! X448 and Ed448 operations of the `crypto_ecc` target, checked against
//! the RustCrypto `x448` and `ed448-goldilocks` crates.

use browntls_crypto::Error;
use browntls_crypto::curve448::ed448::{self, MAX_CONTEXT_LEN, SigningKey, VerifyingKey};
use browntls_crypto::curve448::x448::{self, PrivateKey};
use browntls_crypto::rand::FixedRng;
use ed448_goldilocks::elliptic_curve::group::Group as _;
use ed448_goldilocks::signature::Signer as _;

use super::{edit, flip_bit, message};
use crate::input::Input;

/// Op: the X448 function on a fuzzed scalar and u-coordinate.
pub fn x448_function(input: &mut Input<'_>) {
    let k: [u8; 56] = input.array();
    let u: [u8; 56] = input.array();
    let out = x448::x448(&k, &u);
    assert_eq!(out, ::x448::x448_unchecked(k, u), "X448");
    assert_eq!(x448::is_all_zero(&out), out == [0; 56]);
    assert_eq!(x448::is_all_zero(&u), u == [0; 56]);
    // The comb over edwards448 agrees with the ladder on the base point.
    assert_eq!(x448::x448_base(&k), x448::x448(&k, &x448::BASEPOINT));
}

/// Op: an X448 private key (from bytes, a slice or a byte source),
/// agreement with a second key and with a fuzzed peer value.
pub fn x448_keys(input: &mut Input<'_>) {
    let key = match input.choose(3) {
        0 => PrivateKey::from_bytes(&input.array()),
        1 => {
            let raw = input.short_field();
            match PrivateKey::from_slice(raw) {
                Ok(key) => {
                    assert_eq!(raw.len(), 56);
                    assert_eq!(&key.as_bytes()[..], raw);
                    key
                }
                Err(e) => {
                    assert_eq!(e, Error::InvalidKey);
                    assert_ne!(raw.len(), 56);
                    return;
                }
            }
        }
        _ => {
            let raw = input.short_field();
            match PrivateKey::generate(&FixedRng::new(raw)) {
                Ok(key) => {
                    assert_eq!(&key.as_bytes()[..], &raw[..56]);
                    key
                }
                Err(e) => {
                    assert_eq!(e, Error::RandomFailure);
                    assert!(raw.len() < 56);
                    return;
                }
            }
        }
    };
    let sk = *key.as_bytes();
    let theirs = ::x448::StaticSecret::from(sk);
    let public = key.public_key();
    assert_eq!(&public, ::x448::PublicKey::from(&theirs).as_bytes());
    // Agreement with another key is symmetric and matches the oracle.
    let peer = PrivateKey::from_bytes(&input.array());
    let peer_public = peer.public_key();
    let ab = key.diffie_hellman(&peer_public);
    let ba = peer.diffie_hellman(&public);
    assert_eq!(ab, ba, "X448 agreement is not symmetric");
    let want = ::x448::x448_unchecked(sk, peer_public);
    if want == [0; 56] {
        assert_eq!(ab, Err(Error::KeyAgreementFailed));
    } else {
        assert_eq!(ab, Ok(want));
    }
    // A fuzzed peer value: an all-zero result is rejected.
    let u: [u8; 56] = input.array();
    let want = ::x448::x448_unchecked(sk, u);
    match key.diffie_hellman(&u) {
        Ok(shared) => {
            assert_eq!(shared, want);
            assert!(!x448::is_all_zero(&shared));
        }
        Err(e) => {
            assert_eq!(e, Error::KeyAgreementFailed);
            assert_eq!(want, [0; 56]);
        }
    }
}

/// A context: empty, fuzzed (at most 255 bytes) or one byte too long.
fn context(input: &mut Input<'_>) -> Vec<u8> {
    match input.choose(3) {
        0 => Vec::new(),
        1 => input.short_field().to_vec(),
        _ => vec![input.byte(); MAX_CONTEXT_LEN + 1],
    }
}

/// An Ed448 key from a fuzzed seed or from `generate` over fuzzed bytes.
fn ed448_key(input: &mut Input<'_>) -> Option<SigningKey> {
    if input.bool() {
        return Some(SigningKey::from_seed(&input.array()));
    }
    let raw = input.short_field();
    match SigningKey::generate(&FixedRng::new(raw)) {
        Ok(key) => {
            assert_eq!(&key.seed()[..], &raw[..57]);
            Some(key)
        }
        Err(e) => {
            assert_eq!(e, Error::RandomFailure);
            assert!(raw.len() < 57);
            None
        }
    }
}

/// Whether the oracle accepts `sig` on `msg` under `context`.
fn oracle_verifies(
    vk: &ed448_goldilocks::VerifyingKey,
    context: &[u8],
    msg: &[u8],
    sig: &[u8; 114],
) -> bool {
    ed448_goldilocks::Signature::from_slice(sig)
        .map(|s| vk.verify_ctx(&s, context, msg).is_ok())
        .unwrap_or(false)
}

/// Op: Ed448 key derivation, signing with and without a context, and
/// verification round trips.
pub fn ed448_sign(input: &mut Input<'_>) {
    let Some(key) = ed448_key(input) else {
        return;
    };
    let ctx = context(input);
    let msg = message(input);
    let seed = *key.seed();
    let theirs = ed448_goldilocks::SigningKey::try_from(&seed[..]).expect("57-byte seed");
    let their_vk = theirs.verifying_key();
    let vk = key.verifying_key();
    assert_eq!(&vk.as_bytes()[..], &their_vk.as_bytes()[..]);
    assert_eq!(VerifyingKey::from_bytes(vk.as_bytes()), Ok(vk));
    assert_eq!(VerifyingKey::from_slice(vk.as_bytes()), Ok(vk));
    let sig = key.sign(msg);
    assert_eq!(
        &sig[..],
        &theirs.sign(msg).to_bytes()[..],
        "Ed448 signature"
    );
    assert_eq!(vk.verify(msg, &sig), Ok(()));
    assert_eq!(key.sign_with_context(&[], msg), Ok(sig));
    let sig_ctx = match key.sign_with_context(&ctx, msg) {
        Ok(sig_ctx) => sig_ctx,
        Err(e) => {
            assert_eq!(e, Error::InvalidLength);
            assert!(ctx.len() > MAX_CONTEXT_LEN);
            assert_eq!(
                vk.verify_with_context(&ctx, msg, &sig),
                Err(Error::InvalidSignature)
            );
            return;
        }
    };
    let their_sig_ctx = theirs.sign_ctx(&ctx, msg).expect("context fits");
    assert_eq!(
        &sig_ctx[..],
        &their_sig_ctx.to_bytes()[..],
        "Ed448ctx signature"
    );
    assert_eq!(vk.verify_with_context(&ctx, msg, &sig_ctx), Ok(()));
    assert!(oracle_verifies(&their_vk, &ctx, msg, &sig_ctx));
    if !ctx.is_empty() {
        assert!(vk.verify(msg, &sig_ctx).is_err());
    }
    // A flipped bit fails, here and in the oracle.
    let bad: [u8; 114] = flip_bit(&sig_ctx, input).try_into().expect("114 bytes");
    assert!(vk.verify_with_context(&ctx, msg, &bad).is_err());
    assert!(!oracle_verifies(&their_vk, &ctx, msg, &bad));
    // PKCS #8 round trip.
    let der = key.to_pkcs8_der();
    let back = SigningKey::from_pkcs8_der(&der[..]).expect("own PKCS #8");
    assert_eq!(back.seed(), &seed);
    assert_eq!(back.verifying_key(), vk);
}

/// Op: verification of fuzzed keys and signatures, against
/// `ed448-goldilocks`.
pub fn ed448_verify(input: &mut Input<'_>) {
    let ctx = context(input);
    let msg = message(input);
    let (pk, sig): ([u8; 57], [u8; 114]) = match input.choose(3) {
        0 => (input.array(), input.array()),
        mode => {
            let key = SigningKey::from_seed(&input.array());
            let mut pk = *key.verifying_key().as_bytes();
            let mut sig = key
                .sign_with_context(&ctx[..ctx.len().min(MAX_CONTEXT_LEN)], msg)
                .expect("context fits");
            let mask: [u8; 4] = input.array();
            let at = usize::from(input.byte());
            if mode == 1 {
                for (i, m) in mask.iter().enumerate() {
                    sig[(at + i) % 114] ^= m;
                }
            } else {
                pk[at % 57] ^= mask[0];
            }
            (pk, sig)
        }
    };
    let ours = VerifyingKey::from_bytes(&pk);
    assert_eq!(VerifyingKey::from_slice(&pk), ours);
    let len = input.choose(120);
    if len != 57 {
        let mut other = pk.to_vec();
        other.resize(len, 0);
        assert_eq!(VerifyingKey::from_slice(&other), Err(Error::InvalidKey));
    }
    // Accepted keys: canonical encodings of curve points that are not of
    // small order. The oracle's `VerifyingKey` also rejects points with a
    // torsion component, which RFC 8032 and browntls accept, so acceptance
    // is checked on the oracle's unchecked decoding.
    let expected = ed448_goldilocks::CompressedEdwardsY(pk)
        .decompress_unchecked()
        .into_option()
        .is_some_and(|a| {
            let e = a.to_edwards();
            bool::from(a.is_on_curve())
                && a.compress().0 == pk
                && !bool::from(e.double().double().is_identity())
        });
    assert_eq!(ours.is_ok(), expected, "Ed448 key acceptance");
    let Ok(vk) = ours else {
        return;
    };
    assert_eq!(vk.as_bytes(), &pk);
    let ok = vk.verify_with_context(&ctx, msg, &sig);
    assert!(matches!(ok, Ok(()) | Err(Error::InvalidSignature)));
    if ctx.len() > MAX_CONTEXT_LEN {
        assert!(ok.is_err());
    } else if let Ok(their_vk) = ed448_goldilocks::VerifyingKey::from_bytes(&pk) {
        // Keys without a torsion component, where the cofactored (browntls)
        // and cofactorless (oracle) equations agree on every signature not
        // built adversarially from the private key.
        assert_eq!(
            ok.is_ok(),
            oracle_verifies(&their_vk, &ctx, msg, &sig),
            "Ed448 verdict"
        );
    }
    if ctx.is_empty() {
        assert_eq!(vk.verify(msg, &sig), ok);
    }
}

/// A PKCS #8 v2 (`OneAsymmetricKey`) Ed448 key with its public key.
fn ed448_pkcs8_v2(seed: &[u8; 57], public: &[u8; 57]) -> Vec<u8> {
    let mut v = vec![
        0x30, 0x81, 0x83, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x04, 0x3b,
        0x04, 0x39,
    ];
    v.extend_from_slice(seed);
    v.extend_from_slice(&[0x81, 0x3a, 0x00]);
    v.extend_from_slice(public);
    v
}

/// Op: Ed448 PKCS #8 parsing, including the oracle's encoding.
pub fn ed448_pkcs8(input: &mut Input<'_>) {
    use ed448_goldilocks::pkcs8::EncodePrivateKey as _;
    let (bytes, unedited) = if input.bool() {
        (input.short_field().to_vec(), false)
    } else {
        let seed: [u8; 57] = input.array();
        let key = SigningKey::from_seed(&seed);
        let mut v = match input.choose(3) {
            0 => key.to_pkcs8_der().to_vec(),
            1 => ed448_pkcs8_v2(key.seed(), key.verifying_key().as_bytes()),
            _ => ed448_goldilocks::SigningKey::try_from(&seed[..])
                .expect("57-byte seed")
                .to_pkcs8_der()
                .expect("oracle PKCS #8")
                .as_bytes()
                .to_vec(),
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
            assert_eq!(key.to_pkcs8_der().len(), ed448::PKCS8_V1_LEN);
        }
        Err(e) => {
            assert!(!unedited, "valid encoding rejected: {e:?}");
            assert!(
                matches!(e, Error::InvalidEncoding | Error::InvalidKey),
                "{e:?}"
            );
        }
    }
}
