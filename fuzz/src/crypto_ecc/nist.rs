//! P-256, P-384 and P-521 operations of the `crypto_ecc` target, checked
//! against the RustCrypto `p256`, `p384` and `p521` crates and between the
//! portable and accelerated backends.
//!
//! Each curve gets the same five operations from [`nist_ops`]: keys (raw,
//! generated; ECDH; SEC 1 and PKCS #8), public keys (SEC 1 points; SPKI;
//! ECDH), DER (fuzzed SEC 1, PKCS #8 and SPKI documents), signing
//! (deterministic, hedged, prehashed; encodings) and verification of fuzzed
//! signatures.

use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::hash::HashAlgorithm;
use num_bigint::BigUint;

/// Every hash ECDSA accepts.
pub const HASHES: [HashAlgorithm; 7] = [
    HashAlgorithm::Sha224,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_256,
    HashAlgorithm::Sha3_384,
    HashAlgorithm::Sha3_512,
];

/// The digest of `msg`, computed by RustCrypto.
pub fn digest(hash: HashAlgorithm, msg: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    match hash {
        HashAlgorithm::Sha224 => sha2::Sha224::digest(msg).to_vec(),
        HashAlgorithm::Sha256 => sha2::Sha256::digest(msg).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(msg).to_vec(),
        HashAlgorithm::Sha512 => sha2::Sha512::digest(msg).to_vec(),
        HashAlgorithm::Sha3_256 => sha3::Sha3_256::digest(msg).to_vec(),
        HashAlgorithm::Sha3_384 => sha3::Sha3_384::digest(msg).to_vec(),
        HashAlgorithm::Sha3_512 => sha3::Sha3_512::digest(msg).to_vec(),
        other => panic!("no reference for {other:?}"),
    }
}

/// Runs `f` under the portable backend of `alg`, then restores PREFERRED.
pub fn portable<T>(alg: Algorithm, f: impl FnOnce() -> T) -> T {
    accel::set_policy(alg, Policy::NONE).expect("policy");
    let out = f();
    accel::set_policy(alg, Policy::PREFERRED).expect("policy");
    out
}

/// `n - small` as `len` big-endian bytes, for scalars near the order.
pub fn order_minus(order_hex: &str, small: u64, len: usize) -> Vec<u8> {
    let n = BigUint::parse_bytes(order_hex.as_bytes(), 16).expect("order");
    let v = (n - BigUint::from(small)).to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(v.len())];
    out.extend_from_slice(&v);
    out
}

macro_rules! nist_ops {
    ($m:ident, $ours:ident, $rc:ident, $fl:literal, $alg:ident, $order:literal) => {
        pub mod $m {
            use ::$rc::ecdsa::signature::hazmat::PrehashVerifier as _;
            use ::$rc::ecdsa::signature::Signer as _;
            use ::$rc::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
            use ::$rc::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
            use browntls_crypto::Error;
            use browntls_crypto::accel::Algorithm;
            use browntls_crypto::nist::$ours as ours;
            use browntls_crypto::rand::FixedRng;

            use super::{HASHES, digest, order_minus, portable};
            use crate::crypto_ecc::{edit, flip_bit, message};
            use crate::input::Input;

            const FL: usize = $fl;
            const ALG: Algorithm = Algorithm::$alg;

            /// A scalar: fuzzed bytes, small, `n - small`, or of a fuzzed
            /// length.
            fn scalar(input: &mut Input<'_>) -> Vec<u8> {
                match input.choose(4) {
                    0 => {
                        let mut d = input.bytes(FL).to_vec();
                        d.resize(FL, 0);
                        d
                    }
                    1 => {
                        let mut d = vec![0u8; FL - 2];
                        d.extend_from_slice(&input.u16().to_be_bytes());
                        d
                    }
                    2 => order_minus($order, u64::from(input.u16()), FL),
                    _ => input.short_field().to_vec(),
                }
            }

            /// A valid key from a fuzzed scalar, or `None`.
            fn secret(input: &mut Input<'_>) -> Option<ours::SecretKey> {
                ours::SecretKey::from_bytes(&scalar(input)).ok()
            }

            /// The oracle's key for a valid one of ours.
            fn their_secret(key: &ours::SecretKey) -> ::$rc::SecretKey {
                ::$rc::SecretKey::from_slice(&key.to_bytes()[..]).expect("valid scalar")
            }

            fn their_verifying_key(key: &ours::PublicKey) -> ::$rc::ecdsa::VerifyingKey {
                ::$rc::ecdsa::VerifyingKey::from_sec1_bytes(&key.to_uncompressed())
                    .expect("valid point")
            }

            /// ECDH of `key` with `peer` matches the oracle and the
            /// portable backend.
            fn check_ecdh(key: &ours::SecretKey, peer: &ours::PublicKey) -> [u8; FL] {
                let shared = key.diffie_hellman(peer).expect("validated peer");
                let theirs = ::$rc::ecdh::diffie_hellman(
                    their_secret(key).to_nonzero_scalar(),
                    ::$rc::PublicKey::from_sec1_bytes(&peer.to_uncompressed())
                        .expect("valid point")
                        .as_affine(),
                );
                assert_eq!(&shared[..], &theirs.raw_secret_bytes()[..], "ECDH");
                let slow = portable(ALG, || key.diffie_hellman(peer));
                assert_eq!(slow, Ok(shared), "ECDH portable backend");
                shared
            }

            /// Op: private keys from scalars and byte sources; public key
            /// derivation; ECDH; SEC 1 and PKCS #8 encodings.
            pub fn keys(input: &mut Input<'_>) {
                let d = scalar(input);
                let result = ours::SecretKey::from_bytes(&d);
                if d.len() == FL {
                    let theirs = ::$rc::SecretKey::from_slice(&d);
                    assert_eq!(result.is_ok(), theirs.is_ok(), "scalar acceptance");
                }
                let key = match result {
                    Ok(key) => key,
                    Err(e) => {
                        assert_eq!(e, Error::InvalidKey);
                        // A key from a fuzzed byte source instead.
                        let raw = input.short_field();
                        let generated = if input.bool() {
                            ours::SecretKey::generate(&FixedRng::new(raw))
                        } else {
                            ours::SigningKey::generate(&FixedRng::new(raw))
                                .map(|k| k.secret_key().clone())
                        };
                        match generated {
                            Ok(key) => key,
                            Err(e) => {
                                assert_eq!(e, Error::RandomFailure);
                                return;
                            }
                        }
                    }
                };
                let bytes = key.to_bytes();
                let theirs = their_secret(&key);
                let public = key.public_key();
                assert_eq!(
                    &public.to_uncompressed()[..],
                    &theirs.public_key().to_sec1_bytes()[..],
                    "public key"
                );
                let slow = portable(ALG, || ours::SecretKey::from_bytes(&bytes[..]));
                assert_eq!(slow.map(|k| k.public_key()), Ok(public), "portable public key");
                let signer = ours::SigningKey::new(key.clone());
                assert_eq!(signer.secret_key().to_bytes()[..], bytes[..]);
                assert_eq!(signer.verifying_key(), public);
                // Agreement with a second key is symmetric.
                if let Some(peer) = secret(input) {
                    let ab = check_ecdh(&key, &peer.public_key());
                    assert_eq!(peer.diffie_hellman(&public), Ok(ab), "ECDH symmetry");
                }
                // SEC 1: ours and the oracle's are identical and load both
                // ways; a fuzzed buffer size.
                let mut buf = [0u8; ours::SEC1_PRIVATE_MAX_LEN];
                let n = key.to_sec1_der(&mut buf).expect("full buffer");
                let theirs_sec1 = theirs.to_sec1_der().expect("oracle SEC 1");
                assert_eq!(&buf[..n], &theirs_sec1[..], "SEC 1 encoding");
                let back = ours::SecretKey::from_sec1_der(&buf[..n]).expect("own SEC 1");
                assert_eq!(back.to_bytes()[..], bytes[..]);
                let size = input.choose(ours::SEC1_PRIVATE_MAX_LEN + 8);
                let mut out = vec![0u8; size];
                match key.to_sec1_der(&mut out) {
                    Ok(m) => assert_eq!(out[..m], buf[..n]),
                    Err(e) => assert_eq!(e, Error::InvalidLength),
                }
                let pkcs8 = theirs.to_pkcs8_der().expect("oracle PKCS #8");
                let back = ours::SecretKey::from_pkcs8_der(pkcs8.as_bytes()).expect("PKCS #8");
                assert_eq!(back.to_bytes()[..], bytes[..]);
            }

            /// A SEC 1 point: raw bytes, a valid point (either form) with an
            /// edit, or random coordinates behind a fuzzed tag.
            fn point(input: &mut Input<'_>) -> Vec<u8> {
                match input.choose(3) {
                    0 => input.short_field().to_vec(),
                    1 => {
                        let Some(key) = secret(input) else {
                            return Vec::new();
                        };
                        let unc = key.public_key().to_uncompressed();
                        let mut v = if input.bool() {
                            unc.to_vec()
                        } else {
                            let mut c = vec![2 | (unc[2 * FL] & 1)];
                            c.extend_from_slice(&unc[1..=FL]);
                            c
                        };
                        edit(&mut v, input);
                        v
                    }
                    _ => {
                        let tag = input.choose(8) as u8;
                        let mut v = vec![tag];
                        let mut x = input.bytes(FL).to_vec();
                        x.resize(FL, 0);
                        v.extend_from_slice(&x);
                        if tag >= 4 {
                            let mut y = input.bytes(FL).to_vec();
                            y.resize(FL, 0);
                            v.extend_from_slice(&y);
                        }
                        v
                    }
                }
            }

            /// Op: public keys from fuzzed SEC 1 points; SPKI; ECDH.
            pub fn public(input: &mut Input<'_>) {
                let bytes = point(input);
                let ours = ours::PublicKey::from_sec1_bytes(&bytes);
                let theirs = ::$rc::PublicKey::from_sec1_bytes(&bytes);
                if matches!(bytes.first(), Some(2..=4)) {
                    assert_eq!(ours.is_ok(), theirs.is_ok(), "point acceptance");
                } else {
                    assert!(ours.is_err());
                }
                let Ok(public) = ours else {
                    let e = ours.expect_err("checked");
                    assert!(matches!(e, Error::InvalidEncoding | Error::InvalidKey), "{e:?}");
                    return;
                };
                let theirs = theirs.expect("checked");
                let unc = public.to_uncompressed();
                assert_eq!(&unc[..], &theirs.to_sec1_bytes()[..], "decoded point");
                assert_eq!(ours::PublicKey::from_sec1_bytes(&unc), Ok(public));
                // SPKI: identical to the oracle's; round trip; fuzzed size.
                let mut buf = [0u8; ours::SPKI_MAX_LEN];
                let n = public.to_spki_der(&mut buf).expect("full buffer");
                let their_spki = theirs.to_public_key_der().expect("oracle SPKI");
                assert_eq!(&buf[..n], their_spki.as_bytes(), "SPKI encoding");
                assert_eq!(ours::PublicKey::from_spki_der(&buf[..n]), Ok(public));
                let mut out = vec![0u8; input.choose(ours::SPKI_MAX_LEN + 8)];
                match public.to_spki_der(&mut out) {
                    Ok(m) => assert_eq!(out[..m], buf[..n]),
                    Err(e) => assert_eq!(e, Error::InvalidLength),
                }
                if let Some(key) = secret(input) {
                    check_ecdh(&key, &public);
                }
            }

            /// Op: fuzzed SEC 1 private keys, PKCS #8 private keys and
            /// SPKIs.
            pub fn der(input: &mut Input<'_>) {
                let kind = input.choose(3);
                let (bytes, unedited) = if input.bool() {
                    (input.field().iter().take(400).copied().collect::<Vec<u8>>(), false)
                } else {
                    let Some(key) = secret(input) else {
                        return;
                    };
                    let mut v = match kind {
                        0 => {
                            let mut buf = [0u8; ours::SEC1_PRIVATE_MAX_LEN];
                            let n = key.to_sec1_der(&mut buf).expect("full buffer");
                            buf[..n].to_vec()
                        }
                        1 => their_secret(&key).to_pkcs8_der().expect("PKCS #8").as_bytes().to_vec(),
                        _ => {
                            let mut buf = [0u8; ours::SPKI_MAX_LEN];
                            let n = key.public_key().to_spki_der(&mut buf).expect("full buffer");
                            buf[..n].to_vec()
                        }
                    };
                    let changed = edit(&mut v, input);
                    (v, !changed)
                };
                match kind {
                    0 | 1 => {
                        let (ours, theirs) = if kind == 0 {
                            (
                                ours::SecretKey::from_sec1_der(&bytes),
                                ::$rc::SecretKey::from_sec1_der(&bytes).ok(),
                            )
                        } else {
                            (
                                ours::SecretKey::from_pkcs8_der(&bytes),
                                ::$rc::SecretKey::from_pkcs8_der(&bytes).ok(),
                            )
                        };
                        let key = match ours {
                            Ok(key) => key,
                            Err(e) => {
                                assert!(!unedited, "valid encoding rejected: {e:?}");
                                assert!(matches!(e, Error::InvalidEncoding | Error::InvalidKey));
                                return;
                            }
                        };
                        let theirs = theirs.expect("key accepted by browntls but not by the oracle");
                        assert_eq!(&key.to_bytes()[..], &theirs.to_bytes()[..]);
                        let mut buf = [0u8; ours::SEC1_PRIVATE_MAX_LEN];
                        let n = key.to_sec1_der(&mut buf).expect("full buffer");
                        let back = ours::SecretKey::from_sec1_der(&buf[..n]).expect("own SEC 1");
                        assert_eq!(back.to_bytes()[..], key.to_bytes()[..]);
                        assert_eq!(back.public_key(), key.public_key());
                    }
                    _ => {
                        let public = match ours::PublicKey::from_spki_der(&bytes) {
                            Ok(public) => public,
                            Err(e) => {
                                assert!(!unedited, "valid encoding rejected: {e:?}");
                                return;
                            }
                        };
                        let theirs = ::$rc::PublicKey::from_public_key_der(&bytes)
                            .expect("SPKI accepted by browntls but not by the oracle");
                        assert_eq!(&public.to_uncompressed()[..], &theirs.to_sec1_bytes()[..]);
                        let mut buf = [0u8; ours::SPKI_MAX_LEN];
                        let n = public.to_spki_der(&mut buf).expect("full buffer");
                        assert_eq!(ours::PublicKey::from_spki_der(&buf[..n]), Ok(public));
                    }
                }
            }

            /// Op: signing (deterministic, hedged, prehashed) and its
            /// round trips, against the oracle and the portable backend.
            pub fn sign(input: &mut Input<'_>) {
                let Some(key) = secret(input) else {
                    return;
                };
                let hash = *input.pick(&HASHES);
                let msg = message(input);
                let public = key.public_key();
                let signer = ours::SigningKey::new(key);
                let digest = digest(hash, msg);
                let sig = signer.sign_deterministic(hash, msg).expect("RFC 6979 nonce");
                assert_eq!(signer.sign_prehashed(hash, &digest, None), Ok(sig));
                let slow = portable(ALG, || signer.sign_deterministic(hash, msg));
                assert_eq!(slow, Ok(sig), "portable backend signature");
                // The oracle's RFC 6979 with the curve's own hash agrees.
                if hash == ours::TLS_HASH {
                    let their_signer = ::$rc::ecdsa::SigningKey::from(&their_secret(signer.secret_key()));
                    let theirs: ::$rc::ecdsa::Signature = their_signer.sign(msg);
                    assert_eq!(&sig.fixed()[..], &theirs.to_bytes()[..], "RFC 6979 signature");
                    assert_eq!(sig.as_der(), theirs.to_der().as_bytes());
                }
                // Encodings.
                assert!(sig.as_der().len() <= ours::SIGNATURE_DER_MAX_LEN);
                assert_eq!(ours::Signature::from_der(sig.as_der()), Ok(sig));
                assert_eq!(ours::Signature::from_fixed(sig.fixed()), Ok(sig));
                // Every verification path, here and in the oracle.
                assert_eq!(ours::verify(&public, hash, msg, sig.as_der()), Ok(()));
                assert_eq!(ours::verify_fixed(&public, hash, msg, sig.fixed()), Ok(()));
                assert_eq!(ours::verify_prehashed(&public, &digest, sig.as_der()), Ok(()));
                let slow = portable(ALG, || ours::verify(&public, hash, msg, sig.as_der()));
                assert_eq!(slow, Ok(()));
                let vk = their_verifying_key(&public);
                let their_sig = ::$rc::ecdsa::Signature::from_slice(sig.fixed()).expect("r, s");
                assert!(vk.verify_prehash(&digest, &their_sig).is_ok());
                // A flipped bit fails everywhere.
                let bad = flip_bit(sig.fixed(), input);
                assert_eq!(
                    ours::verify_fixed(&public, hash, msg, &bad),
                    Err(Error::InvalidSignature)
                );
                if let Ok(their_bad) = ::$rc::ecdsa::Signature::from_slice(&bad) {
                    assert!(vk.verify_prehash(&digest, &their_bad).is_err());
                }
                // Hedged signing with fuzzed randomness.
                let rng = input.short_field();
                let hedged = signer.sign(hash, msg, &FixedRng::new(rng));
                let prehashed = signer.sign_prehashed(hash, &digest, Some(&FixedRng::new(rng)));
                assert_eq!(hedged, prehashed);
                match hedged {
                    Ok(hedged) => {
                        assert!(rng.len() >= 32);
                        assert_ne!(hedged, sig, "hedging changed nothing");
                        assert_eq!(ours::verify(&public, hash, msg, hedged.as_der()), Ok(()));
                    }
                    Err(e) => {
                        assert_eq!(e, Error::RandomFailure);
                        assert!(rng.len() < 32);
                    }
                }
                // A digest of the wrong length.
                let mut wrong = digest.clone();
                edit(&mut wrong, input);
                if wrong.len() != hash.output_len() {
                    assert_eq!(
                        signer.sign_prehashed(hash, &wrong, None),
                        Err(Error::InvalidLength)
                    );
                }
            }

            /// Op: fuzzed signatures in fixed and DER form, against the
            /// oracle and the portable backend.
            pub fn verify(input: &mut Input<'_>) {
                let Some(key) = secret(input) else {
                    return;
                };
                let hash = *input.pick(&HASHES);
                let msg = message(input);
                let public = key.public_key();
                let digest = digest(hash, msg);
                let vk = their_verifying_key(&public);
                let signer = ours::SigningKey::new(key);
                let valid = signer.sign_deterministic(hash, msg).expect("RFC 6979 nonce");
                let (bytes, der) = match input.choose(5) {
                    0 => (input.bytes(2 * FL).to_vec(), false),
                    1 => (input.short_field().to_vec(), true),
                    2 => {
                        let mut v = valid.fixed().to_vec();
                        let mask: [u8; 4] = input.array();
                        let at = usize::from(input.byte());
                        for (i, m) in mask.iter().enumerate() {
                            v[(at + i) % (2 * FL)] ^= m;
                        }
                        (v, false)
                    }
                    3 => {
                        let mut v = valid.as_der().to_vec();
                        edit(&mut v, input);
                        (v, true)
                    }
                    _ => {
                        // (r, n - s) is the other valid signature.
                        let s = num_bigint::BigUint::from_bytes_be(&valid.fixed()[FL..]);
                        let n = num_bigint::BigUint::parse_bytes($order.as_bytes(), 16).expect("n");
                        let neg = (n - s).to_bytes_be();
                        let mut v = valid.fixed()[..FL].to_vec();
                        v.resize(2 * FL - neg.len(), 0);
                        v.extend_from_slice(&neg);
                        let der = input.bool();
                        if der {
                            let parsed = ours::Signature::from_fixed(&v).expect("r, n - s");
                            v = parsed.as_der().to_vec();
                        }
                        (v, der)
                    }
                };
                let (ours_ok, theirs_ok) = if der {
                    let parsed = ours::Signature::from_der(&bytes);
                    let their_parsed = ::$rc::ecdsa::Signature::from_der(&bytes);
                    assert_eq!(parsed.is_ok(), their_parsed.is_ok(), "DER signature acceptance");
                    if let (Ok(p), Ok(t)) = (&parsed, &their_parsed) {
                        assert_eq!(p.as_der(), &bytes[..], "DER is not canonical");
                        assert_eq!(&p.fixed()[..], &t.to_bytes()[..]);
                        assert_eq!(ours::Signature::from_fixed(p.fixed()).as_ref(), Ok(p));
                    }
                    let ok = ours::verify(&public, hash, msg, &bytes);
                    assert_eq!(ours::verify_prehashed(&public, &digest, &bytes), ok);
                    let slow = portable(ALG, || ours::verify(&public, hash, msg, &bytes));
                    assert_eq!(slow, ok, "portable verification");
                    let theirs = their_parsed.is_ok_and(|s| vk.verify_prehash(&digest, &s).is_ok());
                    (ok, theirs)
                } else {
                    let parsed = ours::Signature::from_fixed(&bytes);
                    let their_parsed = ::$rc::ecdsa::Signature::from_slice(&bytes);
                    assert_eq!(parsed.is_ok(), their_parsed.is_ok(), "fixed signature acceptance");
                    let ok = ours::verify_fixed(&public, hash, msg, &bytes);
                    if let Ok(p) = &parsed {
                        assert_eq!(&p.fixed()[..], &bytes[..]);
                        assert_eq!(ours::verify(&public, hash, msg, p.as_der()), ok);
                    }
                    let slow = portable(ALG, || ours::verify_fixed(&public, hash, msg, &bytes));
                    assert_eq!(slow, ok, "portable verification");
                    let theirs = their_parsed.is_ok_and(|s| vk.verify_prehash(&digest, &s).is_ok());
                    (ok, theirs)
                };
                assert!(matches!(ours_ok, Ok(()) | Err(Error::InvalidSignature)));
                assert_eq!(ours_ok.is_ok(), theirs_ok, "ECDSA verdict");
            }
        }
    };
}

nist_ops!(
    p256,
    p256,
    p256,
    32,
    P256,
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);
nist_ops!(
    p384,
    p384,
    p384,
    48,
    P384,
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
);
nist_ops!(
    p521,
    p521,
    p521,
    66,
    P521,
    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
);
