//! Key operations of the `crypto_rsa` target: public keys from components
//! and DER, key algorithm identifiers, private-key DER and key generation.

use browntls_crypto::Error;
use browntls_crypto::accel::Policy;
use browntls_crypto::rand::FixedRng;
use browntls_crypto::rsa::{
    LEGACY_MIN_MODULUS_BITS, MAX_ALGORITHM_IDENTIFIER_LEN, MAX_MODULUS_BITS,
    MAX_PKCS1_PRIVATE_KEY_DER_LEN, MAX_PKCS8_PRIVATE_KEY_DER_LEN, MIN_MODULUS_BITS,
    RsaKeyAlgorithm, RsaPrivateKey, RsaPublicKey,
};
use num_bigint::BigUint;

use super::oracle::{self, HASHES};
use super::{
    ALL_ALGORITHMS, Fixture, KEY_ALGORITHMS, algorithm_identifier, backend_policies, check_verify,
    edit, message, public_pkcs1, spki, with_policy,
};
use crate::input::Input;

/// The documented rule of `RsaPublicKey::from_components_with_min_bits`.
fn expected_components(n_be: &[u8], e_be: &[u8], min_bits: usize) -> Result<(), Error> {
    if !(LEGACY_MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&min_bits) {
        return Err(Error::Unsupported);
    }
    let n = BigUint::from_bytes_be(n_be);
    let bits = usize::try_from(n.bits()).expect("bits");
    let e = BigUint::from_bytes_be(e_be);
    let n_ok = n.bit(0) && bits >= min_bits && bits <= MAX_MODULUS_BITS;
    let e_ok = e.bit(0) && e >= BigUint::from(3u8) && e < BigUint::from(1u64 << 33);
    if n_ok && e_ok {
        Ok(())
    } else {
        Err(Error::InvalidKey)
    }
}

/// `len` bytes expanded from a 64-bit seed (xorshift).
fn expand(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 32) as u8
        })
        .collect()
}

/// Modulus sizes for structured moduli.
pub(super) const MODULUS_SIZES: [usize; 12] = [
    1023, 1024, 1025, 1088, 2047, 2048, 2056, 2080, 3072, 4096, 8192, 8193,
];
/// Minimum sizes passed to `*_with_min_bits`.
const MIN_BITS: [usize; 7] = [1024, 2048, 1023, 4096, 8192, 8193, 0];

/// Op 0: a public key from fuzzed components.
pub(super) fn op_components(fx: &Fixture, input: &mut Input<'_>) {
    let n_be: Vec<u8> = match input.choose(3) {
        0 => input.field().to_vec(),
        1 => {
            let bits = match input.choose(4) {
                0 => usize::from(input.u16()) % 8300 + 1,
                _ => *input.pick(&MODULUS_SIZES),
            };
            let mut n = expand(input.u64(), bits.div_ceil(8));
            let top = (bits - 1) % 8;
            n[0] &= 0xffu8 >> (7 - top);
            n[0] |= 1 << top;
            let mut padded = vec![0u8; input.choose(3)];
            padded.extend_from_slice(&n);
            let last = padded.len() - 1;
            padded[last] |= u8::from(input.bool());
            padded
        }
        _ => {
            let key = input.pick(&fx.keys);
            let mut n = key.public().n_be().to_vec();
            edit(&mut n, input);
            n
        }
    };
    let e_be: Vec<u8> = match input.choose(3) {
        0 => vec![1, 0, 1],
        1 => vec![3],
        _ => input.short_field().iter().take(7).copied().collect(),
    };
    let min_bits = match input.choose(4) {
        0 => usize::from(input.u16()),
        _ => *input.pick(&MIN_BITS),
    };
    let expected = expected_components(&n_be, &e_be, min_bits);
    let result = RsaPublicKey::from_components_with_min_bits(&n_be, &e_be, min_bits);
    assert_eq!(result.as_ref().err().copied(), expected.err(), "components");
    let default = RsaPublicKey::from_components(&n_be, &e_be);
    assert_eq!(
        default.as_ref().err().copied(),
        expected_components(&n_be, &e_be, MIN_MODULUS_BITS).err()
    );
    let Ok(key) = result else {
        return;
    };
    let reference = oracle::Public::new(&n_be, &e_be);
    assert_eq!(key.modulus_bits(), reference.bits);
    assert_eq!(key.modulus_len_bytes(), reference.k);
    assert_eq!(key.n_be().len(), reference.k);
    assert_eq!(BigUint::from_bytes_be(key.n_be()), reference.n);
    assert_eq!(BigUint::from_bytes_be(key.e_be()), reference.e);
    assert_eq!(BigUint::from(key.e()), reference.e);
    assert!(key.e_be().first().is_some_and(|&b| b != 0));
    // PKCS #1 encoding into a fuzzed buffer, and back.
    let full = public_pkcs1(&key);
    let mut out = vec![0u8; usize::from(input.u16()) % (full.len() + 8)];
    match key.to_pkcs1_der(&mut out) {
        Ok(n) => assert_eq!(out[..n], full[..]),
        Err(e) => {
            assert_eq!(e, Error::InvalidLength);
            assert!(out.len() < full.len());
        }
    }
    let back = RsaPublicKey::from_pkcs1_der_with_min_bits(&full, min_bits).expect("own encoding");
    assert_eq!((back.n_be(), back.e_be()), (key.n_be(), key.e_be()));
    assert_eq!(public_pkcs1(&back), full);
    let info = spki(RsaKeyAlgorithm::RsaEncryption, &full);
    let back = RsaPublicKey::from_spki_der_with_min_bits(&info, min_bits).expect("own SPKI");
    assert_eq!((back.n_be(), back.e_be()), (key.n_be(), key.e_be()));
    // Fuzzed signatures against an arbitrary odd modulus: the public
    // exponentiation of every backend against num-bigint.
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let sig = match input.choose(3) {
        0 => input.field().to_vec(),
        1 => oracle::to_fixed(&BigUint::from(input.u64()), reference.k),
        _ => expand(input.u64(), reference.k),
    };
    let policies = if reference.bits <= 4096 {
        backend_policies()
    } else {
        vec![Policy::PREFERRED]
    };
    for policy in policies {
        let key = with_policy(policy, || {
            RsaPublicKey::from_components_with_min_bits(&n_be, &e_be, min_bits)
        })
        .expect("accepted under another policy");
        check_verify(&key, &reference, hash, msg, &sig);
    }
}

/// Whether two parse results are the same key or the same error.
fn same_key(a: &Result<RsaPublicKey, Error>, b: &Result<RsaPublicKey, Error>) -> bool {
    match (a, b) {
        (Ok(a), Ok(b)) => a.n_be() == b.n_be() && a.e_be() == b.e_be(),
        (Err(a), Err(b)) => a == b,
        _ => false,
    }
}

/// Op 1: public-key DER.
pub(super) fn op_public_der(fx: &Fixture, input: &mut Input<'_>) {
    let bytes: Vec<u8> = if input.bool() {
        input.field().to_vec()
    } else {
        let key = input.pick(&fx.keys);
        let mut v = if input.bool() {
            key.public_pkcs1.clone()
        } else {
            input.pick(&key.spki).clone()
        };
        edit(&mut v, input);
        v
    };
    let min_bits = match input.choose(3) {
        0 => LEGACY_MIN_MODULUS_BITS,
        1 => MIN_MODULUS_BITS,
        _ => usize::from(input.u16()),
    };
    let pkcs1 = RsaPublicKey::from_pkcs1_der(&bytes);
    assert!(same_key(
        &pkcs1,
        &RsaPublicKey::from_pkcs1_der_with_min_bits(&bytes, MIN_MODULUS_BITS)
    ));
    let pkcs1_min = RsaPublicKey::from_pkcs1_der_with_min_bits(&bytes, min_bits);
    let spki_default = RsaPublicKey::from_spki_der(&bytes);
    assert!(same_key(
        &spki_default,
        &RsaPublicKey::from_spki_der_with_min_bits(&bytes, MIN_MODULUS_BITS)
    ));
    let spki_min = RsaPublicKey::from_spki_der_with_min_bits(&bytes, min_bits);
    let with_alg = RsaPublicKey::from_spki_der_with_algorithm(&bytes);
    match (&spki_default, &with_alg) {
        (Ok(a), Ok((b, alg))) => {
            assert_eq!(*alg, RsaKeyAlgorithm::RsaEncryption);
            assert_eq!((a.n_be(), a.e_be()), (b.n_be(), b.e_be()));
        }
        (Ok(_), Err(e)) => panic!("rsaEncryption SPKI rejected with its algorithm: {e:?}"),
        (Err(_), Ok((_, alg))) => assert_ne!(*alg, RsaKeyAlgorithm::RsaEncryption),
        (Err(_), Err(_)) => {}
    }
    if let Ok((_, alg)) = &with_alg {
        let back = RsaKeyAlgorithm::from_algorithm_identifier(&algorithm_identifier(*alg));
        assert_eq!(back, Ok(*alg));
    }
    let keys = [
        pkcs1.ok(),
        pkcs1_min.ok(),
        spki_min.ok(),
        with_alg.ok().map(|(k, _)| k),
    ];
    for key in keys.into_iter().flatten() {
        let der = public_pkcs1(&key);
        let back = RsaPublicKey::from_pkcs1_der_with_min_bits(&der, LEGACY_MIN_MODULUS_BITS)
            .expect("own encoding");
        assert_eq!(public_pkcs1(&back), der);
        assert_eq!(back.modulus_bits(), key.modulus_bits());
        assert_eq!(back.e(), key.e());
    }
}

/// Op 2: key algorithm identifiers.
pub(super) fn op_algorithm(input: &mut Input<'_>) {
    let bytes: Vec<u8> = if input.bool() {
        input.short_field().to_vec()
    } else {
        let mut v = algorithm_identifier(*input.pick(&KEY_ALGORITHMS));
        edit(&mut v, input);
        v
    };
    if let Ok(alg) = RsaKeyAlgorithm::from_algorithm_identifier(&bytes) {
        let canonical = algorithm_identifier(alg);
        assert_eq!(
            RsaKeyAlgorithm::from_algorithm_identifier(&canonical),
            Ok(alg)
        );
        assert_eq!(alg.allows_pkcs1v15(), alg == RsaKeyAlgorithm::RsaEncryption);
        for hash in HASHES {
            let expected = match alg {
                RsaKeyAlgorithm::RsaEncryption | RsaKeyAlgorithm::RsassaPss(None) => true,
                RsaKeyAlgorithm::RsassaPss(Some(h)) => h == hash,
            };
            assert_eq!(alg.allows_pss(hash), expected);
        }
    }
    // Any algorithm into a fuzzed buffer.
    let alg = *input.pick(&ALL_ALGORITHMS);
    let mut full = [0u8; MAX_ALGORITHM_IDENTIFIER_LEN];
    let full_result = alg.encode_algorithm_identifier(&mut full);
    let mut out = vec![0u8; input.choose(MAX_ALGORITHM_IDENTIFIER_LEN + 8)];
    let result = alg.encode_algorithm_identifier(&mut out);
    match full_result {
        Ok(n) => {
            assert!(KEY_ALGORITHMS.contains(&alg));
            assert_eq!(
                RsaKeyAlgorithm::from_algorithm_identifier(&full[..n]),
                Ok(alg)
            );
            match result {
                Ok(m) => assert_eq!(out[..m], full[..n]),
                Err(e) => {
                    assert_eq!(e, Error::InvalidLength);
                    assert!(out.len() < n);
                }
            }
        }
        Err(e) => {
            assert_eq!(e, Error::Unsupported);
            assert!(!KEY_ALGORITHMS.contains(&alg));
            assert!(result.is_err());
        }
    }
}

/// Number of private-key encodings per fixed key: PKCS #8 for each of
/// [`KEY_ALGORITHMS`], then PKCS #1.
const PRIVATE_ENCODINGS: usize = KEY_ALGORITHMS.len() + 1;

/// Op 7: private-key DER.
pub(super) fn op_private_der(fx: &Fixture, input: &mut Input<'_>) {
    let parser = input.choose(3);
    // `Some(which)` for an unedited fixture encoding.
    let (bytes, unedited) = if input.bool() {
        let raw = input.field();
        let raw = &raw[..raw.len().min(MAX_PKCS8_PRIVATE_KEY_DER_LEN + 16)];
        (raw.to_vec(), None)
    } else {
        let key = input.pick(&fx.keys);
        let which = input.choose(PRIVATE_ENCODINGS);
        let mut v = key.pkcs8.get(which).unwrap_or(&key.pkcs1).clone();
        let changed = edit(&mut v, input);
        (v, (!changed).then_some(which))
    };
    let result = match parser {
        0 => RsaPrivateKey::from_pkcs1_der(&bytes).map(|k| (k, None)),
        1 => RsaPrivateKey::from_pkcs8_der(&bytes).map(|k| (k, None)),
        _ => RsaPrivateKey::from_pkcs8_der_with_algorithm(&bytes).map(|(k, a)| (k, Some(a))),
    };
    // Unedited encodings load with the parser for their form.
    let must_load = unedited.is_some_and(|which| match parser {
        0 => which == KEY_ALGORITHMS.len(),
        1 => which == 0,
        _ => which < KEY_ALGORITHMS.len(),
    });
    let (key, alg) = match result {
        Ok(loaded) => loaded,
        Err(e) => {
            assert!(!must_load, "fixture encoding rejected: {e:?}");
            return;
        }
    };
    let public = key.public_key();
    assert_eq!(key.modulus_len_bytes(), public.modulus_len_bytes());
    assert_eq!(key.modulus_bits(), public.modulus_bits());
    let reference = oracle::Public::new(public.n_be(), public.e_be());
    // An accepted key signs correctly with both paddings.
    let hash = *input.pick(&HASHES);
    let k = key.modulus_len_bytes();
    let mut sig = vec![0u8; k];
    let msg = b"key check";
    let result = key.sign_pkcs1v15_with_rng(hash, msg, &FixedRng::new(&[7; 32]), &mut sig);
    assert_eq!(result, Ok(k));
    assert!(reference.verify_pkcs1v15(hash, msg, &sig));
    let result = key.sign_pss(hash, msg, &FixedRng::new(&[9; 96]), &mut sig);
    assert_eq!(result, Ok(k));
    assert!(reference.verify_pss(hash, msg, &sig).is_some());
    // Encodings into full and fuzzed buffers.
    let mut full1 = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let n1 = key.to_pkcs1_der(&mut full1).expect("PKCS #1");
    full1.truncate(n1);
    let out_alg = *input.pick(&ALL_ALGORITHMS);
    let mut full8 = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
    let result = key.to_pkcs8_der_with_algorithm(out_alg, &mut full8);
    if KEY_ALGORITHMS.contains(&out_alg) {
        full8.truncate(result.expect("PKCS #8"));
    } else {
        assert_eq!(result, Err(Error::Unsupported));
        assert!(full8.iter().all(|&b| b == 0), "failed write left data");
    }
    let mut buf8 = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
    let n8 = key.to_pkcs8_der(&mut buf8).expect("PKCS #8");
    if out_alg == RsaKeyAlgorithm::RsaEncryption {
        assert_eq!(buf8[..n8], full8[..]);
    }
    let size = usize::from(input.u16()) % (MAX_PKCS8_PRIVATE_KEY_DER_LEN + 1);
    let mut out = vec![0xa5u8; size];
    match key.to_pkcs1_der(&mut out) {
        Ok(n) => assert_eq!(out[..n], full1[..]),
        Err(e) => {
            assert_eq!(e, Error::InvalidLength);
            assert!(size < n1);
            assert!(out.iter().all(|&b| b == 0), "failed write left data");
        }
    }
    let mut out = vec![0xa5u8; size];
    match key.to_pkcs8_der_with_algorithm(out_alg, &mut out) {
        Ok(n) => assert_eq!(out[..n], full8[..]),
        // A failed write leaves the buffer untouched or zeroed.
        Err(_) => assert!(
            out.iter().all(|&b| b == 0) || out.iter().all(|&b| b == 0xa5),
            "failed write left data"
        ),
    }
    // Unedited encodings re-encode byte for byte.
    if let Some(which) = unedited {
        match (parser, alg) {
            (0, _) => assert_eq!(full1, bytes),
            (1, _) => assert_eq!(buf8[..n8], bytes[..]),
            (_, Some(alg)) => {
                assert_eq!(alg, KEY_ALGORITHMS[which]);
                let mut out = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
                let n = key
                    .to_pkcs8_der_with_algorithm(alg, &mut out)
                    .expect("PKCS #8");
                assert_eq!(out[..n], bytes[..]);
            }
            _ => unreachable!("the algorithm parser returns one"),
        }
    }
}

/// Op 8: key generation that must fail, cheaply.
pub(super) fn op_generate(input: &mut Input<'_>) {
    const SIZES: [usize; 8] = [0, 1024, 2047, 2048, 3072, 4096, 8192, 2049];
    let bits = match input.choose(4) {
        0 => usize::from(input.u16()),
        _ => *input.pick(&SIZES),
    };
    // At most 255 bytes: too few for two prime candidates of 1024 bits.
    let bytes = input.short_field();
    let result = RsaPrivateKey::generate(bits, &FixedRng::new(bytes)).map(|_| ());
    if matches!(bits, 2048 | 3072 | 4096) {
        assert_eq!(result, Err(Error::RandomFailure));
    } else {
        assert_eq!(result, Err(Error::Unsupported));
    }
}
