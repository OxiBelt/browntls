//! Signature operations of the `crypto_rsa` target: PKCS #1 v1.5 and PSS
//! signing on every backend, verification of fuzzed signatures and
//! encodings forged with the reference.

use browntls_crypto::Error;
use browntls_crypto::rand::FixedRng;
use browntls_crypto::rsa::{verify_pkcs1v15, verify_pss};
use num_bigint::BigUint;

use super::oracle::{self, HASHES};
use super::{Fixture, check_routed, check_verify, edit, message, out_len, tamper};
use crate::input::Input;

/// Op 3: PKCS #1 v1.5 signing.
pub(super) fn op_sign_pkcs1(fx: &Fixture, input: &mut Input<'_>) {
    let key = input.pick(&fx.keys);
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let entropy = input.short_field();
    let k = key.k();
    let mut out = vec![0u8; out_len(k, input)];
    let signer = input.pick(&key.loaded);
    let result = signer.sign_pkcs1v15_with_rng(hash, msg, &FixedRng::new(entropy), &mut out);
    if entropy.len() < 32 {
        assert_eq!(result, Err(Error::RandomFailure));
        return;
    }
    if out.len() < k {
        assert_eq!(result, Err(Error::InvalidLength));
        let mut short = vec![0u8; out.len()];
        assert_eq!(
            signer.sign_pkcs1v15(hash, msg, &mut short),
            Err(Error::InvalidLength)
        );
        return;
    }
    assert_eq!(result, Ok(k));
    let sig = &out[..k];
    // One signature whatever the blinding entropy and the backend.
    let other = input.pick(&key.loaded);
    let mut again = vec![0u8; k];
    assert_eq!(other.sign_pkcs1v15(hash, msg, &mut again), Ok(k));
    assert_eq!(again, sig);
    let public = &key.reference.public;
    assert_eq!(
        check_verify(key.public(), public, hash, msg, sig),
        (true, false)
    );
    let bad = tamper(sig, input);
    assert_eq!(
        check_verify(key.public(), public, hash, msg, &bad),
        (false, false)
    );
    let other = *input.pick(&HASHES);
    if other != hash {
        assert!(verify_pkcs1v15(key.public(), other, msg, sig).is_err());
    }
    check_routed(key, signer, sig, input, |signer, out| {
        signer.sign_pkcs1v15(hash, msg, out)
    });
}

/// Op 4: PSS signing.
pub(super) fn op_sign_pss(fx: &Fixture, input: &mut Input<'_>) {
    let key = input.pick(&fx.keys);
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let rng_bytes = input.short_field();
    let k = key.k();
    let mut out = vec![0u8; out_len(k, input)];
    let signer = input.pick(&key.loaded);
    let result = signer.sign_pss(hash, msg, &FixedRng::new(rng_bytes), &mut out);
    let h_len = hash.output_len();
    if out.len() < k {
        assert_eq!(result, Err(Error::InvalidLength));
        return;
    }
    if rng_bytes.len() < h_len + 32 {
        assert_eq!(result, Err(Error::RandomFailure));
        return;
    }
    assert_eq!(result, Ok(k));
    let sig = &out[..k];
    let public = &key.reference.public;
    let salt = public.verify_pss(hash, msg, sig);
    assert_eq!(salt.as_deref(), Some(&rng_bytes[..h_len]), "PSS salt");
    assert_eq!(
        check_verify(key.public(), public, hash, msg, sig),
        (false, true)
    );
    // Fixed salt and blinding entropy: every backend signs identically.
    let other = input.pick(&key.loaded);
    let mut again = vec![0u8; k];
    let rng = FixedRng::new(rng_bytes);
    assert_eq!(other.sign_pss(hash, msg, &rng, &mut again), Ok(k));
    assert_eq!(again, sig);
    let bad = tamper(sig, input);
    assert_eq!(
        check_verify(key.public(), public, hash, msg, &bad),
        (false, false)
    );
    check_routed(key, signer, sig, input, |signer, out| {
        signer.sign_pss(hash, msg, &FixedRng::new(rng_bytes), out)
    });
}

/// Op 5: fuzzed signatures under the fixed keys.
pub(super) fn op_verify(fx: &Fixture, input: &mut Input<'_>) {
    let key = input.pick(&fx.keys);
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let k = key.k();
    let n = &key.reference.public.n;
    let sig: Vec<u8> = match input.choose(5) {
        0 => input.field().iter().take(k + 2).copied().collect(),
        1 => {
            let mut sig = vec![0u8; k];
            key.loaded[0]
                .sign_pkcs1v15(hash, msg, &mut sig)
                .expect("signing");
            edit(&mut sig, input);
            sig
        }
        2 => {
            let mut sig = vec![0u8; k];
            key.loaded[0]
                .sign_pss(hash, msg, &FixedRng::new(&[0x5a; 96]), &mut sig)
                .expect("signing");
            edit(&mut sig, input);
            sig
        }
        3 => oracle::to_fixed(&BigUint::from(input.u64()), k),
        _ => {
            let small = BigUint::from(input.u64()) % n;
            oracle::to_fixed(&(n - small), k)
        }
    };
    check_verify(key.public(), &key.reference.public, hash, msg, &sig);
}

/// Op 6: encodings built and signed by the reference.
pub(super) fn op_forge(fx: &Fixture, input: &mut Input<'_>) {
    let key = input.pick(&fx.keys);
    let hash = *input.pick(&HASHES);
    let msg = message(input);
    let reference = &key.reference;
    let k = reference.public.k;
    let h_len = hash.output_len();
    if input.bool() {
        // PSS with a fuzzed salt length: only sLen = hLen verifies.
        let em_bits = reference.public.bits - 1;
        let max_salt = em_bits.div_ceil(8) - h_len - 2;
        let salt_len = if input.bool() {
            h_len
        } else {
            usize::from(input.u16()) % (max_salt + 1)
        };
        let mut salt = input.bytes(salt_len).to_vec();
        salt.resize(salt_len, 0);
        let em = oracle::pss_encode(hash, msg, &salt, em_bits).expect("salt fits");
        let mut padded = vec![0u8; k - em.len()];
        padded.extend_from_slice(&em);
        let sig = reference.sign_raw(&padded).expect("EM < n");
        let accepted = salt_len == h_len;
        assert_eq!(
            verify_pss(key.public(), hash, msg, &sig).is_ok(),
            accepted,
            "salt length {salt_len}"
        );
        assert_eq!(
            check_verify(key.public(), &reference.public, hash, msg, &sig).1,
            accepted
        );
    } else {
        // PKCS #1 v1.5 encodings near the canonical one.
        let digest = oracle::digest(hash, &[msg]);
        let canonical =
            oracle::pkcs1_em(&oracle::digest_info(hash, &digest, true), k).expect("fits");
        let mut em = canonical.clone();
        match input.choose(3) {
            0 => {
                let at = usize::from(input.u16()) % k;
                em[at] ^= input.byte().max(1);
            }
            1 => {
                // Garbage after the DigestInfo, taken from the padding.
                let ps_len = em[2..].iter().take_while(|&&b| b == 0xff).count();
                let g = usize::from(input.u16()) % (ps_len + 1);
                em.drain(2..2 + g);
                for _ in 0..g {
                    em.push(input.byte());
                }
            }
            _ => {
                // A DigestInfo without the NULL parameters.
                em = oracle::pkcs1_em(&oracle::digest_info(hash, &digest, false), k).expect("fits");
            }
        }
        let Some(sig) = reference.sign_raw(&em) else {
            return;
        };
        let accepted = em == canonical;
        assert_eq!(
            verify_pkcs1v15(key.public(), hash, msg, &sig).is_ok(),
            accepted
        );
        assert_eq!(
            check_verify(key.public(), &reference.public, hash, msg, &sig).0,
            accepted
        );
    }
}
