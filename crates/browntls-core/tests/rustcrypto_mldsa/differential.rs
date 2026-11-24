//! The native and RustCrypto ML-DSA verifiers (and the `browntls-pki` test
//! oracle, which uses the same `ml-dsa` crate as the RustCrypto provider)
//! agree on valid inputs and on a fixed set of mutated ones, for every
//! parameter set: a small deterministic loop, not a fuzzer.

use browntls_pki::{InvalidSignature, SignatureVerificationAlgorithm};

use crate::ml_dsa::{SETS, Set};
use crate::x509::flip;
use crate::{Impl, MlKey, native_alg, rc_alg};

/// FIPS 204 Table 1: `(omega, k)`. The encoded hint is the last
/// `omega + k` octets of a signature: `omega` indices, then `k` cuts.
fn hint_params(set: Set) -> (usize, usize) {
    match set {
        Set::MlDsa44 => (80, 4),
        Set::MlDsa65 => (55, 6),
        Set::MlDsa87 => (75, 8),
    }
}

/// A deterministic byte stream (xorshift64), for filler keys and
/// signatures.
fn filler(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Signatures whose hint encoding FIPS 204 `HintBitUnpack` (Algorithm 21)
/// rejects, each derived from the valid `sig`.
fn malformed_hints(set: Set, sig: &[u8]) -> Vec<(String, Vec<u8>)> {
    let (omega, k) = hint_params(set);
    let hint_at = sig.len() - omega - k;
    let cut_at = sig.len() - k;
    let cuts: Vec<usize> = sig[cut_at..].iter().map(|&c| usize::from(c)).collect();
    let mut out = Vec::new();
    // Two indices of one row swapped: no longer strictly increasing.
    let mut start = 0;
    for &end in &cuts {
        if end >= start + 2 {
            let mut bad = sig.to_vec();
            bad.swap(hint_at + start, hint_at + start + 1);
            out.push(("swapped hint indices".to_string(), bad));
            break;
        }
        start = end;
    }
    // A non-zero index after the last cut.
    let total = cuts[k - 1];
    if total < omega {
        let mut bad = sig.to_vec();
        bad[hint_at + omega - 1] = 1;
        out.push(("non-zero hint padding".to_string(), bad));
    }
    // Decreasing cuts.
    let mut bad = sig.to_vec();
    bad[cut_at] = u8::try_from(total + 1).unwrap();
    out.push(("decreasing hint cuts".to_string(), bad));
    // A cut beyond omega.
    let mut bad = sig.to_vec();
    bad[cut_at + k - 1] = u8::try_from(omega + 1).unwrap();
    out.push(("hint cut beyond omega".to_string(), bad));
    // The fixed keys and message give a hint with a row of two or more
    // indices and fewer than `omega` in all, so every case is built.
    assert_eq!(out.len(), 4, "{set:?}");
    out
}

/// `(what, public key, message, signature, expected to verify)`.
type Case = (String, Vec<u8>, Vec<u8>, Vec<u8>, bool);

fn cases(key: &MlKey, other: &MlKey) -> Vec<Case> {
    let set = key.set;
    let msg = b"differential to-be-signed bytes".to_vec();
    let pk = key.native_public_key();
    let sig = key.sign(Impl::Native, &msg);
    let mut cases: Vec<Case> = vec![
        ("valid".into(), pk.clone(), msg.clone(), sig.clone(), true),
        (
            "valid, hedged".into(),
            pk.clone(),
            msg.clone(),
            key.sign_hedged(&msg),
            true,
        ),
        (
            "valid, empty message".into(),
            pk.clone(),
            Vec::new(),
            key.sign(Impl::Oracle, b""),
            true,
        ),
        (
            "other message".into(),
            pk.clone(),
            b"other".to_vec(),
            sig.clone(),
            false,
        ),
    ];
    let step = sig.len() / 24;
    for at in (0..sig.len()).step_by(step).chain([sig.len() - 1]) {
        let bad = flip(sig.clone(), at);
        cases.push((
            format!("signature bit {at}"),
            pk.clone(),
            msg.clone(),
            bad,
            false,
        ));
    }
    for at in [0, 31, 32, pk.len() / 2, pk.len() - 1] {
        let bad = flip(pk.clone(), at);
        cases.push((
            format!("key bit {at}"),
            bad,
            msg.clone(),
            sig.clone(),
            false,
        ));
    }
    for (what, bad) in malformed_hints(set, &sig) {
        cases.push((what, pk.clone(), msg.clone(), bad, false));
    }
    let lengths = [
        ("key short", pk[..pk.len() - 1].to_vec(), sig.clone()),
        ("key long", [&pk[..], &[0]].concat(), sig.clone()),
        ("signature short", pk.clone(), sig[..sig.len() - 1].to_vec()),
        ("signature long", pk.clone(), [&sig[..], &[0]].concat()),
        ("empty", Vec::new(), Vec::new()),
    ];
    for (what, k, s) in lengths {
        cases.push((what.into(), k, msg.clone(), s, false));
    }
    for seed in 1..4u64 {
        cases.push((
            format!("filler signature {seed}"),
            pk.clone(),
            msg.clone(),
            filler(seed, sig.len()),
            false,
        ));
        cases.push((
            format!("filler key {seed}"),
            filler(seed + 100, pk.len()),
            msg.clone(),
            sig.clone(),
            false,
        ));
    }
    cases.push((
        "zero signature".into(),
        pk.clone(),
        msg.clone(),
        vec![0; sig.len()],
        false,
    ));
    cases.push((
        "0xff key".into(),
        vec![0xff; pk.len()],
        msg.clone(),
        sig.clone(),
        false,
    ));
    let other_pk = other.native_public_key();
    let other_sig = other.sign(Impl::Native, &msg);
    cases.push((
        "other set's key".into(),
        other_pk.clone(),
        msg.clone(),
        sig,
        false,
    ));
    cases.push((
        "other set's signature".into(),
        pk,
        msg.clone(),
        other_sig.clone(),
        false,
    ));
    cases.push(("other set's pair".into(), other_pk, msg, other_sig, false));
    cases
}

#[test]
fn native_and_rustcrypto_verifiers_agree() {
    let keys: Vec<MlKey> = SETS
        .iter()
        .map(|&s| MlKey::new(s, "differential"))
        .collect();
    for (i, key) in keys.iter().enumerate() {
        let set = key.set;
        let other = &keys[(i + 1) % keys.len()];
        let algs: [(&str, &dyn SignatureVerificationAlgorithm); 3] = [
            ("native", native_alg(set)),
            ("rustcrypto", rc_alg(set)),
            ("oracle", set.alg()),
        ];
        let mut checked = 0;
        for (what, pk, msg, sig, valid) in cases(key, other) {
            let expected = if valid { Ok(()) } else { Err(InvalidSignature) };
            for (name, alg) in algs {
                assert_eq!(
                    alg.verify_signature(&pk, &msg, &sig),
                    expected,
                    "{set:?} {name}: {what}"
                );
            }
            checked += 1;
        }
        assert!(checked > 40, "{set:?}: {checked}");
    }
}
