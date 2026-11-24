//! Keys, signing and verification against the oracle.

use browntls_crypto::Error;
use browntls_crypto::mldsa::{MAX_CONTEXT_LEN, SEED_LEN, SigningKey, VerifyingKey};

use super::{Failing, Fixed, Set, encodings, exact, flip};
use crate::input::Input;

/// Bytes 32..64 of an expanded key: the signing seed `K`, which the
/// expanded-key check cannot bind to the rest of the key.
const K: core::ops::Range<usize> = 32..64;

/// Key generation from a fuzzed seed.
pub(super) fn keygen_op<P: Set>(input: &mut Input<'_>) {
    let seed: [u8; SEED_LEN] = input.array();
    let key = SigningKey::<P>::from_seed(&seed);
    let (pk, sk) = P::oracle_keygen(&seed);
    let vk = key.verifying_key();
    assert_eq!(vk.as_bytes(), &pk[..], "public key");
    assert_eq!(key.to_expanded_bytes().as_ref(), &sk[..], "expanded key");
    assert_eq!(key.seed(), Some(&seed));
    assert_eq!(vk.to_bytes().as_ref(), vk.as_bytes());
    assert_eq!(
        VerifyingKey::<P>::from_bytes(vk.as_bytes()).as_ref(),
        Ok(vk)
    );
    let reloaded = SigningKey::<P>::from_expanded_bytes(&sk).expect("a genuine expanded key");
    assert_eq!(reloaded.verifying_key(), vk);
    assert_eq!(reloaded.seed(), None);

    // `generate` draws the seed from its source, and fails with it.
    let generated = SigningKey::<P>::generate(&Fixed(seed)).expect("a working source");
    assert_eq!(generated.seed(), Some(&seed));
    assert_eq!(generated.verifying_key(), vk);
    assert!(matches!(
        SigningKey::<P>::generate(&Failing),
        Err(Error::RandomFailure)
    ));

    // Debug output names the parameter set and nothing else.
    for debug in [format!("{key:?}"), format!("{vk:?}")] {
        assert!(debug.contains(P::NAME), "{debug}");
        assert!(debug.len() < 80, "{debug}");
    }

    // Encodings of the wrong length.
    let len = usize::from(input.u16()) % (P::SIGNING_KEY_LEN + 1);
    if len != P::VERIFYING_KEY_LEN {
        assert_eq!(
            VerifyingKey::<P>::from_bytes(&vec![0; len]),
            Err(Error::InvalidLength)
        );
    }
    if len != P::SIGNING_KEY_LEN {
        assert!(matches!(
            SigningKey::<P>::from_expanded_bytes(&vec![0; len]),
            Err(Error::InvalidLength)
        ));
    }
}

/// Signing with a fuzzed seed, message, context and `rnd`.
pub(super) fn sign_op<P: Set>(input: &mut Input<'_>) {
    let seed: [u8; SEED_LEN] = input.array();
    let msg = input.field();
    let ctx = input.short_field();
    let rnd: [u8; 32] = input.array();
    let key = SigningKey::<P>::from_seed(&seed);
    let vk = key.verifying_key();

    let det = key.sign_deterministic(msg, ctx).expect("signing");
    assert_eq!(
        det.as_ref(),
        P::oracle_sign(&seed, msg, ctx, &[0; 32]),
        "deterministic"
    );
    let hedged = key.sign(msg, ctx, &Fixed(rnd)).expect("signing");
    assert_eq!(
        hedged.as_ref(),
        P::oracle_sign(&seed, msg, ctx, &rnd),
        "hedged"
    );
    for sig in [det.as_ref(), hedged.as_ref()] {
        assert_eq!(sig.len(), P::SIGNATURE_LEN);
        assert_eq!(vk.verify_with_context(msg, ctx, sig), Ok(()));
        assert_eq!(P::oracle_verify(vk.as_bytes(), msg, ctx, sig), Some(true));
        if ctx.is_empty() {
            assert_eq!(vk.verify(msg, sig), Ok(()));
        }
    }

    // A flipped byte, another message, another context: rejected by both.
    let mut bad = hedged.as_ref().to_vec();
    let at = usize::from(input.u16()) % bad.len();
    bad[at] ^= input.byte() | 1;
    let extra = input.byte();
    let other_msg = [msg, &[extra]].concat();
    let other_ctx = if ctx.len() < MAX_CONTEXT_LEN {
        [ctx, &[extra]].concat()
    } else {
        let mut c = ctx.to_vec();
        c[0] ^= 1;
        c
    };
    for (m, c, s) in [
        (msg, ctx, &bad[..]),
        (&other_msg[..], ctx, hedged.as_ref()),
        (msg, &other_ctx[..], hedged.as_ref()),
    ] {
        assert_eq!(
            vk.verify_with_context(m, c, s),
            Err(Error::InvalidSignature)
        );
        assert_eq!(P::oracle_verify(vk.as_bytes(), m, c, s), Some(false));
    }

    // A context that is too long, a failing random source.
    let long = [0u8; MAX_CONTEXT_LEN + 1];
    assert!(matches!(
        key.sign(msg, &long, &Fixed(rnd)),
        Err(Error::InvalidLength)
    ));
    assert!(matches!(
        key.sign_deterministic(msg, &long),
        Err(Error::InvalidLength)
    ));
    assert_eq!(
        vk.verify_with_context(msg, &long, det.as_ref()),
        Err(Error::InvalidLength)
    );
    assert!(matches!(
        key.sign(msg, ctx, &Failing),
        Err(Error::RandomFailure)
    ));

    // The key reloaded from its expanded encoding signs identically.
    let reloaded = SigningKey::<P>::from_expanded_bytes(key.to_expanded_bytes().as_ref())
        .expect("a genuine expanded key");
    let again = reloaded.sign_deterministic(msg, ctx).expect("signing");
    assert_eq!(again.as_ref(), det.as_ref());
}

/// Verification of fuzzed or genuine-then-flipped signatures under fuzzed
/// or genuine keys: the oracle's verdict.
pub(super) fn verify_op<P: Set>(input: &mut Input<'_>) {
    let key_mode = input.choose(3);
    let mut seed = None;
    let pk = match key_mode {
        0 => {
            let s: [u8; SEED_LEN] = input.array();
            seed = Some(s);
            P::oracle_keygen(&s).0
        }
        1 => exact(input, P::VERIFYING_KEY_LEN),
        _ => input.field().to_vec(),
    };
    let msg = input.field();
    let ctx = input.short_field();
    let sig = match (input.choose(3), seed) {
        (0, Some(s)) => {
            let key = SigningKey::<P>::from_seed(&s);
            let mut sig = key
                .sign_deterministic(msg, ctx)
                .expect("signing")
                .as_ref()
                .to_vec();
            flip(input, &mut sig);
            sig
        }
        (1, _) => exact(input, P::SIGNATURE_LEN),
        _ => input.field().to_vec(),
    };

    let theirs = P::oracle_verify(&pk, msg, ctx, &sig);
    let vk = match VerifyingKey::<P>::from_bytes(&pk) {
        Ok(vk) => vk,
        Err(e) => {
            assert_eq!(e, Error::InvalidLength);
            assert_ne!(pk.len(), P::VERIFYING_KEY_LEN);
            assert_eq!(theirs, None);
            return;
        }
    };
    assert_eq!(vk.as_bytes(), &pk[..]);
    let ours = vk.verify_with_context(msg, ctx, &sig);
    assert_eq!(Some(ours.is_ok()), theirs, "verdict");
    if let Err(e) = ours {
        assert_eq!(e, Error::InvalidSignature);
    }
    if ctx.is_empty() {
        assert_eq!(vk.verify(msg, &sig), ours);
    }
}

/// `from_expanded_bytes` of fuzzed keys and of genuine keys with flips.
pub(super) fn expanded_op<P: Set>(input: &mut Input<'_>) {
    let mode = input.choose(3);
    let mut genuine = None;
    let bytes = match mode {
        0 => input.field().to_vec(),
        1 => exact(input, P::SIGNING_KEY_LEN),
        _ => {
            let seed: [u8; SEED_LEN] = input.array();
            let key = SigningKey::<P>::from_seed(&seed);
            let original = key.to_expanded_bytes().as_ref().to_vec();
            let mut bytes = original.clone();
            flip(input, &mut bytes);
            genuine = Some((original, key));
            bytes
        }
    };
    let result = SigningKey::<P>::from_expanded_bytes(&bytes);
    if bytes.len() != P::SIGNING_KEY_LEN {
        assert!(matches!(result, Err(Error::InvalidLength)));
        return;
    }
    if let Some((original, key)) = &genuine {
        // Only a change confined to K goes unnoticed.
        let only_k = bytes[..K.start] == original[..K.start] && bytes[K.end..] == original[K.end..];
        assert_eq!(result.is_ok(), only_k, "a flipped expanded key");
        if let Ok(loaded) = &result {
            assert_eq!(loaded.verifying_key(), key.verifying_key());
        }
    }
    let key = match result {
        Ok(key) => key,
        Err(e) => {
            assert_eq!(e, Error::InvalidKey);
            return;
        }
    };
    assert_eq!(key.seed(), None);
    assert_eq!(key.to_expanded_bytes().as_ref(), &bytes[..]);
    assert_eq!(
        key.verifying_key().as_bytes(),
        P::oracle_expanded_public_key(&bytes)
    );
    let msg = input.short_field();
    let sig = key.sign_deterministic(msg, b"").expect("signing");
    assert_eq!(
        sig.as_ref(),
        P::oracle_sign_expanded(&bytes, msg, b"", &[0; 32])
    );
    assert_eq!(key.verifying_key().verify(msg, sig.as_ref()), Ok(()));
    encodings::check_signing_key(&key);
}
