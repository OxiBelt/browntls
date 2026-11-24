//! ML-DSA integration tests: differential against the RustCrypto `ml-dsa`
//! crate, decoder and validation negative tests, hedged-signing behaviour
//! and an ignored throughput test. The ACVP and Wycheproof known-answer
//! tests are unit tests (`src/mldsa/kat_tests.rs`), since some of them need
//! the internal signing interface.
#![allow(clippy::unwrap_used, clippy::panic, clippy::cast_possible_truncation)]

use browntls_crypto::Error;
use browntls_crypto::mldsa::{
    MAX_CONTEXT_LEN, MlDsa44, MlDsa65, MlDsa87, ParameterSet, SEED_LEN, SigningKey, VerifyingKey,
};
use browntls_crypto::rand::{FixedRng, OsRng, SecureRandom};

/// splitmix64 (test data only).
struct TestRng(u64);

impl TestRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.next() as u8;
        }
        out
    }

    fn vec(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

/// A random source that always fails.
struct FailingRng;

impl SecureRandom for FailingRng {
    fn fill(&self, _dest: &mut [u8]) -> Result<(), Error> {
        Err(Error::RandomFailure)
    }
}

// ---------------------------------------------------------------------------
// Differential against RustCrypto `ml-dsa`.
// ---------------------------------------------------------------------------

macro_rules! differential {
    ($name:ident, $ours:ty, $theirs:ty, $iters:expr) => {
        #[test]
        fn $name() {
            type Theirs = $theirs;
            let mut rng = TestRng(0x6d6c_6473_6100 + <$ours>::K as u64);
            for iter in 0..$iters {
                let seed: [u8; 32] = match iter {
                    0 => [0; 32],
                    1 => [0xff; 32],
                    _ => rng.bytes(),
                };
                let msg = rng.vec(300);
                let ctx = if iter == 2 {
                    vec![0xa5; MAX_CONTEXT_LEN]
                } else {
                    rng.vec(40)
                };

                let rc_sk = ml_dsa::SigningKey::<Theirs>::from_seed(&seed.into());
                let rc_esk = rc_sk.expanded_key();
                let rc_vk = rc_esk.verifying_key();
                #[allow(deprecated)]
                let rc_sk_bytes = rc_esk.to_expanded();

                let sk = SigningKey::<$ours>::from_seed(&seed);
                let vk = sk.verifying_key();
                assert_eq!(sk.seed(), Some(&seed));
                assert_eq!(vk.as_bytes(), rc_vk.encode().as_slice(), "pk");
                assert_eq!(
                    sk.to_expanded_bytes().as_ref(),
                    rc_sk_bytes.as_slice(),
                    "sk"
                );

                // Deterministic signatures are byte-identical.
                let sig = sk.sign_deterministic(&msg, &ctx).unwrap();
                let rc_sig = rc_esk.sign_deterministic(&msg, &ctx).unwrap();
                assert_eq!(sig.as_ref(), rc_sig.encode().as_slice(), "sig");

                // Cross-verification both ways, including a hedged signature.
                let hedged = sk.sign(&msg, &ctx, &OsRng).unwrap();
                for s in [sig, hedged] {
                    vk.verify_with_context(&msg, &ctx, s.as_ref()).unwrap();
                    let rs = ml_dsa::Signature::<Theirs>::try_from(s.as_ref()).unwrap();
                    assert!(rc_vk.verify_with_context(&msg, &ctx, &rs));
                }
                let rc_hedged = rc_esk.sign_internal(
                    &[&[0, ctx.len() as u8], &ctx, &msg],
                    &rng.bytes::<32>().into(),
                );
                vk.verify_with_context(&msg, &ctx, rc_hedged.encode().as_slice())
                    .unwrap();

                // Tampered signatures, messages, contexts and keys are
                // rejected by both.
                let rejected_by_both = |pk: &[u8], m: &[u8], c: &[u8], s: &[u8]| {
                    let ours = VerifyingKey::<$ours>::from_bytes(pk)
                        .unwrap()
                        .verify_with_context(m, c, s);
                    assert_eq!(ours, Err(Error::InvalidSignature));
                    let enc = ml_dsa::EncodedVerifyingKey::<Theirs>::try_from(pk).unwrap();
                    let theirs = ml_dsa::VerifyingKey::<Theirs>::decode(&enc);
                    if let Ok(rs) = ml_dsa::Signature::<Theirs>::try_from(s) {
                        assert!(!theirs.verify_with_context(m, c, &rs));
                    }
                };
                let pk = vk.as_bytes();
                for _ in 0..3 {
                    let mut bad = sig.as_ref().to_vec();
                    let pos = rng.below(bad.len());
                    bad[pos] ^= 1 << (rng.next() % 8);
                    rejected_by_both(pk, &msg, &ctx, &bad);
                }
                let mut bad_msg = msg.clone();
                bad_msg.push(0);
                rejected_by_both(pk, &bad_msg, &ctx, sig.as_ref());
                let mut bad_ctx = ctx.clone();
                if bad_ctx.len() < MAX_CONTEXT_LEN {
                    bad_ctx.push(0);
                } else {
                    bad_ctx[0] ^= 1;
                }
                rejected_by_both(pk, &msg, &bad_ctx, sig.as_ref());
                let mut bad_pk = pk.to_vec();
                let pos = rng.below(bad_pk.len());
                bad_pk[pos] ^= 1 << (rng.next() % 8);
                rejected_by_both(&bad_pk, &msg, &ctx, sig.as_ref());

                // Expanded round trip signs identically.
                let sk2 = SigningKey::<$ours>::from_expanded_bytes(sk.to_expanded_bytes().as_ref())
                    .unwrap();
                assert_eq!(sk2.seed(), None);
                assert_eq!(sk2.verifying_key(), vk);
                assert_eq!(sk2.sign_deterministic(&msg, &ctx).unwrap(), sig);
            }
        }
    };
}

differential!(mldsa44_differential, MlDsa44, ml_dsa::MlDsa44, 12);
differential!(mldsa65_differential, MlDsa65, ml_dsa::MlDsa65, 12);
differential!(mldsa87_differential, MlDsa87, ml_dsa::MlDsa87, 12);

// ---------------------------------------------------------------------------
// Negative and edge cases.
// ---------------------------------------------------------------------------

/// Overwrites the `bits`-bit little-endian field at bit offset `bit` of
/// `bytes` with `val`.
fn set_bits(bytes: &mut [u8], bit: usize, bits: usize, val: u32) {
    for i in 0..bits {
        let (byte, shift) = ((bit + i) / 8, (bit + i) % 8);
        bytes[byte] = (bytes[byte] & !(1 << shift)) | ((((val >> i) & 1) as u8) << shift);
    }
}

fn edge_cases<P: ParameterSet>() {
    let mut rng = TestRng(0x6564_6765 + P::K as u64);
    let seed: [u8; SEED_LEN] = rng.bytes();
    let sk = SigningKey::<P>::from_seed(&seed);
    let vk = sk.verifying_key();
    let msg = b"edge cases";

    // Decoder lengths.
    for len in [0, P::VERIFYING_KEY_LEN - 1, P::VERIFYING_KEY_LEN + 1] {
        let bytes = vec![0; len];
        assert_eq!(
            VerifyingKey::<P>::from_bytes(&bytes).unwrap_err(),
            Error::InvalidLength
        );
    }
    for len in [0, P::SIGNING_KEY_LEN - 1, P::SIGNING_KEY_LEN + 1] {
        let bytes = vec![0; len];
        assert_eq!(
            SigningKey::<P>::from_expanded_bytes(&bytes).unwrap_err(),
            Error::InvalidLength
        );
    }
    let sig = sk.sign_deterministic(msg, b"").unwrap();
    let sig = sig.as_ref();
    vk.verify(msg, sig).unwrap();
    for len in [0, P::SIGNATURE_LEN - 1, P::SIGNATURE_LEN + 1] {
        let mut bad = sig.to_vec();
        bad.resize(len, 0);
        assert_eq!(vk.verify(msg, &bad), Err(Error::InvalidSignature));
    }

    // Context of 255 and 256 bytes.
    let ctx255 = [7u8; MAX_CONTEXT_LEN];
    let s = sk.sign_deterministic(msg, &ctx255).unwrap();
    vk.verify_with_context(msg, &ctx255, s.as_ref()).unwrap();
    assert_eq!(vk.verify(msg, s.as_ref()), Err(Error::InvalidSignature));
    let ctx256 = [7u8; MAX_CONTEXT_LEN + 1];
    assert_eq!(
        sk.sign_deterministic(msg, &ctx256).unwrap_err(),
        Error::InvalidLength
    );
    assert_eq!(
        sk.sign(msg, &ctx256, &OsRng).unwrap_err(),
        Error::InvalidLength
    );
    assert_eq!(
        vk.verify_with_context(msg, &ctx256, s.as_ref()),
        Err(Error::InvalidLength)
    );

    // Hint encoding malformations. Layout: c~ || z || h with h being omega
    // index bytes followed by k cumulative counts.
    let h_off = P::SIGNATURE_LEN - P::OMEGA - P::K;
    let counts = &sig[h_off + P::OMEGA..];
    let total = usize::from(counts[P::K - 1]);
    assert!(total >= 2, "test signature needs two hints");
    let mutate = |f: &dyn Fn(&mut [u8])| {
        let mut bad = sig.to_vec();
        f(&mut bad[h_off..]);
        assert_eq!(vk.verify(msg, &bad), Err(Error::InvalidSignature));
    };
    // The row holding the first two hints, if any row has two.
    if let Some(row) = (0..P::K).find(|&i| {
        let start = if i == 0 { 0 } else { counts[i - 1] };
        counts[i] >= start + 2
    }) {
        let start = if row == 0 {
            0
        } else {
            usize::from(counts[row - 1])
        };
        // Non-increasing index within a row.
        mutate(&|h| h[start + 1] = h[start]);
        mutate(&|h| h.swap(start, start + 1));
    }
    // Too many hints (a count above omega), decreasing counts.
    mutate(&|h| h[P::OMEGA + P::K - 1] = P::OMEGA as u8 + 1);
    if P::K > 1 && counts[0] > 0 {
        mutate(&|h| h[P::OMEGA] = h[P::OMEGA + 1] + 1);
    }
    // Non-zero padding after the last index.
    if total < P::OMEGA {
        mutate(&|h| h[P::OMEGA - 1] = 1);
    }

    // The z norm check is not tested here: changing z in a real signature
    // also changes w' and so fails on the challenge, whatever the norm. The
    // crate-internal unit test `mldsa::tests::z_norm_boundary_is_exclusive`
    // builds self-consistent signatures with ||z|| exactly gamma1 - beta and
    // gamma1 - beta - 1, and the Wycheproof vectors include norm-violation
    // and boundary cases.

    // Expanded private keys: out-of-range s1 / s2 coefficients, flipped t0
    // and tr bits. Here the stored t0 and tr are left as they were, so the
    // out-of-range cases are also caught by the consistency check; the unit
    // test `mldsa::tests::expanded_key_range_check` recomputes t0 and tr so
    // that only the range check can reject.
    let esk = sk.to_expanded_bytes();
    let esk = esk.as_ref();
    let eta_bits = if P::ETA == 2 { 3 } else { 4 };
    let s1 = 128;
    let s2 = s1 + P::L * 32 * eta_bits;
    let t0 = s2 + P::K * 32 * eta_bits;
    let check_invalid = |f: &dyn Fn(&mut [u8])| {
        let mut bad = esk.to_vec();
        f(&mut bad);
        assert_eq!(
            SigningKey::<P>::from_expanded_bytes(&bad).unwrap_err(),
            Error::InvalidKey
        );
    };
    for (off, coeff) in [(s1, 0), (s1, 255), (s2, 17), (s2 + 32 * eta_bits, 0)] {
        // Packed value eta - c > 2 eta means c < -eta.
        let top = (1u32 << eta_bits) - 1;
        for v in 2 * P::ETA as u32 + 1..=top {
            check_invalid(&|k| set_bits(&mut k[off..], coeff * eta_bits, eta_bits, v));
        }
    }
    for bit in [0, 7, 8 * 416 * P::K - 1] {
        check_invalid(&|k| k[t0 + bit / 8] ^= 1 << (bit % 8));
    }
    for bit in [0, 511] {
        check_invalid(&|k| k[64 + bit / 8] ^= 1 << (bit % 8));
    }
    // A changed rho changes A and therefore t: also rejected.
    check_invalid(&|k| k[0] ^= 1);
    // A changed K is undetectable (it only seeds the masks) and still yields
    // a key whose signatures verify.
    let mut other_k = esk.to_vec();
    other_k[40] ^= 1;
    let sk_k = SigningKey::<P>::from_expanded_bytes(&other_k).unwrap();
    let s = sk_k.sign_deterministic(msg, b"").unwrap();
    vk.verify(msg, s.as_ref()).unwrap();

    // Debug output is redacted.
    let dbg = format!("{sk:?}");
    assert!(dbg.contains(P::NAME) && !dbg.contains("sk:") && !dbg.contains("seed"));
}

#[test]
fn mldsa_edge_cases() {
    edge_cases::<MlDsa44>();
    edge_cases::<MlDsa65>();
    edge_cases::<MlDsa87>();
}

fn hedged<P: ParameterSet>() {
    let sk = SigningKey::<P>::generate(&OsRng).unwrap();
    assert!(sk.seed().is_some());
    let vk = sk.verifying_key();
    let msg = b"hedged";

    // Fresh randomness: signatures differ and all verify.
    let sigs: Vec<_> = (0..4)
        .map(|_| sk.sign(msg, b"ctx", &OsRng).unwrap())
        .collect();
    for (i, s) in sigs.iter().enumerate() {
        vk.verify_with_context(msg, b"ctx", s.as_ref()).unwrap();
        for t in &sigs[..i] {
            assert_ne!(s, t);
        }
    }
    // rnd = 0^32 through the hedged API is the deterministic variant.
    assert_eq!(
        sk.sign(msg, b"ctx", &FixedRng::new(&[0; 32])).unwrap(),
        sk.sign_deterministic(msg, b"ctx").unwrap()
    );
    // A failing source is an error, never a deterministic fallback.
    assert_eq!(
        sk.sign(msg, b"", &FailingRng).unwrap_err(),
        Error::RandomFailure
    );
    assert_eq!(
        sk.sign(msg, b"", &FixedRng::new(&[1; 31])).unwrap_err(),
        Error::RandomFailure
    );
    assert_eq!(
        SigningKey::<P>::generate(&FailingRng).unwrap_err(),
        Error::RandomFailure
    );
}

#[test]
fn mldsa_hedged_signing() {
    hedged::<MlDsa44>();
    hedged::<MlDsa65>();
    hedged::<MlDsa87>();
}

#[test]
fn mldsa_constants() {
    for (k, pk, sk, sig) in [
        (
            MlDsa44::K,
            MlDsa44::VERIFYING_KEY_LEN,
            MlDsa44::SIGNING_KEY_LEN,
            MlDsa44::SIGNATURE_LEN,
        ),
        (
            MlDsa65::K,
            MlDsa65::VERIFYING_KEY_LEN,
            MlDsa65::SIGNING_KEY_LEN,
            MlDsa65::SIGNATURE_LEN,
        ),
        (
            MlDsa87::K,
            MlDsa87::VERIFYING_KEY_LEN,
            MlDsa87::SIGNING_KEY_LEN,
            MlDsa87::SIGNATURE_LEN,
        ),
    ] {
        assert_eq!(pk, 32 + 320 * k);
        assert!(sk > pk && sig > 2000);
    }
    assert_eq!(
        (MlDsa44::BETA, MlDsa65::BETA, MlDsa87::BETA),
        (78, 196, 120)
    );
    assert_eq!(<MlDsa65 as ParameterSet>::SIGNATURE_LEN, 3309);
    assert_eq!(MlDsa87::NAME, "ML-DSA-87");
}

// ---------------------------------------------------------------------------
// Throughput (`cargo test --release -p browntls-crypto --test mldsa --
// --ignored --nocapture`).
// ---------------------------------------------------------------------------

fn bench<P: ParameterSet>() {
    use std::time::{Duration, Instant};
    fn rate(mut f: impl FnMut()) -> f64 {
        let budget = Duration::from_millis(500);
        let start = Instant::now();
        let mut n = 0u64;
        while start.elapsed() < budget {
            for _ in 0..4 {
                f();
            }
            n += 4;
        }
        n as f64 / start.elapsed().as_secs_f64()
    }
    let seed = [7u8; 32];
    let sk = SigningKey::<P>::from_seed(&seed);
    let sig = sk.sign_deterministic(b"msg", b"").unwrap();
    let mut counter = 0u8;
    let kg = rate(|| {
        std::hint::black_box(SigningKey::<P>::from_seed(std::hint::black_box(&seed)));
    });
    let sign = rate(|| {
        counter = counter.wrapping_add(1);
        std::hint::black_box(sk.sign_deterministic(&[counter], b"").unwrap());
    });
    let vk = sk.verifying_key();
    let verify = rate(|| {
        std::hint::black_box(vk.verify(b"msg", std::hint::black_box(sig.as_ref()))).unwrap();
    });
    println!(
        "{:<10} keygen {:>7.0}/s  sign {:>7.0}/s  verify {:>7.0}/s",
        P::NAME,
        kg,
        sign,
        verify
    );
}

#[test]
#[ignore = "throughput measurement"]
fn mldsa_throughput() {
    bench::<MlDsa44>();
    bench::<MlDsa65>();
    bench::<MlDsa87>();
}
