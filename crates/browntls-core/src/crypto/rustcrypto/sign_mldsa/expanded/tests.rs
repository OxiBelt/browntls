use alloc::vec;

use ml_dsa::{B32, ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams};

use super::*;

#[test]
fn zetas_are_those_of_fips_204() {
    // FIPS 204 Appendix B: the first and last entries of the table (whose
    // entry 0, which no algorithm reads, is zero there).
    assert_eq!(ZETAS[1..5], [4_808_194, 3_765_607, 3_761_513, 5_178_923]);
    assert_eq!(ZETAS[252..], [1_900_052, 7_598_542, 1_054_478, 7_648_983]);
    // zeta has order 512: zeta^256 = -1.
    assert_eq!(mul(ZETAS[1], ZETAS[1]), Q - 1);
}

#[test]
fn reduction() {
    let top = u64::from(Q - 1) * u64::from(Q - 1);
    for a in [0, 1, u64::from(Q) - 1, u64::from(Q), u64::from(Q) + 1, top] {
        assert_eq!(u64::from(reduce(a)), a % u64::from(Q), "{a}");
    }
    // A multiplicative walk over the field, and the largest input.
    let (mut x, mut wide) = (1u32, 1u64);
    for _ in 0..100_000 {
        wide = wide * 1_234_567 % u64::from(Q);
        x = mul(x, 1_234_567);
        assert_eq!(u64::from(x), wide);
        let square = wide * wide;
        assert_eq!(u64::from(reduce(square)), square % u64::from(Q));
    }
    assert_eq!(
        u64::from(reduce((1 << 46) - 1)),
        ((1 << 46) - 1) % u64::from(Q)
    );
    assert_eq!(add(Q - 1, Q - 1), Q - 2);
    assert_eq!(sub(0, Q - 1), 1);
    assert_eq!(sub(5, 5), 0);
}

fn sample() -> Poly {
    let mut poly = [0; N];
    let mut x = 7;
    for c in &mut poly {
        x = mul(x, 2_718_281);
        *c = x;
    }
    poly
}

#[test]
fn ntt_round_trip_and_convolution() {
    let a = sample();
    let mut a_hat = a;
    ntt(&mut a_hat);
    assert_ne!(a_hat, a);
    let mut back = a_hat;
    inverse_ntt(&mut back);
    assert_eq!(back, a);

    // Multiplying by X in the ring (X^256 = -1) is a negacyclic shift.
    let mut x = [0; N];
    x[1] = 1;
    ntt(&mut x);
    let mut product = [0; N];
    for ((p, a), x) in product.iter_mut().zip(a_hat).zip(x) {
        *p = mul(a, x);
    }
    inverse_ntt(&mut product);
    assert_eq!(product[0], sub(0, a[N - 1]));
    assert_eq!(product[1..], a[..N - 1]);
}

#[test]
fn packing() {
    // 13-bit values: 8 coefficients in 13 bytes.
    let mut bytes = [0u8; T0_LEN];
    bytes[..13].copy_from_slice(&[0xff; 13]);
    bytes[13] = 1;
    bytes[T0_LEN - 1] = 0x80;
    let mut out = [0; N];
    unpack(&bytes, D, &mut out);
    assert_eq!(
        out[..9],
        [
            0x1fff, 0x1fff, 0x1fff, 0x1fff, 0x1fff, 0x1fff, 0x1fff, 0x1fff, 1
        ]
    );
    assert_eq!(out[N - 1], 0x1000);

    // eta = 2: three bits, 0 to 4 are valid (2 to -2).
    let mut bytes = [0u8; 96];
    bytes[0] = 0b00_100_000;
    assert_eq!(unpack_eta(&bytes, &ML_DSA_44, &mut out), 0);
    assert_eq!(out[..3], [2, Q - 2, 2]);
    for v in 5..8 {
        bytes[95] = v << 5;
        assert_ne!(unpack_eta(&bytes, &ML_DSA_44, &mut out), 0, "{v}");
    }
    // eta = 4: four bits, 0 to 8 are valid.
    let mut bytes = [0u8; 128];
    bytes[0] = 0x80;
    assert_eq!(unpack_eta(&bytes, &ML_DSA_65, &mut out), 0);
    assert_eq!(out[..3], [4, Q - 4, 4]);
    for v in 9..16 {
        bytes[127] = v;
        assert_ne!(unpack_eta(&bytes, &ML_DSA_65, &mut out), 0, "{v}");
    }

    let mut t1 = [0; N];
    t1[0] = 0x3ff;
    t1[2] = 0x201;
    t1[N - 1] = 0x300;
    let mut packed = Vec::new();
    pack_t1(&t1, &mut packed);
    assert_eq!(packed.len(), T1_LEN);
    assert_eq!(packed[..5], [0xff, 0x03, 0x10, 0x20, 0x00]);
    assert_eq!(packed[T1_LEN - 2..], [0x00, 0xc0]);
}

#[test]
fn lengths() {
    // FIPS 204 Table 2.
    assert_eq!(ML_DSA_44.private_key_len(), 2560);
    assert_eq!(ML_DSA_65.private_key_len(), 4032);
    assert_eq!(ML_DSA_87.private_key_len(), 4896);
    for set in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        assert!(usize::from(set.l) <= MAX_L);
        let len = set.private_key_len();
        for len in [0, len - 1, len + 1] {
            assert!(public_key(set, &vec![0; len]).is_none());
        }
    }
}

/// The expanded private key and the public key that `ml-dsa` derives from
/// a seed.
#[allow(deprecated)]
fn genuine<P: MlDsaParams>(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let key = ExpandedSigningKey::<P>::from_seed(&B32::from([seed; 32]));
    (
        key.to_expanded().to_vec(),
        key.verifying_key().encode().to_vec(),
    )
}

/// The public key `ml-dsa` computes for the expanded key `sk`, which it
/// does not check.
#[allow(deprecated)]
fn public_key_of<P: MlDsaParams>(sk: &[u8]) -> Vec<u8> {
    let key = ExpandedSigningKey::<P>::from_expanded(&sk.try_into().unwrap());
    key.verifying_key().encode().to_vec()
}

/// Appends a polynomial of 13-bit values.
fn pack_t0(row: &Poly, out: &mut Vec<u8>) {
    for c in row.as_chunks::<8>().0 {
        let v = c.iter().rev().fold(0u128, |v, c| v << D | u128::from(*c));
        out.extend_from_slice(&v.to_le_bytes()[..13]);
    }
}

/// `sk` with its `t0` and `tr` replaced by those its `rho`, `s1` and `s2`
/// determine, whatever the range of the coefficients.
fn reseal(set: &ParameterSet, sk: &[u8]) -> Vec<u8> {
    let mut t0 = Vec::new();
    let (public_key, _) = derive(set, &split(set, sk).unwrap(), |_, row| {
        pack_t0(row, &mut t0);
    });
    let mut out = sk.to_vec();
    out[RHO_LEN + K_LEN..][..TR_LEN].copy_from_slice(&hash_public_key(&public_key));
    let at = out.len() - t0.len();
    out[at..].copy_from_slice(&t0);
    out
}

/// Coefficient `index` of the packed `s1` or `s2` polynomials in `bytes`.
fn coefficient(bytes: &[u8], bits: usize, index: usize) -> u8 {
    (0..bits).fold(0, |v, b| {
        let at = index * bits + b;
        v | ((bytes[at / 8] >> (at % 8)) & 1) << b
    })
}

fn set_coefficient(bytes: &mut [u8], bits: usize, index: usize, v: u8) {
    for b in 0..bits {
        let at = index * bits + b;
        bytes[at / 8] &= !(1 << (at % 8));
        bytes[at / 8] |= ((v >> b) & 1) << (at % 8);
    }
    assert_eq!(coefficient(bytes, bits, index), v);
}

fn checks<P: MlDsaParams>(set: &ParameterSet) {
    // The arithmetic here and that of `ml-dsa` agree on genuine keys.
    for seed in [0, 1, 0x5a, 0xff] {
        let (sk, pk) = genuine::<P>(seed);
        assert!(public_key(set, &sk) == Some(pk), "{seed}");
        assert!(reseal(set, &sk) == sk, "{seed}");
    }

    let (sk, pk) = genuine::<P>(7);
    let bits = set.eta_bits() as usize;
    let s_start = RHO_LEN + K_LEN + TR_LEN;
    let t0_start = sk.len() - usize::from(set.k) * T0_LEN;
    let s2_start = s_start + usize::from(set.l) * set.s_len();
    let count = (t0_start - s_start) * 8 / bits;

    // `K` is not checked, and does not change the public key.
    for at in RHO_LEN..RHO_LEN + K_LEN {
        let mut changed = sk.clone();
        changed[at] ^= 0x81;
        assert!(public_key(set, &changed).as_ref() == Some(&pk), "{at}");
    }

    // One flipped bit anywhere else: in `rho`, `tr`, `s1`, `s2` (in range
    // or not) and `t0` (the lowest bit of a coefficient included).
    let positions = [
        0,
        RHO_LEN - 1,
        RHO_LEN + K_LEN,
        s_start - 1,
        s_start,
        s2_start - 1,
        s2_start,
        t0_start - 1,
        t0_start,
        t0_start + T0_LEN,
        sk.len() - 1,
    ];
    for at in positions {
        for bit in 0..8 {
            let mut changed = sk.clone();
            changed[at] ^= 1 << bit;
            assert!(public_key(set, &changed).is_none(), "{at} {bit}");
        }
    }
    // Every `tr` byte counts, and so does each `t0` byte tried (one in
    // seven).
    for at in (RHO_LEN + K_LEN..s_start).chain((t0_start..sk.len()).step_by(7)) {
        let mut changed = sk.clone();
        changed[at] ^= 0x10;
        assert!(public_key(set, &changed).is_none(), "{at}");
    }

    // Another coefficient in range, with `t0` and `tr` to match: another
    // valid key, on whose public key `ml-dsa` agrees (a changed `s1`
    // changes it, a changed `s2` mostly `t0` alone). Without them, not.
    let valid = 2 * set.eta as u8 + 1;
    for index in [0, 255, 256, count / 2, count - 256, count - 1] {
        let mut changed = sk.clone();
        let v = coefficient(&changed[s_start..t0_start], bits, index);
        set_coefficient(
            &mut changed[s_start..t0_start],
            bits,
            index,
            (v + 1) % valid,
        );
        assert!(public_key(set, &changed).is_none(), "{index}");
        let resealed = reseal(set, &changed);
        assert!(resealed != changed && resealed != sk, "{index}");
        let other = public_key(set, &resealed).unwrap();
        assert_eq!(other == pk, index >= usize::from(set.l) * N, "{index}");
        assert!(other == public_key_of::<P>(&resealed), "{index}");

        // A coefficient out of range, with `t0` and `tr` to match: only
        // the range check refuses it.
        for v in valid..1 << bits {
            set_coefficient(&mut changed[s_start..t0_start], bits, index, v);
            let resealed = reseal(set, &changed);
            assert!(reseal(set, &resealed) == resealed);
            let key = split(set, &resealed).unwrap();
            let mut t0 = Vec::new();
            let (derived, bad) = derive(set, &key, |_, row| pack_t0(row, &mut t0));
            assert_ne!(bad, 0);
            assert!(t0 == key.t0 && hash_public_key(&derived) == key.tr);
            assert!(public_key(set, &resealed).is_none(), "{index} {v}");
        }
    }

    // Every coefficient out of range, and none: no key.
    assert!(public_key(set, &vec![0xff; sk.len()]).is_none());
    assert!(public_key(set, &vec![0; sk.len()]).is_none());
}

#[test]
fn expanded_keys_are_checked() {
    checks::<MlDsa44>(&ML_DSA_44);
    checks::<MlDsa65>(&ML_DSA_65);
    checks::<MlDsa87>(&ML_DSA_87);
}

/// A fixed stream of test bytes.
#[cfg(feature = "native")]
struct Stream(<Shake256 as ExtendableOutput>::Reader);

#[cfg(feature = "native")]
impl Stream {
    fn new(label: u8) -> Self {
        let mut xof = Shake256::default();
        xof.update(b"browntls expanded key agreement");
        xof.update(&[label]);
        Self(xof.finalize_xof())
    }

    fn fill(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }

    fn below(&mut self, bound: usize) -> usize {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        (u64::from_le_bytes(bytes) % bound as u64) as usize
    }
}

/// Keys that no seed yields, with `t0` and `tr` to match their `rho`, `s1`
/// and `s2`: the checks here and the native provider's
/// (`browntls_crypto::mldsa::SigningKey::from_expanded_bytes`) give the
/// same verdict on each, and on each with one more bit changed, and the
/// same public key (which is also the one `ml-dsa` derives).
#[cfg(feature = "native")]
fn agreement<P: MlDsaParams, Native: browntls_crypto::mldsa::ParameterSet>(set: &ParameterSet) {
    use browntls_crypto::mldsa::SigningKey;

    let mut stream = Stream::new(set.k);
    let bits = set.eta_bits() as usize;
    let s_start = RHO_LEN + K_LEN + TR_LEN;
    let t0_start = set.private_key_len() - usize::from(set.k) * T0_LEN;
    let count = (t0_start - s_start) * 8 / bits;
    // `round` and the byte changed after resealing, if any, name the key
    // in a failure.
    let verdict = |sk: &[u8], round: u8, changed: Option<usize>| {
        let here = public_key(set, sk);
        let native = SigningKey::<Native>::from_expanded_bytes(sk)
            .ok()
            .map(|key| key.verifying_key().as_bytes().to_vec());
        assert!(here == native, "{round} {changed:?}");
        if let Some(here) = &here {
            assert!(*here == public_key_of::<P>(sk), "{round} {changed:?}");
        }
        here.is_some()
    };
    let (mut loaded, mut refused) = (0, 0);
    for round in 0..90 {
        let (mut sk, _) = genuine::<P>(round);
        let expected = match round % 3 {
            // A few coefficients, in range or not.
            0 => {
                for _ in 0..1 + stream.below(3) {
                    let (index, v) = (stream.below(count), stream.below(1 << bits));
                    set_coefficient(&mut sk[s_start..t0_start], bits, index, v as u8);
                }
                None
            }
            // Another `rho` and `K`, and every coefficient in range.
            1 => {
                stream.fill(&mut sk[..RHO_LEN + K_LEN]);
                for index in 0..count {
                    let v = stream.below(2 * set.eta as usize + 1);
                    set_coefficient(&mut sk[s_start..t0_start], bits, index, v as u8);
                }
                Some(true)
            }
            // Any `s1` and `s2` bytes: some coefficient is out of range.
            _ => {
                stream.fill(&mut sk[s_start..t0_start]);
                Some(false)
            }
        };
        let mut sk = reseal(set, &sk);
        let loads = verdict(&sk, round, None);
        assert!(expected.is_none_or(|expected| expected == loads), "{round}");
        let at = stream.below(sk.len());
        sk[at] ^= 1 << stream.below(8);
        // Only a bit of `K` leaves the key as valid as it was.
        let in_k = (RHO_LEN..RHO_LEN + K_LEN).contains(&at);
        assert_eq!(verdict(&sk, round, Some(at)), loads && in_k, "{round} {at}");
        loaded += usize::from(loads);
        refused += usize::from(!loads);
    }
    assert!(loaded >= 30 && refused >= 30, "{loaded} {refused}");
}

#[cfg(feature = "native")]
#[test]
fn resealed_keys_agree_with_the_native_provider() {
    use browntls_crypto::mldsa as native;

    agreement::<MlDsa44, native::MlDsa44>(&ML_DSA_44);
    agreement::<MlDsa65, native::MlDsa65>(&ML_DSA_65);
    agreement::<MlDsa87, native::MlDsa87>(&ML_DSA_87);
}
