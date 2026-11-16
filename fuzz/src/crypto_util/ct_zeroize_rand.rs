//! Constant-time helpers (`ct`), zeroisation (`zeroize`) and randomness
//! sources (`rand`) of the `crypto_util` target.

use browntls_crypto::Error;
use browntls_crypto::ct::{self, Choice};
use browntls_crypto::rand::{self, FixedRng, OsRng};
use browntls_crypto::zeroize::{self, Zeroize, Zeroizing};

use crate::input::Input;

// ---------------------------------------------------------------------------
// ct, zeroize, rand
// ---------------------------------------------------------------------------

fn choice(b: bool) -> Choice {
    Choice::from_bit(u64::from(b))
}

pub(super) fn ct_op(input: &mut Input<'_>) {
    let a = input.u64();
    let b = if input.bool() { a } else { input.u64() };
    let bit = input.u64();
    let c = Choice::from_bit(bit);
    let cb = bit & 1 == 1;
    assert_eq!(c.mask(), if cb { u64::MAX } else { 0 });
    assert_eq!(c.declassify(), cb);
    assert_eq!((!c).declassify(), !cb);
    let d = choice(a & 1 == 1);
    assert_eq!(c.and(d).declassify(), cb && a & 1 == 1);
    assert_eq!(c.or(d).declassify(), cb || a & 1 == 1);
    assert_eq!(Choice::TRUE.mask(), u64::MAX);
    assert_eq!(Choice::FALSE.mask(), 0);

    assert_eq!(ct::is_zero_u64(a).declassify(), a == 0);
    assert_eq!(ct::eq_u64(a, b).declassify(), a == b);
    assert_eq!(ct::lt_u64(a, b).declassify(), a < b);
    assert_eq!(ct::select_u64(c, a, b), if cb { a } else { b });
    let (x, y) = (a.to_le_bytes()[0], b.to_le_bytes()[0]);
    assert_eq!(ct::select_u8(c, x, y), if cb { x } else { y });

    let src = input.short_field();
    let mut dst = exact(input, src.len());
    let original = dst.clone();
    ct::conditional_copy(c, &mut dst, src);
    assert_eq!(dst, if cb { src } else { &original[..] });

    let words: Vec<u64> = (0..input.choose(8)).map(|_| input.u64()).collect();
    let mut p = words.clone();
    let mut q: Vec<u64> = words.iter().map(|w| w.rotate_left(17) ^ a).collect();
    let q0 = q.clone();
    ct::conditional_swap_u64(c, &mut p, &mut q);
    if cb {
        assert_eq!((p, q), (q0, words));
    } else {
        assert_eq!((p, q), (words, q0));
    }

    let l = input.short_field();
    let r = if input.bool() { l } else { input.short_field() };
    assert_eq!(ct::eq_bytes(l, r).declassify(), l == r);
    assert_eq!(ct::eq(l, r), l == r);
}

/// `len` bytes from the input, zero-padded.
fn exact(input: &mut Input<'_>, len: usize) -> Vec<u8> {
    let mut out = input.bytes(len).to_vec();
    out.resize(len, 0);
    out
}

pub(super) fn zeroize_op(input: &mut Input<'_>) {
    let bytes = input.field();
    let words = |n: usize| bytes.chunks(n).count().max(1);

    let mut b = bytes.to_vec();
    zeroize::zeroize_bytes(&mut b);
    assert!(b.iter().all(|&x| x == 0));
    let mut b = bytes.to_vec();
    b.zeroize();
    assert!(b.is_empty(), "Vec::zeroize clears");
    let mut b = bytes.to_vec();
    b.as_mut_slice().zeroize();
    assert_eq!(b.len(), bytes.len());
    assert!(b.iter().all(|&x| x == 0));

    let mut w32 = vec![u32::MAX; words(4)];
    zeroize::zeroize_u32(&mut w32);
    assert!(w32.iter().all(|&x| x == 0));
    let mut w64 = vec![u64::MAX; words(8)];
    zeroize::zeroize_u64(&mut w64);
    assert!(w64.iter().all(|&x| x == 0));
    let mut w16 = vec![-1i16; words(2)];
    zeroize::zeroize_i16(&mut w16);
    assert!(w16.iter().all(|&x| x == 0));

    let mut a8: [u8; 7] = input.array();
    a8.zeroize();
    assert_eq!(a8, [0; 7]);
    let mut a32 = [input.u32(); 3];
    a32.zeroize();
    assert_eq!(a32, [0; 3]);
    let mut a64 = [input.u64(); 2];
    a64.zeroize();
    assert_eq!(a64, [0; 2]);
    let mut a16 = [i16::from_be_bytes(input.array()); 5];
    a16.zeroize();
    assert_eq!(a16, [0; 5]);
    let mut s32 = vec![7u32; 3];
    s32.as_mut_slice().zeroize();
    let mut s64 = vec![7u64; 3];
    s64.as_mut_slice().zeroize();
    let mut s16 = vec![7i16; 3];
    s16.as_mut_slice().zeroize();
    assert!(s32.iter().all(|&x| x == 0) && s64.iter().all(|&x| x == 0));
    assert!(s16.iter().all(|&x| x == 0));

    let mut z = Zeroizing(input.array::<16>());
    let original = *z;
    z[0] ^= 1;
    assert_eq!(z.0[0], original[0] ^ 1);
    assert_eq!(format!("{z:?}"), "Zeroizing(..)");
    let copy = z.clone();
    assert_eq!(copy.0, z.0);
}

pub(super) fn rand_op(input: &mut Input<'_>) {
    let bytes = input.field();
    let rng = FixedRng::new(bytes);
    // Fixed draws replay the bytes in order, then fail without consuming.
    let mut offset = 0;
    for _ in 0..input.choose(6) {
        let result = match input.choose(3) {
            0 => rand::array::<1>(&rng).map(|a| a.to_vec()),
            1 => rand::array::<16>(&&rng).map(|a| a.to_vec()),
            _ => rand::array::<32>(&rng).map(|a| a.to_vec()),
        };
        match result {
            Ok(out) => {
                assert_eq!(out, bytes[offset..offset + out.len()]);
                offset += out.len();
            }
            Err(e) => {
                assert_eq!(e, Error::RandomFailure);
                assert!(bytes.len() - offset < 32);
            }
        }
    }
    let rest = rand::array::<0>(&rng);
    assert_eq!(rest, Ok([]));
    if input.bool() {
        let a = rand::array::<32>(&OsRng).expect("OS randomness");
        let b = rand::array::<32>(&OsRng).expect("OS randomness");
        assert_ne!(a, b, "OS randomness repeated");
    }
}
