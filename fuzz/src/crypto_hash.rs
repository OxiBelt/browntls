//! Hash functions, HMAC, HKDF and the TLS 1.2 PRF of `browntls-crypto`
//! (`fuzz_targets/crypto_hash.rs`).
//!
//! Reaches every public function of `hash` (SHA-1, SHA-2, SHA-3, SHAKE, the
//! four-way SHAKE and Keccak-f\[1600\] APIs, [`DynHash`]), `hmac`, `hkdf`
//! and `tls12_prf`, and checks:
//!
//! - every digest, XOF stream, MAC, HKDF output and PRF output against the
//!   RustCrypto `sha1`, `sha2`, `sha3`, `shake`, `hmac` and `hkdf` crates (or
//!   a reference construction on top of them);
//! - incremental hashing with fuzzed chunk boundaries, and clones taken
//!   mid-stream, against one-shot hashing;
//! - the same results under every acceleration policy of the algorithm
//!   (portable only, SIMD only, dedicated instructions only, best), so each
//!   kind of accelerated backend this CPU has is compared with the portable
//!   one;
//! - Keccak-f\[1600\] against a reference permutation in this file, and
//!   every lane of the four-way APIs against the single-lane result;
//! - HMAC verification accepts exactly the correct tags truncated to between
//!   half and the full digest length.
//!
//! Input: a sequence of at most [`MAX_OPS`] operations, each an op selector
//! byte followed by its arguments (see [`run`]). Lengths are bounded so that
//! one input runs in milliseconds.

use std::fmt::Debug;

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Acceleration, Algorithm, Policy, load};
use browntls_crypto::hash::sha3::{keccak_f1600, keccak_f1600_x4};
use browntls_crypto::hash::{
    DynHash, DynOutput, HashAlgorithm, HashFunction, MAX_BLOCK_LEN, MAX_OUTPUT_LEN, Sha1, Sha3_256,
    Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512, Shake128, Shake128x4, Shake256, Shake256x4,
    ShakeReader,
};
use browntls_crypto::hkdf::Hkdf;
use browntls_crypto::hmac::Hmac;
use browntls_crypto::tls12_prf;
use hmac::digest::Digest;
use hmac::digest::common::BlockSizeUser;
use hmac::{KeyInit as _, Mac as _};
use shake::{ExtendableOutput as _, Update as _, XofReader as _};

use crate::input::{Input, put_field, put_short_field};

/// Most operations one input runs.
pub const MAX_OPS: usize = 64;
/// Number of operations.
const OPS: u8 = 7;

const OP_DIGEST: u8 = 0;
const OP_SHAKE: u8 = 1;
const OP_SHAKE_X4: u8 = 2;
const OP_KECCAK: u8 = 3;
const OP_HMAC: u8 = 4;
const OP_HKDF: u8 = 5;
const OP_PRF: u8 = 6;

/// Number of hash functions selectable by a hash byte.
const HASHES: usize = 8;

/// Acceleration policies every backend-dependent result is computed under:
/// the default, portable only, dedicated instructions only, SIMD only.
const POLICIES: [Policy; 4] = [
    Policy::PREFERRED,
    Policy::NONE,
    Policy::new(Acceleration::None, Acceleration::Preferred),
    Policy::new(Acceleration::Preferred, Acceleration::None),
];

/// The `crypto_hash` fuzz target.
///
/// Each operation is a selector byte (taken modulo the number of operations)
/// and then:
///
/// - 0 digest: hash, message, chunk plan, split point (u16), `DynOutput`
///   bytes (8-bit field);
/// - 1 SHAKE: variant, message, chunk plan, output length (u16), block
///   count, read plan;
/// - 2 four-way SHAKE: variant, four lanes (8-bit field and extension byte
///   each), squeeze plan;
/// - 3 Keccak-f\[1600\]: 25 lanes (u64), lane tweak (u64), iterations;
/// - 4 HMAC: hash, key (a message), message, chunk plan, truncation, flip
///   position (u16), candidate tag (8-bit field);
/// - 5 HKDF: hash, salt flag and salt, IKM, info fragments, output length
///   (u16), PRK flag and PRK, MAC data fragments;
/// - 6 TLS 1.2 PRF: hash, secret, label, seed fragments, output length (u16).
///
/// A hash byte selects SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256,
/// SHA3-384 or SHA3-512. A message is a 16-bit length-prefixed field followed
/// by an extension byte that appends `17 * n` pattern bytes; a chunk plan is
/// an 8-bit length-prefixed list of chunk-size bytes (see [`chunk_len`]);
/// fragments are a count byte (modulo 4) and that many 8-bit fields.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.byte() % OPS {
            OP_DIGEST => op_digest(&mut input),
            OP_SHAKE => op_shake(&mut input),
            OP_SHAKE_X4 => op_shake_x4(&mut input),
            OP_KECCAK => op_keccak(&mut input),
            OP_HMAC => op_hmac(&mut input),
            OP_HKDF => op_hkdf(&mut input),
            _ => op_prf(&mut input),
        }
    }
}

/// Calls `$f::<Ours, Theirs>(alg, $args)` for the hash selected by `$sel`,
/// where `alg` is the acceleration algorithm of its compression function.
macro_rules! with_hash {
    ($sel:expr, $f:ident($($arg:expr),* $(,)?)) => {
        match $sel % HASHES {
            0 => $f::<Sha1, sha1::Sha1>(Algorithm::Sha1, $($arg),*),
            1 => $f::<Sha224, sha2::Sha224>(Algorithm::Sha256, $($arg),*),
            2 => $f::<Sha256, sha2::Sha256>(Algorithm::Sha256, $($arg),*),
            3 => $f::<Sha384, sha2::Sha384>(Algorithm::Sha512, $($arg),*),
            4 => $f::<Sha512, sha2::Sha512>(Algorithm::Sha512, $($arg),*),
            5 => $f::<Sha3_256, sha3::Sha3_256>(Algorithm::Keccak, $($arg),*),
            6 => $f::<Sha3_384, sha3::Sha3_384>(Algorithm::Keccak, $($arg),*),
            _ => $f::<Sha3_512, sha3::Sha3_512>(Algorithm::Keccak, $($arg),*),
        }
    };
}

/// The run-time identifier of hash `sel` (SHA-1 has none).
fn dyn_algorithm(sel: usize) -> Option<HashAlgorithm> {
    Some(match sel % HASHES {
        0 => return None,
        1 => HashAlgorithm::Sha224,
        2 => HashAlgorithm::Sha256,
        3 => HashAlgorithm::Sha384,
        4 => HashAlgorithm::Sha512,
        5 => HashAlgorithm::Sha3_256,
        6 => HashAlgorithm::Sha3_384,
        _ => HashAlgorithm::Sha3_512,
    })
}

/// Computes `f` under every policy in [`POLICIES`] for `alg`, asserts that
/// all results agree and returns one. Restores the default policy.
pub(crate) fn across_policies<R: PartialEq + Debug>(alg: Algorithm, f: impl Fn() -> R) -> R {
    let mut first: Option<R> = None;
    for policy in POLICIES {
        accel::set_policy(alg, policy).expect("a policy without Required always applies");
        let r = f();
        match &first {
            None => first = Some(r),
            Some(want) => assert_eq!(want, &r, "{} under policy {policy}", alg.name()),
        }
    }
    accel::set_policy(alg, Policy::PREFERRED).expect("default policy");
    first.expect("at least one policy")
}

/// Computes `f` with load-aware routing (`accel::load`) enabled and, for
/// every stream of `alg` that has an alternate backend on this CPU,
/// `percent` (modulo 101) of its calls fixed on alternate number `alternate`
/// (modulo their number). Turns routing off again and returns the result,
/// which the caller compares with the one computed without routing.
pub(crate) fn with_fixed_share<R>(
    alg: Algorithm,
    alternate: u8,
    percent: u8,
    f: impl FnOnce() -> R,
) -> R {
    load::enable(load::Config::DEFAULT).expect("built with `std`, which provides the clock");
    for lane in 0..load::lanes(alg) {
        let alternates = load::status(alg, lane).map_or(0, |s| s.alternates);
        if alternates > 0 {
            load::set_fixed(
                alg,
                lane,
                usize::from(alternate) % alternates,
                percent % 101,
            )
            .expect("an existing alternate and a share of at most 100%");
        }
    }
    let r = f();
    load::disable();
    r
}

/// A message: a field and up to `17 * 255` appended pattern bytes, so that
/// long multi-block messages need few input bytes.
pub(crate) fn message(input: &mut Input<'_>) -> Vec<u8> {
    let mut msg = input.field().to_vec();
    let ext = usize::from(input.byte()) * 17;
    msg.extend((0..ext).map(|i| (i % 251) as u8 ^ 0x5a));
    msg
}

/// A chunk size from one plan byte: `0..=127` bytes, or with the top bit set
/// a multiple of 8 up to 1016 (so whole blocks of every rate occur).
pub(crate) fn chunk_len(b: u8) -> usize {
    if b & 0x80 == 0 {
        usize::from(b)
    } else {
        usize::from(b & 0x7f) * 8
    }
}

/// Splits `msg` by `plan` (the remainder is the last chunk).
pub(crate) fn chunks<'a>(msg: &'a [u8], plan: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = msg;
    for &b in plan {
        let n = chunk_len(b).min(rest.len());
        let (head, tail) = rest.split_at(n);
        out.push(head);
        rest = tail;
    }
    out.push(rest);
    out
}

/// Up to three 8-bit length-prefixed fragments, their count from one byte.
fn fragments<'a>(input: &mut Input<'a>) -> Vec<&'a [u8]> {
    let n = input.choose(4);
    (0..n).map(|_| input.short_field()).collect()
}

// ------------------------------------------------------------- digests

fn op_digest(input: &mut Input<'_>) {
    let sel = input.choose(HASHES);
    let msg = message(input);
    let plan = input.short_field();
    let split = usize::from(input.u16());
    let out_bytes = input.short_field();
    with_hash!(sel, digest_op(&msg, plan, split));
    if let Some(alg) = dyn_algorithm(sel) {
        dyn_digest(alg, &msg, plan, split);
    }
    let out_bytes = &out_bytes[..out_bytes.len().min(MAX_OUTPUT_LEN)];
    assert_eq!(DynOutput::new(out_bytes).as_ref(), out_bytes);
}

/// One-shot, chunked and cloned hashing against the oracle `R`.
fn digest_op<H, R>(alg: Algorithm, msg: &[u8], plan: &[u8], split: usize)
where
    H: HashFunction,
    R: Digest + BlockSizeUser,
{
    let want = R::digest(msg).to_vec();
    assert_eq!(H::OUTPUT_LEN, want.len());
    assert_eq!(H::BLOCK_LEN, R::block_size());
    assert!(H::OUTPUT_LEN <= MAX_OUTPUT_LEN && H::BLOCK_LEN <= MAX_BLOCK_LEN);

    let one_shot = across_policies(alg, || H::digest(msg).as_ref().to_vec());
    assert_eq!(one_shot, want, "one-shot digest");

    let parts = chunks(msg, plan);
    let chunked = across_policies(alg, || {
        let mut h = H::new();
        for part in &parts {
            h.update(part);
        }
        h.finalize().as_ref().to_vec()
    });
    assert_eq!(chunked, want, "chunked digest");

    // A clone taken mid-stream continues independently.
    let split = split % (msg.len() + 1);
    let mut h = H::default();
    h.update(&msg[..split]);
    let mut copy = h.clone();
    h.update(&msg[split..]);
    copy.update(&msg[split..]);
    let (a, b) = (h.finalize(), copy.finalize());
    assert_eq!(a, b);
    assert_eq!(a.as_ref(), &want[..]);
}

/// The run-time selected API against the static types.
fn dyn_digest(alg: HashAlgorithm, msg: &[u8], plan: &[u8], split: usize) {
    let want = DynHash::digest(alg, msg);
    assert_eq!(want.as_ref().len(), alg.output_len());
    let mut h = DynHash::new(alg);
    assert_eq!(h.algorithm(), alg);
    for part in chunks(msg, plan) {
        h.update(part);
    }
    assert_eq!(h.finalize(), want);

    let split = split % (msg.len() + 1);
    let mut h = DynHash::new(alg);
    h.update(&msg[..split]);
    let mut copy = h.clone();
    copy.update(&msg[split..]);
    assert_eq!(copy.algorithm(), alg);
    assert_eq!(copy.finalize(), want);
    h.update(&msg[split..]);
    assert_eq!(DynOutput::new(want.as_ref()), h.finalize());

    let fixed = match alg {
        HashAlgorithm::Sha224 => Sha224::digest(msg).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(msg).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(msg).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(msg).to_vec(),
        HashAlgorithm::Sha3_256 => Sha3_256::digest(msg).to_vec(),
        HashAlgorithm::Sha3_384 => Sha3_384::digest(msg).to_vec(),
        HashAlgorithm::Sha3_512 => Sha3_512::digest(msg).to_vec(),
        _ => return,
    };
    assert_eq!(want.as_ref(), &fixed[..]);
}

// ---------------------------------------------------------------- SHAKE

/// The single-lane SHAKE API, abstracted over the two variants.
trait Xof: Clone {
    const RATE: usize;
    type Reader: XofRead;
    fn start() -> Self;
    fn absorb(&mut self, data: &[u8]);
    fn reader(self) -> Self::Reader;
    fn one_shot(data: &[u8], out: &mut [u8]);
}

/// [`ShakeReader`] for any rate.
trait XofRead: Clone {
    fn read(&mut self, out: &mut [u8]);
    fn read_blocks(&mut self, out: &mut [u8]);
}

impl<const RATE: usize> XofRead for ShakeReader<RATE> {
    fn read(&mut self, out: &mut [u8]) {
        ShakeReader::read(self, out);
    }

    fn read_blocks(&mut self, out: &mut [u8]) {
        ShakeReader::read_blocks(self, out);
    }
}

macro_rules! impl_xof {
    ($ty:ty, $rate:literal) => {
        impl Xof for $ty {
            const RATE: usize = <$ty>::RATE;
            type Reader = ShakeReader<$rate>;

            fn start() -> Self {
                <$ty>::new()
            }

            fn absorb(&mut self, data: &[u8]) {
                self.update(data);
            }

            fn reader(self) -> Self::Reader {
                self.finalize_xof()
            }

            fn one_shot(data: &[u8], out: &mut [u8]) {
                <$ty>::digest_into(data, out);
            }
        }
    };
}

impl_xof!(Shake128, 168);
impl_xof!(Shake256, 136);

/// The `shake` crate's output.
fn shake_ref<const RATE: usize>(data: &[u8], len: usize) -> Vec<u8> {
    let mut h = shake::Shake::<RATE>::default();
    h.update(data);
    let mut out = vec![0u8; len];
    h.finalize_xof().read(&mut out);
    out
}

fn op_shake(input: &mut Input<'_>) {
    let wide = input.bool();
    let msg = message(input);
    let plan = input.short_field();
    let out_len = usize::from(input.u16() % 2048);
    let blocks = usize::from(input.byte() % 4);
    let reads = input.short_field();
    if wide {
        shake_op::<Shake256, 136>(&msg, plan, out_len, blocks, reads);
    } else {
        shake_op::<Shake128, 168>(&msg, plan, out_len, blocks, reads);
    }
}

fn shake_op<X: Xof, const RATE: usize>(
    msg: &[u8],
    plan: &[u8],
    out_len: usize,
    blocks: usize,
    reads: &[u8],
) {
    assert_eq!(X::RATE, RATE);
    let want = shake_ref::<RATE>(msg, out_len);
    let one_shot = across_policies(Algorithm::Keccak, || {
        let mut out = vec![0u8; out_len];
        X::one_shot(msg, &mut out);
        out
    });
    assert_eq!(one_shot, want, "one-shot SHAKE");

    // Chunked absorption with a clone taken half-way; the output read as
    // whole blocks first, then in pieces of fuzzed sizes, with a clone of
    // the reader taken before the first piece.
    let mut h = X::start();
    let parts = chunks(msg, plan);
    let (first, second) = parts.split_at(parts.len() / 2);
    for part in first {
        h.absorb(part);
    }
    let mut h2 = h.clone();
    for part in second {
        h.absorb(part);
        h2.absorb(part);
    }
    let mut reader = h.reader();
    let mut out = vec![0u8; out_len];
    let block_bytes = (blocks * RATE).min(out_len / RATE * RATE);
    reader.read_blocks(&mut out[..block_bytes]);
    let copy = (reader.clone(), block_bytes);
    let mut pos = block_bytes;
    for &b in reads {
        let n = chunk_len(b).min(out_len - pos);
        reader.read(&mut out[pos..pos + n]);
        pos += n;
    }
    reader.read(&mut out[pos..]);
    assert_eq!(out, want, "incremental SHAKE");

    let (mut reader, at) = copy;
    let mut rest = vec![0u8; out_len - at];
    reader.read(&mut rest);
    assert_eq!(rest, &want[at..], "cloned SHAKE reader");
    let mut out2 = vec![0u8; out_len];
    h2.reader().read(&mut out2);
    assert_eq!(out2, want, "cloned SHAKE absorber");
}

/// The four-way SHAKE API, abstracted over the two variants.
trait Xof4 {
    const RATE: usize;
    fn start(inputs: [&[u8]; 4]) -> Self;
    fn squeeze_n<const N: usize>(&mut self, out: &mut [[u8; N]; 4]);
    fn squeeze_rate(&mut self) -> [Vec<u8>; 4];
}

macro_rules! impl_xof4 {
    ($ty:ty, $rate:literal) => {
        impl Xof4 for $ty {
            const RATE: usize = <$ty>::RATE;

            fn start(inputs: [&[u8]; 4]) -> Self {
                <$ty>::new(inputs)
            }

            fn squeeze_n<const N: usize>(&mut self, out: &mut [[u8; N]; 4]) {
                self.squeeze(out);
            }

            fn squeeze_rate(&mut self) -> [Vec<u8>; 4] {
                let mut out = [[0u8; $rate]; 4];
                self.squeeze_blocks(&mut out);
                out.map(|lane| lane.to_vec())
            }
        }
    };
}

impl_xof4!(Shake128x4, 168);
impl_xof4!(Shake256x4, 136);

/// Squeezes `N` bytes per lane and appends them to `lanes`.
fn squeeze_into<X: Xof4, const N: usize>(x: &mut X, lanes: &mut [Vec<u8>; 4]) {
    let mut out = [[0u8; N]; 4];
    x.squeeze_n(&mut out);
    for (lane, o) in lanes.iter_mut().zip(&out) {
        lane.extend_from_slice(o);
    }
}

fn op_shake_x4(input: &mut Input<'_>) {
    let wide = input.bool();
    let mut msgs: [Vec<u8>; 4] = Default::default();
    for msg in &mut msgs {
        *msg = input.short_field().to_vec();
        // Lanes may span several, and different numbers of, blocks.
        let ext = usize::from(input.byte() % 8) * 50;
        msg.extend((0..ext).map(|i| (i % 253) as u8 ^ 0xa5));
    }
    let plan = input.short_field();
    let plan = &plan[..plan.len().min(8)];
    let inputs: [&[u8]; 4] = [&msgs[0], &msgs[1], &msgs[2], &msgs[3]];
    if wide {
        x4_op::<Shake256x4, Shake256, 136>(inputs, plan);
    } else {
        x4_op::<Shake128x4, Shake128, 168>(inputs, plan);
    }
}

fn x4_op<X: Xof4, S: Xof, const RATE: usize>(inputs: [&[u8]; 4], plan: &[u8]) {
    assert_eq!(X::RATE, RATE);
    let lanes = across_policies(Algorithm::KeccakX4, || {
        let mut x = X::start(inputs);
        let mut lanes: [Vec<u8>; 4] = Default::default();
        for &step in plan {
            // The sizes ML-KEM squeezes (128, 192, 504) and others.
            match step % 8 {
                6 => squeeze_into::<X, 128>(&mut x, &mut lanes),
                7 => squeeze_into::<X, 192>(&mut x, &mut lanes),
                0 => squeeze_into::<X, 1>(&mut x, &mut lanes),
                1 => squeeze_into::<X, 7>(&mut x, &mut lanes),
                2 => squeeze_into::<X, 32>(&mut x, &mut lanes),
                3 => squeeze_into::<X, 504>(&mut x, &mut lanes),
                4 => squeeze_into::<X, 0>(&mut x, &mut lanes),
                _ => {
                    for (lane, o) in lanes.iter_mut().zip(x.squeeze_rate()) {
                        lane.extend_from_slice(&o);
                    }
                }
            }
        }
        lanes
    });
    for (lane, msg) in lanes.iter().zip(inputs) {
        let mut want = vec![0u8; lane.len()];
        let mut h = S::start();
        h.absorb(msg);
        h.reader().read(&mut want);
        assert_eq!(lane, &want, "four-way SHAKE lane");
        assert_eq!(lane, &shake_ref::<RATE>(msg, lane.len()));
    }
}

// --------------------------------------------------------------- Keccak

const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];
const KECCAK_ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const KECCAK_PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Reference Keccak-f\[1600\] (lane `x + 5y` at index `x + 5 * y`), written
/// from FIPS 202 independently of the library.
fn keccak_ref(st: &mut [u64; 25]) {
    for rc in KECCAK_RC {
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                st[x + 5 * y] ^= d;
            }
        }
        let mut t = st[1];
        for (&j, &r) in KECCAK_PI.iter().zip(&KECCAK_ROT) {
            let next = st[j];
            st[j] = t.rotate_left(r);
            t = next;
        }
        for y in 0..5 {
            let row: [u64; 5] = core::array::from_fn(|x| st[x + 5 * y]);
            for x in 0..5 {
                st[x + 5 * y] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        st[0] ^= rc;
    }
}

fn op_keccak(input: &mut Input<'_>) {
    let base: [u64; 25] = core::array::from_fn(|_| input.u64());
    let tweak = input.u64();
    let iterations = 1 + input.choose(3);
    // Four related, distinct states: the base and three tweaked copies.
    let states: [[u64; 25]; 4] = core::array::from_fn(|j| {
        let mut s = base;
        if j > 0 {
            let lane = (tweak % 25) as usize;
            s[(lane + j) % 25] ^= tweak.rotate_left(16 * j as u32) | 1;
        }
        s
    });
    let mut want = states;
    for s in &mut want {
        for _ in 0..iterations {
            keccak_ref(s);
        }
    }
    let single = across_policies(Algorithm::Keccak, || {
        let mut out = states;
        for s in &mut out {
            for _ in 0..iterations {
                keccak_f1600(s);
            }
        }
        out
    });
    assert_eq!(single, want, "Keccak-f[1600]");
    let batched = across_policies(Algorithm::KeccakX4, || {
        let mut out = states;
        for _ in 0..iterations {
            keccak_f1600_x4(&mut out);
        }
        out
    });
    assert_eq!(batched, want, "Keccak-f[1600] x4");
}

// ----------------------------------------------------------------- HMAC

/// The oracle HMAC of the concatenation of `parts` under `key`.
fn ref_hmac<R: Digest + BlockSizeUser + Clone>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m = hmac::SimpleHmac::<R>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        hmac::Mac::update(&mut m, part);
    }
    m.finalize().into_bytes().to_vec()
}

fn op_hmac(input: &mut Input<'_>) {
    let sel = input.choose(HASHES);
    let key = message(input);
    let msg = message(input);
    let plan = input.short_field();
    let trunc = input.byte();
    let flip = input.u16();
    let candidate = input.short_field();
    with_hash!(sel, hmac_op(&key, &msg, plan, trunc, flip, candidate));
}

fn hmac_op<H, R>(
    alg: Algorithm,
    key: &[u8],
    msg: &[u8],
    plan: &[u8],
    trunc: u8,
    flip: u16,
    candidate: &[u8],
) where
    H: HashFunction,
    R: Digest + BlockSizeUser + Clone,
{
    let want = ref_hmac::<R>(key, &[msg]);
    let one_shot = across_policies(alg, || Hmac::<H>::mac(key, msg).as_ref().to_vec());
    assert_eq!(one_shot, want, "one-shot HMAC");

    // A keyed instance, cloned before use, computes the same tag each time.
    let keyed = Hmac::<H>::new(key);
    let mut m = keyed.clone();
    for part in chunks(msg, plan) {
        m.update(part);
    }
    assert_eq!(m.finalize().as_ref(), &want[..], "chunked HMAC");
    let mut m = keyed.clone();
    m.update(msg);
    assert_eq!(m.finalize().as_ref(), &want[..]);

    // Truncated tags are accepted from half the digest length up; a tag one
    // byte longer than the digest is not.
    let n = H::OUTPUT_LEN;
    let t = usize::from(trunc) % (n + 2);
    let tag = if t <= n {
        want[..t].to_vec()
    } else {
        [&want[..], &[0]].concat()
    };
    let ok = t >= n / 2 && t <= n;
    let mut m = keyed.clone();
    m.update(msg);
    assert_eq!(m.verify(&tag), ok, "HMAC verify of a {t}-byte tag");
    if ok && !tag.is_empty() {
        let mut bad = tag.clone();
        let i = usize::from(flip) % (8 * bad.len());
        bad[i / 8] ^= 1 << (i % 8);
        let mut m = keyed.clone();
        m.update(msg);
        assert!(!m.verify(&bad), "HMAC verify accepted a flipped tag");
    }
    // An arbitrary candidate is accepted exactly when it is a valid prefix.
    let expect = (n / 2..=n).contains(&candidate.len()) && want.starts_with(candidate);
    let mut m = keyed;
    m.update(msg);
    assert_eq!(m.verify(candidate), expect, "HMAC verify of a fuzzed tag");
}

// ----------------------------------------------------------------- HKDF

/// HKDF-Expand (RFC 5869) built on the oracle HMAC, for PRKs of any length.
fn ref_expand<R: Digest + BlockSizeUser + Clone>(
    prk: &[u8],
    info: &[&[u8]],
    len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let c = [counter];
        let mut parts: Vec<&[u8]> = vec![&prev];
        parts.extend_from_slice(info);
        parts.push(&c);
        prev = ref_hmac::<R>(prk, &parts);
        let take = prev.len().min(len - out.len());
        out.extend_from_slice(&prev[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

fn op_hkdf(input: &mut Input<'_>) {
    let sel = input.choose(HASHES);
    let salt = input.bool().then(|| input.short_field());
    let ikm = input.field();
    let info = fragments(input);
    let okm_len = usize::from(input.u16());
    let own_prk = input.bool().then(|| input.short_field());
    let data = fragments(input);
    with_hash!(sel, hkdf_op(salt, ikm, &info, okm_len, own_prk, &data));
}

fn hkdf_op<H, R>(
    alg: Algorithm,
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[&[u8]],
    okm_len: usize,
    own_prk: Option<&[u8]>,
    data: &[&[u8]],
) where
    H: HashFunction,
    R: Digest + BlockSizeUser + Clone,
{
    let n = H::OUTPUT_LEN;
    // Lengths up to a little beyond the 255 * HashLen limit.
    let okm_len = okm_len % (255 * n + 64);
    let (want_prk, oracle) = hkdf::SimpleHkdf::<R>::extract(salt, ikm);
    let prk = Hkdf::<H>::extract_prk(salt, ikm);
    assert_eq!(prk.as_ref(), want_prk.as_slice(), "HKDF-Extract");

    let mut want = vec![0u8; okm_len];
    let want_ok = oracle.expand_multi_info(info, &mut want).is_ok();
    assert_eq!(want_ok, okm_len <= 255 * n);
    let (result, okm) = across_policies(alg, || {
        let mut okm = vec![0u8; okm_len];
        let r = Hkdf::<H>::extract(salt, ikm).expand(info, &mut okm);
        (r, okm)
    });
    if want_ok {
        assert_eq!(result, Ok(()), "HKDF-Expand within the limit");
        assert_eq!(okm, want, "HKDF-Expand");
    } else {
        assert_eq!(
            result,
            Err(Error::InvalidLength),
            "HKDF-Expand beyond the limit"
        );
    }

    // Expand from a given PRK (any length, unlike RFC 5869's minimum).
    let prk_bytes = own_prk.unwrap_or(prk.as_ref());
    let kdf = Hkdf::<H>::from_prk(prk_bytes);
    let short = okm_len.min(4 * n + 1);
    let mut okm = vec![0u8; short];
    kdf.expand(info, &mut okm)
        .expect("at most 4 * HashLen + 1 bytes is within the limit");
    assert_eq!(
        okm,
        ref_expand::<R>(prk_bytes, info, short),
        "HKDF-Expand from PRK"
    );
    let mac = kdf.clone().hmac(data);
    assert_eq!(
        mac.as_ref(),
        &ref_hmac::<R>(prk_bytes, data)[..],
        "Hkdf::hmac"
    );
    assert_eq!(
        mac.as_ref(),
        Hmac::<H>::mac(prk_bytes, &data.concat()).as_ref()
    );
}

// ------------------------------------------------------------------ PRF

/// The TLS 1.2 PRF (RFC 5246, section 5) built on the oracle HMAC.
fn ref_prf<R: Digest + BlockSizeUser + Clone>(
    secret: &[u8],
    label: &[u8],
    seed: &[&[u8]],
    len: usize,
) -> Vec<u8> {
    let mut label_seed: Vec<&[u8]> = vec![label];
    label_seed.extend_from_slice(seed);
    let mut a = ref_hmac::<R>(secret, &label_seed);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut parts: Vec<&[u8]> = vec![&a];
        parts.extend_from_slice(&label_seed);
        let p = ref_hmac::<R>(secret, &parts);
        let take = p.len().min(len - out.len());
        out.extend_from_slice(&p[..take]);
        a = ref_hmac::<R>(secret, &[&a]);
    }
    out
}

fn op_prf(input: &mut Input<'_>) {
    let sel = input.choose(HASHES);
    let secret = input.field();
    let label = input.short_field();
    let seed = fragments(input);
    let len = usize::from(input.u16() % 1024);
    with_hash!(sel, prf_op(secret, label, &seed, len));
}

fn prf_op<H, R>(alg: Algorithm, secret: &[u8], label: &[u8], seed: &[&[u8]], len: usize)
where
    H: HashFunction,
    R: Digest + BlockSizeUser + Clone,
{
    let got = across_policies(alg, || {
        let mut out = vec![0u8; len];
        tls12_prf::prf::<H>(&mut out, secret, label, seed);
        out
    });
    assert_eq!(got, ref_prf::<R>(secret, label, seed, len), "TLS 1.2 PRF");
}

// ---------------------------------------------------------------- seeds

/// Starting inputs for `crypto_hash`: every operation with every hash or
/// variant, lengths around the block sizes, HKDF within and beyond its
/// length limit, and HMAC tags of every length class.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let msg: Vec<u8> = (0..150u8).collect();
    let mut seeds = Vec::new();
    for sel in 0..8u8 {
        let i = usize::from(sel);
        // digest: chunks across block boundaries.
        let mut s = vec![OP_DIGEST, sel];
        put_field(&mut s, &msg[..(i * 23) % 150]);
        s.push(sel * 2);
        put_short_field(&mut s, &[1, 0x88, 63, 0x91, 5]);
        s.extend_from_slice(&[0, 77]);
        put_short_field(&mut s, &msg[..i * 9]);
        seeds.push(s);

        // HMAC: keys shorter and longer than a block, every truncation class.
        let mut s = vec![OP_HMAC, sel];
        put_field(&mut s, &msg[..20 + i * 15]);
        s.push(sel % 3 * 4);
        put_field(&mut s, &msg[..50]);
        s.push(0);
        put_short_field(&mut s, &[3, 0x88]);
        s.push([21, 10, 0, 33, 31, 30, 48, 63][i]);
        s.extend_from_slice(&[0, 9]);
        put_short_field(&mut s, &msg[..i * 4]);
        seeds.push(s);

        // HKDF: with and without salt and PRK, within and beyond the limit.
        let mut s = vec![OP_HKDF, sel, sel & 1];
        if sel & 1 == 1 {
            put_short_field(&mut s, &msg[..13]);
        }
        put_field(&mut s, &msg[..22]);
        s.push(2);
        put_short_field(&mut s, b"tls13 ");
        put_short_field(&mut s, b"derived");
        let len: u16 = if sel == 7 {
            255 * 64 + 1
        } else {
            42 + u16::from(sel) * 20
        };
        s.extend_from_slice(&len.to_be_bytes());
        s.push(sel & 2);
        if sel & 2 != 0 {
            put_short_field(&mut s, &msg[..i * 3]);
        }
        s.push(1);
        put_short_field(&mut s, b"finished");
        seeds.push(s);

        // TLS 1.2 PRF.
        let mut s = vec![OP_PRF, sel];
        put_field(&mut s, &msg[..48]);
        put_short_field(&mut s, b"master secret");
        s.push(2);
        put_short_field(&mut s, &msg[..32]);
        put_short_field(&mut s, &msg[32..64]);
        s.extend_from_slice(&(48 + u16::from(sel) * 13).to_be_bytes());
        seeds.push(s);
    }
    for wide in 0..2u8 {
        // SHAKE: block reads first, then partial reads.
        let mut s = vec![OP_SHAKE, wide];
        put_field(&mut s, &msg[..100]);
        s.push(10);
        put_short_field(&mut s, &[0x95, 7]);
        s.extend_from_slice(&600u16.to_be_bytes());
        s.push(2);
        put_short_field(&mut s, &[1, 0x82, 3]);
        seeds.push(s);

        // Four-way SHAKE: equal and unequal lane lengths, every squeeze kind.
        let mut s = vec![OP_SHAKE_X4, wide];
        for lane in 0..4u8 {
            put_short_field(&mut s, &msg[..usize::from(lane) * 5]);
            s.push(if wide == 0 { 0 } else { lane * 2 });
        }
        put_short_field(&mut s, &[5, 0, 1, 2, 3, 4, 6, 7]);
        seeds.push(s);
    }
    // Keccak-f[1600]: zero and patterned states.
    seeds.push(vec![OP_KECCAK]);
    let mut s = vec![OP_KECCAK];
    s.extend((0..200u8).map(|i| i.wrapping_mul(73)));
    s.extend_from_slice(&0x0123_4567_89ab_cdefu64.to_be_bytes());
    s.push(2);
    seeds.push(s);
    // Several operations in one input.
    let mut s = Vec::new();
    for seed in seeds.iter().take(4) {
        s.extend_from_slice(seed);
    }
    seeds.push(s);
    seeds
}
