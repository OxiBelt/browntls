//! Cross-backend tests: every backend available at run time is compared with
//! the portable backend and with independent implementations (`sha2`,
//! `sha3`, `shake`), on random and edge-case inputs.

use std::vec::Vec;

use sha2::Digest as _;
use shake::{ExtendableOutput as _, Update as _, XofReader as _};

use super::keccak::{self, StateX4};
use super::{HashFunction, sha256, sha512};
use crate::cpu;

/// SplitMix64: deterministic test data without a dev-dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next().to_le_bytes()[0]).collect()
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap_or(0)
    }
}

fn sha256_backends() -> Vec<sha256::Backend> {
    let f = cpu::features();
    sha256::Backend::ALL
        .iter()
        .copied()
        .filter(|b| b.is_available(f))
        .collect()
}

fn sha512_backends() -> Vec<sha512::Backend> {
    let f = cpu::features();
    sha512::Backend::ALL
        .iter()
        .copied()
        .filter(|b| b.is_available(f))
        .collect()
}

fn keccak_backends() -> Vec<keccak::Backend> {
    let f = cpu::features();
    keccak::Backend::ALL
        .iter()
        .copied()
        .filter(|b| b.is_available(f))
        .collect()
}

fn keccak_x4_backends() -> Vec<keccak::BackendX4> {
    let f = cpu::features();
    keccak::BackendX4::ALL
        .iter()
        .copied()
        .filter(|b| b.is_available(f))
        .collect()
}

/// Lengths covering 0..~3 blocks of every hash plus some large inputs.
fn test_lengths(block: usize) -> Vec<usize> {
    let mut v: Vec<usize> = (0..=3 * block + 1).collect();
    v.extend([1000, 4095, 4096, 4097, 10_007, 65_536 + 3]);
    v
}

/// Merkle–Damgård padding for a 64-byte-block hash with a 64-bit length.
fn md_pad(data: &[u8], block: usize, len_bytes: usize) -> Vec<u8> {
    let mut m = data.to_vec();
    m.push(0x80);
    while m.len() % block != block - len_bytes {
        m.push(0);
    }
    let bits = (data.len() as u128) * 8;
    m.extend_from_slice(&bits.to_be_bytes()[16 - len_bytes..]);
    m
}

fn sha256_with(b: sha256::Backend, iv: [u32; 8], data: &[u8]) -> Vec<u8> {
    let mut st = iv;
    let m = md_pad(data, 64, 8);
    // Compress in irregular runs of blocks to exercise multi-block calls.
    let mut rest = &m[..];
    let mut run = 1;
    while !rest.is_empty() {
        let take = (run * 64).min(rest.len());
        b.compress(&mut st, &rest[..take]);
        rest = &rest[take..];
        run = run % 5 + 1;
    }
    st.iter().flat_map(|w| w.to_be_bytes()).collect()
}

fn sha512_with(b: sha512::Backend, iv: [u64; 8], data: &[u8]) -> Vec<u8> {
    let mut st = iv;
    let m = md_pad(data, 128, 16);
    let mut rest = &m[..];
    let mut run = 1;
    while !rest.is_empty() {
        let take = (run * 128).min(rest.len());
        b.compress(&mut st, &rest[..take]);
        rest = &rest[take..];
        run = run % 5 + 1;
    }
    st.iter().flat_map(|w| w.to_be_bytes()).collect()
}

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA224_IV: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];
const SHA512_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
const SHA384_IV: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

#[test]
fn report_backends() {
    std::println!(
        "features: {:?}\nsha256: {:?}\nsha512: {:?}\nkeccak: {:?}\nkeccak x4: {:?}",
        cpu::features(),
        sha256_backends(),
        sha512_backends(),
        keccak_backends(),
        keccak_x4_backends()
    );
    assert_eq!(sha256_backends().last(), Some(&sha256::Backend::Soft));
}

#[test]
fn sha256_backends_match_soft_on_random_states() {
    let mut rng = Rng(1);
    for b in sha256_backends() {
        for _ in 0..200 {
            let mut s1: [u32; 8] = core::array::from_fn(|_| rng.next() as u32);
            let mut s2 = s1;
            let nb = 1 + rng.below(6);
            let blocks = rng.bytes(64 * nb);
            b.compress(&mut s1, &blocks);
            sha256::soft::compress(&mut s2, &blocks);
            assert_eq!(s1, s2, "{b:?}");
        }
        // Empty input leaves the state unchanged.
        let mut s = SHA256_IV;
        b.compress(&mut s, &[]);
        assert_eq!(s, SHA256_IV, "{b:?}");
    }
}

#[test]
fn sha256_backends_match_sha2_crate() {
    let mut rng = Rng(2);
    for b in sha256_backends() {
        for len in test_lengths(64) {
            let data = rng.bytes(len);
            let want = sha2::Sha256::digest(&data);
            assert_eq!(
                sha256_with(b, SHA256_IV, &data),
                want[..],
                "{b:?} len {len}"
            );
            let want = sha2::Sha224::digest(&data);
            assert_eq!(
                sha256_with(b, SHA224_IV, &data)[..28],
                want[..],
                "{b:?} len {len}"
            );
        }
        // FIPS 180-4 / NIST long-message KAT: one million 'a'.
        let a = std::vec![b'a'; 1_000_000];
        assert_eq!(
            hex::encode(sha256_with(b, SHA256_IV, &a)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            "{b:?}"
        );
    }
}

#[test]
fn sha512_backends_match_soft_on_random_states() {
    let mut rng = Rng(3);
    for b in sha512_backends() {
        for _ in 0..200 {
            let mut s1: [u64; 8] = core::array::from_fn(|_| rng.next());
            let mut s2 = s1;
            let nb = 1 + rng.below(6);
            let blocks = rng.bytes(128 * nb);
            b.compress(&mut s1, &blocks);
            sha512::soft::compress(&mut s2, &blocks);
            assert_eq!(s1, s2, "{b:?}");
        }
        let mut s = SHA512_IV;
        b.compress(&mut s, &[]);
        assert_eq!(s, SHA512_IV, "{b:?}");
    }
}

#[test]
fn sha512_backends_match_sha2_crate() {
    let mut rng = Rng(4);
    for b in sha512_backends() {
        for len in test_lengths(128) {
            let data = rng.bytes(len);
            let want = sha2::Sha512::digest(&data);
            assert_eq!(
                sha512_with(b, SHA512_IV, &data),
                want[..],
                "{b:?} len {len}"
            );
            let want = sha2::Sha384::digest(&data);
            assert_eq!(
                sha512_with(b, SHA384_IV, &data)[..48],
                want[..],
                "{b:?} len {len}"
            );
        }
        let a = std::vec![b'a'; 1_000_000];
        assert_eq!(
            hex::encode(sha512_with(b, SHA512_IV, &a)),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
             de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
            "{b:?}"
        );
    }
}

/// Straightforward FIPS 202 reference permutation (the original portable
/// implementation), used to validate the unrolled code.
fn keccak_reference(a: &mut [u64; 25]) {
    const RHO: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PI: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];
    for rc in keccak::RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut last = a[1];
        for i in 0..24 {
            let tmp = a[PI[i]];
            a[PI[i]] = last.rotate_left(RHO[i]);
            last = tmp;
        }
        for y in 0..5 {
            let row: [u64; 5] = core::array::from_fn(|x| a[5 * y + x]);
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        a[0] ^= rc;
    }
}

#[test]
fn keccak_known_answer() {
    // Keccak-f[1600] applied to the all-zero state (Keccak team test vector).
    let mut s = [0u64; 25];
    keccak::soft::keccak_f1600(&mut s);
    assert_eq!(s[0], 0xF1258F7940E1DDE7);
    assert_eq!(s[1], 0x84D5CCF933C0478A);
    assert_eq!(s[24], 0xEAF1FF7B5CECA249);
}

#[test]
fn keccak_backends_match_reference() {
    let mut rng = Rng(5);
    for b in keccak_backends() {
        for _ in 0..200 {
            let mut s1: [u64; 25] = core::array::from_fn(|_| rng.next());
            let mut s2 = s1;
            b.permute(&mut s1);
            keccak_reference(&mut s2);
            assert_eq!(s1, s2, "{b:?}");
        }
    }
}

#[test]
fn keccak_x4_backends_match_reference() {
    let mut rng = Rng(6);
    for b in keccak_x4_backends() {
        for _ in 0..100 {
            let mut s: StateX4 = core::array::from_fn(|_| core::array::from_fn(|_| rng.next()));
            let mut want = s;
            for j in 0..4 {
                let mut one: [u64; 25] = core::array::from_fn(|i| want[i][j]);
                keccak_reference(&mut one);
                for (lane, v) in want.iter_mut().zip(one) {
                    lane[j] = v;
                }
            }
            b.permute(&mut s);
            assert_eq!(s, want, "{b:?}");
        }
    }
    // Public transposing wrapper.
    let mut states: [[u64; 25]; 4] = core::array::from_fn(|_| core::array::from_fn(|_| rng.next()));
    let mut want = states;
    for st in &mut want {
        keccak_reference(st);
    }
    super::sha3::keccak_f1600_x4(&mut states);
    assert_eq!(states, want);
}

macro_rules! check_sha3 {
    ($ours:ty, $theirs:ty, $data:expr) => {{
        let data: &[u8] = $data;
        let want = <$theirs>::digest(data);
        assert_eq!(<$ours>::digest(data)[..], want[..], "len {}", data.len());
        // Irregular incremental updates.
        let mut h = <$ours>::new();
        let mut rest = data;
        let mut step = 1;
        while !rest.is_empty() {
            let t = step.min(rest.len());
            h.update(&rest[..t]);
            rest = &rest[t..];
            step = step * 3 % 211 + 1;
        }
        assert_eq!(h.finalize()[..], want[..], "len {}", data.len());
    }};
}

#[test]
fn sha3_matches_sha3_crate() {
    let mut rng = Rng(7);
    for len in test_lengths(144) {
        let data = rng.bytes(len);
        check_sha3!(super::Sha3_256, sha3::Sha3_256, &data);
        check_sha3!(super::Sha3_384, sha3::Sha3_384, &data);
        check_sha3!(super::Sha3_512, sha3::Sha3_512, &data);
    }
}

fn shake_ref<const RATE: usize>(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = shake::Shake::<RATE>::default();
    h.update(data);
    let mut out = std::vec![0u8; out_len];
    h.finalize_xof().read(&mut out);
    out
}

#[test]
fn shake_matches_shake_crate() {
    let mut rng = Rng(8);
    for len in test_lengths(168) {
        let data = rng.bytes(len);
        let out_len = rng.below(600);
        let mut out = std::vec![0u8; out_len];
        super::Shake128::digest_into(&data, &mut out);
        assert_eq!(out, shake_ref::<168>(&data, out_len), "len {len}");
        super::Shake256::digest_into(&data, &mut out);
        assert_eq!(out, shake_ref::<136>(&data, out_len), "len {len}");
    }
}

/// Squeezes `total` bytes from a four-way SHAKE in pieces of `N` bytes.
macro_rules! squeeze_x4 {
    ($x4:expr, $n:literal, $total:expr) => {{
        let mut outs: [Vec<u8>; 4] = Default::default();
        while outs[0].len() < $total {
            let mut buf = [[0u8; $n]; 4];
            $x4.squeeze(&mut buf);
            for (o, b) in outs.iter_mut().zip(buf) {
                o.extend_from_slice(&b);
            }
        }
        outs
    }};
}

#[test]
fn shake_x4_matches_shake_crate() {
    let mut rng = Rng(9);
    // Equal lengths (lock-step absorption), including the ML-KEM sizes 33/34.
    let mut cases: Vec<[usize; 4]> = [0, 1, 33, 34, 66, 135, 136, 137, 167, 168, 169, 400]
        .iter()
        .map(|&l| [l; 4])
        .collect();
    // Same block count, different tails; and different block counts.
    cases.extend([[0, 5, 100, 167], [168, 200, 335, 170], [0, 168, 34, 500]]);
    for lens in cases {
        let inputs: [Vec<u8>; 4] = core::array::from_fn(|j| rng.bytes(lens[j]));
        let refs: [&[u8]; 4] = core::array::from_fn(|j| inputs[j].as_slice());

        let mut x = super::Shake128x4::new(refs);
        let mut blocks: [Vec<u8>; 4] = Default::default();
        for _ in 0..3 {
            let mut buf = [[0u8; 168]; 4];
            x.squeeze_blocks(&mut buf);
            for (o, b) in blocks.iter_mut().zip(buf) {
                o.extend_from_slice(&b);
            }
        }
        let odd = squeeze_x4!(x, 7, 300);
        for j in 0..4 {
            let want = shake_ref::<168>(refs[j], 504 + odd[j].len());
            assert_eq!(blocks[j], want[..504], "lens {lens:?} instance {j}");
            assert_eq!(odd[j], want[504..], "lens {lens:?} instance {j}");
        }

        let mut y = super::Shake256x4::new(refs);
        let first = squeeze_x4!(y, 128, 128);
        let more = squeeze_x4!(y, 136, 400);
        for j in 0..4 {
            let want = shake_ref::<136>(refs[j], 128 + more[j].len());
            assert_eq!(first[j], want[..128], "lens {lens:?} instance {j}");
            assert_eq!(more[j], want[128..], "lens {lens:?} instance {j}");
        }
    }
}

#[test]
fn hash_types_match_backend_dispatch() {
    // The public types use the dispatcher; compare with the crates on random
    // lengths (the per-backend tests above cover each tier).
    let mut rng = Rng(10);
    for _ in 0..100 {
        let len = rng.below(700);
        let data = rng.bytes(len);
        assert_eq!(
            super::Sha256::digest(&data)[..],
            sha2::Sha256::digest(&data)[..]
        );
        assert_eq!(
            super::Sha224::digest(&data)[..],
            sha2::Sha224::digest(&data)[..]
        );
        assert_eq!(
            super::Sha384::digest(&data)[..],
            sha2::Sha384::digest(&data)[..]
        );
        assert_eq!(
            super::Sha512::digest(&data)[..],
            sha2::Sha512::digest(&data)[..]
        );
    }
}

/// Rough throughput of every available backend (run with
/// `cargo test --release -p browntls-crypto --lib throughput -- --ignored --nocapture`).
/// Each figure is the best of several trials, to reduce noise on shared
/// machines.
#[test]
#[ignore = "benchmark"]
fn throughput() {
    use std::time::Instant;
    const TRIALS: usize = 9;
    /// Best (shortest) wall time of `TRIALS` runs of `f`, in seconds.
    fn best(mut f: impl FnMut()) -> f64 {
        (0..TRIALS)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed().as_secs_f64()
            })
            .fold(f64::INFINITY, f64::min)
    }
    let data = std::vec![0x5au8; 4 << 20];
    let mib = |bytes: usize, secs: f64| bytes as f64 / secs / (1024.0 * 1024.0);

    for b in sha256_backends() {
        let mut st = SHA256_IV;
        let secs = best(|| b.compress(&mut st, &data));
        std::println!("sha256 {b:?}: {:.0} MiB/s", mib(data.len(), secs));
        core::hint::black_box(st);
    }
    let secs = best(|| {
        core::hint::black_box(sha2::Sha256::digest(&data));
    });
    std::println!("sha256 (sha2 crate): {:.0} MiB/s", mib(data.len(), secs));
    for b in sha512_backends() {
        let mut st = SHA512_IV;
        let secs = best(|| b.compress(&mut st, &data));
        std::println!("sha512 {b:?}: {:.0} MiB/s", mib(data.len(), secs));
        core::hint::black_box(st);
    }
    let secs = best(|| {
        core::hint::black_box(sha2::Sha512::digest(&data));
    });
    std::println!("sha512 (sha2 crate): {:.0} MiB/s", mib(data.len(), secs));

    // Keccak: time per permutation (per instance for the x4 backends) and
    // the equivalent SHA3-256 absorption rate (136 bytes per permutation).
    const PERMS: usize = 20_000;
    let report = |name: &str, secs: f64| {
        std::println!(
            "keccak {name}: {:.0} ns/perm, {:.0} MiB/s SHA3-256 equivalent",
            secs * 1e9 / PERMS as f64,
            mib(PERMS * 136, secs)
        );
    };
    let mut s = [1u64; 25];
    report(
        "reference (previous portable)",
        best(|| (0..PERMS).for_each(|_| keccak_reference(&mut s))),
    );
    for b in keccak_backends() {
        report(
            &std::format!("{b:?}"),
            best(|| (0..PERMS).for_each(|_| b.permute(&mut s))),
        );
    }
    let mut s4: StateX4 = [[1; 4]; 25];
    for b in keccak_x4_backends() {
        report(
            &std::format!("x4 {b:?} (per instance)"),
            best(|| (0..PERMS / 4).for_each(|_| b.permute(&mut s4))),
        );
    }
    let secs = best(|| {
        core::hint::black_box(sha3::Sha3_256::digest(&data[..1 << 20]));
    });
    std::println!("sha3-256 (sha3 crate): {:.0} MiB/s", mib(1 << 20, secs));
    let secs = best(|| {
        core::hint::black_box(super::Sha3_256::digest(&data[..1 << 20]));
    });
    std::println!("sha3-256 (dispatched): {:.0} MiB/s", mib(1 << 20, secs));
    core::hint::black_box((s, s4));
}
