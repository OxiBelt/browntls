//! Differential tests of the public hash API against independent
//! implementations (`sha2`, `sha3`, `shake`). The backend actually used is
//! the one selected on the running CPU; `src/hash/tests.rs` additionally
//! tests every available backend individually.

use browntls_crypto::hash::sha3::{keccak_f1600, keccak_f1600_x4};
use browntls_crypto::hash::{
    DynHash, HashAlgorithm, HashFunction, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384,
    Sha512, Shake128, Shake128x4, Shake256, Shake256x4,
};
use sha2::Digest as _;
use shake::{ExtendableOutput as _, Update as _, XofReader as _};

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
        usize::try_from(self.next() % n as u64).unwrap_or(0)
    }
}

/// Hashes `data` with irregular `update` calls.
fn chunked<H: HashFunction>(data: &[u8], rng: &mut Rng) -> H::Output {
    let mut h = H::new();
    let mut rest = data;
    while !rest.is_empty() {
        let take = (1 + rng.below(300)).min(rest.len());
        h.update(&rest[..take]);
        rest = &rest[take..];
    }
    h.finalize()
}

fn lengths() -> impl Iterator<Item = usize> {
    (0..=400).chain([1000, 4096, 10_007, 100_003])
}

macro_rules! diff {
    ($ours:ty, $theirs:ty, $data:expr, $rng:expr) => {{
        let data: &[u8] = $data;
        let want = <$theirs>::digest(data);
        assert_eq!(<$ours>::digest(data)[..], want[..], "len {}", data.len());
        assert_eq!(
            chunked::<$ours>(data, $rng)[..],
            want[..],
            "len {}",
            data.len()
        );
    }};
}

#[test]
fn sha2_matches_sha2_crate() {
    let mut rng = Rng(0x5a2);
    for len in lengths() {
        let data = rng.bytes(len);
        diff!(Sha224, sha2::Sha224, &data, &mut rng);
        diff!(Sha256, sha2::Sha256, &data, &mut rng);
        diff!(Sha384, sha2::Sha384, &data, &mut rng);
        diff!(Sha512, sha2::Sha512, &data, &mut rng);
    }
}

#[test]
fn sha3_matches_sha3_crate() {
    let mut rng = Rng(0x5a3);
    for len in lengths() {
        let data = rng.bytes(len);
        diff!(Sha3_256, sha3::Sha3_256, &data, &mut rng);
        diff!(Sha3_384, sha3::Sha3_384, &data, &mut rng);
        diff!(Sha3_512, sha3::Sha3_512, &data, &mut rng);
    }
}

fn shake_ref<const RATE: usize>(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = shake::Shake::<RATE>::default();
    h.update(data);
    let mut out = vec![0u8; out_len];
    h.finalize_xof().read(&mut out);
    out
}

#[test]
fn shake_matches_shake_crate() {
    let mut rng = Rng(0x5a4e);
    for len in lengths() {
        let data = rng.bytes(len);
        let out_len = rng.below(1000);
        let mut out = vec![0u8; out_len];
        Shake128::digest_into(&data, &mut out);
        assert_eq!(out, shake_ref::<168>(&data, out_len));
        Shake256::digest_into(&data, &mut out);
        assert_eq!(out, shake_ref::<136>(&data, out_len));
    }
}

#[test]
fn dyn_hash_matches_static_types() {
    let data = b"browntls transcript";
    let pairs: [(HashAlgorithm, Vec<u8>); 7] = [
        (HashAlgorithm::Sha224, Sha224::digest(data).to_vec()),
        (HashAlgorithm::Sha256, Sha256::digest(data).to_vec()),
        (HashAlgorithm::Sha384, Sha384::digest(data).to_vec()),
        (HashAlgorithm::Sha512, Sha512::digest(data).to_vec()),
        (HashAlgorithm::Sha3_256, Sha3_256::digest(data).to_vec()),
        (HashAlgorithm::Sha3_384, Sha3_384::digest(data).to_vec()),
        (HashAlgorithm::Sha3_512, Sha3_512::digest(data).to_vec()),
    ];
    for (alg, want) in pairs {
        assert_eq!(DynHash::digest(alg, data).as_ref(), &want[..], "{alg:?}");
    }
}

#[test]
fn keccak_x4_matches_single() {
    let mut rng = Rng(0x4ecc);
    for _ in 0..50 {
        let mut states: [[u64; 25]; 4] =
            core::array::from_fn(|_| core::array::from_fn(|_| rng.next()));
        let mut want = states;
        for s in &mut want {
            keccak_f1600(s);
        }
        keccak_f1600_x4(&mut states);
        assert_eq!(states, want);
    }
}

/// ML-KEM-style use: SHAKE128(rho || j || i) matrix expansion and
/// SHAKE256(sigma || N) noise sampling, four entries at a time.
#[test]
fn shake_x4_mlkem_usage() {
    let mut rng = Rng(0x313e3);
    let rho = rng.bytes(32);
    let inputs: [Vec<u8>; 4] = core::array::from_fn(|k| {
        let mut v = rho.clone();
        v.extend_from_slice(&[
            u8::try_from(k % 2).unwrap_or(0),
            u8::try_from(k / 2).unwrap_or(0),
        ]);
        v
    });
    let refs: [&[u8]; 4] = core::array::from_fn(|k| inputs[k].as_slice());
    let mut xof = Shake128x4::new(refs);
    let mut first = [[0u8; 504]; 4];
    xof.squeeze(&mut first);
    let mut next = [[0u8; Shake128x4::RATE]; 4];
    xof.squeeze_blocks(&mut next);
    for k in 0..4 {
        let want = shake_ref::<168>(refs[k], 504 + 168);
        assert_eq!(first[k], want[..504]);
        assert_eq!(next[k], want[504..]);
    }

    let sigma = rng.bytes(32);
    let prf_in: [Vec<u8>; 4] = core::array::from_fn(|n| {
        let mut v = sigma.clone();
        v.push(u8::try_from(n).unwrap_or(0));
        v
    });
    let refs: [&[u8]; 4] = core::array::from_fn(|n| prf_in[n].as_slice());
    let mut prf = Shake256x4::new(refs);
    let mut out = [[0u8; 192]; 4];
    prf.squeeze(&mut out);
    for n in 0..4 {
        assert_eq!(out[n][..], shake_ref::<136>(refs[n], 192)[..]);
    }
}
