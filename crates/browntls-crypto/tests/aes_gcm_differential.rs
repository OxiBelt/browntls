//! Differential tests of every available AES / GHASH backend pair against
//! the independent `aes-gcm` crate, plus tampering and throughput checks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aes_gcm::{AeadInOut, KeyInit};
use browntls_crypto::Error;
use browntls_crypto::aead::Aead;
use browntls_crypto::aes;
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm, GhashBackend};

/// Small deterministic PRNG (xorshift64*) so failures are reproducible.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

fn pairs() -> Vec<(aes::Backend, GhashBackend)> {
    let mut v = Vec::new();
    for ab in aes::Backend::ALL.into_iter().filter(|b| b.is_available()) {
        for gb in GhashBackend::ALL.into_iter().filter(|b| b.is_available()) {
            v.push((ab, gb));
        }
    }
    v
}

/// Reference encryption with the `aes-gcm` crate.
fn reference_seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::from(*nonce);
    let tag = if key.len() == 16 {
        aes_gcm::Aes128Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_inout_detached(&nonce, aad, buf.into())
            .unwrap()
    } else {
        aes_gcm::Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_inout_detached(&nonce, aad, buf.into())
            .unwrap()
    };
    tag.into()
}

/// Our implementation for a given key length and backend pair.
enum Ours {
    K128(Aes128Gcm),
    K256(Aes256Gcm),
}

impl Ours {
    fn new(key: &[u8], ab: aes::Backend, gb: GhashBackend) -> Self {
        if key.len() == 16 {
            Self::K128(Aes128Gcm::with_backends(&key.try_into().unwrap(), ab, gb).unwrap())
        } else {
            Self::K256(Aes256Gcm::with_backends(&key.try_into().unwrap(), ab, gb).unwrap())
        }
    }

    fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        match self {
            Self::K128(g) => g.seal_in_place(nonce, aad, buf).unwrap(),
            Self::K256(g) => g.seal_in_place(nonce, aad, buf).unwrap(),
        }
    }

    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Error> {
        match self {
            Self::K128(g) => g.open_in_place(nonce, aad, buf, tag),
            Self::K256(g) => g.open_in_place(nonce, aad, buf, tag),
        }
    }
}

fn lengths() -> Vec<usize> {
    let mut v: Vec<usize> = (0..=300).collect();
    v.extend([
        511,
        512,
        513,
        1000,
        1024,
        2047,
        2048,
        2049,
        4096 + 7,
        8192 + 1,
        16384 + 15,
        16384 + 16,
        16384 + 17,
    ]);
    v
}

#[test]
fn seal_matches_reference_for_all_backend_pairs() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let pairs = pairs();
    println!("backend pairs: {pairs:?}");
    for len in lengths() {
        for key_len in [16usize, 32] {
            let mut key = vec![0u8; key_len];
            rng.fill(&mut key);
            let mut nonce = [0u8; 12];
            rng.fill(&mut nonce);
            let aad_len = rng.below(70);
            let mut aad = vec![0u8; aad_len];
            rng.fill(&mut aad);
            // Random unaligned offset into a larger buffer.
            let offset = rng.below(8);
            let mut pt = vec![0u8; len + offset];
            rng.fill(&mut pt);
            let pt = &pt[offset..];

            let mut expected = pt.to_vec();
            let expected_tag = reference_seal(&key, &nonce, &aad, &mut expected);

            for &(ab, gb) in &pairs {
                let ours = Ours::new(&key, ab, gb);
                let mut buf = vec![0u8; len + offset];
                buf[offset..].copy_from_slice(pt);
                let tag = ours.seal(&nonce, &aad, &mut buf[offset..]);
                assert_eq!(
                    &buf[offset..],
                    &expected[..],
                    "{ab:?}/{gb:?} key={key_len} len={len} ciphertext"
                );
                assert_eq!(
                    tag, expected_tag,
                    "{ab:?}/{gb:?} key={key_len} len={len} tag"
                );
                ours.open(&nonce, &aad, &mut buf[offset..], &tag)
                    .unwrap_or_else(|e| panic!("{ab:?}/{gb:?} len={len} open: {e}"));
                assert_eq!(&buf[offset..], pt, "{ab:?}/{gb:?} len={len} roundtrip");
            }
        }
    }
}

#[test]
fn random_sizes_match_reference() {
    let mut rng = Rng(0x0dd_b1a5_ed00_f00d);
    let pairs = pairs();
    for _ in 0..200 {
        let len = rng.below(3000);
        let key_len = if rng.below(2) == 0 { 16 } else { 32 };
        let mut key = vec![0u8; key_len];
        rng.fill(&mut key);
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let mut aad = vec![0u8; rng.below(300)];
        rng.fill(&mut aad);
        let mut pt = vec![0u8; len];
        rng.fill(&mut pt);
        let mut expected = pt.clone();
        let expected_tag = reference_seal(&key, &nonce, &aad, &mut expected);
        for &(ab, gb) in &pairs {
            let ours = Ours::new(&key, ab, gb);
            let mut buf = pt.clone();
            let tag = ours.seal(&nonce, &aad, &mut buf);
            assert_eq!(buf, expected, "{ab:?}/{gb:?} len={len}");
            assert_eq!(tag, expected_tag, "{ab:?}/{gb:?} len={len}");
        }
    }
}

#[test]
fn counter_wrap_matches_reference() {
    // Nonces whose derived counter is near 2^32 - 1 make the 32-bit counter
    // wrap inside a message (SP 800-38D inc32 semantics).
    let pairs = pairs();
    let key = [0x42u8; 32];
    let mut rng = Rng(77);
    // J0 = nonce || 0^31 || 1, so the counter starts at 2; the keystream
    // wraps only through the GHASH-derived IVs of other lengths, which we
    // do not support. Exercise the CTR wrap through the block API instead.
    let mut pt = vec![0u8; 16 * 10 + 5];
    rng.fill(&mut pt);
    let nonce = [7u8; 12];
    let mut expected = pt.clone();
    let expected_tag = reference_seal(&key, &nonce, b"aad", &mut expected);
    for &(ab, gb) in &pairs {
        let ours = Ours::new(&key, ab, gb);
        let mut buf = pt.clone();
        let tag = ours.seal(&nonce, b"aad", &mut buf);
        assert_eq!(buf, expected, "{ab:?}/{gb:?}");
        assert_eq!(tag, expected_tag, "{ab:?}/{gb:?}");
    }
    // Direct CTR wrap check on every AES backend against the portable one.
    let soft = aes::Aes256::with_backend(&key, aes::Backend::Soft).unwrap();
    let mut ctr = [0x11u8; 16];
    ctr[12..].copy_from_slice(&0xffff_fff9u32.to_be_bytes());
    let mut want = pt.clone();
    soft.ctr32_xor(&ctr, &mut want);
    for ab in aes::Backend::ALL.into_iter().filter(|b| b.is_available()) {
        let a = aes::Aes256::with_backend(&key, ab).unwrap();
        let mut got = pt.clone();
        a.ctr32_xor(&ctr, &mut got);
        assert_eq!(got, want, "{ab:?} counter wrap");
    }
}

#[test]
fn tampering_is_rejected_and_buffer_zeroed() {
    let mut rng = Rng(0xfeed_beef);
    let pairs = pairs();
    for len in [0usize, 1, 16, 17, 100, 300] {
        let key = {
            let mut k = [0u8; 32];
            rng.fill(&mut k);
            k
        };
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let mut aad = vec![0u8; 20];
        rng.fill(&mut aad);
        let mut pt = vec![0u8; len];
        rng.fill(&mut pt);
        for &(ab, gb) in &pairs {
            let gcm = Aes256Gcm::with_backends(&key, ab, gb).unwrap();
            let mut ct = pt.clone();
            let tag = gcm.seal_in_place(&nonce, &aad, &mut ct).unwrap();

            let expect_fail =
                |buf: &mut Vec<u8>, aad: &[u8], nonce: &[u8; 12], tag: &[u8; 16], what: &str| {
                    let r = gcm.open_in_place(nonce, aad, buf, tag);
                    assert_eq!(
                        r,
                        Err(Error::DecryptFailed),
                        "{ab:?}/{gb:?} len={len} {what}"
                    );
                    assert!(
                        buf.iter().all(|&b| b == 0),
                        "{ab:?}/{gb:?} len={len} {what}: buffer not zeroed"
                    );
                };

            // Every bit of the tag.
            for bit in 0..128 {
                let mut t = tag;
                t[bit / 8] ^= 1 << (bit % 8);
                expect_fail(&mut ct.clone(), &aad, &nonce, &t, "tag bit flip");
            }
            // Ciphertext bit flips at several positions.
            if len > 0 {
                for pos in [0, len / 2, len - 1] {
                    for bit in [0, 3, 7] {
                        let mut c = ct.clone();
                        c[pos] ^= 1 << bit;
                        expect_fail(&mut c, &aad, &nonce, &tag, "ciphertext bit flip");
                    }
                }
                // Truncation and extension.
                let mut c = ct.clone();
                c.pop();
                expect_fail(&mut c, &aad, &nonce, &tag, "truncated ciphertext");
                let mut c = ct.clone();
                c.push(0);
                expect_fail(&mut c, &aad, &nonce, &tag, "extended ciphertext");
            }
            // AAD modifications.
            let mut a = aad.clone();
            a[5] ^= 0x80;
            expect_fail(&mut ct.clone(), &a, &nonce, &tag, "aad bit flip");
            expect_fail(&mut ct.clone(), &aad[..19], &nonce, &tag, "aad truncated");
            expect_fail(&mut ct.clone(), &[], &nonce, &tag, "aad removed");
            // Nonce modification.
            let mut n = nonce;
            n[11] ^= 1;
            expect_fail(&mut ct.clone(), &aad, &n, &tag, "nonce bit flip");

            // The untouched ciphertext still opens.
            let mut c = ct.clone();
            gcm.open_in_place(&nonce, &aad, &mut c, &tag).unwrap();
            assert_eq!(c, pt);
        }
    }
}

#[test]
fn backends_report_what_they_were_built_with() {
    for (ab, gb) in pairs() {
        let gcm = Aes128Gcm::with_backends(&[1; 16], ab, gb).unwrap();
        assert_eq!(gcm.backends(), (ab, gb));
    }
    let auto = Aes128Gcm::new(&[1; 16]).unwrap();
    assert_eq!(
        auto.backends(),
        (aes::Backend::select(), GhashBackend::select())
    );
    for backend in aes::Backend::ALL {
        if !backend.is_available() {
            assert_eq!(
                aes::Aes128::with_backend(&[0; 16], backend).err(),
                Some(Error::Unsupported)
            );
        }
    }
}

/// Rough throughput per backend pair (release build recommended):
/// `cargo test -p browntls-crypto --release --test aes_gcm_differential -- --ignored --nocapture throughput`
#[test]
#[ignore = "benchmark; run manually with --ignored --nocapture"]
fn throughput() {
    use std::time::{Duration, Instant};
    let key = [0x5au8; 32];
    let nonce = [1u8; 12];
    let aad = [2u8; 13];
    for &(ab, gb) in &pairs() {
        let gcm = Aes256Gcm::with_backends(&key, ab, gb).unwrap();
        for size in [64usize, 1024, 16384] {
            let mut buf = vec![0u8; size];
            for &op in &["seal", "open"] {
                let mut iters = 0u64;
                let start = Instant::now();
                let mut tag = [0u8; 16];
                while start.elapsed() < Duration::from_millis(300) {
                    for _ in 0..16 {
                        if op == "seal" {
                            tag = gcm.seal_in_place(&nonce, &aad, &mut buf).unwrap();
                        } else {
                            // Keep the buffer authentic: re-seal then open.
                            let t = gcm.seal_in_place(&nonce, &aad, &mut buf).unwrap();
                            gcm.open_in_place(&nonce, &aad, &mut buf, &t).unwrap();
                        }
                        iters += 1;
                    }
                }
                let secs = start.elapsed().as_secs_f64();
                let mbps = (iters as f64 * size as f64) / secs / 1e6;
                let per_op = secs / iters as f64 * 1e9;
                println!(
                    "AES-256-GCM {ab:?}/{gb:?} {op:>4} {size:>6} B: {mbps:8.1} MB/s ({per_op:8.0} ns/op) tag={:02x}",
                    tag[0]
                );
            }
        }
    }
    for ab in aes::Backend::ALL.into_iter().filter(|b| b.is_available()) {
        let a = aes::Aes128::with_backend(&key[..16].try_into().unwrap(), ab).unwrap();
        let mut buf = vec![0u8; 16384];
        let ctr = [3u8; 16];
        let mut iters = 0u64;
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(300) {
            for _ in 0..16 {
                a.ctr32_xor(&ctr, &mut buf);
                iters += 1;
            }
        }
        let secs = start.elapsed().as_secs_f64();
        println!(
            "AES-128-CTR {ab:?} 16384 B: {:8.1} MB/s",
            (iters as f64 * 16384.0) / secs / 1e6
        );
    }
}
