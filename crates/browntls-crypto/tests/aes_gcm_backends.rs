//! Differential tests of every available AES / GHASH backend pair against
//! the portable implementation: every length up to 600 bytes, multiples of
//! 64 KiB with odd tails, AAD from empty to well over sixteen blocks,
//! unaligned buffers, and tampering on long messages (which exercises the
//! fused ZMM loop, its software-pipelined groups and its tails).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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

    fn pick<T: Copy>(&mut self, choices: &[T]) -> T {
        choices[self.below(choices.len())]
    }
}

/// A keyed AES-GCM of either key size for one backend pair.
enum Gcm {
    K128(Aes128Gcm),
    K256(Aes256Gcm),
}

impl Gcm {
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

/// Every available backend pair other than the all-portable reference.
fn accelerated_pairs() -> Vec<(aes::Backend, GhashBackend)> {
    let mut v = Vec::new();
    for ab in aes::Backend::ALL.into_iter().filter(|b| b.is_available()) {
        for gb in GhashBackend::ALL.into_iter().filter(|b| b.is_available()) {
            if (ab, gb) != (aes::Backend::Soft, GhashBackend::Soft) {
                v.push((ab, gb));
            }
        }
    }
    v
}

/// Bytes kept after the plaintext and AAD inside their buffers, so writes
/// past the end of a slice are detected.
const TRAIL: usize = 16;

/// One random message: key, nonce, AAD and plaintext placed at `offset`
/// inside larger buffers (unaligned, followed by [`TRAIL`] canary bytes),
/// with the portable implementation's ciphertext and tag.
struct Case {
    key: Vec<u8>,
    nonce: [u8; 12],
    aad: Vec<u8>,
    aad_offset: usize,
    pt: Vec<u8>,
    offset: usize,
    ct: Vec<u8>,
    tag: [u8; 16],
}

impl Case {
    fn new(rng: &mut Rng, len: usize, aad_len: usize) -> Self {
        let key_len = if rng.below(2) == 0 { 16 } else { 32 };
        Self::with_key_len(rng, key_len, len, aad_len)
    }

    fn with_key_len(rng: &mut Rng, key_len: usize, len: usize, aad_len: usize) -> Self {
        let mut key = vec![0u8; key_len];
        rng.fill(&mut key);
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let aad_offset = rng.below(16);
        let mut aad = vec![0u8; aad_offset + aad_len + TRAIL];
        rng.fill(&mut aad);
        let offset = rng.below(16);
        let mut pt = vec![0u8; offset + len + TRAIL];
        rng.fill(&mut pt);
        let mut ct = pt.clone();
        let reference = Gcm::new(&key, aes::Backend::Soft, GhashBackend::Soft);
        let tag = reference.seal(
            &nonce,
            &aad[aad_offset..aad_offset + aad_len],
            &mut ct[offset..offset + len],
        );
        Self {
            key,
            nonce,
            aad,
            aad_offset,
            pt,
            offset,
            ct,
            tag,
        }
    }

    fn aad(&self) -> &[u8] {
        &self.aad[self.aad_offset..self.aad.len() - TRAIL]
    }

    fn range(&self) -> core::ops::Range<usize> {
        self.offset..self.pt.len() - TRAIL
    }

    fn plaintext(&self) -> &[u8] {
        &self.pt[self.range()]
    }

    fn ciphertext(&self) -> &[u8] {
        &self.ct[self.range()]
    }

    /// The bytes around the message in `buf` equal those of the plaintext
    /// buffer.
    fn assert_surroundings(&self, buf: &[u8], what: &str) {
        let r = self.range();
        assert_eq!(buf[..r.start], self.pt[..r.start], "{what}: prefix");
        assert_eq!(buf[r.end..], self.pt[r.end..], "{what}: suffix");
    }

    /// Seals and opens with `pair`, checking against the reference.
    fn check(&self, pair: (aes::Backend, GhashBackend)) {
        let (ab, gb) = pair;
        let gcm = Gcm::new(&self.key, ab, gb);
        let what = format!(
            "{ab:?}/{gb:?} key={} len={} aad={} offsets={}/{}",
            self.key.len(),
            self.plaintext().len(),
            self.aad().len(),
            self.offset,
            self.aad_offset
        );
        let mut buf = self.pt.clone();
        let tag = gcm.seal(&self.nonce, self.aad(), &mut buf[self.range()]);
        assert!(
            buf[self.range()] == *self.ciphertext(),
            "{what}: ciphertext differs"
        );
        assert_eq!(tag, self.tag, "{what}: tag differs");
        self.assert_surroundings(&buf, &format!("{what} seal"));
        gcm.open(&self.nonce, self.aad(), &mut buf[self.range()], &tag)
            .unwrap_or_else(|e| panic!("{what}: open failed: {e}"));
        assert!(buf[self.range()] == *self.plaintext(), "{what}: round trip");
        self.assert_surroundings(&buf, &format!("{what} open"));
        // A failed open zeroes exactly the message.
        let mut bad = self.tag;
        bad[0] ^= 1;
        let mut buf = self.ct.clone();
        assert_eq!(
            gcm.open(&self.nonce, self.aad(), &mut buf[self.range()], &bad),
            Err(Error::DecryptFailed),
            "{what}: forged tag accepted"
        );
        assert!(
            buf[self.range()].iter().all(|&b| b == 0),
            "{what}: not zeroed"
        );
        let r = self.range();
        assert_eq!(
            buf[..r.start],
            self.ct[..r.start],
            "{what}: failed open prefix"
        );
        assert_eq!(buf[r.end..], self.ct[r.end..], "{what}: failed open suffix");
    }

    /// Checks that `open` with the given modifications fails and zeroes the
    /// buffer.
    fn check_rejected(&self, pair: (aes::Backend, GhashBackend)) {
        let (ab, gb) = pair;
        let gcm = Gcm::new(&self.key, ab, gb);
        let len = self.plaintext().len();
        let what = |detail: &str| {
            format!(
                "{ab:?}/{gb:?} key={} len={} aad={}: {detail}",
                self.key.len(),
                len,
                self.aad().len()
            )
        };
        let expect_fail =
            |buf: &mut [u8], aad: &[u8], nonce: &[u8; 12], tag: &[u8; 16], d: &str| {
                assert_eq!(
                    gcm.open(nonce, aad, buf, tag),
                    Err(Error::DecryptFailed),
                    "{}",
                    what(d)
                );
                assert!(
                    buf.iter().all(|&b| b == 0),
                    "{}: buffer not zeroed",
                    what(d)
                );
            };
        for bit in (0..128).step_by(7).chain([127]) {
            let mut t = self.tag;
            t[bit / 8] ^= 1 << (bit % 8);
            expect_fail(
                &mut self.ciphertext().to_vec(),
                self.aad(),
                &self.nonce,
                &t,
                "tag bit flip",
            );
        }
        if len > 0 {
            let positions = [0, 1, 15, 16, 255, 256, 511, 512, 513, len / 2, len - 1];
            for pos in positions.into_iter().filter(|&p| p < len) {
                let mut c = self.ciphertext().to_vec();
                c[pos] ^= 0x40;
                expect_fail(
                    &mut c,
                    self.aad(),
                    &self.nonce,
                    &self.tag,
                    &format!("ciphertext bit flip at {pos}"),
                );
            }
            let mut c = self.ciphertext().to_vec();
            c.pop();
            expect_fail(&mut c, self.aad(), &self.nonce, &self.tag, "truncated");
        }
        let mut c = self.ciphertext().to_vec();
        c.push(0);
        expect_fail(&mut c, self.aad(), &self.nonce, &self.tag, "extended");
        let mut a = self.aad().to_vec();
        a.push(0);
        expect_fail(
            &mut self.ciphertext().to_vec(),
            &a,
            &self.nonce,
            &self.tag,
            "aad extended",
        );
        if !self.aad().is_empty() {
            let mut a = self.aad().to_vec();
            let pos = a.len() / 2;
            a[pos] ^= 0x01;
            expect_fail(
                &mut self.ciphertext().to_vec(),
                &a,
                &self.nonce,
                &self.tag,
                "aad bit flip",
            );
            a = self.aad().to_vec();
            a.pop();
            expect_fail(
                &mut self.ciphertext().to_vec(),
                &a,
                &self.nonce,
                &self.tag,
                "aad truncated",
            );
        }
        let mut n = self.nonce;
        n[0] ^= 0x80;
        expect_fail(
            &mut self.ciphertext().to_vec(),
            self.aad(),
            &n,
            &self.tag,
            "nonce bit flip",
        );
    }
}

#[test]
fn every_length_up_to_600_matches_portable() {
    let mut rng = Rng(0x600d_cafe_f00d_0001);
    let pairs = accelerated_pairs();
    println!("backend pairs: {pairs:?}");
    for len in 0..=600 {
        // AAD: empty, TLS-like, one register, or long (more than 16 blocks).
        let aad_len = match len % 5 {
            0 => 0,
            1 => 13,
            2 => rng.below(65),
            3 => 257 + rng.below(300),
            _ => rng.below(700),
        };
        let case = Case::new(&mut rng, len, aad_len);
        for &pair in &pairs {
            case.check(pair);
        }
    }
}

#[test]
fn long_messages_match_portable() {
    let mut rng = Rng(0x1004_0000_0000_0007);
    let pairs = accelerated_pairs();
    let tails = [0usize, 1, 17, 511, 513];
    for k in 1..=5usize {
        for &tail in &tails {
            let len = k * 65536 + tail;
            let aad_len = rng.pick(&[0usize, 13, 64, 65, 300, 1000]);
            let case = Case::new(&mut rng, len, aad_len);
            for &pair in &pairs {
                case.check(pair);
            }
        }
    }
}

#[test]
fn random_lengths_and_aad_match_portable() {
    let mut rng = Rng(0xa5a5_5a5a_0000_0042);
    let pairs = accelerated_pairs();
    for _ in 0..150 {
        let len = match rng.below(4) {
            0 => rng.below(64),
            1 => rng.below(600),
            2 => rng.below(5000),
            _ => rng.below(70_000),
        };
        let aad_len = match rng.below(4) {
            0 => 0,
            1 => rng.below(64),
            2 => rng.below(300),
            _ => rng.below(2000),
        };
        let case = Case::new(&mut rng, len, aad_len);
        for &pair in &pairs {
            case.check(pair);
        }
    }
}

#[test]
fn tampering_is_rejected_on_every_pair() {
    let mut rng = Rng(0xbad_f00d_0000_0003);
    let pairs = accelerated_pairs();
    for len in [
        0usize,
        1,
        16,
        17,
        100,
        255,
        256,
        511,
        512,
        513,
        1024,
        1500,
        4097,
        65536 + 13,
    ] {
        for aad_len in [0usize, 13, 49, 64, 300] {
            let case = Case::new(&mut rng, len, aad_len);
            for &pair in &pairs {
                case.check_rejected(pair);
            }
        }
    }
}

#[test]
fn boundary_lengths_match_portable() {
    // Group (512 B), register (64 B) and block (16 B) boundaries of the ZMM
    // path, and the short-message limit (31 ciphertext blocks with a
    // one-block AAD).
    let mut rng = Rng(0x0b0b_0b0b_0000_0009);
    let pairs = accelerated_pairs();
    let mut lengths = Vec::new();
    for base in [
        64usize, 128, 256, 448, 480, 496, 512, 1024, 2048, 16384, 65536,
    ] {
        for d in [-1isize, 0, 1] {
            lengths.push((base as isize + d) as usize);
        }
    }
    for len in lengths {
        for aad_len in [0usize, 13, 16, 17, 64, 65] {
            let case = Case::new(&mut rng, len, aad_len);
            for &pair in &pairs {
                case.check(pair);
            }
        }
    }
}

#[test]
fn short_long_split_for_both_key_sizes() {
    // The ZMM path hashes a message in one reduction when its AAD is at
    // most four blocks and AAD, ciphertext and lengths blocks total at most
    // 32 blocks: cover both sides of that limit for every AAD block count
    // and both key sizes.
    let mut rng = Rng(0x5407_1046_0000_000b);
    let pairs = accelerated_pairs();
    for key_len in [16usize, 32] {
        for aad_len in [0usize, 1, 16, 17, 32, 33, 48, 49, 64, 65] {
            for len in 26 * 16..=32 * 16 + 1 {
                let case = Case::with_key_len(&mut rng, key_len, len, aad_len);
                for &pair in &pairs {
                    case.check(pair);
                }
            }
        }
    }
}

#[test]
fn default_selection_prefers_the_widest_backends() {
    let gcm = Aes128Gcm::new(&[0x11; 16]).unwrap();
    let (ab, gb) = gcm.backends();
    assert_eq!(ab, aes::Backend::select());
    assert_eq!(gb, GhashBackend::select());
    if aes::Backend::VaesAvx512.is_available() {
        assert_eq!(ab, aes::Backend::VaesAvx512);
    } else if aes::Backend::Vaes.is_available() {
        assert_eq!(ab, aes::Backend::Vaes);
    }
    if GhashBackend::VpclmulAvx512.is_available() {
        assert_eq!(gb, GhashBackend::VpclmulAvx512);
    } else if GhashBackend::Vpclmul.is_available() {
        assert_eq!(gb, GhashBackend::Vpclmul);
    }
}
