//! AES-CCM (NIST SP 800-38C; RFC 3610).
//!
//! | Type | Algorithm | Nonce | Tag | API |
//! |---|---|---|---|---|
//! | [`Aes128Ccm`] | AEAD_AES_128_CCM (RFC 5116 §5.3) | 12 bytes | 16 bytes | [`Aead`] |
//! | [`Aes128Ccm8`] | AEAD_AES_128_CCM_8 (RFC 6655 §6.1) | 12 bytes | 8 bytes | its own, since [`Aead`] fixes 16-byte tags |
//!
//! These are the AEADs of the TLS 1.3 suites `TLS_AES_128_CCM_SHA256` and
//! `TLS_AES_128_CCM_8_SHA256` (RFC 9846 Appendix B.4). A 12-byte nonce leaves
//! a 3-byte length and counter field (q = 3), so messages are limited to
//! 2^24 - 1 bytes (RFC 5116 §5.3, `P_MAX`); additional data may have any
//! length and is prefixed with the length encoding of SP 800-38C §A.2.2.
//!
//! The mode runs on the expanded keys of [`crate::aes`], so the AES backend
//! selection and acceleration policy apply unchanged. The keystream comes
//! from the backend's counter-mode routine; CBC-MAC is inherently
//! sequential and encrypts one block per call.
//!
//! CCM authenticates the plaintext rather than the ciphertext, so opening
//! must decrypt before it can verify. To release no unauthenticated
//! plaintext, opening decrypts the ciphertext in chunks into a stack buffer
//! that is fed to CBC-MAC and then wiped, compares the tag in constant time,
//! and only then decrypts into the caller's buffer (a second counter-mode
//! pass). On failure the buffer, which still holds ciphertext, is zeroed as
//! the [`Aead`] contract requires.
//!
//! [`AesCcm`] exposes the general mode (nonces of 7 to 13 bytes, even tag
//! lengths from 4 to 16 bytes, AES-128 or AES-256) for testing against the
//! SP 800-38C, RFC 3610 and Wycheproof vectors.

use crate::Error;
use crate::aead::{Aead, NONCE_LEN, TAG_LEN};
use crate::aes::{self, BLOCK_LEN};
use crate::zeroize::zeroize_bytes;

/// Shortest nonce SP 800-38C §A.1 allows (q = 8).
pub const MIN_NONCE_LEN: usize = 7;
/// Longest nonce SP 800-38C §A.1 allows (q = 2).
pub const MAX_NONCE_LEN: usize = 13;
/// Tag length of [`Aes128Ccm8`] in bytes.
pub const CCM8_TAG_LEN: usize = 8;

/// Opening decrypts this many bytes at a time into a stack buffer.
const CHUNK_LEN: usize = 32 * BLOCK_LEN;

/// Parameters of one message, checked against SP 800-38C §A.1.
struct Params {
    /// Byte length of the message length field and the counter (`q`).
    q: usize,
    /// Tag length in bytes (`t`).
    tag_len: usize,
}

impl Params {
    fn new(nonce_len: usize, tag_len: usize, msg_len: usize) -> Result<Self, Error> {
        // t ∈ {4, 6, 8, 10, 12, 14, 16}, n ∈ {7, ..., 13} and q = 15 - n.
        if !(MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&nonce_len)
            || !(4..=16).contains(&tag_len)
            || !tag_len.is_multiple_of(2)
        {
            return Err(Error::InvalidLength);
        }
        let q = 15 - nonce_len;
        if u64::try_from(msg_len).map_or(true, |len| len > max_msg_len(q)) {
            return Err(Error::InvalidLength);
        }
        Ok(Self { q, tag_len })
    }
}

/// The longest message for a `q`-byte length field, `2^(8q) - 1` bytes
/// (SP 800-38C §A.1). For `q >= 5` it is further capped at `2^32 - 1`
/// blocks so that the 32-bit counter increment of
/// [`aes::Key::ctr32_xor`] never wraps; below that bound the counter
/// (at most `ceil(len / 16)`) never carries out of its `q` bytes either.
fn max_msg_len(q: usize) -> u64 {
    let field = u64::MAX >> (64 - 8 * q);
    field.min(((1 << 32) - 1) * 16)
}

/// The first CBC-MAC block `B_0` (SP 800-38C §A.2.1): the flags octet
/// (`Adata`, `[(t - 2) / 2]_3`, `[q - 1]_3`), the nonce and the message
/// length in `q` bytes.
fn b0(nonce: &[u8], p: &Params, has_aad: bool, msg_len: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    // Both fields are at most 7, so the casts are lossless.
    b[0] = (u8::from(has_aad) << 6) | ((((p.tag_len - 2) / 2) as u8) << 3) | ((p.q - 1) as u8);
    b[1..1 + nonce.len()].copy_from_slice(nonce);
    let len = (msg_len as u64).to_be_bytes();
    b[16 - p.q..].copy_from_slice(&len[8 - p.q..]);
    b
}

/// The counter block `A_0` (SP 800-38C §A.3): flags `[q - 1]_3`, the nonce
/// and a zero counter.
fn a0(nonce: &[u8], q: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = (q - 1) as u8;
    a[1..1 + nonce.len()].copy_from_slice(nonce);
    a
}

/// `A_1`, the first keystream counter block.
fn a1(a0: &[u8; 16]) -> [u8; 16] {
    let mut a = *a0;
    a[15] = 1;
    a
}

/// Advances a counter block by `n` blocks in the same way as
/// [`aes::Key::ctr32_xor`] (big-endian, last 32 bits).
fn advance(ctr: &mut [u8; 16], n: u32) {
    let c = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]).wrapping_add(n);
    ctr[12..].copy_from_slice(&c.to_be_bytes());
}

/// The encoding of the additional-data length `a > 0` (SP 800-38C
/// §A.2.2): two bytes below `2^16 - 2^8`, `0xff 0xfe` and four bytes below
/// `2^32`, otherwise `0xff 0xff` and eight bytes. Returns the buffer and the
/// number of bytes used.
fn aad_len_encoding(a: u64) -> ([u8; 10], usize) {
    let mut enc = [0u8; 10];
    if a < (1 << 16) - (1 << 8) {
        enc[..2].copy_from_slice(&a.to_be_bytes()[6..]);
        (enc, 2)
    } else if a < 1 << 32 {
        enc[..2].copy_from_slice(&[0xff, 0xfe]);
        enc[2..6].copy_from_slice(&a.to_be_bytes()[4..]);
        (enc, 6)
    } else {
        enc[..2].copy_from_slice(&[0xff, 0xff]);
        enc[2..].copy_from_slice(&a.to_be_bytes());
        (enc, 10)
    }
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// CBC-MAC over the formatted input (SP 800-38C §6.1 steps 2-4), fed as a
/// byte stream. The chaining value is zeroised on drop.
struct CbcMac<'k> {
    key: &'k aes::Key,
    /// The chaining value with the bytes of the current partial block
    /// already XORed in.
    y: [u8; 16],
    /// Bytes of the current block absorbed so far.
    pos: usize,
}

impl<'k> CbcMac<'k> {
    /// Starts with `Y_0 = CIPH_K(B_0)` and writes `S_0 = CIPH_K(A_0)`,
    /// computed by the same block-cipher call, to the caller's `s0` (so no
    /// copy of it is left behind in a returned value).
    fn start(key: &'k aes::Key, b0: [u8; 16], a0: [u8; 16], s0: &mut [u8; 16]) -> Self {
        let mut blocks = [b0, a0];
        key.encrypt_blocks(&mut blocks);
        let y = blocks[0];
        *s0 = blocks[1];
        zeroize_bytes(blocks.as_flattened_mut());
        Self { key, y, pos: 0 }
    }

    fn encrypt(&mut self) {
        self.key.encrypt_blocks(core::slice::from_mut(&mut self.y));
        self.pos = 0;
    }

    fn absorb(&mut self, mut data: &[u8]) {
        if self.pos != 0 {
            let take = data.len().min(BLOCK_LEN - self.pos);
            xor_into(&mut self.y[self.pos..self.pos + take], &data[..take]);
            self.pos += take;
            data = &data[take..];
            if self.pos < BLOCK_LEN {
                return;
            }
            self.encrypt();
        }
        let (blocks, rest) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks {
            xor_into(&mut self.y, block);
            self.encrypt();
        }
        xor_into(&mut self.y[..rest.len()], rest);
        self.pos = rest.len();
    }

    /// Completes the current block with zero padding.
    fn pad(&mut self) {
        if self.pos != 0 {
            self.encrypt();
        }
    }

    /// Absorbs the length-prefixed, zero-padded additional data (SP 800-38C
    /// §A.2.2). Nothing is absorbed for empty additional data.
    fn absorb_aad(&mut self, aad: &[u8]) {
        if aad.is_empty() {
            return;
        }
        let (enc, len) = aad_len_encoding(aad.len() as u64);
        self.absorb(&enc[..len]);
        self.absorb(aad);
        self.pad();
    }

    /// Pads the payload and returns the final chaining value `Y_r`.
    fn finish(mut self) -> [u8; 16] {
        self.pad();
        self.y
    }
}

impl Drop for CbcMac<'_> {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.y);
    }
}

/// The mode over an expanded AES key of either size.
struct Ccm {
    aes: aes::Key,
}

impl Ccm {
    fn new(key: &[u8], backend: aes::Backend) -> Result<Self, Error> {
        aes::Key::new(key, backend).map(|aes| Self { aes })
    }

    /// Starts CBC-MAC over `B_0` and the additional data; returns the MAC
    /// and `A_0`, and writes `S_0` to `s0`.
    fn start(
        &self,
        nonce: &[u8],
        p: &Params,
        aad: &[u8],
        msg_len: usize,
        s0: &mut [u8; 16],
    ) -> (CbcMac<'_>, [u8; 16]) {
        let a0 = a0(nonce, p.q);
        let mut mac = CbcMac::start(&self.aes, b0(nonce, p, !aad.is_empty(), msg_len), a0, s0);
        mac.absorb_aad(aad);
        (mac, a0)
    }

    /// SP 800-38C §6.1: encrypts `in_out` and writes the tag, whose length
    /// `tag.len()` selects `t`.
    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), Error> {
        let p = Params::new(nonce.len(), tag.len(), in_out.len())?;
        let mut s0 = [0u8; 16];
        let (mut mac, a0) = self.start(nonce, &p, aad, in_out.len(), &mut s0);
        mac.absorb(in_out);
        let mut y = mac.finish();
        self.aes.ctr32_xor(&a1(&a0), in_out);
        for ((t, y), s) in tag.iter_mut().zip(&y).zip(&s0) {
            *t = y ^ s;
        }
        zeroize_bytes(&mut y);
        zeroize_bytes(&mut s0);
        Ok(())
    }

    /// SP 800-38C §6.2: verifies `tag` over the decryption of `in_out` and
    /// only then decrypts `in_out`; zeroes it on failure.
    fn open(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &[u8]) -> Result<(), Error> {
        let p = Params::new(nonce.len(), tag.len(), in_out.len())?;
        let mut s0 = [0u8; 16];
        let (mut mac, a0) = self.start(nonce, &p, aad, in_out.len(), &mut s0);

        // Authenticate the plaintext without writing it to `in_out`.
        let mut ctr = a1(&a0);
        let mut plain = [0u8; CHUNK_LEN];
        for chunk in in_out.chunks(CHUNK_LEN) {
            let plain = &mut plain[..chunk.len()];
            plain.copy_from_slice(chunk);
            self.aes.ctr32_xor(&ctr, plain);
            mac.absorb(plain);
            advance(&mut ctr, (CHUNK_LEN / BLOCK_LEN) as u32);
        }
        zeroize_bytes(&mut plain);

        let mut y = mac.finish();
        let mut expected = [0u8; 16];
        for ((e, y), s) in expected.iter_mut().zip(&y).zip(&s0) {
            *e = y ^ s;
        }
        let valid = crate::ct::eq(&expected[..p.tag_len], tag);
        zeroize_bytes(&mut y);
        zeroize_bytes(&mut s0);
        zeroize_bytes(&mut expected);
        if !valid {
            zeroize_bytes(in_out);
            return Err(Error::DecryptFailed);
        }
        self.aes.ctr32_xor(&a1(&a0), in_out);
        Ok(())
    }
}

/// AES-CCM with run-time parameters (SP 800-38C): nonces of
/// [`MIN_NONCE_LEN`] to [`MAX_NONCE_LEN`] bytes, tags of 4 to 16 bytes (even
/// lengths only) and AES-128 or AES-256 keys.
///
/// Exposed for testing against published vectors; TLS uses [`Aes128Ccm`]
/// and [`Aes128Ccm8`]. Short tags give weak authentication (SP 800-38C
/// Appendix B).
#[doc(hidden)]
pub struct AesCcm {
    inner: Ccm,
}

impl AesCcm {
    /// Expands a 16- or 32-byte `key` using the best available AES backend.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for other key lengths.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Self::with_backend(key, aes::Backend::select())
    }

    /// Expands `key` for a specific AES backend (differential testing).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for a key that is not 16 or 32 bytes
    /// and [`Error::Unsupported`] if `backend` cannot run here.
    pub fn with_backend(key: &[u8], backend: aes::Backend) -> Result<Self, Error> {
        Ccm::new(key, backend).map(|inner| Self { inner })
    }

    /// The AES backend in use.
    #[must_use]
    pub fn backend(&self) -> aes::Backend {
        self.inner.aes.backend()
    }

    /// Encrypts `in_out` in place and writes the tag into `tag`, whose length
    /// is the tag length `t`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] for an unsupported nonce or tag
    /// length, or a message too long for the nonce's length field.
    pub fn seal_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), Error> {
        self.inner.seal(nonce, aad, in_out, tag)
    }

    /// Verifies `tag` and decrypts `in_out` in place; zeroes `in_out` if
    /// authentication fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptFailed`] if authentication fails and
    /// [`Error::InvalidLength`] as [`Self::seal_in_place`] does.
    pub fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        self.inner.open(nonce, aad, in_out, tag)
    }
}

impl core::fmt::Debug for AesCcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesCcm")
            .field("aes", &self.backend())
            .finish_non_exhaustive()
    }
}

/// AEAD_AES_128_CCM (RFC 5116 §5.3): AES-128, 12-byte nonce, 16-byte tag,
/// messages of at most 2^24 - 1 bytes.
pub struct Aes128Ccm {
    inner: Ccm,
}

impl Aes128Ccm {
    /// Expands `key` for a specific AES backend (differential testing).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] if `backend` cannot run here.
    #[doc(hidden)]
    pub fn with_backend(key: &[u8; 16], backend: aes::Backend) -> Result<Self, Error> {
        Ccm::new(key, backend).map(|inner| Self { inner })
    }

    /// The AES backend in use.
    #[doc(hidden)]
    #[must_use]
    pub fn backend(&self) -> aes::Backend {
        self.inner.aes.backend()
    }
}

impl Aead for Aes128Ccm {
    const KEY_LEN: usize = 16;

    fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != Self::KEY_LEN {
            return Err(Error::InvalidKey);
        }
        Ccm::new(key, aes::Backend::select()).map(|inner| Self { inner })
    }

    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        let mut tag = [0u8; TAG_LEN];
        self.inner.seal(nonce, aad, in_out, &mut tag)?;
        Ok(tag)
    }

    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        self.inner.open(nonce, aad, in_out, tag)
    }
}

impl core::fmt::Debug for Aes128Ccm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes128Ccm")
            .field("aes", &self.backend())
            .finish_non_exhaustive()
    }
}

/// AEAD_AES_128_CCM_8 (RFC 6655 §6.1): AES-128, 12-byte nonce, 8-byte tag,
/// messages of at most 2^24 - 1 bytes.
///
/// The 64-bit tag makes forgeries far cheaper than with the 128-bit tags of
/// the other AEADs here; RFC 9147 Appendix B.3 limits a key to 2^7 failed
/// authentications for the usual TLS security margin. The methods mirror
/// [`Aead`], which cannot express an 8-byte tag.
pub struct Aes128Ccm8 {
    inner: Ccm,
}

impl Aes128Ccm8 {
    /// Key length in bytes.
    pub const KEY_LEN: usize = 16;
    /// Tag length in bytes.
    pub const TAG_LEN: usize = CCM8_TAG_LEN;

    /// Expands `key` using the best available AES backend.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `key.len() != Self::KEY_LEN`.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != Self::KEY_LEN {
            return Err(Error::InvalidKey);
        }
        Ccm::new(key, aes::Backend::select()).map(|inner| Self { inner })
    }

    /// Expands `key` for a specific AES backend (differential testing).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] if `backend` cannot run here.
    #[doc(hidden)]
    pub fn with_backend(key: &[u8; 16], backend: aes::Backend) -> Result<Self, Error> {
        Ccm::new(key, backend).map(|inner| Self { inner })
    }

    /// The AES backend in use.
    #[doc(hidden)]
    #[must_use]
    pub fn backend(&self) -> aes::Backend {
        self.inner.aes.backend()
    }

    /// Encrypts `in_out` in place and returns the authentication tag.
    ///
    /// The caller must never reuse a nonce under the same key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `in_out` is longer than
    /// 2^24 - 1 bytes.
    pub fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; CCM8_TAG_LEN], Error> {
        let mut tag = [0u8; CCM8_TAG_LEN];
        self.inner.seal(nonce, aad, in_out, &mut tag)?;
        Ok(tag)
    }

    /// Verifies `tag` and decrypts `in_out` in place.
    ///
    /// The tag comparison is constant time, and no plaintext is written to
    /// `in_out` before the tag has been verified. On failure `in_out` is
    /// overwritten with zeros.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptFailed`] if authentication fails, or
    /// [`Error::InvalidLength`] when `in_out` is longer than 2^24 - 1 bytes.
    pub fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; CCM8_TAG_LEN],
    ) -> Result<(), Error> {
        self.inner.open(nonce, aad, in_out, tag)
    }
}

impl core::fmt::Debug for Aes128Ccm8 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes128Ccm8")
            .field("aes", &self.backend())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_length_encoding_boundaries() {
        // SP 800-38C §A.2.2.
        let enc = |a: u64| {
            let (buf, len) = aad_len_encoding(a);
            hex::encode(&buf[..len])
        };
        assert_eq!(enc(1), "0001");
        assert_eq!(enc(0xfeff), "feff");
        assert_eq!(enc(0xff00), "fffe0000ff00");
        assert_eq!(enc(0xffff_ffff), "fffeffffffff");
        assert_eq!(enc(1 << 32), "ffff0000000100000000");
        assert_eq!(enc(u64::MAX), "ffffffffffffffffffff");
    }

    #[test]
    fn b0_and_counter_formatting() {
        // SP 800-38C §A.2.1 and §A.3 for the parameters of Appendix C.1
        // (t = 4, n = 7, q = 8, additional data present, Plen = 4).
        let nonce: [u8; 7] = core::array::from_fn(|i| 0x10 + i as u8);
        let p = Params::new(7, 4, 4).unwrap();
        assert_eq!(
            hex::encode(b0(&nonce, &p, true, 4)),
            "4f101112131415160000000000000004"
        );
        assert_eq!(
            hex::encode(a0(&nonce, p.q)),
            "07101112131415160000000000000000"
        );
        assert_eq!(
            hex::encode(a1(&a0(&nonce, p.q))),
            "07101112131415160000000000000001"
        );
        // No additional data clears the Adata bit; a 16-byte tag and q = 3.
        let p = Params::new(12, 16, 0x01_0203).unwrap();
        let nonce = [0xaa; 12];
        assert_eq!(
            hex::encode(b0(&nonce, &p, false, 0x01_0203)),
            "3aaaaaaaaaaaaaaaaaaaaaaaaa010203"
        );
    }

    #[test]
    fn parameter_validation() {
        for n in 0..=16 {
            for t in 0..=18 {
                let ok = (7..=13).contains(&n) && (4..=16).contains(&t) && t % 2 == 0;
                assert_eq!(Params::new(n, t, 0).is_ok(), ok, "n={n} t={t}");
            }
        }
        // q = 2: at most 2^16 - 1 bytes; q = 3: 2^24 - 1; q = 8: capped by
        // the 32-bit counter.
        assert!(Params::new(13, 16, 0xffff).is_ok());
        assert!(Params::new(13, 16, 0x1_0000).is_err());
        assert!(Params::new(12, 16, 0xff_ffff).is_ok());
        assert!(Params::new(12, 16, 0x100_0000).is_err());
        assert_eq!(max_msg_len(4), 0xffff_ffff);
        assert_eq!(max_msg_len(5), ((1 << 32) - 1) * 16);
        assert_eq!(max_msg_len(8), ((1 << 32) - 1) * 16);
    }

    #[test]
    fn counter_advance_matches_ctr32() {
        let mut c = [0u8; 16];
        c[12..].copy_from_slice(&[0, 0xff, 0xff, 0xff]);
        advance(&mut c, 1);
        assert_eq!(c[12..], [1, 0, 0, 0]);
    }

    #[test]
    fn sp800_38c_example_1_on_every_backend() {
        let key: [u8; 16] = core::array::from_fn(|i| 0x40 + i as u8);
        let nonce: [u8; 7] = core::array::from_fn(|i| 0x10 + i as u8);
        let aad: [u8; 8] = core::array::from_fn(|i| i as u8);
        for backend in aes::Backend::ALL {
            let Ok(ccm) = AesCcm::with_backend(&key, backend) else {
                continue;
            };
            let mut buf = [0x20, 0x21, 0x22, 0x23];
            let mut tag = [0u8; 4];
            ccm.seal_in_place(&nonce, &aad, &mut buf, &mut tag).unwrap();
            assert_eq!(hex::encode(buf), "7162015b", "{backend:?}");
            assert_eq!(hex::encode(tag), "4dac255d", "{backend:?}");
            ccm.open_in_place(&nonce, &aad, &mut buf, &tag).unwrap();
            assert_eq!(buf, [0x20, 0x21, 0x22, 0x23]);
        }
    }
}
