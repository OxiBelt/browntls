//! TLS 1.2 CBC record protection: the `GenericBlockCipher` transform of
//! RFC 5246, section 6.2.3.2, with HMAC-SHA1/SHA256/SHA384 and a 16-byte
//! block cipher in CBC mode with an explicit per-record IV.
//!
//! Two MAC orders are supported:
//!
//! * [`MacOrder::MacThenEncrypt`] (RFC 5246): the fragment is
//!   `IV || CBC(content || MAC || padding || padding_length)`, where the MAC
//!   covers `seq_num || type || version || length || content`.
//! * [`MacOrder::EncryptThenMac`] (RFC 7366, section 3): the fragment is
//!   `IV || CBC(content || padding || padding_length) || MAC`, where the MAC
//!   covers `seq_num || type || version || length || IV || ciphertext` and
//!   `length` is that of `IV || ciphertext`.
//!
//! The block cipher is abstracted by [`CbcBlockCipher`].
//!
//! # Decryption and timing (Lucky Thirteen)
//!
//! [`RecordKey::open`] returns the same [`Error::DecryptFailed`] for every
//! failure (bad length, bad padding, bad MAC). With encrypt-then-MAC the MAC
//! is checked over the public ciphertext before anything is decrypted, so
//! the only secret-dependent work happens after authentication.
//!
//! With MAC-then-encrypt the padding length, the padding validity and hence
//! the length of the MACed content are secret, and the implementation is
//! constant time with respect to all of them, following the countermeasure
//! of AlFardan and Paterson ("Lucky Thirteen", 2013) as implemented by
//! BoringSSL's `EVP_tls_cbc_digest_record` and `EVP_tls_cbc_copy_mac`.
//! Every loop bound, memory index and number of hash compression-function
//! calls depends only on the public fragment length; secret values are only
//! combined with masks from [`crate::ct`]. The comments on the private
//! `Keyed::ct_mac`, `check_padding` and `copy_mac` give the detailed argument.

use core::ops::Range;

use crate::Error;
use crate::ct::{self, Choice};
use crate::hash::{MdHash, Sha1, Sha256, Sha384};
use crate::zeroize::{Zeroize, zeroize_bytes};

/// Length of the explicit per-record IV (the cipher block size).
pub const IV_LEN: usize = 16;
/// The cipher block size.
const BLOCK: usize = 16;
/// Maximum plaintext fragment length (RFC 5246, section 6.2.1).
pub const MAX_PLAINTEXT_LEN: usize = 1 << 14;
/// Maximum protected fragment length (RFC 5246, section 6.2.3).
pub const MAX_FRAGMENT_LEN: usize = MAX_PLAINTEXT_LEN + 2048;
/// `seq_num (8) || type (1) || version (2) || length (2)`.
const HEADER_LEN: usize = 13;
/// Largest MAC (HMAC-SHA384).
const MAX_MAC_LEN: usize = 48;
/// Largest hash block (SHA-384).
const MAX_HASH_BLOCK: usize = 128;
/// Bytes of padding (including the length byte) a record may carry.
const MAX_PADDING: usize = 256;

/// A block cipher in CBC mode with 16-byte blocks (AES-CBC for TLS).
///
/// `buf.len()` is always a multiple of 16 (the caller guarantees it).
/// Implementations must be constant time with respect to the data.
pub trait CbcBlockCipher {
    /// Encrypts `buf` in place in CBC mode with initialisation vector `iv`.
    fn cbc_encrypt(&self, iv: &[u8; 16], buf: &mut [u8]);
    /// Decrypts `buf` in place in CBC mode with initialisation vector `iv`.
    fn cbc_decrypt(&self, iv: &[u8; 16], buf: &mut [u8]);
}

/// The record MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacAlgorithm {
    /// HMAC-SHA1 (20-byte tag and key; `*_CBC_SHA` suites).
    HmacSha1,
    /// HMAC-SHA256 (32-byte tag and key; `*_CBC_SHA256` suites).
    HmacSha256,
    /// HMAC-SHA384 (48-byte tag and key; `*_CBC_SHA384` suites).
    HmacSha384,
}

impl MacAlgorithm {
    /// Tag length in bytes, which is also the TLS MAC key length.
    #[must_use]
    pub const fn mac_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
        }
    }
}

/// Where the MAC is applied relative to encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacOrder {
    /// RFC 5246 MAC-then-encrypt.
    MacThenEncrypt,
    /// RFC 7366 encrypt-then-MAC.
    EncryptThenMac,
}

/// HMAC chaining states after the `key ^ ipad` and `key ^ opad` blocks.
struct Keyed<H: MdHash> {
    inner: H::State,
    outer: H::State,
}

impl<H: MdHash> Drop for Keyed<H> {
    fn drop(&mut self) {
        self.inner.zeroize();
        self.outer.zeroize();
    }
}

impl<H: MdHash> Keyed<H> {
    /// Keys HMAC with `key`, at most one hash block long.
    fn new(key: &[u8]) -> Self {
        debug_assert!(key.len() <= H::BLOCK_LEN);
        let mut block = [0u8; MAX_HASH_BLOCK];
        let block = &mut block[..H::BLOCK_LEN];
        block[..key.len()].copy_from_slice(key);
        let mut inner = H::IV;
        let mut outer = H::IV;
        for b in block.iter_mut() {
            *b ^= 0x36;
        }
        H::compress_blocks(&mut inner, block);
        for b in block.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        H::compress_blocks(&mut outer, block);
        zeroize_bytes(block);
        Self { inner, outer }
    }

    /// The outer hash over the inner digest `inner`; writes the tag to
    /// `out[..OUTPUT_LEN]`.
    fn finish(&self, inner: &[u8], out: &mut [u8]) {
        let mut h = H::from_state(self.outer, H::BLOCK_LEN as u64);
        h.update(inner);
        out[..H::OUTPUT_LEN].copy_from_slice(h.finalize().as_ref());
    }

    /// HMAC over the concatenation of `parts` (public lengths); writes the
    /// tag to `out[..OUTPUT_LEN]`.
    fn mac(&self, parts: &[&[u8]], out: &mut [u8]) {
        let mut h = H::from_state(self.inner, H::BLOCK_LEN as u64);
        for p in parts {
            h.update(p);
        }
        let mut d = h.finalize();
        self.finish(d.as_ref(), out);
        d.as_mut().zeroize();
    }

    /// HMAC over `header || data[..len]`, where `len` is secret, in time
    /// independent of `len`. Writes the tag to `out[..OUTPUT_LEN]`.
    ///
    /// `header` is the 11 public bytes `seq_num || type || version`; the
    /// two length bytes that follow it are `len`. The caller guarantees
    /// `min_len <= len <= data.len()`, where `min_len` and `data.len()` are
    /// public.
    ///
    /// # Constant-time argument
    ///
    /// Let `B` be the hash block length and `LB` the length of the
    /// Merkle–Damgård length field. The inner message `M = header || len ||
    /// data[..len]` has `m = 13 + len` bytes; its padded form ends in block
    /// `k = (m + LB) / B` (counting blocks after the `key ^ ipad` block).
    ///
    /// 1. Blocks `0 .. (13 + min_len) / B` consist only of message bytes for
    ///    every admissible `len`, so they are compressed directly. Their
    ///    number depends only on `min_len`; their content (including the
    ///    secret length bytes) does not affect timing.
    /// 2. Every later block up to `k_max = (13 + data.len() + LB) / B` is
    ///    built byte by byte: the candidate byte at public position `i` is
    ///    read from a public address (`header`/`data` at index `i`, or a
    ///    constant beyond `data`), then masked with `i < m` and combined with
    ///    `0x80` masked by `i == m`; in the last `LB` positions the
    ///    big-endian bit length replaces it under the mask `j == k`. Each such
    ///    block is compressed, and the digest of the resulting state is
    ///    copied into the result under the mask `j == k`.
    /// 3. The outer hash has a fixed-length input.
    ///
    /// The number of compression calls, every loop bound and every memory
    /// address therefore depend only on `min_len` and `data.len()`; `len`
    /// enters only through [`ct`] masks. Blocks after `k` are compressed and
    /// discarded.
    fn ct_mac(&self, header: &[u8; 11], data: &[u8], len: u64, min_len: usize, out: &mut [u8]) {
        let b = H::BLOCK_LEN;
        let lb = H::LEN_BYTES;
        let max_len = data.len();
        debug_assert!(b.is_power_of_two() && b <= MAX_HASH_BLOCK && b > HEADER_LEN + lb);
        debug_assert!(min_len <= max_len && max_len < (1 << 16));

        let mut hdr = [0u8; HEADER_LEN];
        hdr[..11].copy_from_slice(header);
        // `len < 2^16`, so the truncations keep its two bytes.
        #[allow(clippy::cast_possible_truncation)]
        {
            hdr[11] = (len >> 8) as u8;
            hdr[12] = len as u8;
        }
        // Secret: message length, its final block and its bit length
        // (including the `key ^ ipad` block).
        let m = HEADER_LEN as u64 + len;
        let shift = b.trailing_zeros();
        let k = (m + lb as u64) >> shift;
        let bits = (u128::from(m) + b as u128) * 8;
        let bits = bits.to_be_bytes();
        let bits = &bits[16 - lb..];

        let mut state = self.inner;
        // 1. Public prefix of whole message blocks.
        let prefix = (HEADER_LEN + min_len) / b;
        if prefix > 0 {
            let mut first = [0u8; MAX_HASH_BLOCK];
            first[..HEADER_LEN].copy_from_slice(&hdr);
            first[HEADER_LEN..b].copy_from_slice(&data[..b - HEADER_LEN]);
            H::compress_blocks(&mut state, &first[..b]);
            zeroize_bytes(&mut first);
            H::compress_blocks(&mut state, &data[b - HEADER_LEN..prefix * b - HEADER_LEN]);
        }

        // 2. Masked blocks up to the last possible final block.
        let k_max = (HEADER_LEN + max_len + lb) / b;
        let mut block = [0u8; MAX_HASH_BLOCK];
        let mut digest = [0u8; MAX_MAC_LEN];
        let mut inner = [0u8; MAX_MAC_LEN];
        for j in prefix..=k_max {
            let is_final = ct::eq_u64(j as u64, k);
            for (t, slot) in block[..b].iter_mut().enumerate() {
                let i = j * b + t;
                let raw = if i < HEADER_LEN {
                    hdr[i]
                } else if i - HEADER_LEN < max_len {
                    data[i - HEADER_LEN]
                } else {
                    0
                };
                let is_data = ct::lt_u64(i as u64, m);
                let is_pad = ct::eq_u64(i as u64, m);
                let mut v = ct::select_u8(is_data, raw, 0) | ct::select_u8(is_pad, 0x80, 0);
                if t >= b - lb {
                    v = ct::select_u8(is_final, bits[t - (b - lb)], v);
                }
                *slot = v;
            }
            H::compress_blocks(&mut state, &block[..b]);
            H::write_digest(&state, &mut digest[..H::OUTPUT_LEN]);
            ct::conditional_copy(
                is_final,
                &mut inner[..H::OUTPUT_LEN],
                &digest[..H::OUTPUT_LEN],
            );
        }
        zeroize_bytes(&mut block);
        zeroize_bytes(&mut digest);
        state.zeroize();

        // 3. Outer hash.
        self.finish(&inner[..H::OUTPUT_LEN], out);
        zeroize_bytes(&mut inner);
    }
}

enum MacKey {
    Sha1(Keyed<Sha1>),
    Sha256(Keyed<Sha256>),
    Sha384(Keyed<Sha384>),
}

/// Runs `$e` with `$k` bound to the keyed HMAC of whichever hash `$mac` uses.
macro_rules! with_key {
    ($mac:expr, $k:ident => $e:expr) => {
        match $mac {
            MacKey::Sha1($k) => $e,
            MacKey::Sha256($k) => $e,
            MacKey::Sha384($k) => $e,
        }
    };
}

/// Keys for protecting or opening the records of one direction of a TLS 1.2
/// CBC connection: the block cipher and the MAC key (wiped on drop).
pub struct RecordKey<C: CbcBlockCipher> {
    cipher: C,
    mac: MacKey,
    alg: MacAlgorithm,
    order: MacOrder,
}

impl<C: CbcBlockCipher> core::fmt::Debug for RecordKey<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordKey")
            .field("mac", &self.alg)
            .field("order", &self.order)
            .finish_non_exhaustive()
    }
}

/// `seq_num || type || version` followed by a big-endian 16-bit length.
fn header(seq: u64, content_type: u8, version: [u8; 2], len: usize) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(&seq.to_be_bytes());
    h[8] = content_type;
    h[9..11].copy_from_slice(&version);
    debug_assert!(len <= MAX_FRAGMENT_LEN);
    // Lengths are bounded by `MAX_FRAGMENT_LEN` < 2^16.
    #[allow(clippy::cast_possible_truncation)]
    {
        h[11..].copy_from_slice(&(len as u16).to_be_bytes());
    }
    h
}

/// Checks the CBC padding of the decrypted `plaintext` (content, then
/// `reserved` bytes of MAC, then padding and its length byte) in time
/// independent of the padding.
///
/// Returns whether the padding is well formed and the number of bytes to
/// strip from the end: `padding_length + 1` if well formed, else 0 (so a bad
/// padding still yields a well-defined MAC input).
///
/// The padding is well formed when `padding_length + 1 + reserved <=
/// plaintext.len()` and each of the `padding_length` bytes before the length
/// byte equals it. The loop always inspects the last `min(256,
/// plaintext.len())` bytes (a public bound) and decides with masks which of
/// them belong to the padding.
fn check_padding(plaintext: &[u8], reserved: usize) -> (Choice, u64) {
    let n = plaintext.len();
    debug_assert!(n > reserved);
    let pad = u64::from(plaintext[n - 1]);
    let mut good = !ct::lt_u64((n - reserved) as u64, pad + 1);
    for i in 0..n.min(MAX_PADDING) {
        let in_pad = ct::lt_u64(i as u64, pad + 1);
        let differs = !ct::eq_u64(u64::from(plaintext[n - 1 - i]), pad);
        good = good.and(!in_pad.and(differs));
    }
    (good, ct::select_u64(good, pad + 1, 0))
}

/// Copies the `out.len()`-byte MAC that ends `strip` bytes before the end
/// of `plaintext` into `out`, in time independent of `strip` (at most 256).
///
/// Every byte of the last `min(plaintext.len(), out.len() + 256)` bytes is
/// read once and OR-ed under a mask into position `(i - scan_start) %
/// out.len()` of a rotated copy; the secret rotation is then undone in
/// `log2(out.len())` passes that each conditionally rotate by a power of two
/// with [`ct::select_u8`] (BoringSSL's `EVP_tls_cbc_copy_mac`).
fn copy_mac(plaintext: &[u8], strip: u64, out: &mut [u8]) {
    let n = plaintext.len();
    let h = out.len();
    debug_assert!(n >= h && h <= MAX_MAC_LEN);
    let mac_end = n as u64 - strip;
    let mac_start = mac_end - h as u64;
    let scan_start = n - n.min(h + MAX_PADDING);
    let mut rotated = [0u8; MAX_MAC_LEN];
    let mut offset = 0u64;
    let mut started = Choice::FALSE;
    let mut j = 0;
    for (i, &byte) in plaintext.iter().enumerate().skip(scan_start) {
        if j >= h {
            j -= h;
        }
        let is_start = ct::eq_u64(i as u64, mac_start);
        started = started.or(is_start);
        let in_mac = started.and(ct::lt_u64(i as u64, mac_end));
        rotated[j] |= ct::select_u8(in_mac, byte, 0);
        offset |= is_start.mask() & j as u64;
        j += 1;
    }
    // Rotate left by `offset` (< h): one conditional rotation per bit.
    let mut tmp = [0u8; MAX_MAC_LEN];
    let mut step = 1;
    while step < h {
        let c = Choice::from_bit(offset & 1);
        for i in 0..h {
            let mut src = i + step;
            if src >= h {
                src -= h;
            }
            tmp[i] = ct::select_u8(c, rotated[src], rotated[i]);
        }
        rotated[..h].copy_from_slice(&tmp[..h]);
        step <<= 1;
        offset >>= 1;
    }
    out.copy_from_slice(&rotated[..h]);
    zeroize_bytes(&mut rotated);
    zeroize_bytes(&mut tmp);
}

/// Rounds `n` up to a multiple of the cipher block size.
const fn round_up(n: usize) -> usize {
    n.div_ceil(BLOCK) * BLOCK
}

impl<C: CbcBlockCipher> RecordKey<C> {
    /// Combines a block cipher with an HMAC key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] unless `mac_key.len() == mac.mac_len()` (the
    /// TLS 1.2 `mac_key_length`).
    pub fn new(
        cipher: C,
        mac: MacAlgorithm,
        mac_key: &[u8],
        order: MacOrder,
    ) -> Result<Self, Error> {
        if mac_key.len() != mac.mac_len() {
            return Err(Error::InvalidKey);
        }
        let key = match mac {
            MacAlgorithm::HmacSha1 => MacKey::Sha1(Keyed::new(mac_key)),
            MacAlgorithm::HmacSha256 => MacKey::Sha256(Keyed::new(mac_key)),
            MacAlgorithm::HmacSha384 => MacKey::Sha384(Keyed::new(mac_key)),
        };
        Ok(Self {
            cipher,
            mac: key,
            alg: mac,
            order,
        })
    }

    /// The MAC algorithm.
    #[must_use]
    pub fn mac_algorithm(&self) -> MacAlgorithm {
        self.alg
    }

    /// The MAC order.
    #[must_use]
    pub fn mac_order(&self) -> MacOrder {
        self.order
    }

    /// Tag length in bytes.
    #[must_use]
    pub fn mac_len(&self) -> usize {
        self.alg.mac_len()
    }

    /// Total fragment length (IV, ciphertext and, for encrypt-then-MAC, the
    /// MAC) that [`seal`](Self::seal) produces for `plaintext_len` bytes,
    /// using minimal padding.
    #[must_use]
    pub fn sealed_len(&self, plaintext_len: usize) -> usize {
        let h = self.mac_len();
        match self.order {
            MacOrder::MacThenEncrypt => IV_LEN + round_up(plaintext_len + h + 1),
            MacOrder::EncryptThenMac => IV_LEN + round_up(plaintext_len + 1) + h,
        }
    }

    /// Protects one record in place.
    ///
    /// `buf[16..16 + plaintext_len]` holds the plaintext and `buf.len()`
    /// must be at least [`sealed_len`](Self::sealed_len)`(plaintext_len)`.
    /// Writes `iv` to `buf[..16]`, then the protected record, and returns
    /// the fragment length. `iv` must be unpredictable (fresh random bytes
    /// for each record).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `plaintext_len` exceeds
    /// [`MAX_PLAINTEXT_LEN`] or `buf` is too short.
    pub fn seal(
        &self,
        seq: u64,
        content_type: u8,
        version: [u8; 2],
        iv: &[u8; 16],
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, Error> {
        if plaintext_len > MAX_PLAINTEXT_LEN {
            return Err(Error::InvalidLength);
        }
        let total = self.sealed_len(plaintext_len);
        let Some(buf) = buf.get_mut(..total) else {
            return Err(Error::InvalidLength);
        };
        let h = self.mac_len();
        buf[..IV_LEN].copy_from_slice(iv);
        let content_end = IV_LEN + plaintext_len;
        match self.order {
            MacOrder::MacThenEncrypt => {
                let hdr = header(seq, content_type, version, plaintext_len);
                let (head, tail) = buf.split_at_mut(content_end);
                with_key!(&self.mac, k => k.mac(&[&hdr, &head[IV_LEN..]], &mut tail[..h]));
                fill_padding(&mut tail[h..]);
                self.cipher.cbc_encrypt(iv, &mut buf[IV_LEN..]);
            }
            MacOrder::EncryptThenMac => {
                let enc_end = total - h;
                fill_padding(&mut buf[content_end..enc_end]);
                self.cipher.cbc_encrypt(iv, &mut buf[IV_LEN..enc_end]);
                let hdr = header(seq, content_type, version, enc_end);
                let (head, tag) = buf.split_at_mut(enc_end);
                with_key!(&self.mac, k => k.mac(&[&hdr, head], tag));
            }
        }
        Ok(total)
    }

    /// Opens one record in place.
    ///
    /// `buf` is the whole record fragment (`TLSCiphertext.fragment`). On
    /// success the plaintext is `buf[range]` for the returned range.
    ///
    /// # Errors
    ///
    /// [`Error::DecryptFailed`] for every failure: a public length that no
    /// sender could produce (shorter than an IV and one block, not
    /// block-aligned, too short for the MAC, or longer than
    /// [`MAX_FRAGMENT_LEN`]), a bad padding, a bad MAC, or a plaintext
    /// longer than [`MAX_PLAINTEXT_LEN`]. With MAC-then-encrypt, padding and
    /// MAC failures take the same time as success for a given fragment
    /// length. On failure `buf` is wiped.
    pub fn open(
        &self,
        seq: u64,
        content_type: u8,
        version: [u8; 2],
        buf: &mut [u8],
    ) -> Result<Range<usize>, Error> {
        let r = match self.order {
            MacOrder::MacThenEncrypt => self.open_mte(seq, content_type, version, buf),
            MacOrder::EncryptThenMac => self.open_etm(seq, content_type, version, buf),
        };
        match r {
            Some(range) if range.len() <= MAX_PLAINTEXT_LEN => Ok(range),
            _ => {
                zeroize_bytes(buf);
                Err(Error::DecryptFailed)
            }
        }
    }

    fn open_etm(
        &self,
        seq: u64,
        content_type: u8,
        version: [u8; 2],
        buf: &mut [u8],
    ) -> Option<Range<usize>> {
        let h = self.mac_len();
        let len = buf.len();
        if !(IV_LEN + BLOCK + h..=MAX_FRAGMENT_LEN).contains(&len)
            || !(len - h).is_multiple_of(BLOCK)
        {
            return None;
        }
        let enc_end = len - h;
        // Authenticate the public IV and ciphertext before decrypting.
        let hdr = header(seq, content_type, version, enc_end);
        let mut tag = [0u8; MAX_MAC_LEN];
        let (body, received) = buf.split_at_mut(enc_end);
        with_key!(&self.mac, k => k.mac(&[&hdr, body], &mut tag[..h]));
        if !ct::eq(&tag[..h], received) {
            return None;
        }
        let (iv, ciphertext) = body.split_at_mut(IV_LEN);
        let iv: &[u8; 16] = (&*iv).try_into().ok()?;
        self.cipher.cbc_decrypt(iv, ciphertext);
        // RFC 5246: the receiver MUST check the padding. It is authenticated
        // at this point, so its validity is not an oracle; the check is
        // constant time anyway.
        let (good, strip) = check_padding(ciphertext, 0);
        if !good.declassify() {
            return None;
        }
        let strip = usize::try_from(strip).ok()?;
        Some(IV_LEN..enc_end - strip)
    }

    fn open_mte(
        &self,
        seq: u64,
        content_type: u8,
        version: [u8; 2],
        buf: &mut [u8],
    ) -> Option<Range<usize>> {
        let h = self.mac_len();
        let len = buf.len();
        // Public checks: an IV, at least one block, block-aligned, room for
        // the MAC and the padding length byte, and the RFC 5246 bound.
        if !(IV_LEN + BLOCK..=MAX_FRAGMENT_LEN).contains(&len)
            || !(len - IV_LEN).is_multiple_of(BLOCK)
            || len - IV_LEN < h + 1
        {
            return None;
        }
        let (iv, plaintext) = buf.split_at_mut(IV_LEN);
        let iv: &[u8; 16] = (&*iv).try_into().ok()?;
        self.cipher.cbc_decrypt(iv, plaintext);
        let plaintext = &*plaintext;
        let n = plaintext.len();

        // Secret from here on: `strip` (padding length + 1, or 0 for a bad
        // padding), the content length `n - h - strip` and `good`.
        let (good, strip) = check_padding(plaintext, h);
        let content_len = n as u64 - h as u64 - strip;
        // Any admissible content length lies in
        // [n - h - 256, n - h] (clamped at 0).
        let min_len = (n - h).saturating_sub(MAX_PADDING);

        let mut hdr = [0u8; 11];
        hdr[..8].copy_from_slice(&seq.to_be_bytes());
        hdr[8] = content_type;
        hdr[9..].copy_from_slice(&version);
        let mut expected = [0u8; MAX_MAC_LEN];
        with_key!(&self.mac, k => k.ct_mac(
            &hdr,
            &plaintext[..n - h],
            content_len,
            min_len,
            &mut expected[..h],
        ));
        let mut received = [0u8; MAX_MAC_LEN];
        copy_mac(plaintext, strip, &mut received[..h]);
        let ok = good.and(ct::eq_bytes(&expected[..h], &received[..h]));
        zeroize_bytes(&mut expected);
        zeroize_bytes(&mut received);
        // The outcome is public; on success so is the content length.
        if !ok.declassify() {
            return None;
        }
        let content_len = usize::try_from(content_len).ok()?;
        Some(IV_LEN..IV_LEN + content_len)
    }
}

/// Fills `pad` (padding plus length byte, at most 256 bytes) with its
/// length minus one.
fn fill_padding(pad: &mut [u8]) {
    debug_assert!(!pad.is_empty() && pad.len() <= MAX_PADDING);
    // At most 256 bytes, so the value fits in a byte.
    #[allow(clippy::cast_possible_truncation)]
    let v = (pad.len() - 1) as u8;
    pad.fill(v);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac::Hmac;

    fn ct_mac_matches<H: MdHash>() {
        let key: std::vec::Vec<u8> = (0..H::OUTPUT_LEN).map(|i| i as u8 ^ 0x5a).collect();
        let keyed = Keyed::<H>::new(&key);
        let header = [1u8, 2, 3, 4, 5, 6, 7, 8, 23, 3, 3];
        let data: std::vec::Vec<u8> = (0..700u32).map(|i| (i * 13 + 7) as u8).collect();
        for max_len in [0usize, 1, 40, 50, 51, 52, 64, 115, 116, 128, 300, 400, 700] {
            let min_len = max_len.saturating_sub(MAX_PADDING);
            for len in min_len..=max_len {
                let mut got = [0u8; MAX_MAC_LEN];
                keyed.ct_mac(&header, &data[..max_len], len as u64, min_len, &mut got);
                let mut m = Hmac::<H>::new(&key);
                m.update(&header);
                m.update(&(len as u16).to_be_bytes());
                m.update(&data[..len]);
                let want = m.finalize();
                assert_eq!(
                    &got[..H::OUTPUT_LEN],
                    want.as_ref(),
                    "max {max_len} len {len}"
                );
                let mut plain = [0u8; MAX_MAC_LEN];
                keyed.mac(
                    &[&header, &(len as u16).to_be_bytes(), &data[..len]],
                    &mut plain,
                );
                assert_eq!(plain, got);
            }
        }
    }

    #[test]
    fn ct_mac_matches_hmac() {
        ct_mac_matches::<Sha1>();
        ct_mac_matches::<Sha256>();
        ct_mac_matches::<Sha384>();
    }

    #[test]
    fn padding_and_mac_extraction() {
        for h in [20usize, 32, 48] {
            for n in [h + 1, h + 16, 64, 300, 400] {
                if n <= h {
                    continue;
                }
                for pad in 0..=255usize {
                    let mut p: std::vec::Vec<u8> = (0..n).map(|i| (i * 7 + 1) as u8).collect();
                    let fits = pad + 1 + h <= n;
                    if fits {
                        p[n - 1 - pad..].fill(pad as u8);
                    } else {
                        p[n - 1] = pad as u8;
                    }
                    let (good, strip) = check_padding(&p, h);
                    assert_eq!(good.declassify(), fits, "h {h} n {n} pad {pad}");
                    let strip_u = usize::try_from(strip).unwrap();
                    assert_eq!(strip_u, if fits { pad + 1 } else { 0 });
                    let mut mac = [0u8; MAX_MAC_LEN];
                    copy_mac(&p, strip, &mut mac[..h]);
                    assert_eq!(mac[..h], p[n - strip_u - h..n - strip_u]);
                    if fits && pad > 0 {
                        // Corrupt each padding byte in turn.
                        for i in n - 1 - pad..n - 1 {
                            p[i] ^= 1;
                            assert!(!check_padding(&p, h).0.declassify());
                            p[i] ^= 1;
                        }
                    }
                }
            }
        }
    }
}
