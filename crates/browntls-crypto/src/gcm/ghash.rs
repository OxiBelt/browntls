//! GHASH on its own ([`Ghash`]): the universal hash of GCM (NIST SP 800-38D,
//! section 6.4) over the backends AES-GCM uses.

use super::{GhashBackend, GhashKey, soft};
use crate::zeroize::zeroize_bytes;

/// Length in bytes of a GHASH block, of the hash subkey `H` and of a GHASH
/// value: each is one 128-bit block (SP 800-38D, section 6.4).
pub const GHASH_BLOCK_LEN: usize = 16;

/// GHASH (NIST SP 800-38D, section 6.4), the universal hash over GF(2^128)
/// that authenticates AES-GCM, keyed by the hash subkey `H`.
///
/// It computes what the RustCrypto `ghash` crate's `GHash` computes, and is
/// to [`Aes128Gcm`](super::Aes128Gcm) and [`Aes256Gcm`](super::Aes256Gcm)
/// what [`Poly1305`](crate::chacha::Poly1305) is to ChaCha20-Poly1305.
///
/// # Input
///
/// A `Ghash` absorbs a byte string `X`, and [`finalize`](Self::finalize)
/// returns `GHASH_H(X)` with `X` zero-padded to whole blocks:
///
/// - [`update`](Self::update) appends bytes. It takes any length, any number
///   of times: a trailing partial block is kept in a 16-byte buffer until
///   later bytes complete it, so the value does not depend on how the input
///   is split between calls.
/// - [`update_blocks`](Self::update_blocks) appends whole blocks. From a new
///   `Ghash` (or one whose input so far is whole blocks), absorbing the
///   blocks `X_1 .. X_m` gives SP 800-38D's `GHASH_H(X_1 || .. || X_m)`; it
///   corresponds to the RustCrypto `UniversalHash::update`. It is `update` of
///   the same bytes: after an `update` that left a partial block, the blocks
///   continue that partial block.
/// - [`update_padded`](Self::update_padded) appends bytes and then zero bytes
///   up to the next multiple of 16 bytes of the whole input (none if it
///   already is one): GCM's padding of the additional data and of the
///   ciphertext. `update_padded(&[])` only pads, ending a run of `update`
///   calls on a block boundary.
/// - [`finalize`](Self::finalize) pads as `update_padded(&[])` does and
///   returns the value.
///
/// So `update(a)` followed by `update_padded(b)` equals `update_padded` of
/// `a || b`, and padding only ever happens in `update_padded` and
/// `finalize`.
///
/// # Security
///
/// GHASH is a building block, not a MAC. It is linear in its input: a value
/// computed under `H` for a known input tells whoever sees it about `H` (one
/// non-zero block `X` with value `Y` gives `H = Y / X`), and with `H` known
/// any value can be matched by other input. Keep `H` secret and mask every
/// value before it leaves your control, with a mask used only once (GCM
/// adds `E_K(J0)`, which differs for every nonce). This type checks nothing
/// about `H`: every 16-byte value is accepted, including the zero block,
/// under which every value is zero. Deriving `H` is the caller's business
/// (GCM uses `E_K(0^128)`).
///
/// The arithmetic is the AES-GCM code's and runs in time independent of `H`
/// and of the input bytes on every backend: masked integer multiplications
/// in the portable one, carry-less multiplication instructions (PCLMULQDQ,
/// VPCLMULQDQ, PMULL, Zvkg, Zvbc, Zbc/Zbkc), whose timing does not depend
/// on their operands, in the others; no table is indexed by secret data.
/// The time taken depends only on the input lengths and on how the input is
/// split between calls.
///
/// `H` as the backend stores it (with its precomputed powers), the
/// accumulator and the buffered partial block are zeroised when a `Ghash`
/// is dropped, which [`finalize`](Self::finalize) does. The caller's `H` and
/// the returned value are the caller's to wipe. Zeroisation is best effort,
/// as everywhere in this crate ([`crate::zeroize`]): copies the compiler
/// makes when the value is moved are not reached. [`Debug`] shows the backend
/// only.
///
/// There is no limit on the input length, and no input length makes a
/// method panic: GHASH itself has none. The limits on the lengths of the
/// additional data and the plaintext belong to GCM (the AES-GCM types
/// enforce them), as does the length block, which the caller builds.
///
/// # Backends
///
/// The backend is chosen when the value is created and kept for its
/// lifetime: [`new`](Self::new) takes the one the dispatcher selects under
/// the current GHASH policy ([`crate::accel`]), [`with_backend`](Self::with_backend)
/// the one named. Every backend computes the same function. A `Ghash` does
/// not take part in load-aware routing ([`crate::accel::load`]): unlike the
/// AES-GCM keys, it never hands work to another backend.
///
/// # Example
///
/// The AES-GCM tag is `GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 ||
/// [len(C)]_64) xor E_K(J0)` with `H = E_K(0^128)` (SP 800-38D, section 7.1):
///
/// ```
/// use browntls_crypto::aead::Aead as _;
/// use browntls_crypto::aes::Aes128;
/// use browntls_crypto::gcm::{Aes128Gcm, GHASH_BLOCK_LEN, Ghash};
///
/// let key = [0x42; 16];
/// let nonce = [7; 12];
/// let aad = b"header";
/// let mut ct = *b"some plaintext";
/// let tag = Aes128Gcm::new(&key)?.seal_in_place(&nonce, aad, &mut ct)?;
///
/// // H = E_K(0^128); J0 = nonce || 0^31 || 1 for a 96-bit nonce.
/// let aes = Aes128::new(&key);
/// let mut h = [0; GHASH_BLOCK_LEN];
/// aes.encrypt_block(&mut h);
/// let mut mask = [0; GHASH_BLOCK_LEN];
/// mask[..12].copy_from_slice(&nonce);
/// mask[15] = 1;
/// aes.encrypt_block(&mut mask);
///
/// let mut lengths = [0; GHASH_BLOCK_LEN];
/// lengths[..8].copy_from_slice(&(8 * aad.len() as u64).to_be_bytes());
/// lengths[8..].copy_from_slice(&(8 * ct.len() as u64).to_be_bytes());
///
/// let mut ghash = Ghash::new(&h);
/// ghash.update_padded(aad);
/// ghash.update_padded(&ct);
/// ghash.update_blocks(&[lengths]);
/// let mut s = ghash.finalize();
/// for (s, m) in s.iter_mut().zip(mask) {
///     *s ^= m;
/// }
/// assert_eq!(s, tag);
/// # Ok::<(), browntls_crypto::Error>(())
/// ```
pub struct Ghash {
    key: GhashKey,
    /// The accumulator `Y`.
    y: [u8; GHASH_BLOCK_LEN],
    /// Input bytes not absorbed yet: `buf[..buf_len]`, a partial block.
    buf: [u8; GHASH_BLOCK_LEN],
    /// Always below [`GHASH_BLOCK_LEN`].
    buf_len: usize,
}

impl core::fmt::Debug for Ghash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ghash")
            .field("backend", &self.backend())
            .finish_non_exhaustive()
    }
}

impl Ghash {
    /// Creates a GHASH instance keyed by the hash subkey `h`, on the backend
    /// the dispatcher selects under the current GHASH policy
    /// ([`GhashBackend::select`]).
    #[must_use]
    pub fn new(h: &[u8; GHASH_BLOCK_LEN]) -> Self {
        Self::with_backend(h, GhashBackend::select())
    }

    /// Like [`Ghash::new`] with an explicit backend (for tests and
    /// diagnostics; the GHASH policy does not apply); falls back to
    /// [`GhashBackend::Soft`] if `backend` is not available on this CPU.
    #[must_use]
    pub fn with_backend(h: &[u8; GHASH_BLOCK_LEN], backend: GhashBackend) -> Self {
        // `GhashKey::new` fails only for a backend this CPU cannot run.
        let key = GhashKey::new(h, backend).unwrap_or_else(|_| GhashKey::Soft(soft::Key::new(h)));
        Self {
            key,
            y: [0; GHASH_BLOCK_LEN],
            buf: [0; GHASH_BLOCK_LEN],
            buf_len: 0,
        }
    }

    /// The backend in use.
    #[must_use]
    pub fn backend(&self) -> GhashBackend {
        self.key.backend()
    }

    /// Appends `data` to the input, keeping a trailing partial block until
    /// later input completes it.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (GHASH_BLOCK_LEN - self.buf_len).min(data.len());
            let (head, rest) = data.split_at(take);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(head);
            self.buf_len += take;
            data = rest;
            if self.buf_len < GHASH_BLOCK_LEN {
                return;
            }
            self.key.update(&mut self.y, &self.buf);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<GHASH_BLOCK_LEN>();
        if !blocks.is_empty() {
            self.key.update(&mut self.y, blocks.as_flattened());
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    /// Appends whole blocks to the input: the same as [`Ghash::update`] of
    /// their bytes.
    pub fn update_blocks(&mut self, blocks: &[[u8; GHASH_BLOCK_LEN]]) {
        self.update(blocks.as_flattened());
    }

    /// Appends `data` to the input and then zero bytes up to the next block
    /// boundary of the whole input (none if it is on one).
    pub fn update_padded(&mut self, data: &[u8]) {
        self.update(data);
        self.pad();
    }

    /// Absorbs the buffered partial block, if any, padded with zeros.
    fn pad(&mut self) {
        if self.buf_len > 0 {
            self.buf[self.buf_len..].fill(0);
            self.key.update(&mut self.y, &self.buf);
            self.buf_len = 0;
        }
    }

    /// Returns `GHASH_H` of the input, zero-padded to a block boundary.
    #[must_use]
    pub fn finalize(mut self) -> [u8; GHASH_BLOCK_LEN] {
        self.pad();
        self.y
    }

    /// Wipes the accumulator and the buffer (the key wipes itself).
    fn wipe(&mut self) {
        zeroize_bytes(&mut self.y);
        zeroize_bytes(&mut self.buf);
        self.buf_len = 0;
    }
}

impl Drop for Ghash {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dropping wipes the accumulator and a buffered partial block.
    #[test]
    fn wipe_clears_accumulator_and_buffer() {
        let mut g = Ghash::with_backend(&[0x5a; 16], GhashBackend::Soft);
        g.update(&[0xa5; 21]);
        assert_ne!(g.y, [0; 16]);
        assert_eq!(g.buf_len, 5);
        assert_ne!(g.buf, [0; 16]);
        g.wipe();
        assert_eq!((g.y, g.buf, g.buf_len), ([0; 16], [0; 16], 0));
    }

    /// The buffer never holds a whole block, whatever the split.
    #[test]
    fn buffer_stays_partial() {
        let data = [7u8; 70];
        for first in 0..=data.len() {
            let mut g = Ghash::with_backend(&[3; 16], GhashBackend::Soft);
            let (a, b) = data.split_at(first);
            g.update(a);
            assert_eq!(g.buf_len, a.len() % 16);
            g.update(b);
            assert_eq!(g.buf_len, data.len() % 16);
            g.update_padded(&[]);
            assert_eq!(g.buf_len, 0);
        }
    }

    /// `Debug` names the backend and nothing else.
    #[test]
    fn debug_hides_key_and_state() {
        let mut g = Ghash::with_backend(&[0xab; 16], GhashBackend::Soft);
        g.update(&[0xcd; 20]);
        let s = std::format!("{g:?}");
        assert_eq!(s, "Ghash { backend: Soft, .. }");
    }
}
