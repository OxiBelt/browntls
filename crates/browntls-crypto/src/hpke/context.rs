//! The key schedule and encryption contexts (RFC 9180 §5.1, §5.2, §5.3).

use super::labeled::{Secret, labeled_expand, labeled_extract};
use super::modes::{Mode, Psk};
use super::{Aead, MAX_SECRET_LEN, NONCE_LEN, Suite, TAG_LEN};
use crate::Error;
use crate::aead::Aead as _;
use crate::chacha::ChaCha20Poly1305;
use crate::gcm::{Aes128Gcm, Aes256Gcm};
use crate::zeroize::{Zeroizing, zeroize_bytes};

enum AeadKey {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
    ExportOnly,
}

pub(super) struct Context {
    suite: Suite,
    mode: Mode,
    aead: AeadKey,
    base_nonce: [u8; NONCE_LEN],
    seq: u64,
    exporter_secret: Secret,
}

impl Drop for Context {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.base_nonce);
    }
}

/// `KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id)`, where an
/// absent `psk` stands for `default_psk` and `default_psk_id` (both "").
///
/// `VerifyPSKInputs` holds by construction: a [`Psk`] always carries a
/// non-empty key and identifier, so the inputs are either both present or
/// both absent, and this function checks that they are present exactly for
/// the modes that take a PSK.
pub(super) fn key_schedule(
    suite: Suite,
    mode: Mode,
    shared_secret: &Secret,
    info: &[u8],
    psk: Option<&Psk<'_>>,
) -> Result<Context, Error> {
    // The callers derive `mode` from the same inputs, so this cannot fail
    // today; it guards a future caller against a PSK that is silently left
    // out of, or added to, the key schedule.
    if mode.uses_psk() != psk.is_some() {
        return Err(Error::Unsupported);
    }
    let (psk, psk_id) = psk.map_or((&b""[..], &b""[..]), |p| (p.key(), p.id()));
    let kdf = suite.kdf;
    let sid = suite.suite_id();
    let psk_id_hash = labeled_extract(kdf, &sid, b"", b"psk_id_hash", psk_id);
    let info_hash = labeled_extract(kdf, &sid, b"", b"info_hash", info);
    let mut ks_context = [0u8; 1 + 2 * MAX_SECRET_LEN];
    let nh = kdf.output_len();
    ks_context[0] = mode.id();
    ks_context[1..=nh].copy_from_slice(psk_id_hash.as_bytes());
    ks_context[1 + nh..=2 * nh].copy_from_slice(info_hash.as_bytes());
    let ks_context = &ks_context[..=2 * nh];

    let secret = labeled_extract(kdf, &sid, shared_secret.as_bytes(), b"secret", psk);
    let prk = secret.as_bytes();

    let mut key = Zeroizing([0u8; 32]);
    let key = &mut key[..suite.aead.key_len()];
    labeled_expand(kdf, &sid, prk, b"key", (ks_context, b""), key)?;
    let aead = match suite.aead {
        Aead::Aes128Gcm => AeadKey::Aes128Gcm(Aes128Gcm::new(key)?),
        Aead::Aes256Gcm => AeadKey::Aes256Gcm(Aes256Gcm::new(key)?),
        Aead::ChaCha20Poly1305 => AeadKey::ChaCha20Poly1305(ChaCha20Poly1305::new(key)?),
        Aead::ExportOnly => AeadKey::ExportOnly,
    };

    let mut base_nonce = [0u8; NONCE_LEN];
    if suite.aead != Aead::ExportOnly {
        labeled_expand(
            kdf,
            &sid,
            prk,
            b"base_nonce",
            (ks_context, b""),
            &mut base_nonce,
        )?;
    }

    let mut exporter_secret = Secret::zeroed(nh);
    labeled_expand(
        kdf,
        &sid,
        prk,
        b"exp",
        (ks_context, b""),
        exporter_secret.as_mut_bytes(),
    )?;

    Ok(Context {
        suite,
        mode,
        aead,
        base_nonce,
        seq: 0,
        exporter_secret,
    })
}

impl Context {
    /// `ComputeNonce(seq)`, failing once the sequence number is exhausted.
    ///
    /// The counter is a `u64`, so the limit is 2^64 - 1 messages rather than
    /// RFC 9180's 2^96 - 1; neither is reachable in practice.
    fn nonce(&self) -> Result<[u8; NONCE_LEN], Error> {
        if self.seq == u64::MAX {
            return Err(Error::InvalidLength);
        }
        let mut nonce = self.base_nonce;
        for (n, s) in nonce[NONCE_LEN - 8..]
            .iter_mut()
            .zip(self.seq.to_be_bytes())
        {
            *n ^= s;
        }
        Ok(nonce)
    }

    fn seal_in_place(&mut self, aad: &[u8], in_out: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        let nonce = self.nonce()?;
        let tag = match &self.aead {
            AeadKey::Aes128Gcm(k) => k.seal_in_place(&nonce, aad, in_out)?,
            AeadKey::Aes256Gcm(k) => k.seal_in_place(&nonce, aad, in_out)?,
            AeadKey::ChaCha20Poly1305(k) => k.seal_in_place(&nonce, aad, in_out)?,
            AeadKey::ExportOnly => return Err(Error::Unsupported),
        };
        self.seq += 1;
        Ok(tag)
    }

    fn open_in_place(
        &mut self,
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        let nonce = self.nonce()?;
        match &self.aead {
            AeadKey::Aes128Gcm(k) => k.open_in_place(&nonce, aad, in_out, tag)?,
            AeadKey::Aes256Gcm(k) => k.open_in_place(&nonce, aad, in_out, tag)?,
            AeadKey::ChaCha20Poly1305(k) => k.open_in_place(&nonce, aad, in_out, tag)?,
            AeadKey::ExportOnly => return Err(Error::Unsupported),
        }
        // RFC 9180 §5.2: the sequence number advances only on success.
        self.seq += 1;
        Ok(())
    }

    fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        labeled_expand(
            self.suite.kdf,
            &self.suite.suite_id(),
            self.exporter_secret.as_bytes(),
            b"sec",
            (exporter_context, b""),
            out,
        )
    }
}

macro_rules! common_methods {
    () => {
        /// The suite this context was set up with.
        #[must_use]
        pub fn suite(&self) -> Suite {
            self.0.suite
        }

        /// The mode this context was set up in.
        #[must_use]
        pub fn mode(&self) -> Mode {
            self.0.mode
        }

        /// The number of messages processed so far (the next sequence number).
        #[must_use]
        pub fn sequence_number(&self) -> u64 {
            self.0.seq
        }

        /// `Context.Export(exporter_context, L)` (RFC 9180 §5.3) with
        /// `L = out.len()`.
        ///
        /// # Errors
        ///
        /// Returns [`Error::InvalidLength`] if `L` exceeds `255 * Nh`.
        pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), Error> {
            self.0.export(exporter_context, out)
        }
    };
}

/// The sender's encryption context (`ContextS`).
pub struct SenderContext(pub(super) Context);

impl SenderContext {
    common_methods!();

    /// `ContextS.Seal(aad, pt)`: encrypts `in_out` in place and returns the
    /// tag. The ciphertext is `in_out || tag`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] for an export-only suite, or
    /// [`Error::InvalidLength`] if the message or sequence number is too
    /// large. A failed call leaves the sequence number unchanged.
    pub fn seal_in_place(&mut self, aad: &[u8], in_out: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        self.0.seal_in_place(aad, in_out)
    }

    /// `ContextS.Seal(aad, pt)`, returning `ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// As [`SenderContext::seal_in_place`].
    #[cfg(feature = "alloc")]
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
        let mut out = alloc::vec::Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        let tag = self.seal_in_place(aad, &mut out)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

impl core::fmt::Debug for SenderContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SenderContext")
            .field("suite", &self.0.suite)
            .field("mode", &self.0.mode)
            .field("seq", &self.0.seq)
            .finish_non_exhaustive()
    }
}

/// The recipient's decryption context (`ContextR`).
pub struct RecipientContext(pub(super) Context);

impl RecipientContext {
    common_methods!();

    /// `ContextR.Open(aad, ct)`: verifies `tag` and decrypts `in_out` in
    /// place. On failure `in_out` is zeroed and the sequence number is
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptFailed`] if authentication fails,
    /// [`Error::Unsupported`] for an export-only suite, or
    /// [`Error::InvalidLength`].
    pub fn open_in_place(
        &mut self,
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        self.0.open_in_place(aad, in_out, tag)
    }

    /// `ContextR.Open(aad, ct)` on `ciphertext || tag`, returning the
    /// plaintext.
    ///
    /// # Errors
    ///
    /// As [`RecipientContext::open_in_place`]; a ciphertext shorter than a
    /// tag fails with [`Error::DecryptFailed`].
    #[cfg(feature = "alloc")]
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
        let split = ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptFailed)?;
        let (ct, tag) = ciphertext.split_at(split);
        let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| Error::DecryptFailed)?;
        let mut out = alloc::vec::Vec::from(ct);
        self.open_in_place(aad, &mut out, tag)?;
        Ok(out)
    }
}

impl core::fmt::Debug for RecipientContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecipientContext")
            .field("suite", &self.0.suite)
            .field("mode", &self.0.mode)
            .field("seq", &self.0.seq)
            .finish_non_exhaustive()
    }
}
