//! The HPKE modes (RFC 9180 §5.1) and the pre-shared key of the PSK modes
//! (§5.1.2, §5.1.4).

use super::{EncapsulatedKey, PrivateKey, PublicKey, RecipientContext, SenderContext, Suite};
use crate::Error;
use crate::rand::SecureRandom;

/// Shortest pre-shared key [`Psk::new`] accepts, in bytes.
///
/// RFC 9180 §5.1.2 and §9.5 require a PSK with at least 32 bytes of entropy
/// and recommend `Nh` bytes or more. Entropy cannot be measured, so this
/// length is a floor and not a guarantee: a password or other low-entropy
/// secret is unsuitable however long it is, since HKDF does not slow down a
/// dictionary attack (§9.5).
pub const MIN_PSK_LEN: usize = 32;

/// An HPKE mode (RFC 9180 §5, Table 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mode {
    /// `mode_base`, `0x00`: encryption to a public key (§5.1.1).
    Base,
    /// `mode_psk`, `0x01`: the recipient also learns that the sender held a
    /// pre-shared key (§5.1.2).
    Psk,
    /// `mode_auth`, `0x02`: the recipient also learns that the sender held
    /// the private key of a given public key (§5.1.3).
    Auth,
    /// `mode_auth_psk`, `0x03`: both of the above (§5.1.4).
    AuthPsk,
}

impl Mode {
    /// Every implemented mode.
    pub const ALL: [Self; 4] = [Self::Base, Self::Psk, Self::Auth, Self::AuthPsk];

    /// The one-byte mode identifier of the key schedule.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Base => 0x00,
            Self::Psk => 0x01,
            Self::Auth => 0x02,
            Self::AuthPsk => 0x03,
        }
    }

    /// Looks up a mode by its identifier.
    #[must_use]
    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.id() == id)
    }

    /// Whether the mode takes a pre-shared key.
    #[must_use]
    pub const fn uses_psk(self) -> bool {
        matches!(self, Self::Psk | Self::AuthPsk)
    }

    /// Whether the mode authenticates the sender's KEM key pair.
    #[must_use]
    pub const fn uses_sender_key(self) -> bool {
        matches!(self, Self::Auth | Self::AuthPsk)
    }

    /// The mode that takes a PSK if `psk` and a sender key if `sender_key`.
    pub(super) const fn of(psk: bool, sender_key: bool) -> Self {
        match (psk, sender_key) {
            (false, false) => Self::Base,
            (true, false) => Self::Psk,
            (false, true) => Self::Auth,
            (true, true) => Self::AuthPsk,
        }
    }
}

/// A pre-shared key `psk` and its identifier `psk_id` (RFC 9180 §5.1.2).
///
/// It borrows both from the caller, who owns the key, keeps it secret and
/// zeroises it: the setup functions read it once, into the key schedule, and
/// keep no copy. The identifier is not secret; RFC 9180 does not protect it
/// and an application usually sends it to the recipient in the clear. The
/// [`Debug`](core::fmt::Debug) form shows neither.
#[derive(Clone, Copy)]
pub struct Psk<'a> {
    key: &'a [u8],
    id: &'a [u8],
}

impl<'a> Psk<'a> {
    /// Pairs a key with its identifier.
    ///
    /// RFC 9180's `VerifyPSKInputs` requires both or neither. A `Psk` always
    /// has both, and the modes without a PSK take none, so the check holds by
    /// construction.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `key` is shorter than
    /// [`MIN_PSK_LEN`] or `id` is empty.
    pub fn new(key: &'a [u8], id: &'a [u8]) -> Result<Self, Error> {
        if key.len() < MIN_PSK_LEN || id.is_empty() {
            return Err(Error::InvalidLength);
        }
        Ok(Self { key, id })
    }

    /// The identifier `psk_id`.
    #[must_use]
    pub fn id(&self) -> &'a [u8] {
        self.id
    }

    /// The key `psk`: for the key schedule only.
    pub(super) fn key(&self) -> &'a [u8] {
        self.key
    }
}

impl core::fmt::Debug for Psk<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Psk(..)")
    }
}

impl Suite {
    /// `SetupPSKS(pkR, info, psk, psk_id)` (RFC 9180 §5.1.2): as
    /// [`Suite::setup_sender`], with `psk` in the key schedule, so that only
    /// a recipient holding the same key and identifier can open what the
    /// context seals or export what it exports.
    ///
    /// # Errors
    ///
    /// As [`Suite::setup_sender`].
    pub fn setup_sender_psk(
        self,
        pk_r: &PublicKey,
        info: &[u8],
        psk: &Psk<'_>,
        rng: &dyn SecureRandom,
    ) -> Result<(EncapsulatedKey, SenderContext), Error> {
        let ephemeral = self.kem.generate_key_pair(rng)?;
        self.setup_sender_with_ephemeral(pk_r, info, &ephemeral, Some(psk), None, None)
    }

    /// `SetupPSKR(enc, skR, info, psk, psk_id)` (RFC 9180 §5.1.2).
    ///
    /// A wrong key or identifier is not detected here: the setup succeeds
    /// and the context's first `open` fails, and its exports differ from the
    /// sender's.
    ///
    /// # Errors
    ///
    /// As [`Suite::setup_recipient`].
    pub fn setup_recipient_psk(
        self,
        enc: &[u8],
        sk_r: &PrivateKey,
        info: &[u8],
        psk: &Psk<'_>,
    ) -> Result<RecipientContext, Error> {
        self.setup_recipient_capturing(enc, sk_r, info, Some(psk), None, None)
    }

    /// `SetupAuthS(pkR, info, skS)` (RFC 9180 §5.1.3): as
    /// [`Suite::setup_sender`], with `AuthEncap`, so that the recipient can
    /// tell that the sender held `sk_s`.
    ///
    /// Only the key pair is authenticated, not a name: an application that
    /// binds messages to a sender identity (an address, a domain) puts it in
    /// `info` (§5.1.3). The recipient's private key suffices to forge such
    /// messages (key-compromise impersonation, §9.1.1); an application that
    /// must resist that signs `enc` and the ciphertext as well.
    ///
    /// # Errors
    ///
    /// As [`Suite::setup_sender`]; also [`Error::InvalidKey`] if `sk_s`
    /// belongs to another KEM, and [`Error::KeyAgreementFailed`] if either
    /// Diffie-Hellman result is rejected.
    pub fn setup_sender_auth(
        self,
        pk_r: &PublicKey,
        info: &[u8],
        sk_s: &PrivateKey,
        rng: &dyn SecureRandom,
    ) -> Result<(EncapsulatedKey, SenderContext), Error> {
        let ephemeral = self.kem.generate_key_pair(rng)?;
        self.setup_sender_with_ephemeral(pk_r, info, &ephemeral, None, Some(sk_s), None)
    }

    /// `SetupAuthR(enc, skR, info, pkS)` (RFC 9180 §5.1.3): `AuthDecap` with
    /// the sender's public key `pk_s`.
    ///
    /// A message from another sender is not detected here: the setup
    /// succeeds and the context's first `open` fails, and its exports
    /// differ from the sender's. Read [`Suite::setup_sender_auth`] for what
    /// the authentication covers.
    ///
    /// # Errors
    ///
    /// As [`Suite::setup_recipient`]; also [`Error::InvalidKey`] if `pk_s`
    /// belongs to another KEM, and [`Error::KeyAgreementFailed`] if either
    /// Diffie-Hellman result is rejected.
    pub fn setup_recipient_auth(
        self,
        enc: &[u8],
        sk_r: &PrivateKey,
        info: &[u8],
        pk_s: &PublicKey,
    ) -> Result<RecipientContext, Error> {
        self.setup_recipient_capturing(enc, sk_r, info, None, Some(pk_s), None)
    }

    /// `SetupAuthPSKS(pkR, info, psk, psk_id, skS)` (RFC 9180 §5.1.4): the
    /// authenticated mode of [`Suite::setup_sender_auth`] with the
    /// pre-shared key of [`Suite::setup_sender_psk`]. Forging a message then
    /// takes both the recipient's private key and the PSK (§9.1.1).
    ///
    /// # Errors
    ///
    /// As [`Suite::setup_sender_auth`].
    pub fn setup_sender_auth_psk(
        self,
        pk_r: &PublicKey,
        info: &[u8],
        psk: &Psk<'_>,
        sk_s: &PrivateKey,
        rng: &dyn SecureRandom,
    ) -> Result<(EncapsulatedKey, SenderContext), Error> {
        let ephemeral = self.kem.generate_key_pair(rng)?;
        self.setup_sender_with_ephemeral(pk_r, info, &ephemeral, Some(psk), Some(sk_s), None)
    }

    /// `SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS)` (RFC 9180 §5.1.4).
    /// A wrong PSK or sender key is found at the first `open`, as for
    /// [`Suite::setup_recipient_psk`] and [`Suite::setup_recipient_auth`].
    ///
    /// # Errors
    ///
    /// As [`Suite::setup_recipient_auth`].
    pub fn setup_recipient_auth_psk(
        self,
        enc: &[u8],
        sk_r: &PrivateKey,
        info: &[u8],
        psk: &Psk<'_>,
        pk_s: &PublicKey,
    ) -> Result<RecipientContext, Error> {
        self.setup_recipient_capturing(enc, sk_r, info, Some(psk), Some(pk_s), None)
    }
}
