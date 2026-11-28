//! The HPKE modes beyond base mode (RFC 9180 §5.1.2 to §5.1.4), for
//! applications. ECH uses base mode only, through [`Hpke`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use super::{EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer};
use crate::error::Error;

/// A pre-shared key `psk` and its identifier `psk_id`, for the PSK and
/// AuthPSK modes (RFC 9180 §5.1.2, §5.1.4).
///
/// The sender and the recipient need the same key and identifier. A
/// recipient with another one is not told so at setup: its first
/// [`HpkeOpener::open`] fails and its exports differ from the sender's.
///
/// The key must hold at least 32 bytes of entropy (RFC 9180 §9.5), such as
/// [`Self::MIN_KEY_LEN`] bytes from a cryptographic random generator. It
/// must not be a password or another low-entropy secret, however long:
/// HKDF does not slow guessing down, so an attacker who knows the KEM
/// shared secret (in PSK mode, anyone acting as a sender) and can tell a
/// right key from a wrong one, for example by whether the recipient opens a
/// message, can try candidate keys (§9.5). The constructor can only check
/// the length.
///
/// The key is zeroised on drop. The identifier is not secret: RFC 9180
/// does not protect it, and an application usually sends it to the
/// recipient in the clear. The [`Debug`](fmt::Debug) form shows neither.
#[derive(Clone)]
pub struct HpkePsk {
    key: Vec<u8>,
    id: Vec<u8>,
}

impl HpkePsk {
    /// The shortest key accepted, in bytes: the 32 bytes of entropy that
    /// RFC 9180 §9.5 requires (it recommends `Nh` bytes or more).
    pub const MIN_KEY_LEN: usize = 32;

    /// Pairs `key` with its identifier `id`.
    ///
    /// RFC 9180's `VerifyPSKInputs` requires both or neither; an `HpkePsk`
    /// always has both, and the modes without a PSK take none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::General`] if `key` is shorter than
    /// [`Self::MIN_KEY_LEN`] or `id` is empty. The rejected key is
    /// zeroised.
    pub fn new(key: Vec<u8>, id: Vec<u8>) -> Result<Self, Error> {
        // Built first, so that the key is zeroised on the error path too.
        let psk = Self { key, id };
        if psk.key.len() < Self::MIN_KEY_LEN {
            return Err(Error::general("HPKE PSK shorter than 32 bytes"));
        }
        if psk.id.is_empty() {
            return Err(Error::general("HPKE PSK identifier is empty"));
        }
        Ok(psk)
    }

    /// The identifier `psk_id`.
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// The key `psk`, for an [`HpkeModes`] implementation's key schedule.
    ///
    /// Keep no copy of it: read it once into the key schedule, as the
    /// native provider does.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for HpkePsk {
    fn drop(&mut self) {
        crate::crypto::zeroize_vec(&mut self.key);
    }
}

impl fmt::Debug for HpkePsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkePsk(..)")
    }
}

/// The mode of a sender setup (RFC 9180 §5.1) and its sender-side inputs.
///
/// What the recipient learns besides "only the holder of my private key can
/// read this" (which base mode gives):
///
/// * [`Psk`](Self::Psk): the sender held the pre-shared key.
/// * [`Auth`](Self::Auth): the sender held the private key of the public
///   key the recipient expects. Only that key pair is authenticated, not a
///   name: an application that binds messages to a sender identity puts it
///   in `info` (§5.1.3). The authentication does not survive the compromise
///   of the recipient's private key (key-compromise impersonation, §9.1.1):
///   whoever holds it can create messages that seem to come from any
///   sender. An application that must resist that signs the encapsulated
///   key and the ciphertext as well.
/// * [`AuthPsk`](Self::AuthPsk): both. Forging a message then takes the
///   recipient's private key and the pre-shared key (§9.1.1).
///
/// The proposed successor of RFC 9180, `draft-ietf-hpke-hpke-06`, no longer
/// specifies Auth and AuthPSK: it reserves their identifiers (`0x02`, `0x03`)
/// and does not deprecate them. ECH uses base mode only.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum HpkeSealMode<'a> {
    /// `mode_base` (§5.1.1): as [`Hpke::setup_sealer`].
    Base,
    /// `mode_psk` (§5.1.2) with this pre-shared key.
    Psk(&'a HpkePsk),
    /// `mode_auth` (§5.1.3) with the sender's private key.
    Auth(&'a HpkePrivateKey),
    /// `mode_auth_psk` (§5.1.4) with the pre-shared key and the sender's
    /// private key.
    AuthPsk(&'a HpkePsk, &'a HpkePrivateKey),
}

/// The mode of a recipient setup (RFC 9180 §5.1) and its recipient-side
/// inputs; it must match the sender's [`HpkeSealMode`].
///
/// [`HpkeSealMode`] says what each mode authenticates and what it does
/// not. A recipient whose mode, pre-shared key or sender public key differs
/// from the sender's is not told so at setup: its first
/// [`HpkeOpener::open`] fails and its exports differ from the sender's.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum HpkeOpenMode<'a> {
    /// `mode_base` (§5.1.1): as [`Hpke::setup_opener`].
    Base,
    /// `mode_psk` (§5.1.2) with this pre-shared key.
    Psk(&'a HpkePsk),
    /// `mode_auth` (§5.1.3) with the sender's public key.
    Auth(&'a HpkePublicKey),
    /// `mode_auth_psk` (§5.1.4) with the pre-shared key and the sender's
    /// public key.
    AuthPsk(&'a HpkePsk, &'a HpkePublicKey),
}

/// One HPKE suite in every mode of RFC 9180 §5.1, for applications.
///
/// It extends [`Hpke`], whose base-mode setups ECH keeps using; ECH never
/// calls these. The native provider implements it for every suite in
/// `native::hpke::ALL_SUPPORTED_SUITES_WITH_MODES`; the RustCrypto provider
/// has no HPKE. [`HpkeSealMode`] says what each mode authenticates, and why
/// the Auth modes do not resist key-compromise impersonation (§9.1.1).
///
/// Keys are serialized bytes read under this suite's KEM: a key of another
/// KEM fails the setup when its length differs, and is otherwise taken as a
/// key of this KEM. Among the native KEMs only private keys collide: a
/// 32-byte P-256 key reads as an X25519 key and the other way round.
///
/// The mode enums are `#[non_exhaustive]`: an implementation outside this
/// crate fails the setup for a mode it does not know.
pub trait HpkeModes: Hpke {
    /// `SetupBaseS`, `SetupPSKS`, `SetupAuthS` or `SetupAuthPSKS`
    /// (RFC 9180 §5.1), by `mode`: an encapsulated key and a sealing
    /// context. [`HpkeSealMode::Base`] is [`Hpke::setup_sealer`].
    ///
    /// # Errors
    ///
    /// Fails if `pub_key` or the sender's private key is invalid for the
    /// KEM, a Diffie-Hellman result is rejected, or randomness fails.
    fn setup_sealer_with_mode(
        &self,
        mode: HpkeSealMode<'_>,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error>;

    /// `SetupBaseR`, `SetupPSKR`, `SetupAuthR` or `SetupAuthPSKR`
    /// (RFC 9180 §5.1), by `mode`: an opening context.
    /// [`HpkeOpenMode::Base`] is [`Hpke::setup_opener`].
    ///
    /// # Errors
    ///
    /// Fails if `enc`, `secret_key` or the sender's public key is invalid
    /// for the KEM, or a Diffie-Hellman result is rejected. A wrong mode,
    /// pre-shared key or sender key is not an error here (see
    /// [`HpkeOpenMode`]).
    fn setup_opener_with_mode(
        &self,
        mode: HpkeOpenMode<'_>,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error>;
}
