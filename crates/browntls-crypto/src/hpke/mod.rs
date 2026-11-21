//! Hybrid Public Key Encryption (RFC 9180), base mode.
//!
//! A [`Suite`] names a KEM, a KDF and an AEAD by their IANA identifiers.
//! [`Suite::setup_sender`] encapsulates to a recipient public key and returns
//! the encapsulated key together with a [`SenderContext`];
//! [`Suite::setup_recipient`] decapsulates it with the matching [`PrivateKey`]
//! and returns a [`RecipientContext`]. Both contexts encrypt with
//! sequence-numbered nonces (RFC 9180 §5.2) and derive exported secrets
//! (§5.3).
//!
//! Supported algorithms:
//!
//! | Role | Algorithms |
//! |---|---|
//! | KEM | DHKEM(P-256, HKDF-SHA256), DHKEM(P-384, HKDF-SHA384), DHKEM(P-521, HKDF-SHA512), DHKEM(X25519, HKDF-SHA256), DHKEM(X448, HKDF-SHA512) |
//! | KDF | HKDF-SHA256, HKDF-SHA384, HKDF-SHA512 |
//! | AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, export-only |
//!
//! Only `mode_base` (RFC 9180 §5.1.1) is implemented. The PSK and
//! authenticated modes are not: Encrypted Client Hello (RFC 9849), the user
//! of this module in browntls, needs base mode only.
//!
//! The module is allocation-free: encapsulated keys, public keys and secrets
//! live in fixed-size buffers, and the AEAD operates in place.

mod ber;
mod context;
mod kem;
mod labeled;
mod pkcs8;
#[cfg(all(test, feature = "alloc"))]
mod tests;

pub use context::{RecipientContext, SenderContext};
pub use kem::{EncapsulatedKey, PrivateKey, PublicKey};
pub use pkcs8::MAX_PKCS8_DER_LEN;

use crate::Error;
use crate::rand::SecureRandom;

/// Largest encapsulated key (`Nenc`) of any supported KEM (P-521: 133 bytes).
pub const MAX_ENC_LEN: usize = 133;
/// Largest serialized public key (`Npk`) of any supported KEM.
pub const MAX_PUBLIC_KEY_LEN: usize = 133;
/// Largest serialized private key (`Nsk`) of any supported KEM.
pub const MAX_PRIVATE_KEY_LEN: usize = 66;
/// Largest KEM shared secret (`Nsecret`) or KDF output (`Nh`).
pub(crate) const MAX_SECRET_LEN: usize = 64;
/// AEAD nonce length (`Nn`) of every supported AEAD.
pub const NONCE_LEN: usize = 12;
/// AEAD tag length (`Nt`) of every supported AEAD.
pub const TAG_LEN: usize = 16;

/// A key encapsulation mechanism (RFC 9180 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kem {
    /// DHKEM(P-256, HKDF-SHA256), `0x0010`.
    DhP256HkdfSha256,
    /// DHKEM(P-384, HKDF-SHA384), `0x0011`.
    DhP384HkdfSha384,
    /// DHKEM(P-521, HKDF-SHA512), `0x0012`.
    DhP521HkdfSha512,
    /// DHKEM(X25519, HKDF-SHA256), `0x0020`.
    DhX25519HkdfSha256,
    /// DHKEM(X448, HKDF-SHA512), `0x0021`.
    DhX448HkdfSha512,
}

impl Kem {
    /// Every supported KEM.
    pub const ALL: [Self; 5] = [
        Self::DhP256HkdfSha256,
        Self::DhP384HkdfSha384,
        Self::DhP521HkdfSha512,
        Self::DhX25519HkdfSha256,
        Self::DhX448HkdfSha512,
    ];

    /// The IANA `HPKE KEM Identifier`.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::DhP256HkdfSha256 => 0x0010,
            Self::DhP384HkdfSha384 => 0x0011,
            Self::DhP521HkdfSha512 => 0x0012,
            Self::DhX25519HkdfSha256 => 0x0020,
            Self::DhX448HkdfSha512 => 0x0021,
        }
    }

    /// Looks up a KEM by its IANA identifier.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.id() == id)
    }

    /// Length of a serialized public key (`Npk`), which equals `Nenc`.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::DhP256HkdfSha256 => 65,
            Self::DhP384HkdfSha384 => 97,
            Self::DhP521HkdfSha512 => 133,
            Self::DhX25519HkdfSha256 => 32,
            Self::DhX448HkdfSha512 => 56,
        }
    }

    /// Length of an encapsulated key (`Nenc`).
    #[must_use]
    pub const fn enc_len(self) -> usize {
        self.public_key_len()
    }

    /// Length of a serialized private key (`Nsk`).
    #[must_use]
    pub const fn private_key_len(self) -> usize {
        match self {
            Self::DhP256HkdfSha256 | Self::DhX25519HkdfSha256 => 32,
            Self::DhP384HkdfSha384 => 48,
            Self::DhP521HkdfSha512 => 66,
            Self::DhX448HkdfSha512 => 56,
        }
    }

    /// Length of the KEM shared secret (`Nsecret`).
    #[must_use]
    pub const fn shared_secret_len(self) -> usize {
        self.kdf().output_len()
    }

    /// The KDF that the DHKEM uses internally.
    #[must_use]
    pub const fn kdf(self) -> Kdf {
        match self {
            Self::DhP256HkdfSha256 | Self::DhX25519HkdfSha256 => Kdf::HkdfSha256,
            Self::DhP384HkdfSha384 => Kdf::HkdfSha384,
            Self::DhP521HkdfSha512 | Self::DhX448HkdfSha512 => Kdf::HkdfSha512,
        }
    }

    /// `DeriveKeyPair(ikm)` (RFC 9180 §7.1.3): derives a key pair
    /// deterministically from input keying material.
    ///
    /// `ikm` must be at least `Nsk` bytes long and should hold that much
    /// entropy (RFC 9180 §7.1.3).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `ikm` is shorter than `Nsk`, or
    /// [`Error::InvalidKey`] if no valid NIST scalar is found within 256
    /// candidates (probability below 2^-200 for honest input).
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<PrivateKey, Error> {
        if ikm.len() < self.private_key_len() {
            return Err(Error::InvalidLength);
        }
        kem::derive_key_pair(self, ikm)
    }

    /// `GenerateKeyPair()`: a fresh random key pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomFailure`] if `rng` fails.
    pub fn generate_key_pair(self, rng: &dyn SecureRandom) -> Result<PrivateKey, Error> {
        let mut ikm = crate::zeroize::Zeroizing([0u8; MAX_PRIVATE_KEY_LEN]);
        let ikm = &mut ikm[..self.private_key_len()];
        rng.fill(ikm)?;
        kem::derive_key_pair(self, ikm)
    }
}

/// A key derivation function (RFC 9180 §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kdf {
    /// HKDF-SHA256, `0x0001`.
    HkdfSha256,
    /// HKDF-SHA384, `0x0002`.
    HkdfSha384,
    /// HKDF-SHA512, `0x0003`.
    HkdfSha512,
}

impl Kdf {
    /// Every supported KDF.
    pub const ALL: [Self; 3] = [Self::HkdfSha256, Self::HkdfSha384, Self::HkdfSha512];

    /// The IANA `HPKE KDF Identifier`.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::HkdfSha256 => 0x0001,
            Self::HkdfSha384 => 0x0002,
            Self::HkdfSha512 => 0x0003,
        }
    }

    /// Looks up a KDF by its IANA identifier.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.id() == id)
    }

    /// Output length of the underlying hash (`Nh`).
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::HkdfSha256 => 32,
            Self::HkdfSha384 => 48,
            Self::HkdfSha512 => 64,
        }
    }
}

/// An AEAD algorithm (RFC 9180 §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Aead {
    /// AES-128-GCM, `0x0001`.
    Aes128Gcm,
    /// AES-256-GCM, `0x0002`.
    Aes256Gcm,
    /// ChaCha20-Poly1305, `0x0003`.
    ChaCha20Poly1305,
    /// Export-only, `0xFFFF`: contexts can export secrets but not encrypt.
    ExportOnly,
}

impl Aead {
    /// Every supported AEAD identifier.
    pub const ALL: [Self; 4] = [
        Self::Aes128Gcm,
        Self::Aes256Gcm,
        Self::ChaCha20Poly1305,
        Self::ExportOnly,
    ];

    /// The IANA `HPKE AEAD Identifier`.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
            Self::ChaCha20Poly1305 => 0x0003,
            Self::ExportOnly => 0xffff,
        }
    }

    /// Looks up an AEAD by its IANA identifier.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.id() == id)
    }

    /// Key length (`Nk`); zero for export-only.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            Self::ExportOnly => 0,
        }
    }

    /// Nonce length (`Nn`); zero for export-only.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::ExportOnly => 0,
            _ => NONCE_LEN,
        }
    }

    /// Tag length (`Nt`); zero for export-only.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::ExportOnly => 0,
            _ => TAG_LEN,
        }
    }
}

/// An HPKE ciphersuite: one KEM, one KDF and one AEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Suite {
    /// The key encapsulation mechanism.
    pub kem: Kem,
    /// The key schedule KDF.
    pub kdf: Kdf,
    /// The AEAD.
    pub aead: Aead,
}

impl Suite {
    /// Bundles three algorithms into a suite.
    #[must_use]
    pub const fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Self {
        Self { kem, kdf, aead }
    }

    /// Looks up a suite by its three IANA identifiers.
    #[must_use]
    pub fn from_ids(kem: u16, kdf: u16, aead: u16) -> Option<Self> {
        Some(Self::new(
            Kem::from_id(kem)?,
            Kdf::from_id(kdf)?,
            Aead::from_id(aead)?,
        ))
    }

    /// The `suite_id` used by the key schedule: `"HPKE" || kem || kdf || aead`.
    pub(crate) fn suite_id(self) -> [u8; 10] {
        let [k0, k1] = self.kem.id().to_be_bytes();
        let [f0, f1] = self.kdf.id().to_be_bytes();
        let [a0, a1] = self.aead.id().to_be_bytes();
        [b'H', b'P', b'K', b'E', k0, k1, f0, f1, a0, a1]
    }

    /// `SetupBaseS(pkR, info)` (RFC 9180 §5.1.1): encapsulates a fresh shared
    /// secret to `pk_r` and returns the encapsulated key `enc`, to send to
    /// the recipient, and the sender's encryption context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `pk_r` is not a valid public key for
    /// the suite's KEM, [`Error::KeyAgreementFailed`] if the Diffie-Hellman
    /// result is rejected, or [`Error::RandomFailure`].
    pub fn setup_sender(
        self,
        pk_r: &PublicKey,
        info: &[u8],
        rng: &dyn SecureRandom,
    ) -> Result<(EncapsulatedKey, SenderContext), Error> {
        let ephemeral = self.kem.generate_key_pair(rng)?;
        self.setup_sender_with_ephemeral(pk_r, info, &ephemeral)
    }

    /// `SetupBaseS` with the ephemeral key derived from `ikm_e` through
    /// `DeriveKeyPair` (as RFC 9180's test vectors do). Test-only: a reused
    /// `ikm_e` would reuse the ephemeral key.
    #[cfg(all(test, feature = "alloc"))]
    pub(crate) fn setup_sender_derandomized(
        self,
        pk_r: &PublicKey,
        info: &[u8],
        ikm_e: &[u8],
    ) -> Result<(EncapsulatedKey, SenderContext), Error> {
        let ephemeral = self.kem.derive_key_pair(ikm_e)?;
        self.setup_sender_with_ephemeral(pk_r, info, &ephemeral)
    }

    fn setup_sender_with_ephemeral(
        self,
        pk_r: &PublicKey,
        info: &[u8],
        ephemeral: &PrivateKey,
    ) -> Result<(EncapsulatedKey, SenderContext), Error> {
        if pk_r.kem() != self.kem || ephemeral.kem() != self.kem {
            return Err(Error::InvalidKey);
        }
        let (enc, shared_secret) = kem::encap(ephemeral, pk_r)?;
        let ctx = context::key_schedule(self, &shared_secret, info)?;
        Ok((enc, SenderContext(ctx)))
    }

    /// `SetupBaseR(enc, skR, info)` (RFC 9180 §5.1.1): decapsulates `enc`
    /// with `sk_r` and returns the recipient's decryption context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `enc` is malformed or `sk_r` belongs
    /// to another KEM, or [`Error::KeyAgreementFailed`] if the
    /// Diffie-Hellman result is rejected.
    pub fn setup_recipient(
        self,
        enc: &[u8],
        sk_r: &PrivateKey,
        info: &[u8],
    ) -> Result<RecipientContext, Error> {
        if sk_r.kem() != self.kem {
            return Err(Error::InvalidKey);
        }
        let shared_secret = kem::decap(enc, sk_r)?;
        let ctx = context::key_schedule(self, &shared_secret, info)?;
        Ok(RecipientContext(ctx))
    }
}
