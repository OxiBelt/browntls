//! Hybrid Public Key Encryption (RFC 9180) for Encrypted Client Hello.
//!
//! ECH (RFC 9849) seals the inner ClientHello with HPKE in base mode. An
//! [`Hpke`] implementation provides one suite: a KEM, a KDF and an AEAD.
//! The native provider supplies every suite of `browntls_crypto::hpke` in
//! `native::hpke::ALL_SUPPORTED_SUITES` (feature `native`);
//! other libraries can implement the traits here.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::error::Error;

/// An HPKE KEM identifier (RFC 9180 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HpkeKem(pub u16);

impl HpkeKem {
    /// DHKEM(P-256, HKDF-SHA256).
    pub const DHKEM_P256_HKDF_SHA256: Self = Self(0x0010);
    /// DHKEM(P-384, HKDF-SHA384).
    pub const DHKEM_P384_HKDF_SHA384: Self = Self(0x0011);
    /// DHKEM(P-521, HKDF-SHA512).
    pub const DHKEM_P521_HKDF_SHA512: Self = Self(0x0012);
    /// DHKEM(X25519, HKDF-SHA256).
    pub const DHKEM_X25519_HKDF_SHA256: Self = Self(0x0020);
    /// DHKEM(X448, HKDF-SHA512).
    pub const DHKEM_X448_HKDF_SHA512: Self = Self(0x0021);
}

/// An HPKE KDF identifier (RFC 9180 §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HpkeKdf(pub u16);

impl HpkeKdf {
    /// HKDF-SHA256.
    pub const HKDF_SHA256: Self = Self(0x0001);
    /// HKDF-SHA384.
    pub const HKDF_SHA384: Self = Self(0x0002);
    /// HKDF-SHA512.
    pub const HKDF_SHA512: Self = Self(0x0003);
}

/// An HPKE AEAD identifier (RFC 9180 §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HpkeAead(pub u16);

impl HpkeAead {
    /// AES-128-GCM.
    pub const AES_128_GCM: Self = Self(0x0001);
    /// AES-256-GCM.
    pub const AES_256_GCM: Self = Self(0x0002);
    /// ChaCha20-Poly1305.
    pub const CHACHA20_POLY_1305: Self = Self(0x0003);
    /// Export-only: cannot seal, so never usable for ECH.
    pub const EXPORT_ONLY: Self = Self(0xffff);

    /// The ciphertext expansion (`Nt`), when known.
    pub fn tag_len(self) -> Option<usize> {
        match self {
            Self::AES_128_GCM | Self::AES_256_GCM | Self::CHACHA20_POLY_1305 => Some(16),
            _ => None,
        }
    }
}

/// The symmetric half of a suite, as `ECHConfig` lists it
/// (`HpkeSymmetricCipherSuite`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HpkeSymmetricCipherSuite {
    /// The KDF.
    pub kdf_id: HpkeKdf,
    /// The AEAD.
    pub aead_id: HpkeAead,
}

/// A complete HPKE suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HpkeSuite {
    /// The KEM.
    pub kem: HpkeKem,
    /// The KDF and AEAD.
    pub sym: HpkeSymmetricCipherSuite,
}

/// A serialized HPKE public key (`SerializePublicKey`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkePublicKey(pub Vec<u8>);

/// A serialized HPKE private key (`SerializePrivateKey`), zeroised on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct HpkePrivateKey(Vec<u8>);

impl HpkePrivateKey {
    /// The serialized key.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Drop for HpkePrivateKey {
    fn drop(&mut self) {
        super::zeroize_vec(&mut self.0);
    }
}

impl Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HpkePrivateKey(..)")
    }
}

/// An encapsulated key (`enc`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncapsulatedSecret(pub Vec<u8>);

/// One HPKE suite in base mode.
pub trait Hpke: Debug + Send + Sync {
    /// The suite implemented.
    fn suite(&self) -> HpkeSuite;

    /// `SetupBaseS(pkR, info)`: an encapsulated key and a sealing context.
    ///
    /// # Errors
    ///
    /// Fails if `pub_key` is invalid for the KEM or randomness fails.
    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error>;

    /// `SetupBaseR(enc, skR, info)`: an opening context.
    ///
    /// # Errors
    ///
    /// Fails if `enc` or `secret_key` is invalid; callers treat every
    /// failure alike (as a decryption failure).
    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error>;

    /// A fresh key pair for this suite's KEM.
    ///
    /// # Errors
    ///
    /// Fails if randomness fails.
    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error>;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// A sender context (`ContextS`).
pub trait HpkeSealer: Debug + Send + Sync {
    /// `Seal(aad, pt)`: returns `ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// Fails when the message limit is reached.
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;
}

/// A recipient context (`ContextR`).
pub trait HpkeOpener: Debug + Send + Sync {
    /// `Open(aad, ct)`: returns the plaintext.
    ///
    /// # Errors
    ///
    /// Fails when authentication fails; the sequence number then stays put.
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}
