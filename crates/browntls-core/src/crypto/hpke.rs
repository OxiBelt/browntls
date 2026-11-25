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
pub struct HpkePrivateKey {
    bytes: Vec<u8>,
    #[cfg(feature = "native")]
    pub(crate) pkcs8_ecdh_oid: bool,
}

impl HpkePrivateKey {
    /// The serialized key.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[cfg(feature = "native")]
    pub(crate) fn secret_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            #[cfg(feature = "native")]
            pkcs8_ecdh_oid: false,
        }
    }
}

impl Drop for HpkePrivateKey {
    fn drop(&mut self) {
        super::zeroize_vec(&mut self.bytes);
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

    /// The built-in provider's hook for writing the KEM shared secret to a
    /// key log (RFC 9850 `ECH_SECRET`). It is not an extension point: the
    /// trait it returns cannot be named outside this crate, so every other
    /// implementation keeps the default, and no `ECH_SECRET` line is ever
    /// written for it.
    #[cfg(feature = "key-log")]
    #[doc(hidden)]
    fn kem_secret_capture(&self) -> Option<&dyn KemSecretCapture> {
        None
    }
}

#[cfg(feature = "key-log")]
pub(crate) use capture::{ECH_SECRET, KemSecret, KemSecretCapture, KeyLogAuthorisation};

/// Capture of the KEM shared secret for the key log.
///
/// The module is private, so [`KemSecretCapture`] is sealed: only a provider
/// inside this crate can implement it, and the secret's provenance is the
/// built-in HPKE's `Encap` or `Decap` output, never a value an application
/// supplied.
#[cfg(feature = "key-log")]
mod capture {
    use alloc::boxed::Box;
    use core::fmt;

    use super::{EncapsulatedSecret, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer};
    use crate::error::Error;
    use crate::key_log::KeyLog;

    /// The key log label of the KEM shared secret (RFC 9850 §2.3).
    pub(crate) const ECH_SECRET: &str = "ECH_SECRET";

    /// Proof that a key log takes `ECH_SECRET`.
    ///
    /// The setup functions of [`KemSecretCapture`] demand one, and
    /// [`ask`](Self::ask) is the only way to make one, so no caller can
    /// reach the capture without the sink's answer for that connection.
    #[allow(unreachable_pub)]
    pub struct KeyLogAuthorisation(());

    impl KeyLogAuthorisation {
        /// Asks `key_log` whether it takes the secret: `None` unless
        /// [`KeyLog::will_log`] says so.
        pub(crate) fn ask(key_log: &dyn KeyLog) -> Option<Self> {
            key_log.will_log(ECH_SECRET).then_some(Self(()))
        }
    }

    impl fmt::Debug for KeyLogAuthorisation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("KeyLogAuthorisation")
        }
    }

    /// The largest `Nsecret` of a KEM in RFC 9180 (the output of
    /// HKDF-SHA512).
    const MAX_KEM_SECRET_LEN: usize = 64;

    /// A caller-owned buffer for one KEM shared secret (`shared_secret` in
    /// RFC 9180 §5.1.1).
    ///
    /// The setup functions of [`KemSecretCapture`] fill it in place. It is
    /// zeroised when cleared and on drop, it can be neither cloned nor
    /// compared, and its [`Debug`](fmt::Debug) form shows no byte of it.
    /// Keep it a local of the function that emits the key log line: it must
    /// not become part of a connection's state.
    #[allow(unreachable_pub)]
    pub struct KemSecret {
        bytes: [u8; MAX_KEM_SECRET_LEN],
        len: usize,
    }

    impl KemSecret {
        /// An empty buffer.
        #[cfg_attr(
            not(all(test, feature = "native")),
            expect(dead_code, reason = "used by the handshake in the next change")
        )]
        pub(crate) const fn empty() -> Self {
            Self {
                bytes: [0; MAX_KEM_SECRET_LEN],
                len: 0,
            }
        }

        /// Zeroises and empties the buffer.
        pub(crate) fn clear(&mut self) {
            crate::crypto::zeroize_slice(&mut self.bytes);
            self.len = 0;
        }

        /// Replaces the content with a copy of `secret`. A length no KEM
        /// has leaves the buffer empty.
        #[cfg_attr(not(feature = "native"), allow(dead_code))]
        pub(crate) fn set(&mut self, secret: &[u8]) {
            self.clear();
            if let Some(dst) = self.bytes.get_mut(..secret.len()) {
                dst.copy_from_slice(secret);
                self.len = secret.len();
            }
        }

        /// The secret, or `None` while the buffer is empty.
        pub(crate) fn get(&self) -> Option<&[u8]> {
            match self.len {
                0 => None,
                len => self.bytes.get(..len),
            }
        }
    }

    impl Drop for KemSecret {
        fn drop(&mut self) {
            self.clear();
        }
    }

    impl fmt::Debug for KemSecret {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("KemSecret(..)")
        }
    }

    /// [`Hpke::setup_sealer`](super::Hpke::setup_sealer) and
    /// [`Hpke::setup_opener`](super::Hpke::setup_opener) that also copy the
    /// KEM shared secret into `kem_secret`.
    ///
    /// Both clear `kem_secret` first, so that it is empty after an error
    /// and never holds the secret of an earlier call. Each takes the
    /// [`KeyLogAuthorisation`] of the key log the secret is for.
    #[allow(unreachable_pub)]
    pub trait KemSecretCapture {
        /// `SetupBaseS(pkR, info)`, capturing the secret.
        ///
        /// # Errors
        ///
        /// As [`Hpke::setup_sealer`](super::Hpke::setup_sealer).
        fn setup_sealer(
            &self,
            authorised: &KeyLogAuthorisation,
            info: &[u8],
            pub_key: &HpkePublicKey,
            kem_secret: &mut KemSecret,
        ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error>;

        /// `SetupBaseR(enc, skR, info)`, capturing the secret. Success does
        /// not show that `enc` is honest: the caller logs the secret only
        /// after the context opened a ciphertext.
        ///
        /// # Errors
        ///
        /// As [`Hpke::setup_opener`](super::Hpke::setup_opener).
        fn setup_opener(
            &self,
            authorised: &KeyLogAuthorisation,
            enc: &EncapsulatedSecret,
            info: &[u8],
            secret_key: &HpkePrivateKey,
            kem_secret: &mut KemSecret,
        ) -> Result<Box<dyn HpkeOpener>, Error>;
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
