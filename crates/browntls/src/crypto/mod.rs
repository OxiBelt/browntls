//! The cryptography provider mount point.
//!
//! A [`CryptoProvider`] bundles everything the protocol needs from a
//! cryptography library: cipher suites, key exchange groups, signature
//! verification algorithms, a random source and a loader for private keys.
//! Every trait here can be implemented outside this crate, so integrators can
//! bring their own library.
//!
//! Two providers ship with the crate behind cargo features:
//!
//! * [`rustcrypto`] (feature `rustcrypto`): backed by the RustCrypto crates.
//! * `native` (feature `native`): backed by `browntls-crypto`.
//!
//! When exactly one of them is enabled it becomes the process default, unless
//! another provider is installed first with [`CryptoProvider::install_default`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use browntls_pki::PrivateKeyDer;

use crate::enums::ProtocolVersion;
use crate::error::Error;
use crate::msgs::enums::NamedGroup;
use crate::sync::Arc;
use crate::versions::SupportedProtocolVersion;

pub mod cipher;
pub mod hash;
pub mod hmac;
pub(crate) mod signer;
#[cfg(feature = "tls12")]
pub mod tls12;
pub mod tls13;

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

// The `native` provider (feature `native`, backed by `browntls-crypto`) is
// added by the integrator as `crypto/native/mod.rs`, declared here as
// `#[cfg(feature = "native")] pub mod native;` and wired into
// `CryptoProvider::from_crate_features` below.

pub use crate::msgs::handshake::KeyExchangeAlgorithm;
pub use crate::rand::GetRandomFailed;
pub use crate::suites::CipherSuiteCommon;
pub use crate::webpki::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};

/// Everything the protocol needs from a cryptography library.
#[derive(Debug, Clone)]
pub struct CryptoProvider {
    /// Cipher suites, in preference order.
    pub cipher_suites: Vec<crate::suites::SupportedCipherSuite>,

    /// Key exchange groups, in preference order.
    pub kx_groups: Vec<&'static dyn SupportedKxGroup>,

    /// Signature verification algorithms for certificates and handshake signatures.
    pub signature_verification_algorithms: WebPkiSupportedAlgorithms,

    /// The random source.
    pub secure_random: &'static dyn SecureRandom,

    /// Turns private keys into signing keys.
    pub key_provider: &'static dyn KeyProvider,
}

impl CryptoProvider {
    /// Installs this provider as the process default.
    ///
    /// Fails (returning the provider) if a default was already installed.
    /// Without the `std` feature there is no process-wide state; the call then
    /// always fails and configurations must be built with
    /// `builder_with_provider` or rely on the single enabled provider feature.
    pub fn install_default(self) -> Result<(), Arc<Self>> {
        static_default::install_default(self)
    }

    /// The installed default provider, if any.
    pub fn get_default() -> Option<&'static Arc<Self>> {
        static_default::get_default()
    }

    pub(crate) fn get_default_or_install_from_crate_features() -> Result<Arc<Self>, Error> {
        if let Some(provider) = Self::get_default() {
            return Ok(provider.clone());
        }
        let provider = Self::from_crate_features().ok_or_else(|| {
            Error::general(
                "no default CryptoProvider: call CryptoProvider::install_default() or \
                 enable exactly one of the `native` and `rustcrypto` features",
            )
        })?;
        let _ = static_default::install_default(provider);
        match Self::get_default() {
            Some(p) => Ok(p.clone()),
            None => Self::from_crate_features()
                .map(Arc::new)
                .ok_or_else(|| Error::general("no default CryptoProvider")),
        }
    }

    fn from_crate_features() -> Option<Self> {
        #[cfg(all(feature = "rustcrypto", not(feature = "native")))]
        {
            return Some(rustcrypto::default_provider());
        }
        // `native`-only builds return `Some(native::default_provider())` here
        // once that provider lands.
        #[allow(unreachable_code)]
        None
    }

    /// Whether every component of this provider claims FIPS validation.
    pub fn fips(&self) -> bool {
        let Self {
            cipher_suites,
            kx_groups,
            signature_verification_algorithms,
            secure_random,
            key_provider,
        } = self;
        cipher_suites.iter().all(|cs| cs.fips())
            && kx_groups.iter().all(|kx| kx.fips())
            && signature_verification_algorithms.fips()
            && secure_random.fips()
            && key_provider.fips()
    }
}

/// A source of cryptographically secure random bytes.
pub trait SecureRandom: Send + Sync + Debug {
    /// Fills `buf` with random bytes.
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// Loads private keys into [`SigningKey`](signer::SigningKey)s.
pub trait KeyProvider: Send + Sync + Debug {
    /// Parses `key_der` and returns a signing key for it.
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn signer::SigningKey>, Error>;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// A key exchange group the provider supports.
pub trait SupportedKxGroup: Send + Sync + Debug {
    /// Begins a key exchange, generating a fresh key pair.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error>;

    /// Begins and immediately completes a key exchange with `peer_pub_key`.
    ///
    /// Servers use this: they learn the client's share before choosing theirs.
    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let kx = self.start()?;
        Ok(CompletedKeyExchange {
            group: kx.group(),
            pub_key: kx.pub_key().to_vec(),
            secret: kx.complete(peer_pub_key)?,
        })
    }

    /// The group's code point.
    fn name(&self) -> NamedGroup;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }

    /// Whether the group may be used with `version` (hybrid groups are TLS 1.3 only).
    fn usable_for_version(&self, _version: ProtocolVersion) -> bool {
        true
    }
}

/// A key exchange in progress: our key pair exists, the peer's share is awaited.
pub trait ActiveKeyExchange: Send + Sync {
    /// Completes the exchange with the peer's public share.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error>;

    /// Completes the exchange for `tls_version`; TLS 1.2 FFDHE strips leading zeros.
    fn complete_for_tls_version(
        self: Box<Self>,
        peer_pub_key: &[u8],
        tls_version: &SupportedProtocolVersion,
    ) -> Result<SharedSecret, Error> {
        if tls_version.version != ProtocolVersion::TLSv1_2 {
            return self.complete(peer_pub_key);
        }
        let group = self.group();
        let mut secret = self.complete(peer_pub_key)?;
        if group.key_exchange_algorithm() == KeyExchangeAlgorithm::DHE {
            secret.strip_leading_zeros();
        }
        Ok(secret)
    }

    /// For hybrid groups: the classical component's group and public key, so a
    /// HelloRetryRequest for that classical group can reuse this key pair.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        None
    }

    /// Completes only the classical component of a hybrid exchange.
    fn complete_hybrid_component(
        self: Box<Self>,
        _peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        Err(Error::general(
            "complete_hybrid_component called on a non-hybrid key exchange",
        ))
    }

    /// Our public share.
    fn pub_key(&self) -> &[u8];

    /// The group in use.
    fn group(&self) -> NamedGroup;
}

/// The result of a completed key exchange.
pub struct CompletedKeyExchange {
    /// The group used.
    pub group: NamedGroup,
    /// Our public share.
    pub pub_key: Vec<u8>,
    /// The shared secret.
    pub secret: SharedSecret,
}

impl Debug for CompletedKeyExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompletedKeyExchange")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

/// The output of a key exchange; zeroised on drop.
pub struct SharedSecret {
    buf: Vec<u8>,
    offset: usize,
}

impl SharedSecret {
    /// The secret bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.buf[self.offset..]
    }

    fn strip_leading_zeros(&mut self) {
        let zeros = self
            .secret_bytes()
            .iter()
            .take_while(|b| **b == 0)
            .count();
        self.offset += zeros;
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        zeroize_vec(&mut self.buf);
    }
}

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(..)")
    }
}

impl From<&[u8]> for SharedSecret {
    fn from(source: &[u8]) -> Self {
        Self {
            buf: source.to_vec(),
            offset: 0,
        }
    }
}

impl From<Vec<u8>> for SharedSecret {
    fn from(buf: Vec<u8>) -> Self {
        Self { buf, offset: 0 }
    }
}

/// Encrypts and decrypts session tickets (RFC 5077, RFC 8446 §4.6.1) for a
/// [`ProducesTickets`](crate::server::ProducesTickets) implementation.
///
/// Providers implement this with an AEAD under a random key; the ticketer in
/// [`crate::ticketer`] adds key rotation and lifetimes on top.
pub trait TicketProducer: Send + Sync + Debug {
    /// Encrypts and authenticates `plain`.
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>>;

    /// Decrypts `cipher`, returning `None` if it is not authentic.
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>>;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// Overwrites a vector's contents with zeros before it is freed.
pub(crate) fn zeroize_vec(v: &mut Vec<u8>) {
    zeroize_slice(v.as_mut_slice());
    v.clear();
}

/// Overwrites a slice with zeros in a way the optimiser does not elide.
pub(crate) fn zeroize_slice(s: &mut [u8]) {
    for b in s.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(&*s);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

mod static_default {
    use super::CryptoProvider;
    use crate::sync::Arc;

    #[cfg(feature = "std")]
    static PROCESS_DEFAULT_PROVIDER: std::sync::OnceLock<Arc<CryptoProvider>> =
        std::sync::OnceLock::new();

    #[cfg(feature = "std")]
    pub(super) fn install_default(provider: CryptoProvider) -> Result<(), Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER.set(Arc::new(provider))
    }

    #[cfg(feature = "std")]
    pub(super) fn get_default() -> Option<&'static Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER.get()
    }

    // Without `std` there is no safe process-wide cell for a boxed value, so
    // installation always fails and callers pass providers explicitly.
    #[cfg(not(feature = "std"))]
    pub(super) fn install_default(provider: CryptoProvider) -> Result<(), Arc<CryptoProvider>> {
        Err(Arc::new(provider))
    }

    #[cfg(not(feature = "std"))]
    pub(super) fn get_default() -> Option<&'static Arc<CryptoProvider>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_strips_leading_zeros() {
        let cases: [(&[u8], &[u8]); 5] = [
            (&[0, 1], &[1]),
            (&[1], &[1]),
            (&[1, 0, 2], &[1, 0, 2]),
            (&[0, 0, 0], &[]),
            (&[], &[]),
        ];
        for (input, expected) in cases {
            let mut s = SharedSecret::from(input);
            assert_eq!(s.secret_bytes(), input);
            s.strip_leading_zeros();
            assert_eq!(s.secret_bytes(), expected);
        }
    }
}
