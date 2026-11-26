//! The type-state configuration builder shared by clients and servers.

use alloc::format;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::msgs::handshake::ALL_KEY_EXCHANGE_ALGORITHMS;
use crate::sync::Arc;
use crate::time_provider::TimeProvider;
use crate::versions;

/// Builds a [`ClientConfig`](crate::ClientConfig) or
/// [`ServerConfig`](crate::ServerConfig) in stages, each fixing one decision.
#[derive(Clone)]
pub struct ConfigBuilder<Side: ConfigSide, State> {
    pub(crate) state: State,
    pub(crate) provider: Arc<CryptoProvider>,
    pub(crate) time_provider: Arc<dyn TimeProvider>,
    pub(crate) side: PhantomData<Side>,
}

impl<Side: ConfigSide, State> ConfigBuilder<Side, State> {
    /// The provider this configuration will use.
    pub fn crypto_provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }
}

impl<Side: ConfigSide, State: fmt::Debug> fmt::Debug for ConfigBuilder<Side, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side_name = core::any::type_name::<Side>();
        let (ty, _) = side_name.split_once('<').unwrap_or((side_name, ""));
        let (_, name) = ty.rsplit_once("::").unwrap_or(("", ty));
        f.debug_struct(&format!("ConfigBuilder<{name}, _>"))
            .field("state", &self.state)
            .finish()
    }
}

/// The builder is waiting for the protocol versions.
#[derive(Clone, Debug)]
pub struct WantsVersions {}

impl<S: ConfigSide> ConfigBuilder<S, WantsVersions> {
    /// Enables every protocol version this build supports (TLS 1.3, and
    /// TLS 1.2 with the `tls12` feature), even one the provider has no
    /// suites for; fails only when no enabled version has a suite.
    ///
    /// Two peers that both have TLS 1.3 negotiate it. Whether TLS 1.2 is
    /// in this list depends on the `tls12` feature, which any crate of the
    /// application can turn on: an application that must not negotiate
    /// TLS 1.2 uses [`Self::with_protocol_versions`].
    pub fn with_safe_default_protocol_versions(
        self,
    ) -> Result<ConfigBuilder<S, WantsVerifier>, Error> {
        self.with_protocol_versions(versions::DEFAULT_VERSIONS)
    }

    /// Enables exactly `versions`; their order means nothing.
    ///
    /// The list is the version policy of the configuration. With
    /// `&[&version::TLS13]`, for a protocol that requires TLS 1.3 (RFC 9852
    /// §4 makes it the default of every new protocol), a client offers
    /// nothing of TLS 1.2, a server refuses a ClientHello that does not
    /// offer TLS 1.3 with a `protocol_version` alert, and a handshake with
    /// a peer that has TLS 1.2 alone fails on either side.
    /// `protocol_version()` on a connection reports what was negotiated.
    ///
    /// Fails if the provider has no suite for any enabled version, no key
    /// exchange groups, or a suite of an enabled version whose key exchange
    /// no group can serve. Suites of versions that are not enabled are not
    /// checked: they are never offered or selected.
    pub fn with_protocol_versions(
        self,
        versions: &[&'static versions::SupportedProtocolVersion],
    ) -> Result<ConfigBuilder<S, WantsVerifier>, Error> {
        if !self
            .provider
            .cipher_suites
            .iter()
            .any(|suite| versions.contains(&suite.version()))
        {
            return Err(Error::general("no usable cipher suites configured"));
        }
        if self.provider.kx_groups.is_empty() {
            return Err(Error::general("no kx groups configured"));
        }

        let mut supported_kx_algos = Vec::with_capacity(ALL_KEY_EXCHANGE_ALGORITHMS.len());
        for group in &self.provider.kx_groups {
            let kx = group.name().key_exchange_algorithm();
            if !supported_kx_algos.contains(&kx) {
                supported_kx_algos.push(kx);
            }
        }
        for cs in self
            .provider
            .cipher_suites
            .iter()
            .filter(|cs| versions.contains(&cs.version()))
        {
            let cs_kx = cs.key_exchange_algorithms();
            if !cs_kx.iter().any(|kx| supported_kx_algos.contains(kx)) {
                return Err(Error::General(format!(
                    "cipher suite {:?} requires {cs_kx:?} key exchange, but no compatible \
                     key exchange groups were present in the provider's `kx_groups`",
                    cs.suite()
                )));
            }
        }

        Ok(ConfigBuilder {
            state: WantsVerifier {
                versions: versions::EnabledVersions::new(versions),
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: self.side,
        })
    }
}

/// The builder is waiting for the certificate verifier (client: how to check
/// servers; server: whether and how to check clients).
#[derive(Clone, Debug)]
pub struct WantsVerifier {
    pub(crate) versions: versions::EnabledVersions,
}

/// Marks the two configuration types; implemented only within this crate.
pub trait ConfigSide: sealed::Sealed {}

impl ConfigSide for crate::ClientConfig {}
impl ConfigSide for crate::ServerConfig {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::ClientConfig {}
    impl Sealed for crate::ServerConfig {}
}
