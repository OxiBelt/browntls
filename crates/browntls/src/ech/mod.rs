//! Encrypted Client Hello (RFC 9849).
//!
//! A client configured with [`EchMode::Enable`] encrypts its real
//! ClientHello (the "inner" one, carrying the true server name and ALPN)
//! under the server's published HPKE key, and sends it inside an "outer"
//! ClientHello that names only the configuration's public name. A server
//! holding the key ([`EchServerConfig`]) decrypts it and completes the
//! handshake with the inner ClientHello; the client learns this from a
//! confirmation value in the ServerHello.
//!
//! When the server cannot decrypt (stale keys, or a server without ECH),
//! the client completes the handshake with the public name only to
//! authenticate the rejection, then fails with [`Error::RejectedEch`],
//! carrying the server's new configurations for a retry
//! ([`RejectedEch::retry_configs`]).
//!
//! [`EchMode::Grease`] sends a well-formed but meaningless extension, so that
//! connections without ECH look like connections with it (§6.2).
//!
//! The configurations usually come from the `ech` parameter of a DNS HTTPS
//! or SVCB record (RFC 9848); the [`svcb`] module extracts them.
//!
//! ECH restricts a connection to TLS 1.3: a client offering it sends neither
//! TLS 1.2 nor 0-RTT data, and resumes only TLS 1.3 sessions.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use browntls_pki::DnsName;

use crate::crypto::hpke::{
    Hpke, HpkeAead, HpkeKem, HpkePrivateKey, HpkePublicKey, HpkeSuite, HpkeSymmetricCipherSuite,
};
use crate::crypto::tls13::Hkdf;
use crate::error::{Error, InvalidMessage};
use crate::msgs::base::PayloadU16;

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod config;
pub(crate) mod server;
pub mod svcb;
#[cfg(test)]
mod tests;

use config::{EchConfigContents, EchConfigEntry, HpkeKeyConfig};

/// The prefix of the HPKE `info` (RFC 9849 §6.1): `"tls ech" || 0x00`.
const INFO_PREFIX: &[u8] = b"tls ech\0";

/// The HPKE `info` for `config`, the serialized `ECHConfig`.
fn hpke_info(config: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(INFO_PREFIX.len() + config.len());
    info.extend_from_slice(INFO_PREFIX);
    info.extend_from_slice(config);
    info
}

/// The label for a ServerHello's confirmation (RFC 9849 §7.2).
pub(crate) const ACCEPT_LABEL: &[u8] = b"ech accept confirmation";
/// The label for a HelloRetryRequest's confirmation (RFC 9849 §7.2.1).
pub(crate) const HRR_ACCEPT_LABEL: &[u8] = b"hrr ech accept confirmation";

/// `HKDF-Expand-Label(HKDF-Extract(0, inner_random), label, transcript_hash, 8)`.
pub(crate) fn accept_confirmation(
    hkdf: &dyn Hkdf,
    inner_random: &[u8; 32],
    label: &[u8],
    transcript_hash: &[u8],
) -> [u8; 8] {
    // An empty salt is a string of Hash.length zeros (RFC 5869 §2.2).
    let expander = hkdf.extract_from_secret(None, inner_random);
    let mut out = [0u8; 8];
    crate::tls13::key_schedule::hkdf_expand_label(&*expander, label, transcript_hash, &mut out);
    out
}

/// Finds a suite among `suites` for one of `config`'s cipher suites, in the
/// configuration's order. Export-only AEADs cannot seal and are skipped.
fn select_suite(
    key_config: &HpkeKeyConfig,
    suites: &[&'static dyn Hpke],
) -> Option<(&'static dyn Hpke, HpkeSymmetricCipherSuite)> {
    key_config.cipher_suites.iter().find_map(|cs| {
        // Export-only AEADs cannot seal.
        cs.aead_id.tag_len()?;
        suites
            .iter()
            .copied()
            .find(|s| {
                let suite = s.suite();
                suite.kem == key_config.kem_id && suite.sym == *cs
            })
            .map(|s| (s, *cs))
    })
}

/// A client's ECH configuration for one server: one `ECHConfig` chosen from
/// the server's `ECHConfigList` and an HPKE suite to seal with.
#[derive(Clone)]
pub struct EchConfig {
    pub(crate) encoded: Vec<u8>,
    pub(crate) contents: EchConfigContents,
    pub(crate) hpke: &'static dyn Hpke,
    pub(crate) cipher_suite: HpkeSymmetricCipherSuite,
    pub(crate) public_name: DnsName<'static>,
}

impl EchConfig {
    /// Chooses the first usable configuration in `ech_config_list` (an
    /// `ECHConfigList` with its length prefix, as DNS carries it), and the
    /// first of its cipher suites that `hpke_suites` implements.
    ///
    /// A configuration is skipped if its version is not RFC 9849's, it has
    /// an unknown mandatory extension (§4.2), its public name is not a valid
    /// DNS name or could be read as an IPv4 address (§6.1.7), or no suite
    /// matches.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidMessage`] if the list is malformed; [`Error::General`]
    /// if no configuration is usable.
    pub fn new(ech_config_list: &[u8], hpke_suites: &[&'static dyn Hpke]) -> Result<Self, Error> {
        let entries = config::read_config_list(ech_config_list)?;
        for entry in entries {
            let Some(contents) = entry.contents else {
                continue;
            };
            if contents.extensions.iter().any(|e| e.is_mandatory()) {
                continue;
            }
            let Some(public_name) = config::valid_public_name(&contents.public_name) else {
                continue;
            };
            let Some((hpke, cipher_suite)) = select_suite(&contents.key_config, hpke_suites) else {
                continue;
            };
            return Ok(Self {
                encoded: entry.encoded,
                contents,
                hpke,
                cipher_suite,
                public_name,
            });
        }
        Err(Error::General(String::from(
            "no usable ECH configuration in the list",
        )))
    }

    /// The public name the outer ClientHello carries, and which a server
    /// rejecting ECH authenticates as.
    pub fn public_name(&self) -> &DnsName<'static> {
        &self.public_name
    }

    /// The configuration identifier.
    pub fn config_id(&self) -> u8 {
        self.contents.key_config.config_id
    }

    /// The HPKE suite that will seal the inner ClientHello.
    pub fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: self.contents.key_config.kem_id,
            sym: self.cipher_suite,
        }
    }
}

impl fmt::Debug for EchConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchConfig")
            .field("config_id", &self.config_id())
            .field("public_name", &self.public_name)
            .field("suite", &self.suite())
            .finish_non_exhaustive()
    }
}

/// Settings for GREASE ECH (RFC 9849 §6.2): an extension shaped like a real
/// offer, sent when no configuration is known.
#[derive(Clone, Debug)]
pub struct EchGreaseConfig {
    pub(crate) hpke: &'static dyn Hpke,
    pub(crate) placeholder_key: HpkePublicKey,
}

impl EchGreaseConfig {
    /// GREASE with `suite`, encapsulating to `placeholder_key` (any valid
    /// public key for the suite's KEM) so that `enc` is well formed.
    pub fn new(suite: &'static dyn Hpke, placeholder_key: HpkePublicKey) -> Self {
        Self {
            hpke: suite,
            placeholder_key,
        }
    }

    /// GREASE with `suite` and a freshly generated placeholder key.
    ///
    /// # Errors
    ///
    /// Fails if key generation fails.
    pub fn generate(suite: &'static dyn Hpke) -> Result<Self, Error> {
        let (placeholder_key, _) = suite.generate_key_pair()?;
        Ok(Self::new(suite, placeholder_key))
    }
}

/// How a client uses ECH.
#[derive(Clone, Debug)]
pub enum EchMode {
    /// Offer ECH with this configuration.
    Enable(EchConfig),
    /// Send a GREASE ECH extension.
    Grease(EchGreaseConfig),
}

impl From<EchConfig> for EchMode {
    fn from(config: EchConfig) -> Self {
        Self::Enable(config)
    }
}

impl From<EchGreaseConfig> for EchMode {
    fn from(config: EchGreaseConfig) -> Self {
        Self::Grease(config)
    }
}

/// Where ECH stands on a connection.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EchStatus {
    /// Not used: no configuration (client), or the client sent no ECH
    /// extension or the server has no keys (server).
    #[default]
    NotOffered,
    /// The client sent a GREASE extension.
    Grease,
    /// The client offered ECH and awaits the server's answer.
    Offered,
    /// The server used the inner ClientHello.
    Accepted,
    /// The server used the outer ClientHello. A server reports this for
    /// every ECH extension it could not decrypt, GREASE included.
    Rejected,
}

/// The server rejected ECH; see [`Error::RejectedEch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedEch {
    pub(crate) retry_configs: Option<Vec<u8>>,
}

impl RejectedEch {
    /// The server's retry configurations: an `ECHConfigList` for
    /// [`EchConfig::new`] on a new connection, if the server sent one.
    ///
    /// RFC 9849 §6.1.6: use them for one retry only; a server rejecting the
    /// retry too is misconfigured.
    pub fn retry_configs(&self) -> Option<&[u8]> {
        self.retry_configs.as_deref()
    }

    /// Whether the retry configurations hold at least one configuration of
    /// the version this crate implements. Without one, the server has
    /// securely disabled ECH, and a client may retry without it (§6.1.6).
    pub fn can_retry(&self) -> bool {
        self.retry_configs
            .as_deref()
            .and_then(|list| config::read_config_list(list).ok())
            .is_some_and(|entries| entries.iter().any(|e| e.contents.is_some()))
    }
}

/// One ECH key of a server: an `ECHConfig` and its HPKE private key.
#[derive(Clone)]
pub struct EchServerKey {
    pub(crate) encoded: Vec<u8>,
    pub(crate) key_config: HpkeKeyConfig,
    pub(crate) private_key: HpkePrivateKey,
    /// The suites usable with this key, matching the configuration's
    /// `cipher_suites`.
    pub(crate) suites: Vec<&'static dyn Hpke>,
}

impl EchServerKey {
    /// A key from a serialized `ECHConfig` (version, length and contents,
    /// as one entry of an `ECHConfigList`) and its private key.
    ///
    /// # Errors
    ///
    /// Fails if `ech_config` is malformed or of another version, or if none
    /// of its cipher suites is in `hpke_suites`.
    pub fn new(
        ech_config: &[u8],
        private_key: HpkePrivateKey,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let len = u16::try_from(ech_config.len())
            .map_err(|_| Error::InvalidMessage(InvalidMessage::InvalidEchConfig))?;
        let mut list = Vec::with_capacity(2 + ech_config.len());
        list.extend_from_slice(&len.to_be_bytes());
        list.extend_from_slice(ech_config);
        let mut entries = config::read_config_list(&list)?;
        let (Some(entry), true) = (entries.pop(), entries.is_empty()) else {
            return Err(Error::InvalidMessage(InvalidMessage::InvalidEchConfig));
        };
        let Some(contents) = entry.contents else {
            return Err(Error::General(String::from(
                "unsupported ECHConfig version",
            )));
        };
        Self::from_parts(entry.encoded, contents.key_config, private_key, hpke_suites)
    }

    /// Generates a key pair for the KEM of `hpke_suites[0]` and an
    /// `ECHConfig` offering every suite in `hpke_suites` with that KEM.
    ///
    /// `public_name` is the name clients put in the outer ClientHello; the
    /// server must hold a certificate for it, so that clients can
    /// authenticate a rejection. `maximum_name_length` is the longest
    /// server name the key will hide (clients pad to it); 0 lets clients
    /// choose.
    ///
    /// # Errors
    ///
    /// Fails if `hpke_suites` is empty, `public_name` is not a valid public
    /// name (RFC 9849 §6.1.7), or key generation fails.
    pub fn generate(
        config_id: u8,
        public_name: &str,
        maximum_name_length: u8,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let first = hpke_suites
            .first()
            .ok_or_else(|| Error::General(String::from("no HPKE suites")))?;
        let kem = first.suite().kem;
        if config::valid_public_name(public_name.as_bytes()).is_none() || public_name.len() > 255 {
            return Err(Error::General(String::from("invalid ECH public name")));
        }
        let cipher_suites: Vec<HpkeSymmetricCipherSuite> = hpke_suites
            .iter()
            .map(|s| s.suite())
            .filter(|s| s.kem == kem && s.sym.aead_id != HpkeAead::EXPORT_ONLY)
            .map(|s| s.sym)
            .collect();
        if cipher_suites.is_empty() {
            return Err(Error::General(String::from("no HPKE suite can seal")));
        }
        let (public_key, private_key) = first.generate_key_pair()?;
        let key_config = HpkeKeyConfig {
            config_id,
            kem_id: kem,
            public_key: PayloadU16::new(public_key.0),
            cipher_suites,
        };
        let entry = EchConfigEntry::from_contents(EchConfigContents {
            key_config: key_config.clone(),
            maximum_name_length,
            public_name: public_name.as_bytes().to_vec(),
            extensions: Vec::new(),
        });
        Self::from_parts(entry.encoded, key_config, private_key, hpke_suites)
    }

    fn from_parts(
        encoded: Vec<u8>,
        key_config: HpkeKeyConfig,
        private_key: HpkePrivateKey,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let suites: Vec<&'static dyn Hpke> = hpke_suites
            .iter()
            .copied()
            .filter(|s| {
                let suite = s.suite();
                suite.kem == key_config.kem_id
                    && suite.sym.aead_id.tag_len().is_some()
                    && key_config.cipher_suites.contains(&suite.sym)
            })
            .collect();
        if suites.is_empty() {
            return Err(Error::General(String::from(
                "no HPKE suite matches the ECHConfig",
            )));
        }
        Ok(Self {
            encoded,
            key_config,
            private_key,
            suites,
        })
    }

    /// The serialized `ECHConfig`.
    pub fn ech_config(&self) -> &[u8] {
        &self.encoded
    }

    /// The configuration identifier.
    pub fn config_id(&self) -> u8 {
        self.key_config.config_id
    }

    /// The KEM.
    pub fn kem(&self) -> HpkeKem {
        self.key_config.kem_id
    }

    /// The private key, for storing the generated key.
    pub fn private_key(&self) -> &HpkePrivateKey {
        &self.private_key
    }
}

impl fmt::Debug for EchServerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchServerKey")
            .field("config_id", &self.config_id())
            .field("kem", &self.kem())
            .finish_non_exhaustive()
    }
}

/// A server's ECH keys (RFC 9849 §7), in shared mode: the server decrypts
/// the inner ClientHello and completes the handshake with it itself.
#[derive(Debug)]
pub struct EchServerConfig {
    pub(crate) keys: Vec<EchServerKey>,
    list: Vec<u8>,
}

impl EchServerConfig {
    /// Serves `keys`, which are also the retry configurations sent to a
    /// client whose ECH extension did not decrypt, in this order.
    ///
    /// Keys are matched by configuration identifier (§7.1, the default
    /// method); several keys may share one, and are then tried in turn.
    ///
    /// # Errors
    ///
    /// Fails if `keys` is empty or too large for an `ECHConfigList`.
    pub fn new(keys: Vec<EchServerKey>) -> Result<Self, Error> {
        if keys.is_empty() {
            return Err(Error::General(String::from("no ECH keys")));
        }
        let total: usize = keys.iter().map(|k| k.encoded.len()).sum();
        if total > usize::from(u16::MAX) {
            return Err(Error::General(String::from("ECHConfigList too long")));
        }
        let list = config::encode_config_list(keys.iter().map(|k| k.encoded.as_slice()));
        Ok(Self { keys, list })
    }

    /// The `ECHConfigList` to publish (in DNS, RFC 9848) and to send as
    /// retry configurations.
    pub fn ech_config_list(&self) -> &[u8] {
        &self.list
    }
}
