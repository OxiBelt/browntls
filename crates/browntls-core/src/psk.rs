//! TLS 1.3 external pre-shared keys (RFC 9846 §4.3.11) and the external
//! PSK importer (RFC 9258).
//!
//! An external PSK (EPSK) is a key both peers obtained outside TLS, with an
//! identity that names it in the `pre_shared_key` extension. A client lists
//! its keys in
//! [`ClientConfig::external_psks`](crate::ClientConfig::external_psks); a
//! server finds them through a [`ResolvesExternalPsk`] in
//! [`ServerConfig::external_psks`](crate::ServerConfig::external_psks).
//!
//! browntls always combines an external PSK with an (EC)DHE exchange
//! (`psk_dhe_ke`); the `psk_ke` mode, which would give up forward secrecy
//! (RFC 9257), is neither offered nor accepted.
//! Resumption tickets derived from an external-PSK session are bound to the
//! key bytes. [`ExternalPsk::with_key_generation`] can additionally invalidate
//! those tickets without changing the key.
//!
//! The guidance of RFC 9257 that browntls cannot enforce is the caller's
//! responsibility:
//!
//! - a PSK is shared by exactly two parties, and a node that acts as client
//!   and as server uses a different PSK in each role;
//! - the key carries at least 128 bits of entropy (browntls rejects keys
//!   shorter than 128 bits, [`ExternalPsk::MIN_KEY_LEN`], but cannot measure
//!   entropy; a password is not a PSK);
//! - the identity is sent in clear in the ClientHello, so it must not reveal
//!   anything its owner wants to keep private, and a stable identity lets an
//!   observer link connections.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{DnsName, ServerName, UnixTime};

mod replay;
pub use replay::{ExternalPskReplayDecision, ExternalPskReplayKey, ExternalPskReplayPolicy};

use crate::crypto::hash::HashAlgorithm;
use crate::ct::constant_time_eq;
use crate::enums::{CipherSuite, ProtocolVersion};
use crate::error::Error;
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::{
    BinderLabel, Protocol, derive_imported_psk, hkdf_expand_label_block,
};

/// An external pre-shared key and the parameters provisioned with it.
///
/// The key material is wiped when the value is dropped.
pub struct ExternalPsk {
    identity: Vec<u8>,
    key: Vec<u8>,
    hash: HashAlgorithm,
    cipher_suite: Option<CipherSuite>,
    server_name: Option<DnsName<'static>>,
    alpn_protocol: Option<Vec<u8>>,
    max_early_data_size: u32,
    early_data_record_size_limit: u16,
    early_data_expiry: Option<UnixTime>,
    import_context: Option<Vec<u8>>,
    key_generation: Option<Vec<u8>>,
}

impl ExternalPsk {
    /// The shortest key accepted, in bytes: RFC 9257 requires external PSKs
    /// to be at least 128 bits long.
    pub const MIN_KEY_LEN: usize = 16;

    /// The longest key accepted, in bytes (a local bound).
    pub const MAX_KEY_LEN: usize = 1024;

    /// The longest caller-provided key generation accepted, in bytes.
    pub const MAX_KEY_GENERATION_LEN: usize = u16::MAX as usize;

    /// An external PSK named `identity`, used with the TLS 1.3 cipher suites
    /// whose hash is `hash` (SHA-256 or SHA-384).
    ///
    /// RFC 9846 §4.3.11 makes SHA-256 the hash of an external PSK that was
    /// provisioned without one. The identity must be 1 to 65535 bytes long and
    /// the key [`Self::MIN_KEY_LEN`] to [`Self::MAX_KEY_LEN`] bytes.
    pub fn new(identity: Vec<u8>, mut key: Vec<u8>, hash: HashAlgorithm) -> Result<Self, Error> {
        let problem = if identity.is_empty() || identity.len() > usize::from(u16::MAX) {
            Some("external PSK identity must be 1 to 65535 bytes")
        } else if key.len() < Self::MIN_KEY_LEN {
            Some("external PSK shorter than 128 bits (RFC 9257)")
        } else if key.len() > Self::MAX_KEY_LEN {
            Some("external PSK longer than 1024 bytes")
        } else if !matches!(hash, HashAlgorithm::SHA256 | HashAlgorithm::SHA384) {
            Some("external PSK hash must be SHA-256 or SHA-384")
        } else {
            None
        };
        if let Some(problem) = problem {
            // The rejected key is still key material: wipe it.
            crate::crypto::zeroize_vec(&mut key);
            return Err(Error::general(problem));
        }
        Ok(Self {
            identity,
            key,
            hash,
            cipher_suite: None,
            server_name: None,
            alpn_protocol: None,
            max_early_data_size: 0,
            early_data_record_size_limit: crate::common_state::max_record_size_limit(true),
            early_data_expiry: None,
            import_context: None,
            key_generation: None,
        })
    }

    /// Restricts the key to one TLS 1.3 cipher suite, which must use the
    /// key's hash (or, for an imported key, a hash the importer targets).
    ///
    /// A cipher suite is part of what must be provisioned for 0-RTT
    /// (RFC 9846 §4.3.10).
    pub fn with_cipher_suite(mut self, suite: CipherSuite) -> Self {
        self.cipher_suite = Some(suite);
        self
    }

    /// Restricts the key to connections for `server_name`: a client offers
    /// it only to that name, a server accepts it only from a client that
    /// indicated that name.
    pub fn with_server_name(mut self, server_name: DnsName<'static>) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Restricts the key to connections that negotiate the ALPN protocol
    /// `protocol`: a client offers it only when it offers that protocol and
    /// refuses a server that picks another one with it; a server does not
    /// select it otherwise.
    pub fn with_alpn_protocol(mut self, protocol: Vec<u8>) -> Self {
        self.alpn_protocol = Some(protocol);
        self
    }

    /// Allows 0-RTT data of up to `max_early_data_size` bytes under this
    /// key. Off (zero) by default.
    ///
    /// Enable this only for replay-safe application traffic. Both peers need
    /// the same provisioned cipher suite and a nonzero allowance, and the key
    /// must be the first offered. Clients also need
    /// [`ClientConfig::enable_early_data`](crate::ClientConfig::enable_early_data).
    /// Servers require [`Self::with_early_data_expiry`] and
    /// [`ServerConfig::external_psk_replay_policy`](crate::ServerConfig::external_psk_replay_policy).
    pub fn with_early_data(mut self, max_early_data_size: u32) -> Self {
        self.max_early_data_size = max_early_data_size;
        self
    }

    /// Sets the largest TLS 1.3 inner plaintext allowed in one 0-RTT
    /// record under this PSK, including its type byte and padding.
    ///
    /// Provision the same value on both peers. The range is 64 through
    /// 16385, with 16385 used by default. This is independent of the
    /// total early-data allowance and the new handshake's record limit.
    pub fn with_early_data_record_size_limit(mut self, limit: u16) -> Result<Self, Error> {
        if !(crate::common_state::MIN_RECORD_SIZE_LIMIT
            ..=crate::common_state::max_record_size_limit(true))
            .contains(&limit)
        {
            return Err(Error::general(
                "invalid external PSK early-data record size limit",
            ));
        }
        self.early_data_record_size_limit = limit;
        Ok(self)
    }

    pub(crate) fn early_data_record_size_limit(&self) -> u16 {
        self.early_data_record_size_limit
    }

    /// Sets the exclusive server-side cutoff for 0-RTT under this key.
    ///
    /// Set the same cutoff on servers sharing the credential, and rotate to
    /// fresh key material to extend its early-data lifetime. Ordinary 1-RTT
    /// authentication with this key is independent of the cutoff.
    pub fn with_early_data_expiry(mut self, expiry: UnixTime) -> Self {
        self.early_data_expiry = Some(expiry);
        self
    }

    pub(crate) fn early_data_expiry(&self) -> Option<UnixTime> {
        self.early_data_expiry
    }

    /// Uses this key only through the external PSK importer (RFC 9258) with
    /// `context`: the client offers one imported identity per hash of its
    /// TLS 1.3 cipher suites instead of the external identity itself, and a
    /// server accepts the key only as an imported identity with the same
    /// context. An imported key is never used directly.
    pub fn imported(mut self, context: Vec<u8>) -> Result<Self, Error> {
        // The encoded ImportedIdentity must fit a PskIdentity (u16 length).
        if self.identity.len() + context.len() + 8 > usize::from(u16::MAX) {
            return Err(Error::general(
                "imported PSK identity would exceed 65535 bytes",
            ));
        }
        self.import_context = Some(context);
        Ok(self)
    }

    /// Adds an opaque generation for invalidating resumption credentials.
    ///
    /// browntls always binds tickets to the key material itself. This value is
    /// additional: changing it invalidates tickets even when the key bytes stay
    /// the same, while accidentally reusing it cannot make a rotated key accept
    /// old tickets. It is local configuration, independently applied by each
    /// endpoint, and is not sent on the wire.
    pub fn with_key_generation(mut self, generation: Vec<u8>) -> Result<Self, Error> {
        if generation.is_empty() || generation.len() > Self::MAX_KEY_GENERATION_LEN {
            return Err(Error::general(
                "external PSK key generation must be 1 to 65535 bytes",
            ));
        }
        self.key_generation = Some(generation);
        Ok(self)
    }

    /// The external identity.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// The hash associated with the key.
    pub fn hash(&self) -> HashAlgorithm {
        self.hash
    }

    /// The cipher suite the key is restricted to, if any.
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    /// The server name the key is restricted to, if any.
    pub fn server_name(&self) -> Option<&DnsName<'static>> {
        self.server_name.as_ref()
    }

    /// The ALPN protocol the key is restricted to, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol.as_deref()
    }

    /// The 0-RTT limit; zero when early data is not allowed.
    pub fn max_early_data_size(&self) -> u32 {
        self.max_early_data_size
    }

    /// The importer context, when the key is used only through the importer.
    pub fn import_context(&self) -> Option<&[u8]> {
        self.import_context.as_deref()
    }

    /// The caller-provided key generation, when one was configured.
    pub fn key_generation(&self) -> Option<&[u8]> {
        self.key_generation.as_deref()
    }

    /// Whether the key may be offered on a connection to `server_name`
    /// that offers the ALPN protocols `alpn`.
    pub(crate) fn usable_by_client(&self, server_name: &ServerName<'_>, alpn: &[Vec<u8>]) -> bool {
        let name_ok = match (&self.server_name, server_name) {
            (None, _) => true,
            (Some(ours), ServerName::DnsName(theirs)) => ours == theirs,
            (Some(_), _) => false,
        };
        let alpn_ok = self.alpn_protocol.as_ref().is_none_or(|p| alpn.contains(p));
        name_ok && alpn_ok
    }

    /// Whether a server may select the key for a client that indicated
    /// `sni`, with `alpn` negotiated.
    pub(crate) fn usable_by_server(
        &self,
        sni: Option<&DnsName<'static>>,
        alpn: Option<&[u8]>,
    ) -> bool {
        let name_ok = self
            .server_name
            .as_ref()
            .is_none_or(|ours| sni.is_some_and(|theirs| ours == theirs));
        let alpn_ok = self
            .alpn_protocol
            .as_deref()
            .is_none_or(|p| alpn == Some(p));
        name_ok && alpn_ok
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    /// A per-ticket verifier for this key and optional generation.
    fn ticket_key_tag(
        &self,
        suites: &[SupportedCipherSuite],
        resumption_secret: &[u8],
    ) -> Option<Vec<u8>> {
        let suite = tls13_suite_for_hash(suites, self.hash)?;
        let secret_len = u16::try_from(resumption_secret.len()).ok()?.to_be_bytes();
        let generation = self.key_generation.as_deref().unwrap_or_default();
        let generation_len = u16::try_from(generation.len()).ok()?.to_be_bytes();

        // Hash the variable-length context first so HKDF-Expand-Label's
        // one-byte context length cannot constrain an application generation.
        let mut context = suite.common.hash_provider.start();
        context.update(&secret_len);
        context.update(resumption_secret);
        context.update(&[u8::from(self.key_generation.is_some())]);
        context.update(&generation_len);
        context.update(generation);
        let context = context.finish();

        let key = suite.hkdf_provider.extract_from_secret(None, self.key());
        Some(
            hkdf_expand_label_block(&*key, b"ext psk bind", context.as_ref())
                .as_ref()
                .to_vec(),
        )
    }
}

impl Drop for ExternalPsk {
    fn drop(&mut self) {
        crate::crypto::zeroize_vec(&mut self.key);
    }
}

impl fmt::Debug for ExternalPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalPsk")
            .field("identity", &PayloadU16::new(self.identity.clone()))
            .field("hash", &self.hash)
            .field("cipher_suite", &self.cipher_suite)
            .field("server_name", &self.server_name)
            .field("max_early_data_size", &self.max_early_data_size)
            .field(
                "early_data_record_size_limit",
                &self.early_data_record_size_limit,
            )
            .field("imported", &self.import_context.is_some())
            .field("has_key_generation", &self.key_generation.is_some())
            .finish_non_exhaustive()
    }
}

/// What a resumption ticket records of the external PSK its session was
/// established with: the PSK is looked up again (and its restrictions
/// checked again) when the ticket is used.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExternalPskBinding {
    pub(crate) identity: Vec<u8>,
    /// The importer context, for a PSK used through the importer (RFC 9258).
    pub(crate) import_context: Option<Vec<u8>>,
    /// A per-ticket tag derived from the key material and resumption secret.
    pub(crate) key_tag: Vec<u8>,
}

impl ExternalPskBinding {
    pub(crate) fn of(
        psk: &ExternalPsk,
        suites: &[SupportedCipherSuite],
        resumption_secret: &[u8],
    ) -> Option<Self> {
        Some(Self {
            identity: psk.identity.clone(),
            import_context: psk.import_context.clone(),
            key_tag: psk.ticket_key_tag(suites, resumption_secret)?,
        })
    }

    /// Whether `psk` is the key this binding names, used the same way.
    pub(crate) fn matches(
        &self,
        psk: &ExternalPsk,
        suites: &[SupportedCipherSuite],
        resumption_secret: &[u8],
    ) -> bool {
        if psk.identity != self.identity || psk.import_context != self.import_context {
            return false;
        }
        let Some(mut tag) = psk.ticket_key_tag(suites, resumption_secret) else {
            return false;
        };
        let matches = constant_time_eq(&tag, &self.key_tag);
        crate::crypto::zeroize_vec(&mut tag);
        matches
    }
}

impl Drop for ExternalPskBinding {
    fn drop(&mut self) {
        crate::crypto::zeroize_vec(&mut self.key_tag);
    }
}

impl fmt::Debug for ExternalPskBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalPskBinding")
            .field("identity", &PayloadU16::new(self.identity.clone()))
            .field("imported", &self.import_context.is_some())
            .field("key_tag_len", &self.key_tag.len())
            .finish_non_exhaustive()
    }
}

/// Finds a server's external PSK by the identity a client offered.
pub trait ResolvesExternalPsk: fmt::Debug + Send + Sync {
    /// The key whose [`ExternalPsk::identity`] is `identity`, if any.
    ///
    /// For an imported identity (RFC 9258) this is called with its
    /// `external_identity`; the key must then be configured with
    /// [`ExternalPsk::imported`] and the same context. `identity` comes
    /// from the peer and is unauthenticated until the binder is checked.
    fn resolve(&self, identity: &[u8]) -> Option<Arc<ExternalPsk>>;
}

/// A fixed set of keys, searched in order.
impl ResolvesExternalPsk for Vec<Arc<ExternalPsk>> {
    fn resolve(&self, identity: &[u8]) -> Option<Arc<ExternalPsk>> {
        self.iter().find(|psk| psk.identity() == identity).cloned()
    }
}

/// An `ImportedIdentity` (RFC 9258): what an imported PSK's `identity` in
/// the `pre_shared_key` extension encodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedIdentity {
    /// The identity of the external PSK being imported.
    pub external_identity: Vec<u8>,
    /// Application context bound into the imported key.
    pub context: Vec<u8>,
    /// The protocol the key is imported for: `TLSv1_3` or `DTLSv1_3`.
    pub target_protocol: ProtocolVersion,
    /// The KDF the key is imported for, from the IANA "TLS KDF
    /// Identifiers" registry ([`Self::HKDF_SHA256`], [`Self::HKDF_SHA384`]).
    pub target_kdf: u16,
}

impl ImportedIdentity {
    /// `HKDF_SHA256` in the TLS KDF Identifiers registry.
    pub const HKDF_SHA256: u16 = 0x0001;
    /// `HKDF_SHA384` in the TLS KDF Identifiers registry.
    pub const HKDF_SHA384: u16 = 0x0002;

    /// The wire encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.external_identity.len() + self.context.len() + 8);
        PayloadU16::encode_slice(&self.external_identity, &mut out);
        PayloadU16::encode_slice(&self.context, &mut out);
        self.target_protocol.encode(&mut out);
        self.target_kdf.encode(&mut out);
        out
    }

    /// Parses an encoding, which must contain nothing else.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::init(bytes);
        let external_identity = PayloadU16::read(&mut r).ok()?.0;
        let context = PayloadU16::read(&mut r).ok()?.0;
        let target_protocol = ProtocolVersion::read(&mut r).ok()?;
        let target_kdf = u16::read(&mut r).ok()?;
        if external_identity.is_empty() || r.any_left() {
            return None;
        }
        Some(Self {
            external_identity,
            context,
            target_protocol,
            target_kdf,
        })
    }

    /// The hash of the target KDF, if browntls knows it.
    pub(crate) fn target_hash(&self) -> Option<HashAlgorithm> {
        match self.target_kdf {
            Self::HKDF_SHA256 => Some(HashAlgorithm::SHA256),
            Self::HKDF_SHA384 => Some(HashAlgorithm::SHA384),
            _ => None,
        }
    }

    fn kdf_for_hash(hash: HashAlgorithm) -> Option<u16> {
        match hash {
            HashAlgorithm::SHA256 => Some(Self::HKDF_SHA256),
            HashAlgorithm::SHA384 => Some(Self::HKDF_SHA384),
            _ => None,
        }
    }
}

/// How many `pre_shared_key` identities a server examines: later ones are
/// ignored, which bounds the work (lookups, ticket decryption) one
/// ClientHello can cause.
pub(crate) const MAX_PSK_IDENTITIES_CONSIDERED: usize = 16;

/// A PSK value (an external key, an imported key or a resumption secret);
/// wiped on drop.
pub(crate) struct PskSecret(Vec<u8>);

impl PskSecret {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl AsRef<[u8]> for PskSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for PskSecret {
    fn drop(&mut self) {
        crate::crypto::zeroize_vec(&mut self.0);
    }
}

/// The first TLS 1.3 suite in `suites` with `hash`: its HKDF serves to
/// import a key whose hash is `hash`.
fn tls13_suite_for_hash(
    suites: &[SupportedCipherSuite],
    hash: HashAlgorithm,
) -> Option<&'static Tls13CipherSuite> {
    suites
        .iter()
        .filter_map(|s| s.tls13())
        .find(|s| s.common.hash_provider.algorithm() == hash)
}

/// `ipskx` for `psk` imported as `identity` (RFC 9258): `HKDF-Expand-Label(
/// HKDF-Extract(0, epsk), "derived psk", Hash(ImportedIdentity), L)` with
/// the EPSK's hash, `L` being the target KDF's hash length.
fn import(
    psk: &ExternalPsk,
    identity: &ImportedIdentity,
    suites: &[SupportedCipherSuite],
    protocol: Protocol,
) -> Option<PskSecret> {
    let epsk_suite = tls13_suite_for_hash(suites, psk.hash)?;
    let target_suite = tls13_suite_for_hash(suites, identity.target_hash()?)?;
    Some(PskSecret(derive_imported_psk(
        epsk_suite,
        psk.key(),
        &identity.encode(),
        protocol,
        target_suite.common.hash_provider.output_len(),
    )))
}

/// The output length of the hashes external PSKs may have.
fn hash_len(hash: HashAlgorithm) -> Option<usize> {
    match hash {
        HashAlgorithm::SHA256 => Some(32),
        HashAlgorithm::SHA384 => Some(48),
        _ => None,
    }
}

/// An identity in a ClientHello that resolved to one of our external PSKs.
pub(crate) struct ExternalPskCandidate {
    /// The identity's position in the `pre_shared_key` extension.
    pub(crate) index: usize,
    pub(crate) psk: Arc<ExternalPsk>,
    /// The importer parameters, when the identity is an imported one.
    pub(crate) imported: Option<ImportedIdentity>,
    protocol: Protocol,
}

impl ExternalPskCandidate {
    /// Whether the PSK can be used with `suite`: the hash must match, and
    /// the suite the key is restricted to, if any.
    pub(crate) fn compatible_with(&self, suite: &Tls13CipherSuite) -> bool {
        let hash = match &self.imported {
            Some(identity) => identity.target_hash(),
            None => Some(self.psk.hash),
        };
        hash == Some(suite.common.hash_provider.algorithm())
            && self
                .psk
                .cipher_suite
                .is_none_or(|cs| cs == suite.common.suite)
    }

    pub(crate) fn binder_label(&self) -> BinderLabel {
        if self.imported.is_some() {
            BinderLabel::Imported
        } else {
            BinderLabel::External
        }
    }

    /// The PSK to feed into the key schedule.
    pub(crate) fn secret(&self, suites: &[SupportedCipherSuite]) -> Option<PskSecret> {
        match &self.imported {
            None => Some(PskSecret::new(self.psk.key())),
            Some(identity) => import(&self.psk, identity, suites, self.protocol),
        }
    }
}

/// The identities among the first [`MAX_PSK_IDENTITIES_CONSIDERED`] that
/// name one of the server's external PSKs, usable for a client that
/// indicated `sni` with `alpn` negotiated.
///
/// `offered` yields each identity with the length of its binder. A binder
/// whose length is not that of the key's hash cannot be valid: the client
/// holds the key with another hash, and the identity is passed over rather
/// than selected and failed.
pub(crate) fn external_psk_candidates<'a>(
    resolver: &dyn ResolvesExternalPsk,
    offered: impl Iterator<Item = (&'a [u8], usize)>,
    sni: Option<&DnsName<'static>>,
    alpn: Option<&[u8]>,
    protocol: Protocol,
) -> Vec<ExternalPskCandidate> {
    let mut out = Vec::new();
    for (index, (identity, binder_len)) in offered.take(MAX_PSK_IDENTITIES_CONSIDERED).enumerate() {
        let direct = resolver
            .resolve(identity)
            .filter(|psk| psk.import_context.is_none() && psk.identity() == identity)
            .map(|psk| (psk, None));
        let found = direct.or_else(|| {
            let imported = ImportedIdentity::decode(identity)?;
            let target_protocol = match protocol {
                Protocol::Tls13 => ProtocolVersion::TLSv1_3,
                Protocol::Dtls13 => ProtocolVersion::DTLSv1_3,
            };
            if imported.target_protocol != target_protocol {
                return None;
            }
            imported.target_hash()?;
            let psk = resolver.resolve(&imported.external_identity)?;
            (psk.identity() == imported.external_identity
                && psk.import_context.as_deref() == Some(imported.context.as_slice()))
            .then_some((psk, Some(imported)))
        });
        let Some((psk, imported)) = found else {
            continue;
        };
        let target_hash = match &imported {
            Some(identity) => identity.target_hash(),
            None => Some(psk.hash),
        };
        if target_hash.and_then(hash_len) == Some(binder_len) && psk.usable_by_server(sni, alpn) {
            out.push(ExternalPskCandidate {
                index,
                psk,
                imported,
                protocol,
            });
        }
    }
    out
}

/// A PSK a client offers, with what it takes to compute its binder and,
/// once the server selects it, its key schedule.
pub(crate) struct OfferedPsk {
    pub(crate) identity: Vec<u8>,
    pub(crate) obfuscated_ticket_age: u32,
    /// The suite whose hash the binder (and the early secret) uses.
    pub(crate) suite: &'static Tls13CipherSuite,
    pub(crate) secret: PskSecret,
    pub(crate) label: BinderLabel,
    /// The external key, for an external or imported PSK; `None` for a
    /// resumption ticket.
    pub(crate) external: Option<Arc<ExternalPsk>>,
}

/// The external PSKs a client offers, in configuration order: each direct
/// key once (with the first offered suite of its hash), each imported key
/// once per hash among the offered suites (RFC 9258).
///
/// `suites` are the offered TLS 1.3 suites in preference order; after a
/// HelloRetryRequest, `committed` is the suite it selected, and only PSKs
/// usable with it remain (RFC 9846 §4.2.2).
pub(crate) fn client_external_offers(
    psks: &[Arc<ExternalPsk>],
    suites: &[SupportedCipherSuite],
    committed: Option<&'static Tls13CipherSuite>,
    server_name: &ServerName<'_>,
    alpn: &[Vec<u8>],
    protocol: Protocol,
) -> Vec<OfferedPsk> {
    let offered: Vec<&'static Tls13CipherSuite> = suites
        .iter()
        .filter_map(|s| s.tls13())
        .filter(|s| committed.is_none_or(|c| c.common.suite == s.common.suite))
        .collect();
    let mut out = Vec::new();
    for psk in psks {
        if !psk.usable_by_client(server_name, alpn) {
            continue;
        }
        let pinned_ok =
            |s: &&'static Tls13CipherSuite| psk.cipher_suite.is_none_or(|cs| cs == s.common.suite);
        match &psk.import_context {
            None => {
                if let Some(suite) = offered
                    .iter()
                    .copied()
                    .filter(pinned_ok)
                    .find(|s| s.common.hash_provider.algorithm() == psk.hash)
                {
                    out.push(OfferedPsk {
                        identity: psk.identity.clone(),
                        // RFC 9846 §4.3.11: zero for external identities.
                        obfuscated_ticket_age: 0,
                        suite,
                        secret: PskSecret::new(psk.key()),
                        label: BinderLabel::External,
                        external: Some(psk.clone()),
                    });
                }
            }
            Some(context) => {
                let mut hashes: Vec<HashAlgorithm> = Vec::new();
                for suite in offered.iter().copied().filter(pinned_ok) {
                    let hash = suite.common.hash_provider.algorithm();
                    if hashes.contains(&hash) {
                        continue;
                    }
                    hashes.push(hash);
                    let Some(target_kdf) = ImportedIdentity::kdf_for_hash(hash) else {
                        continue;
                    };
                    let identity = ImportedIdentity {
                        external_identity: psk.identity.clone(),
                        context: context.clone(),
                        target_protocol: match protocol {
                            Protocol::Tls13 => ProtocolVersion::TLSv1_3,
                            Protocol::Dtls13 => ProtocolVersion::DTLSv1_3,
                        },
                        target_kdf,
                    };
                    if let Some(secret) = import(psk, &identity, suites, protocol) {
                        out.push(OfferedPsk {
                            identity: identity.encode(),
                            obfuscated_ticket_age: 0,
                            suite,
                            secret,
                            label: BinderLabel::Imported,
                            external: Some(psk.clone()),
                        });
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
