//! External session and identity binding (RFC 8844): the
//! `external_id_hash` and `external_session_id` extensions.
//!
//! Protocols that set up a TLS (or DTLS) connection through a separate
//! signaling channel (SDP offers and answers, WebRTC identity assertions,
//! SIP with PASSporT) learn values about the session there: each side's
//! `tls-id` (RFC 8842) and, with an identity system, each side's identity
//! assertion. RFC 8844 carries them in the handshake as well, so that the
//! TLS connection is bound to the signaled session and the Finished messages
//! authenticate the binding:
//!
//! * `external_id_hash` (RFC 8844 §3.2): the SHA-256 hash of the identity
//!   assertion the sender gave its peer, or empty when it gave none;
//! * `external_session_id` (RFC 8844 §4.3): the sender's `tls-id`.
//!
//! # Configuration
//!
//! [`ClientConfig::external_binding`](crate::ClientConfig::external_binding)
//! and
//! [`ServerConfig::external_binding`](crate::ServerConfig::external_binding)
//! hold an [`ExternalBinding`]: our own values to send and the peer's values
//! to expect. `None` (the default) turns the feature off: a client sends
//! neither extension and a server ignores both. The values belong to one
//! connection, so an application clones its base configuration for each
//! connection and sets them.
//!
//! A server that chooses its configuration from the ClientHello (through
//! [`Acceptor`](crate::server::Acceptor),
//! [`UnbufferedAcceptor`](crate::server::UnbufferedAcceptor) or the Tokio
//! `LazyConfigAcceptor`) finds the client's values on the
//! [`ClientHello`](crate::server::ClientHello) view
//! ([`ClientHello::external_session_id`](crate::server::ClientHello::external_session_id),
//! [`ClientHello::external_id_hash`](crate::server::ClientHello::external_id_hash)),
//! looks the signaled session up by them, and only then builds the
//! connection's `ServerConfig`.
//!
//! # Resumption and early data
//!
//! A connection with a binding neither resumes a session nor leaves one
//! behind, on either side and in either version: a client offers no ticket
//! or session ID and stores none it receives, and a server accepts none and
//! issues none (no NewSessionTicket in TLS 1.3, no ticket or cacheable
//! session ID in TLS 1.2). RFC 8844 §5 forbids using security-sensitive
//! information from one TLS connection in another, even one established
//! from the same signaling session; and an application that pins the
//! peer's signaled certificate fingerprint in its verifier, as RFC 8844
//! §3.2 and §4.3 require in addition to these extensions, would have that
//! check skipped by a resumed handshake. A later connection without a
//! binding cannot resume a bound one either, since nothing was stored.
//!
//! A client with a binding sends no 0-RTT data, even with
//! [`ClientConfig::enable_early_data`](crate::ClientConfig::enable_early_data):
//! it checks the server's answer only in EncryptedExtensions, after the
//! server has read the early data.
//!
//! External PSKs ([`ClientConfig::external_psks`],
//! [`ServerConfig::external_psks`]) are keys the application provisions,
//! not state from an earlier connection: they keep working with a binding
//! (without early data).
//!
//! [`ClientConfig::external_psks`]: crate::ClientConfig::external_psks
//! [`ServerConfig::external_psks`]: crate::ServerConfig::external_psks
//!
//! # What is sent and checked
//!
//! * A client with a binding always sends `external_id_hash`: its own hash
//!   ([`ExternalBinding::id_hash`]), or the empty one (RFC 8844 §3.2: an
//!   endpoint that produces no identity binding sends the empty
//!   extension). It sends `external_session_id` when
//!   [`ExternalBinding::session_id`] is set. Both go in every ClientHello,
//!   the second one after a HelloRetryRequest included, and never in the
//!   ClientHelloOuter of Encrypted Client Hello (RFC 9849): they identify the
//!   signaling session, so they are sent encrypted only.
//! * A server with a binding answers only an extension the client sent, in
//!   the TLS 1.2 ServerHello or the TLS 1.3 EncryptedExtensions (RFC 8844
//!   §3.2, §4.3): `external_id_hash` always (its own hash, or the empty
//!   one), `external_session_id` when [`ExternalBinding::session_id`] is
//!   set.
//! * After a stateful HelloRetryRequest, the second ClientHello must carry
//!   the same values as the first, or neither
//!   ([`PeerMisbehaved::ExternalBindingChangedOnRetry`]). A stateless retry
//!   (cookies) starts a fresh state: the second ClientHello is checked
//!   against the expectations like any other, and the first is bound
//!   through the transcript hash the cookie carries.
//! * A received value that differs from the expectation
//!   ([`ExternalBinding::peer_id_hash`], [`ExternalBinding::peer_session_id`])
//!   ends the handshake with `illegal_parameter`
//!   ([`PeerMisbehaved::ExternalIdHashMismatch`],
//!   [`PeerMisbehaved::ExternalSessionIdMismatch`]). Lengths and bytes are
//!   compared exactly: an empty `external_id_hash` only matches
//!   [`ExternalIdHash::EMPTY`].
//! * A peer that omits an extension for which an expectation is set is
//!   accepted (RFC 8844 lets an endpoint interoperate with peers that do not
//!   implement it), unless [`ExternalBinding::require_peer_support`] is set:
//!   the handshake then fails with `missing_extension` in TLS 1.3 and
//!   `handshake_failure` in TLS 1.2
//!   ([`PeerIncompatible::ExternalIdHashExtensionRequired`],
//!   [`PeerIncompatible::ExternalSessionIdExtensionRequired`]), as for other
//!   extensions the configuration requires.
//! * Without an expectation the library does not compare: the value the
//!   peer sent is only reported by
//!   [`CommonState::peer_external_id_hash`] and
//!   [`CommonState::peer_external_session_id`], and the application must
//!   then check it itself, as RFC 8844 requires of an endpoint.
//! * A malformed extension (an `external_id_hash` of a length other than 0
//!   or 32, an `external_session_id` outside 20 to 255 bytes, trailing
//!   bytes) is `decode_error`, whether or not a binding is configured: like
//!   every extension the library parses, it is checked when the hello
//!   message is decoded.
//!
//! The values become authenticated once the handshake completes: the
//! Finished messages cover them.
//!
//! With Encrypted Client Hello, a client checks nothing after the server
//! rejected its offer (the handshake then only authenticates the retry
//! configurations and fails with `ech_required`). A server that rejects an
//! offer cannot tell a GREASE offer, whose ClientHello is the client's real
//! one, from a real offer under keys it does not hold: it checks the
//! ClientHello it answers as any other. A server with
//! [`ExternalBinding::require_peer_support`] therefore refuses the outer
//! ClientHello of a stale real offer with `missing_extension` rather than
//! sending its retry configurations. An [`Acceptor`] sees the outer
//! ClientHello, so its view has no values for a real offer; a server that
//! uses ECH keys chooses its configuration by other means (the inner server
//! name is not visible there either).
//!
//! [`Acceptor`]: crate::server::Acceptor
//!
//! # Security considerations
//!
//! RFC 8844 binds the TLS connection to the signaling session; it does not
//! by itself authenticate the signaling peer.
//!
//! * Without identity assertions, `external_session_id` prevents the
//!   session splicing (unknown key-share) attack of RFC 8844 §4, provided
//!   the signaling channel delivers the `tls-id` values with integrity.
//! * Session concatenation (§5): an attacker who forwards signaling between
//!   two peers can still make them connect directly while each believes it
//!   talks to the attacker. Identity systems (WebRTC identity, SIP
//!   identity: here `external_id_hash` with assertions the application
//!   verifies) prevent this single-connection concatenation, but not two
//!   back-to-back connections through the attacker. Defending against
//!   concatenation also requires that peers cannot claim other entities'
//!   certificate fingerprints (§6).
//! * With identity assertions, the identity of TLS peers cannot be
//!   misrepresented even by an attacker that can modify signaling (§6).
//! * What is learned on one TLS connection does not transfer to another,
//!   even of the same signaling session (§5): the library resumes nothing
//!   with a binding (see above), and the application must not assume that
//!   its TLS peer is its signaling peer, nor carry information from one
//!   connection into a protocol that does.
//!
//! The library compares what it is given: the expectations must come from
//! the peer's verified signaling, and our own values from what we
//! signaled.

use alloc::vec::Vec;
use core::fmt;

use crate::common_state::CommonState;
use crate::crypto::CryptoProvider;
use crate::crypto::hash::HashAlgorithm;
use crate::error::{Error, InvalidMessage};
#[cfg(doc)]
use crate::error::{PeerIncompatible, PeerMisbehaved};
use crate::msgs::codec::{Codec, Reader};

pub(crate) mod handshake;
#[cfg(test)]
mod tests;

/// The `extension_data` of `external_id_hash` (RFC 8844 §3.2): empty, or
/// the SHA-256 hash of the sender's identity assertion.
///
/// ```text
/// struct {
///    opaque binding_hash<0..32>;
/// } ExternalIdentityHash;
/// ```
///
/// Only the lengths 0 and 32 are valid, so a value of this type is always
/// one of the two.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExternalIdHash(Option<[u8; 32]>);

impl ExternalIdHash {
    /// The empty hash: the sender supports the extension but gave no
    /// identity assertion (RFC 8844 §3.2).
    pub const EMPTY: Self = Self(None);

    /// The length of a non-empty hash: a SHA-256 digest.
    pub const SHA256_LEN: usize = 32;

    /// A hash computed by the caller: the SHA-256 digest of the identity
    /// assertion's octets (RFC 8844 §3.2.1, §3.2.2).
    pub const fn from_sha256(digest: [u8; 32]) -> Self {
        Self(Some(digest))
    }

    /// The hash of an identity assertion, computed with `provider`'s
    /// SHA-256: `assertion` is the decoded assertion, that is the octets of
    /// the base64-decoded SDP `identity` attribute (WebRTC, RFC 8844
    /// §3.2.1) or of the full-form PASSporT's `signed-identity-digest`
    /// (SIP, §3.2.2). The library decodes no base64 or JSON.
    ///
    /// `None` if none of `provider`'s cipher suites hashes with SHA-256.
    pub fn for_assertion(provider: &CryptoProvider, assertion: &[u8]) -> Option<Self> {
        let hash = provider
            .cipher_suites
            .iter()
            .map(|suite| suite.hash_provider())
            .find(|hash| hash.algorithm() == HashAlgorithm::SHA256)?;
        let digest: [u8; 32] = hash.hash(assertion).as_ref().try_into().ok()?;
        Some(Self::from_sha256(digest))
    }

    /// The hash: empty, or 32 bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Some(digest) => digest,
            None => &[],
        }
    }

    /// Whether this is [`Self::EMPTY`].
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// Decodes a complete `extension_data` (the hash with its one-byte
    /// length).
    ///
    /// # Errors
    ///
    /// [`InvalidMessage::InvalidExternalIdHash`] for a hash length other
    /// than 0 or 32; another [`InvalidMessage`] for truncated input or
    /// trailing bytes. A peer sending any of these gets `decode_error`.
    pub fn from_extension_data(data: &[u8]) -> Result<Self, InvalidMessage> {
        Self::read_bytes(data)
    }

    /// The `extension_data` encoding: the hash with its one-byte length.
    pub fn to_extension_data(&self) -> Vec<u8> {
        self.get_encoding()
    }
}

impl Codec<'_> for ExternalIdHash {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let hash = self.as_bytes();
        // Zero or 32: always fits the one-byte length.
        bytes.push(hash.len() as u8);
        bytes.extend_from_slice(hash);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = usize::from(u8::read(r)?);
        match len {
            0 => Ok(Self::EMPTY),
            Self::SHA256_LEN => {
                let bytes = r.take(len).ok_or(InvalidMessage::MessageTooShort)?;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(bytes);
                Ok(Self::from_sha256(digest))
            }
            _ => Err(InvalidMessage::InvalidExternalIdHash),
        }
    }
}

impl fmt::Debug for ExternalIdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExternalIdHash(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// The `extension_data` of `external_session_id` (RFC 8844 §4.3): the
/// sender's unique session identifier, with SDP its `tls-id` attribute
/// value (RFC 8842) in ASCII.
///
/// ```text
/// struct {
///    opaque session_id<20..255>;
/// } ExternalSessionId;
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ExternalSessionId(Vec<u8>);

impl ExternalSessionId {
    /// The shortest valid identifier, in bytes.
    pub const MIN_LEN: usize = 20;

    /// The longest valid identifier, in bytes.
    pub const MAX_LEN: usize = 255;

    /// An identifier of 20 to 255 bytes, such as the ASCII bytes of a
    /// `tls-id` (whose RFC 8842 grammar allows 20 to 255 characters).
    ///
    /// # Errors
    ///
    /// [`Error::BadExternalSessionIdLength`] for any other length.
    pub fn new(id: &[u8]) -> Result<Self, Error> {
        if (Self::MIN_LEN..=Self::MAX_LEN).contains(&id.len()) {
            Ok(Self(id.to_vec()))
        } else {
            Err(Error::BadExternalSessionIdLength)
        }
    }

    /// The identifier.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decodes a complete `extension_data` (the identifier with its
    /// one-byte length).
    ///
    /// # Errors
    ///
    /// [`InvalidMessage::InvalidExternalSessionId`] for an identifier
    /// outside 20 to 255 bytes; another [`InvalidMessage`] for truncated
    /// input or trailing bytes. A peer sending any of these gets
    /// `decode_error`.
    pub fn from_extension_data(data: &[u8]) -> Result<Self, InvalidMessage> {
        Self::read_bytes(data)
    }

    /// The `extension_data` encoding: the identifier with its one-byte
    /// length.
    pub fn to_extension_data(&self) -> Vec<u8> {
        self.get_encoding()
    }
}

impl Codec<'_> for ExternalSessionId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // 20 to 255 bytes, checked on construction.
        bytes.push(self.0.len() as u8);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = usize::from(u8::read(r)?);
        if len < Self::MIN_LEN {
            return Err(InvalidMessage::InvalidExternalSessionId);
        }
        let id = r.take(len).ok_or(InvalidMessage::MessageTooShort)?;
        Ok(Self(id.to_vec()))
    }
}

impl fmt::Debug for ExternalSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(&self.0) {
            Ok(s) if s.chars().all(|c| c.is_ascii_graphic()) => {
                write!(f, "ExternalSessionId({s:?})")
            }
            _ => {
                f.write_str("ExternalSessionId(")?;
                for b in &self.0 {
                    write!(f, "{b:02x}")?;
                }
                f.write_str(")")
            }
        }
    }
}

/// The RFC 8844 values of one connection: ours to send, and the peer's to
/// expect. See the [module documentation](self) for what is sent and
/// checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExternalBinding {
    /// Our `external_id_hash`: the hash of the identity assertion we gave
    /// the peer in signaling. `None` sends [`ExternalIdHash::EMPTY`]: with a
    /// binding configured the extension is always sent (by a server, in
    /// answer to the client's), empty when we gave no assertion (RFC 8844
    /// §3.2).
    pub id_hash: Option<ExternalIdHash>,

    /// The `external_id_hash` the peer must send: the hash of the identity
    /// assertion it gave us in signaling, verified by the application, or
    /// [`ExternalIdHash::EMPTY`] if it gave none. `None`: the library does
    /// not compare, and the application must check
    /// [`CommonState::peer_external_id_hash`] itself.
    pub peer_id_hash: Option<ExternalIdHash>,

    /// Our `external_session_id` (with SDP, our own `tls-id`). `None`: not
    /// sent. A client that sets [`Self::peer_session_id`] must set it too,
    /// since a server only answers the extension when the client sent it.
    pub session_id: Option<ExternalSessionId>,

    /// The `external_session_id` the peer must send (with SDP, the `tls-id`
    /// of its session description). `None`: the library does not compare,
    /// and the application must check
    /// [`CommonState::peer_external_session_id`] itself.
    pub peer_session_id: Option<ExternalSessionId>,

    /// Whether a peer that omits an extension we have an expectation for
    /// is refused (`missing_extension` in TLS 1.3, `handshake_failure` in
    /// TLS 1.2). Off by default: RFC 8844 lets an endpoint continue with a
    /// peer that does not implement the extensions.
    pub require_peer_support: bool,
}

impl ExternalBinding {
    /// The `external_id_hash` we send: ours, or the empty one (RFC 8844
    /// §3.2: an endpoint that produces no identity binding sends it empty).
    pub(crate) fn id_hash_to_send(&self) -> ExternalIdHash {
        self.id_hash.unwrap_or(ExternalIdHash::EMPTY)
    }
}

/// The values the peer sent, as recorded on a connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PeerExternalBinding {
    pub(crate) id_hash: Option<ExternalIdHash>,
    pub(crate) session_id: Option<ExternalSessionId>,
}

impl CommonState {
    /// The `external_id_hash` the peer sent (RFC 8844 §3.2), when an
    /// [`ExternalBinding`] is configured.
    ///
    /// `None` when the peer sent none, before it was received, and when the
    /// feature is off. When [`ExternalBinding::peer_id_hash`] is set, a
    /// value reported here matched it; otherwise the application must
    /// compare it with the hash of the peer's identity assertion itself
    /// (RFC 8844 §3.2: a mismatch MUST fail the connection). The value is
    /// authenticated once the handshake has completed.
    pub fn peer_external_id_hash(&self) -> Option<&ExternalIdHash> {
        self.peer_external_binding.as_ref()?.id_hash.as_ref()
    }

    /// The `external_session_id` the peer sent (RFC 8844 §4.3), when an
    /// [`ExternalBinding`] is configured.
    ///
    /// `None` when the peer sent none, before it was received, and when the
    /// feature is off. When [`ExternalBinding::peer_session_id`] is set, a
    /// value reported here matched it; otherwise the application must
    /// compare it with the peer's signaled `tls-id` itself (RFC 8844 §4.3).
    /// The value is authenticated once the handshake has completed.
    pub fn peer_external_session_id(&self) -> Option<&ExternalSessionId> {
        self.peer_external_binding.as_ref()?.session_id.as_ref()
    }
}

impl<'a> crate::server::ClientHello<'a> {
    /// The client's `external_id_hash` (RFC 8844 §3.2), if it sent one.
    ///
    /// Present whether or not the server has an [`ExternalBinding`]
    /// configured, so that a server choosing its configuration from the
    /// ClientHello can find the signaled session. The value is not yet
    /// authenticated: the handshake has not run.
    pub fn external_id_hash(&self) -> Option<&'a ExternalIdHash> {
        self.external_id_hash
    }

    /// The client's `external_session_id` (RFC 8844 §4.3), if it sent one:
    /// with SDP the client's `tls-id`, by which a server can find the
    /// signaled session before choosing its configuration.
    ///
    /// Present whether or not the server has an [`ExternalBinding`]
    /// configured. The value is not yet authenticated: the handshake has not
    /// run.
    pub fn external_session_id(&self) -> Option<&'a ExternalSessionId> {
        self.external_session_id
    }
}
