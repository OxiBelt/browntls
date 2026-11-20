//! Cached information (RFC 7924, the `cached_info` extension), TLS 1.2 only.
//!
//! A client that kept the server's Certificate message, or the server's
//! CertificateRequest message, from an earlier handshake offers its
//! fingerprint in the ClientHello. A server whose own message has that
//! fingerprint lists the type in its ServerHello and sends the fingerprint
//! (`opaque hash_value<1..255>`) in place of the message (RFC 7924 §4.1,
//! §4.2). The fingerprint is the SHA-256 hash of the complete handshake
//! message, its four-byte header included (§5, Appendix A): see
//! [`fingerprint`].
//!
//! Both sides are off by default. The fingerprints travel in the clear, so
//! an observer can link connections of the same client to the same server
//! (§7); an application turns the extension on knowing that.
//!
//! # Client
//!
//! Set [`ClientConfig::cached_info`](crate::ClientConfig::cached_info) to a
//! [`ClientCachedInfoStore`], such as the built-in
//! [`ClientCachedInfoMemoryCache`]. A ClientHello that offers TLS 1.2 then
//! carries the fingerprints the store holds for the server name (at most
//! [`MAX_OFFERED_PER_TYPE`] of each type). A message the server replaces by
//! its fingerprint is restored from the store and processed exactly as if it
//! had been received: a restored certificate chain is verified at the
//! current time, its name checked, its revocation status established and
//! its key checks the ServerKeyExchange signature, as for any other chain.
//! Being cached never makes a chain trusted.
//!
//! The handshake transcript (Finished, the extended master secret session
//! hash and a client CertificateVerify) covers each message as it was sent,
//! in its short form when replaced. A message received in full enters the
//! store only once the handshake completed: the server's Finished verified,
//! after the certificate chain was. A restored message is never stored again.
//!
//! # Server
//!
//! Turn on the types to answer in
//! [`ServerConfig::cached_info`](crate::ServerConfig::cached_info). In a full
//! TLS 1.2 handshake the server computes the fingerprint of the Certificate
//! (for the certificate its resolver selected) and of the CertificateRequest
//! it is about to send, and replaces the message only when the client
//! offered exactly that fingerprint. A stale or unknown fingerprint, or one
//! of another length, gets the message in full and the type is not listed
//! (§4). TLS 1.3 and resumed handshakes never use the extension.
//!
//! # Observing it
//!
//! [`CommonState::cached_info_replaced`] reports, on both sides and on every
//! connection type (buffered, unbuffered, `browntls-tokio`), which messages
//! of this handshake travelled as fingerprints.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::ServerName;

use crate::common_state::CommonState;
use crate::crypto::CryptoProvider;
use crate::crypto::hash::{Hash, HashAlgorithm};
use crate::enums::{HandshakeType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::codec::Reader;
use crate::msgs::handshake::{
    CertificateChain, CertificateRequestPayload, HandshakeMessagePayload, HandshakePayload,
};
use crate::sync::Arc;

#[cfg(feature = "tls12")]
pub(crate) mod client;
mod codec;
#[cfg(feature = "std")]
mod memory;
#[cfg(feature = "tls12")]
pub(crate) mod server;
#[cfg(test)]
mod tests;

pub(crate) use codec::{ClientHelloCachedInfo, ServerHelloCachedInfo, read_handshake};
#[cfg(feature = "std")]
pub use memory::ClientCachedInfoMemoryCache;

/// The length of a fingerprint: a SHA-256 output (RFC 7924 §5).
pub const FINGERPRINT_LEN: usize = 32;

/// The most objects of one type a client offers in one ClientHello.
pub const MAX_OFFERED_PER_TYPE: usize = 4;

/// A cached information type (RFC 7924 §3, §8.2).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CachedInformationType {
    /// `cert(1)`: the server's Certificate message (RFC 7924 §4.1).
    Cert,
    /// `cert_req(2)`: the server's CertificateRequest message (RFC 7924
    /// §4.2).
    CertReq,
}

impl CachedInformationType {
    /// Every type, in code point order.
    pub(crate) const ALL: [Self; 2] = [Self::Cert, Self::CertReq];

    /// The IANA code point.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Cert => 1,
            Self::CertReq => 2,
        }
    }

    /// The type of an IANA code point, if it is one we implement.
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.code() == code)
    }

    /// The handshake message an object of this type holds.
    pub(crate) const fn handshake_type(self) -> HandshakeType {
        match self {
            Self::Cert => HandshakeType::Certificate,
            Self::CertReq => HandshakeType::CertificateRequest,
        }
    }

    const fn bit(self) -> u8 {
        1 << self.code()
    }
}

/// A set of [`CachedInformationType`]s.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct CachedInformationTypes(u8);

impl CachedInformationTypes {
    /// Whether `typ` is in the set.
    pub fn contains(self, typ: CachedInformationType) -> bool {
        self.0 & typ.bit() != 0
    }

    /// Whether the set is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn insert(&mut self, typ: CachedInformationType) {
        self.0 |= typ.bit();
    }

    pub(crate) fn remove(&mut self, typ: CachedInformationType) {
        self.0 &= !typ.bit();
    }

    pub(crate) fn iter(self) -> impl Iterator<Item = CachedInformationType> {
        CachedInformationType::ALL
            .into_iter()
            .filter(move |t| self.contains(*t))
    }
}

impl fmt::Debug for CachedInformationTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// The SHA-256 fingerprint of a complete handshake message (RFC 7924 §5):
/// `message` holds its four-byte header (type and 24-bit length) and its
/// body, not the record layer.
///
/// The hash is the provider's SHA-256, taken from its cipher suites; a
/// provider without a SHA-256 suite cannot compute fingerprints, and the
/// extension is then never used.
pub fn fingerprint(
    provider: &CryptoProvider,
    message: &[u8],
) -> Result<[u8; FINGERPRINT_LEN], Error> {
    let hash = sha256(provider)
        .ok_or_else(|| Error::general("cached_info needs a SHA-256 cipher suite"))?;
    <[u8; FINGERPRINT_LEN]>::try_from(hash.hash(message).as_ref())
        .map_err(|_| Error::general("SHA-256 output of the wrong length"))
}

/// The provider's SHA-256, from any of its cipher suites.
fn sha256(provider: &CryptoProvider) -> Option<&'static dyn Hash> {
    provider
        .cipher_suites
        .iter()
        .map(|suite| suite.hash_provider())
        .find(|hash| {
            hash.algorithm() == HashAlgorithm::SHA256 && hash.output_len() == FINGERPRINT_LEN
        })
}

/// A cached handshake message (RFC 7924 §3): its type, the complete message
/// (header included) and its fingerprint.
///
/// The fingerprint is always computed here from the message; it cannot be
/// supplied. Applications may build objects themselves, for instance to
/// provision a constrained device with its server's certificate.
#[derive(Clone)]
pub struct CachedObject {
    typ: CachedInformationType,
    message: Vec<u8>,
    fingerprint: [u8; FINGERPRINT_LEN],
}

impl CachedObject {
    /// Wraps `message`, a complete TLS 1.2 handshake message of `typ`'s kind
    /// (header included), and computes its fingerprint with `provider`'s
    /// SHA-256.
    ///
    /// Fails unless `message` is exactly one well-formed Certificate message
    /// with at least one certificate (for [`CachedInformationType::Cert`])
    /// or CertificateRequest message (for
    /// [`CachedInformationType::CertReq`]), or when the provider has no
    /// SHA-256.
    pub fn new(
        provider: &CryptoProvider,
        typ: CachedInformationType,
        message: Vec<u8>,
    ) -> Result<Self, Error> {
        check_message(typ, &message)?;
        let fingerprint = fingerprint(provider, &message)?;
        Ok(Self {
            typ,
            message,
            fingerprint,
        })
    }

    /// The type of message held.
    pub fn typ(&self) -> CachedInformationType {
        self.typ
    }

    /// The complete handshake message, header included.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// The SHA-256 fingerprint of [`Self::message`].
    pub fn fingerprint(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.fingerprint
    }

    /// The certificate chain of a [`CachedInformationType::Cert`] object.
    pub(crate) fn certificate_chain(&self) -> Result<CertificateChain<'static>, Error> {
        match parse(&self.message)? {
            HandshakePayload::Certificate(chain) => Ok(chain.into_owned()),
            _ => Err(Error::general("cached object is not a Certificate")),
        }
    }

    /// The payload of a [`CachedInformationType::CertReq`] object.
    pub(crate) fn certificate_request(&self) -> Result<CertificateRequestPayload, Error> {
        match parse(&self.message)? {
            HandshakePayload::CertificateRequest(request) => Ok(request),
            _ => Err(Error::general("cached object is not a CertificateRequest")),
        }
    }
}

impl fmt::Debug for CachedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Hex<'a>(&'a [u8]);
        impl fmt::Debug for Hex<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                crate::msgs::base::hex(f, self.0)
            }
        }
        f.debug_struct("CachedObject")
            .field("typ", &self.typ)
            .field("message_len", &self.message.len())
            .field("fingerprint", &Hex(&self.fingerprint))
            .finish()
    }
}

/// Parses exactly one TLS 1.2 handshake message.
fn parse(message: &[u8]) -> Result<HandshakePayload<'_>, Error> {
    let mut r = Reader::init(message);
    let parsed = HandshakeMessagePayload::read_version(&mut r, ProtocolVersion::TLSv1_2)?;
    r.expect_empty("CachedObject")?;
    Ok(parsed.0)
}

fn check_message(typ: CachedInformationType, message: &[u8]) -> Result<(), Error> {
    match (typ, parse(message)?) {
        (CachedInformationType::Cert, HandshakePayload::Certificate(chain))
            if !chain.0.is_empty() =>
        {
            Ok(())
        }
        (CachedInformationType::CertReq, HandshakePayload::CertificateRequest(_)) => Ok(()),
        _ => Err(Error::general(
            "cached object is not a message of its cached information type",
        )),
    }
}

/// Where a client keeps the messages it may offer (RFC 7924), keyed by
/// server name.
///
/// The library calls [`Self::insert`] only with a message received in full
/// in a TLS 1.2 handshake that completed (RFC 7924 §7): the server's
/// certificate chain verified and its Finished checked.
/// [`Self::lookup`] may return objects the application provisioned itself.
pub trait ClientCachedInfoStore: fmt::Debug + Send + Sync {
    /// Objects of `typ` to offer to `server_name`, most preferred first.
    /// Only the first [`MAX_OFFERED_PER_TYPE`] are offered.
    fn lookup(
        &self,
        server_name: &ServerName<'_>,
        typ: CachedInformationType,
    ) -> Vec<Arc<CachedObject>>;

    /// Remembers `object`, a message received in full from `server_name` in
    /// a handshake that completed.
    fn insert(&self, server_name: ServerName<'static>, object: Arc<CachedObject>);
}

/// Which messages a server replaces by their fingerprint when a client
/// offers it (RFC 7924 §4.1, §4.2). Both are off by default.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerCachedInfoPolicy {
    /// The Certificate message (`cert`).
    pub cert: bool,
    /// The CertificateRequest message (`cert_req`).
    pub cert_req: bool,
}

impl ServerCachedInfoPolicy {
    pub(crate) fn allows(&self, typ: CachedInformationType) -> bool {
        match typ {
            CachedInformationType::Cert => self.cert,
            CachedInformationType::CertReq => self.cert_req,
        }
    }
}

/// Per-connection cached information state, in [`CommonState`].
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CachedInfoState {
    /// Client: the TLS 1.2 messages the server acknowledged, whose next
    /// occurrence is read as an opaque hash form ([`read_handshake`]).
    pub(crate) expect_hash_form: CachedInformationTypes,
    /// The messages of this handshake that travelled as fingerprints.
    pub(crate) replaced: CachedInformationTypes,
}

impl CommonState {
    /// The handshake messages of this connection that travelled as their
    /// RFC 7924 fingerprint instead of in full: on a client, the messages it
    /// restored from its [`ClientCachedInfoStore`]; on a server, those it
    /// replaced. Empty unless a TLS 1.2 handshake used `cached_info`.
    pub fn cached_info_replaced(&self) -> CachedInformationTypes {
        self.cached_info.replaced
    }
}
