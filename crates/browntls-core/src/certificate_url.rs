//! Client certificate URLs (RFC 6066 §5): a TLS 1.2 client that holds no
//! certificate, or does not want to send it, names it with URLs and SHA-1
//! hashes in a CertificateURL message instead of a Certificate message.
//!
//! # The library never opens a connection to a URL
//!
//! A server that fetches what a client names lets the client make it send
//! requests to addresses of the client's choosing, internal services
//! included (server-side request forgery, RFC 6066 §11.3). This crate fetches
//! nothing. A server connection that receives a CertificateURL message
//! pauses with a [`ClientCertificateUrlQuery`]
//! ([`CommonState::pending_client_certificate_url`]) and the application
//! performs and authorizes every fetch, then hands the bytes over with
//! `resolve_client_certificate_url` (buffered and unbuffered connections).
//! Before it does, the application must decide that the destination is one
//! it is willing to contact: scheme, host, port and the address actually
//! dialled (loopback, private and link-local ranges), never follow redirects
//! (RFC 6066 §5: MUST NOT), bound time and size, and beware of loops back
//! into the same server over HTTPS.
//!
//! # Client
//!
//! Set [`ClientConfig::enable_client_certificate_url`] and give the
//! [`CertifiedKey`] that the client certificate resolver returns a
//! [`CertificateUrl`] ([`CertifiedKey::set_certificate_url`]). The key may
//! hold no certificate at all (`CertifiedKey::new(vec![], key)`). The
//! extension is offered only when TLS 1.2 is among the offered versions, and
//! the CertificateURL message is sent only when a TLS 1.2 server
//! acknowledged the extension and asked for a certificate. Otherwise the
//! ordinary Certificate message is sent (empty for a key without a chain,
//! and then without CertificateVerify). TLS 1.3 does not have the extension.
//!
//! # Server
//!
//! Set [`ServerConfig::client_certificate_url`] to a
//! [`ClientCertificateUrlPolicy`]. A TLS 1.2 server acknowledges the
//! extension only on a full handshake that requests an X.509 client
//! certificate. A CertificateURL message whose URLs the policy refuses ends
//! the handshake with `certificate_unobtainable` before anything reaches the
//! application. Otherwise the connection pauses with a query; its answer
//! ([`ClientCertificateUrlResponse`]) is checked against the hashes the
//! client sent (`bad_certificate_hash_value` on a mismatch), and the chain
//! is then verified exactly as one from a Certificate message would be.
//! Nothing about the client counts as authenticated before its
//! CertificateVerify verified.
//!
//! A chain that cannot be obtained is always fatal (`certificate_unobtainable`),
//! also when client authentication is optional. RFC 6066 §5 lets a server
//! that does not require the certificate continue, but the client still sends
//! a CertificateVerify that cannot be checked without its key, and this crate
//! does not go on with an unverified one: a deliberate narrowing.
//!
//! SHA-1 only names the objects here; the certificates are verified as
//! usual. The caller supplies the SHA-1 function
//! (`crypto::native::sha1` or `crypto::rustcrypto::sha1`).
//!
//! [`CommonState::pending_client_certificate_url`]: crate::CommonState::pending_client_certificate_url
//! [`ClientConfig::enable_client_certificate_url`]: crate::ClientConfig::enable_client_certificate_url
//! [`ServerConfig::client_certificate_url`]: crate::ServerConfig::client_certificate_url
//! [`CertifiedKey`]: crate::sign::CertifiedKey
//! [`CertifiedKey::set_certificate_url`]: crate::sign::CertifiedKey::set_certificate_url

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::enums::AlertDescription;
use crate::error::Error;

mod pending;
mod pki_path;
mod policy;
#[cfg(test)]
mod tests;

pub(crate) use pending::PendingCertificateUrl;
pub use pki_path::{decode_pki_path, encode_pki_path};
pub(crate) use policy::{check_policy, refused_url};

/// The length of a SHA-1 digest.
pub(crate) const SHA1_LEN: usize = 20;

/// The longest `url` the wire format allows (`opaque url<1..2^16-1>`).
const MAX_URL_LEN: usize = 0xffff;

/// The longest `url_and_hash_list` the wire format allows.
const MAX_LIST_LEN: usize = 0xffff;

/// The most certificates a PkiPath object may hold.
pub const MAX_PKI_PATH_CERTIFICATES: usize = 16;

/// What the URLs of a CertificateURL message point to (RFC 6066 §5,
/// `CertChainType`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CertChainType {
    /// `individual_certs`: one DER certificate per URL, end entity first.
    IndividualCerts,
    /// `pkipath`: one URL naming a DER `PkiPath` (RFC 6066 §10.1).
    PkiPath,
}

impl CertChainType {
    pub(crate) fn to_u8(self) -> u8 {
        match self {
            Self::IndividualCerts => 0,
            Self::PkiPath => 1,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::IndividualCerts),
            1 => Some(Self::PkiPath),
            _ => None,
        }
    }
}

/// One URL and the SHA-1 hash of the object it names (`URLAndHash`).
#[derive(Clone, Eq, PartialEq)]
pub struct UrlAndHash {
    url: String,
    sha1_hash: [u8; SHA1_LEN],
}

impl UrlAndHash {
    /// Pairs `url` with the SHA-1 hash of the object it names.
    ///
    /// Fails unless `url` is 1 to 65535 bytes of printable ASCII without
    /// spaces. It is not otherwise checked: RFC 6066 §5 wants an absolute
    /// URI that can be used immediately, and the server decides which ones
    /// it fetches.
    pub fn new(url: impl Into<String>, sha1_hash: [u8; SHA1_LEN]) -> Result<Self, Error> {
        let url = url.into();
        if url.is_empty() || url.len() > MAX_URL_LEN || !policy::is_printable(url.as_bytes()) {
            return Err(Error::General(
                "certificate URL must be 1 to 65535 bytes of printable ASCII without spaces".into(),
            ));
        }
        Ok(Self { url, sha1_hash })
    }

    /// Pairs `url` with the SHA-1 hash of `object`, the DER certificate or
    /// PkiPath ([`encode_pki_path`]) it serves, computed with `sha1`.
    pub fn for_object(
        url: impl Into<String>,
        object: &[u8],
        sha1: fn(&[u8]) -> [u8; SHA1_LEN],
    ) -> Result<Self, Error> {
        Self::new(url, sha1(object))
    }

    /// The URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The SHA-1 hash of the object the URL names.
    pub fn sha1_hash(&self) -> &[u8; SHA1_LEN] {
        &self.sha1_hash
    }

    /// The bytes this entry takes in `url_and_hash_list`.
    fn encoded_len(&self) -> usize {
        2 + self.url.len() + 1 + SHA1_LEN
    }
}

impl fmt::Debug for UrlAndHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlAndHash")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// What a client sends in place of its certificate chain: the contents of
/// a CertificateURL message (RFC 6066 §5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateUrl {
    chain_type: CertChainType,
    entries: Vec<UrlAndHash>,
}

impl CertificateUrl {
    /// One URL per certificate, in TLS order: the end entity first, each
    /// following certificate certifying the one before. The self-signed
    /// root may be left out.
    ///
    /// Fails for an empty list, or one longer than the message allows.
    pub fn individual_certs(entries: Vec<UrlAndHash>) -> Result<Self, Error> {
        if entries.is_empty() {
            return Err(Error::General("certificate URL list is empty".into()));
        }
        Self::checked(CertChainType::IndividualCerts, entries)
    }

    /// One URL naming the whole chain as a DER PkiPath
    /// ([`encode_pki_path`]).
    ///
    /// Fails if the entry is longer than the message allows.
    pub fn pkipath(entry: UrlAndHash) -> Result<Self, Error> {
        Self::checked(CertChainType::PkiPath, alloc::vec![entry])
    }

    fn checked(chain_type: CertChainType, entries: Vec<UrlAndHash>) -> Result<Self, Error> {
        let len = entries
            .iter()
            .map(UrlAndHash::encoded_len)
            .fold(0usize, usize::saturating_add);
        if len > MAX_LIST_LEN {
            return Err(Error::General("certificate URL list is too long".into()));
        }
        Ok(Self {
            chain_type,
            entries,
        })
    }

    /// What the URLs point to.
    pub fn chain_type(&self) -> CertChainType {
        self.chain_type
    }

    /// The URLs and hashes, in the order they are sent.
    pub fn entries(&self) -> &[UrlAndHash] {
        &self.entries
    }
}

/// A server's rules for fetching client certificates named by URL; see the
/// [module documentation](self).
///
/// Setting [`ServerConfig::client_certificate_url`] to one makes the server
/// accept CertificateURL messages. The policy only narrows what the
/// application is asked to fetch: the application still decides whether it
/// contacts each destination.
///
/// [`ServerConfig::client_certificate_url`]: crate::ServerConfig::client_certificate_url
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ClientCertificateUrlPolicy {
    /// The SHA-1 function the fetched objects are checked with
    /// (`crypto::native::sha1` or `crypto::rustcrypto::sha1`).
    pub sha1: fn(&[u8]) -> [u8; SHA1_LEN],
    /// The URI schemes a URL may have, compared without regard to case.
    /// Only `http` by default: RFC 6066 §5 requires it, and §11.3 asks for
    /// schemes to be enabled one by one, as few as possible.
    pub allowed_schemes: Vec<String>,
    /// The most URLs one message may carry (8 by default).
    pub max_urls: usize,
    /// The longest URL accepted, in bytes (2048 by default).
    pub max_url_len: usize,
    /// The most bytes the fetched objects may take together (64 KiB by
    /// default, the bound a Certificate message has).
    pub max_fetched_len: usize,
}

impl ClientCertificateUrlPolicy {
    /// The default policy, checking fetched objects with `sha1`.
    pub fn new(sha1: fn(&[u8]) -> [u8; SHA1_LEN]) -> Self {
        Self {
            sha1,
            allowed_schemes: alloc::vec![String::from("http")],
            max_urls: 8,
            max_url_len: 2048,
            max_fetched_len: 0x1_0000,
        }
    }
}

/// The URLs a client sent, for the application to fetch; see the [module
/// documentation](self).
///
/// They passed the server's [`ClientCertificateUrlPolicy`], and nothing
/// more: they are chosen by an unauthenticated client. Authorize every
/// destination before contacting it.
#[derive(Clone)]
pub struct ClientCertificateUrlQuery {
    id: u64,
    chain_type: CertChainType,
    entries: Vec<UrlAndHash>,
}

impl ClientCertificateUrlQuery {
    pub(crate) fn new(chain_type: CertChainType, entries: Vec<UrlAndHash>) -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed) as u64,
            chain_type,
            entries,
        }
    }

    /// Identifies this query. Use it only with its originating connection.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// What the URLs point to: one certificate each, or one PkiPath.
    pub fn chain_type(&self) -> CertChainType {
        self.chain_type
    }

    /// The URLs and the hashes the objects must have, in the client's
    /// order. A cached copy of an object may be answered when its hash
    /// matches (RFC 6066 §5).
    pub fn entries(&self) -> &[UrlAndHash] {
        &self.entries
    }
}

impl fmt::Debug for ClientCertificateUrlQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCertificateUrlQuery")
            .field("id", &self.id)
            .field("chain_type", &self.chain_type)
            .field("urls", &self.entries.len())
            .finish()
    }
}

/// The application's answer to a [`ClientCertificateUrlQuery`].
#[non_exhaustive]
pub enum ClientCertificateUrlResponse {
    /// The fetched objects, one per URL, in the query's order. Each is
    /// checked against its hash.
    Fetched(Vec<Vec<u8>>),
    /// The objects could not, or may not, be fetched. The handshake fails
    /// with `certificate_unobtainable`.
    Unobtainable,
}

impl fmt::Debug for ClientCertificateUrlResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetched(objects) => f
                .debug_struct("Fetched")
                .field("objects", &objects.len())
                .finish(),
            Self::Unobtainable => f.write_str("Unobtainable"),
        }
    }
}

/// Why a server could not use the chain a client named by URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CertificateUrlError {
    /// A URL broke the server's [`ClientCertificateUrlPolicy`]; it was not
    /// shown to the application (`certificate_unobtainable`).
    RefusedByPolicy,
    /// The application answered
    /// [`ClientCertificateUrlResponse::Unobtainable`]
    /// (`certificate_unobtainable`).
    Unobtainable,
    /// The application answered a number of objects other than the number
    /// of URLs (`certificate_unobtainable`).
    WrongObjectCount,
    /// The objects were longer together than
    /// [`ClientCertificateUrlPolicy::max_fetched_len`]
    /// (`certificate_unobtainable`).
    FetchedTooLarge,
    /// An object's SHA-1 hash differs from the one the client sent
    /// (`bad_certificate_hash_value`).
    HashMismatch,
    /// A PkiPath object is not a strict DER `SEQUENCE OF Certificate` of 1
    /// to [`MAX_PKI_PATH_CERTIFICATES`] certificates (`bad_certificate`).
    MalformedPkiPath,
}

impl From<CertificateUrlError> for AlertDescription {
    fn from(e: CertificateUrlError) -> Self {
        match e {
            CertificateUrlError::RefusedByPolicy
            | CertificateUrlError::Unobtainable
            | CertificateUrlError::WrongObjectCount
            | CertificateUrlError::FetchedTooLarge => Self::CertificateUnobtainable,
            CertificateUrlError::HashMismatch => Self::BadCertificateHashValue,
            CertificateUrlError::MalformedPkiPath => Self::BadCertificate,
        }
    }
}

impl From<CertificateUrlError> for Error {
    fn from(e: CertificateUrlError) -> Self {
        Self::CertificateUrl(e)
    }
}

impl fmt::Display for CertificateUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RefusedByPolicy => "a certificate URL was refused by the server's policy",
            Self::Unobtainable => "the certificates named by URL could not be obtained",
            Self::WrongObjectCount => "the number of fetched objects differs from the URLs",
            Self::FetchedTooLarge => "the fetched objects exceed the size limit",
            Self::HashMismatch => "a fetched object does not have the hash the client sent",
            Self::MalformedPkiPath => "the fetched PkiPath is malformed",
        })
    }
}
