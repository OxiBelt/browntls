//! Delegated credentials for TLS 1.3 (RFC 9345).
//!
//! A delegated credential (DC) is a short-lived key pair whose public half is
//! signed by the private key of an end-entity certificate. A peer that
//! offered the `delegated_credential` extension accepts a CertificateVerify
//! made with the DC key instead of the certificate key, so the certificate
//! key can stay offline (or in another trust domain) while the DC key, which
//! expires within days, is deployed on the TLS endpoints.
//!
//! The certificate must carry the `DelegationUsage` extension (OID
//! 1.3.6.1.4.1.44363.44) and the `digitalSignature` key usage (RFC 9345
//! §4.2). A DC is valid for at most seven days from the time it is checked
//! (§4.1.3), and only in TLS 1.3.
//!
//! - Issue one with [`DelegatedCredential::issue`], signing with the
//!   certificate's [`SigningKey`]; the native provider also generates the
//!   DC key pair (`crypto::native::delegated_credential`).
//! - A server attaches it to its certificate with
//!   [`CertifiedKey::with_delegated_credential`](crate::sign::CertifiedKey::with_delegated_credential);
//!   it is used when the client offered a compatible scheme. A client
//!   accepts one with `ClientConfig::enable_delegated_credentials`.
//! - A client attaches one issued for [`Side::Client`] with
//!   [`CertifiedKey::with_client_delegated_credential`](crate::sign::CertifiedKey::with_client_delegated_credential);
//!   it is used when the server's CertificateRequest lists a compatible
//!   scheme (§4.1.2). A server asks for and accepts one with
//!   `ServerConfig::enable_delegated_credentials`.
//! - [`validate`] is the check both sides run on a received credential,
//!   for callers that handle credentials outside a handshake.
//!
//! No other TLS implementation browntls is tested against (rustls, OpenSSL,
//! GnuTLS) supports RFC 9345, so only browntls-to-browntls handshakes are
//! exercised.

use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use browntls_pki::{CertificateDer, EndEntityCert, SubjectPublicKeyInfoDer, UnixTime};

use crate::common_state::Side;
use crate::crypto::CryptoProvider;
use crate::crypto::signer::SigningKey;
use crate::enums::SignatureScheme;
use crate::error::{Error, InconsistentKeys, InvalidMessage, PeerMisbehaved};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader, u24};
use crate::sync::Arc;
use crate::verify::{DigitallySignedStruct, HandshakeSignatureValid};

/// The longest validity a delegated credential may have left when it is
/// checked: seven days (RFC 9345 §4.1.3).
pub const MAX_VALIDITY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The `ASN1_subjectPublicKeyInfo<1..2^24-1>` field is bounded by the
/// handshake message size anyway; this is a much smaller local bound.
const MAX_SPKI_LEN: usize = 0x4000;

/// The sizes of valid_time, both schemes, and the SPKI and signature
/// length prefixes. The enclosing TLS extension header is four more bytes.
const CREDENTIAL_OVERHEAD: usize = 4 + 2 + 3 + 2 + 2;
pub(crate) const EXTENSION_HEADER_LEN: usize = 4;

const SERVER_CONTEXT: &[u8] = b"TLS, server delegated credentials";
const CLIENT_CONTEXT: &[u8] = b"TLS, client delegated credentials";

/// Why a locally configured delegated credential could not be used.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentError {
    /// The leaf has no valid delegation authorization.
    UnauthorizedCertificate,
    /// The credential or its certificate extensions cannot be encoded.
    InvalidEncoding,
    /// A required signature scheme is unavailable or disallowed.
    UnsupportedScheme,
    /// The signature does not authenticate the configured leaf and role.
    BadIssuerSignature,
    /// The delegated signer did not produce a signature for key association.
    KeyProofFailed,
    /// The expiry is outside the parent certificate's validity interval.
    InvalidExpiry,
    /// The credential has expired.
    Expired,
    /// The staged credential is outside its usable window at the time supplied.
    NotYetUsable,
}

impl fmt::Display for AttachmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnauthorizedCertificate => "the leaf does not authorize delegation",
            Self::InvalidEncoding => "invalid credential encoding",
            Self::UnsupportedScheme => "unavailable or disallowed signature scheme",
            Self::BadIssuerSignature => "the signature does not match the leaf and role",
            Self::KeyProofFailed => "the delegated signer could not prove key possession",
            Self::InvalidExpiry => "expiry outside the parent certificate validity interval",
            Self::Expired => "the credential has expired",
            Self::NotYetUsable => "the credential is outside its activation window",
        })
    }
}

impl From<AttachmentError> for Error {
    fn from(value: AttachmentError) -> Self {
        Self::InvalidDelegatedCredential(value)
    }
}

/// Whether `scheme` may be a credential's `dc_cert_verify_algorithm`: a
/// TLS 1.3 scheme whose key is not an `rsaEncryption` key. RFC 9345 §4
/// forbids `rsaEncryption` credential keys, so the `rsa_pss_rsae_*` schemes
/// are excluded (`rsa_pss_pss_*` keys are allowed). The handshakes offer
/// only such schemes in `delegated_credential`, and [`validate`] accepts no
/// other.
pub fn credential_scheme_allowed(scheme: SignatureScheme) -> bool {
    scheme.supported_in_tls13()
        && !matches!(
            scheme,
            SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
        )
}

/// The `Credential` structure of RFC 9345 §4: the delegated public key, the
/// scheme it signs with and its lifetime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    /// Seconds after the delegation certificate's `notBefore` at which the
    /// credential expires.
    pub valid_time: u32,
    /// The scheme the delegated key signs CertificateVerify with.
    pub dc_cert_verify_algorithm: SignatureScheme,
    /// The delegated public key.
    pub public_key: SubjectPublicKeyInfoDer<'static>,
}

impl Codec<'_> for Credential {
    /// [`DelegatedCredential::issue`] and [`DelegatedCredentialKey::new`]
    /// refuse public keys above 16 KiB (the decoding bound). A key too long
    /// for the 24-bit length, only possible by filling the public fields by
    /// hand, is written as an empty key, which every decoder rejects,
    /// rather than with a wrong length.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.valid_time.encode(bytes);
        self.dc_cert_verify_algorithm.encode(bytes);
        let spki = self.public_key.as_ref();
        match u24::from_usize(spki.len()) {
            Some(len) => {
                len.encode(bytes);
                bytes.extend_from_slice(spki);
            }
            None => {
                u24(0).encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let valid_time = u32::read(r)?;
        let dc_cert_verify_algorithm = SignatureScheme::read(r)?;
        let len = usize::from(u24::read(r)?);
        if len == 0 {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        if len > MAX_SPKI_LEN {
            return Err(InvalidMessage::MessageTooLarge);
        }
        let spki = r
            .take(len)
            .ok_or(InvalidMessage::MissingData("Credential"))?;
        Ok(Self {
            valid_time,
            dc_cert_verify_algorithm,
            public_key: SubjectPublicKeyInfoDer::from(spki.to_vec()),
        })
    }
}

/// A delegated credential (RFC 9345 §4): a [`Credential`] signed by the
/// delegation certificate's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedCredential {
    /// The signed credential.
    pub credential: Credential,
    /// The scheme of `signature`, made with the certificate's key.
    pub algorithm: SignatureScheme,
    /// The signature over the credential (see [`Self::signed_message`]).
    pub signature: Vec<u8>,
}

impl Codec<'_> for DelegatedCredential {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.credential.encode(bytes);
        self.algorithm.encode(bytes);
        PayloadU16::encode_slice(&self.signature, bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let credential = Credential::read(r)?;
        let algorithm = SignatureScheme::read(r)?;
        let signature = PayloadU16::read(r)?.0;
        // signature<1..2^16-1>
        if signature.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self {
            credential,
            algorithm,
            signature,
        })
    }
}

impl DelegatedCredential {
    /// Decodes the wire form (the body of the `delegated_credential`
    /// extension in a CertificateEntry). Trailing bytes are an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidMessage> {
        if bytes.len() > usize::from(u16::MAX) - EXTENSION_HEADER_LEN {
            return Err(InvalidMessage::MessageTooLarge);
        }
        Self::read_bytes(bytes)
    }

    /// Encodes the wire form after checking its length fields.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.encoded_extension_len()?;
        Ok(self.get_encoding())
    }

    pub(crate) fn encoded_extension_len(&self) -> Result<usize, Error> {
        let spki_len = self.credential.public_key.as_ref().len();
        let sig_len = self.signature.len();
        if !(1..=MAX_SPKI_LEN).contains(&spki_len) || sig_len == 0 {
            return Err(AttachmentError::InvalidEncoding.into());
        }
        CREDENTIAL_OVERHEAD
            .checked_add(EXTENSION_HEADER_LEN + spki_len)
            .and_then(|len| len.checked_add(sig_len))
            .filter(|len| *len <= usize::from(u16::MAX))
            .ok_or_else(|| AttachmentError::InvalidEncoding.into())
    }

    /// The bytes the certificate key signs (RFC 9345 §4): 64 octets of
    /// 0x20, the context string for `side` (the side that will
    /// authenticate with the credential), a zero octet, the DER of the
    /// delegation certificate, the encoded `Credential` and `algorithm`.
    pub fn signed_message(
        side: Side,
        end_entity: &CertificateDer<'_>,
        credential: &Credential,
        algorithm: SignatureScheme,
    ) -> Vec<u8> {
        let context = match side {
            Side::Client => CLIENT_CONTEXT,
            Side::Server => SERVER_CONTEXT,
        };
        let mut msg = Vec::with_capacity(64 + context.len() + 1 + end_entity.as_ref().len() + 128);
        msg.resize(64, 0x20);
        msg.extend_from_slice(context);
        msg.push(0x00);
        msg.extend_from_slice(end_entity.as_ref());
        credential.encode(&mut msg);
        algorithm.encode(&mut msg);
        msg
    }

    /// Issues a delegated credential for `credential`, signed by
    /// `cert_key`, the private key of `end_entity`, with the first scheme of
    /// `schemes` that key can sign with (only schemes usable in TLS 1.3 are
    /// considered). `side` is the side that will authenticate with it.
    ///
    /// The certificate must permit delegation (RFC 9345 §4.2), the
    /// credential's scheme must be usable in TLS 1.3 and not need an
    /// `rsaEncryption` key (`rsa_pss_rsae_*`, forbidden by RFC 9345 §4), and
    /// the public key must be non-empty and at most 16 KiB. The validity is
    /// not checked here; see [`valid_time_until`] to compute `valid_time`.
    pub fn issue(
        side: Side,
        end_entity: &CertificateDer<'_>,
        cert_key: &dyn SigningKey,
        schemes: &[SignatureScheme],
        credential: Credential,
    ) -> Result<Self, Error> {
        check_delegation_certificate(end_entity)?;
        check_credential(&credential)?;
        let schemes: Vec<SignatureScheme> = schemes
            .iter()
            .copied()
            .filter(SignatureScheme::supported_in_tls13)
            .collect();
        let signer = cert_key.choose_scheme(&schemes).ok_or_else(|| {
            Error::General("the certificate key cannot sign with any of the given schemes".into())
        })?;
        let algorithm = signer.scheme();
        if !schemes.contains(&algorithm) {
            return Err(AttachmentError::UnsupportedScheme.into());
        }
        let signature = signer.sign(&Self::signed_message(
            side,
            end_entity,
            &credential,
            algorithm,
        ))?;
        let issued = Self {
            credential,
            algorithm,
            signature,
        };
        issued.encoded_extension_len()?;
        Ok(issued)
    }

    /// When the credential expires: the delegation certificate's
    /// `notBefore` plus `valid_time`.
    pub fn expiry(&self, end_entity: &CertificateDer<'_>) -> Result<UnixTime, Error> {
        let cert = EndEntityCert::try_from(end_entity).map_err(crate::webpki::pki_error)?;
        Ok(expiry_from(cert.not_before(), self.credential.valid_time))
    }
}

/// The `valid_time` that makes a credential for `end_entity` expire at
/// `expiry`. Fails when `expiry` is not after the certificate's `notBefore`
/// or the offset does not fit 32 bits.
pub fn valid_time_until(end_entity: &CertificateDer<'_>, expiry: UnixTime) -> Result<u32, Error> {
    let cert = EndEntityCert::try_from(end_entity).map_err(crate::webpki::pki_error)?;
    expiry
        .as_secs()
        .checked_sub(cert.not_before().as_secs())
        .filter(|secs| *secs > 0)
        .and_then(|secs| u32::try_from(secs).ok())
        .ok_or_else(|| Error::General("delegated credential expiry out of range".into()))
}

fn expiry_from(not_before: UnixTime, valid_time: u32) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(
        not_before.as_secs().saturating_add(u64::from(valid_time)),
    ))
}

/// Checks what we issue or attach: an allowed scheme and a public key that
/// decoding would accept.
fn check_credential(credential: &Credential) -> Result<(), Error> {
    if !credential_scheme_allowed(credential.dc_cert_verify_algorithm) {
        return Err(AttachmentError::UnsupportedScheme.into());
    }
    let len = credential.public_key.as_ref().len();
    if len == 0 || len > MAX_SPKI_LEN {
        return Err(AttachmentError::InvalidEncoding.into());
    }
    Ok(())
}

/// Checks that `end_entity` may sign delegated credentials (RFC 9345
/// §4.2): it has the `DelegationUsage` extension and the `digitalSignature`
/// key usage.
fn check_delegation_certificate<'a>(
    end_entity: &'a CertificateDer<'a>,
) -> Result<EndEntityCert<'a>, Error> {
    let cert = EndEntityCert::try_from(end_entity)
        .map_err(|_| AttachmentError::UnauthorizedCertificate)?;
    if cert.has_delegation_usage() && cert.has_digital_signature_key_usage() {
        Ok(cert)
    } else {
        Err(AttachmentError::UnauthorizedCertificate.into())
    }
}

/// A delegated credential and its private key, attached to a
/// [`CertifiedKey`](crate::sign::CertifiedKey) with
/// [`with_delegated_credential`](crate::sign::CertifiedKey::with_delegated_credential)
/// (a server's) or
/// [`with_client_delegated_credential`](crate::sign::CertifiedKey::with_client_delegated_credential)
/// (a client's).
#[derive(Clone, Debug)]
pub struct DelegatedCredentialKey {
    side: Side,
    credential: DelegatedCredential,
    key: Arc<dyn SigningKey>,
    end_entity: CertificateDer<'static>,
    expiry: UnixTime,
    /// The delegation certificate's `notBefore`.
    not_before: UnixTime,
}

impl DelegatedCredentialKey {
    /// Pairs a server's `credential` (issued for [`Side::Server`]) with its
    /// private `key` for `end_entity`; see [`Self::new_for`].
    pub fn new(
        end_entity: &CertificateDer<'_>,
        credential: DelegatedCredential,
        key: Arc<dyn SigningKey>,
        provider: &CryptoProvider,
    ) -> Result<Self, Error> {
        Self::new_for(Side::Server, end_entity, credential, key, provider)
    }

    /// Pairs `credential` with its private `key` for `end_entity`. `side`
    /// is the side that authenticates with it, as given to
    /// [`DelegatedCredential::issue`]: the credential's signature covers
    /// it, so a credential is only ever presented by that side.
    ///
    /// Checks the authorization, signature and absolute expiry against
    /// the leaf certificate, and verifies the delegated key association.
    /// Check staged activation against an explicit time with
    /// [`Self::check_usable_at`].
    pub fn new_for(
        side: Side,
        end_entity: &CertificateDer<'_>,
        credential: DelegatedCredential,
        key: Arc<dyn SigningKey>,
        provider: &CryptoProvider,
    ) -> Result<Self, Error> {
        let cert = check_delegation_certificate(end_entity)?;
        check_credential(&credential.credential)?;
        credential.encoded_extension_len()?;
        let not_before = cert.not_before();
        let expiry = expiry_from(not_before, credential.credential.valid_time);
        if expiry <= not_before || expiry >= cert.not_after() {
            return Err(AttachmentError::InvalidExpiry.into());
        }
        let scheme = credential.credential.dc_cert_verify_algorithm;
        let algorithms = provider
            .signature_verification_algorithms
            .supported_schemes();
        if !credential.algorithm.supported_in_tls13()
            || !algorithms.contains(&credential.algorithm)
            || !algorithms.contains(&scheme)
        {
            return Err(AttachmentError::UnsupportedScheme.into());
        }
        let spki = &credential.credential.public_key;
        browntls_pki::RawPublicKeyEntity::try_from(spki)
            .map_err(|_| AttachmentError::InvalidEncoding)?;
        verify_issuer_signature(&credential, side, end_entity, provider)?;
        let signer = key
            .choose_scheme(&[scheme])
            .filter(|signer| signer.scheme() == scheme)
            .ok_or(AttachmentError::UnsupportedScheme)?;
        match key.public_key() {
            Some(key_spki) if key_spki.as_ref() != spki.as_ref() => {
                return Err(InconsistentKeys::KeyMismatch.into());
            }
            Some(_) => {}
            None => prove_opaque_key(&*signer, spki, provider)?,
        }
        Ok(Self {
            side,
            credential,
            key,
            end_entity: end_entity.clone().into_owned(),
            expiry,
            not_before,
        })
    }

    /// The side that authenticates with the credential.
    pub fn side(&self) -> Side {
        self.side
    }

    /// The credential.
    pub fn credential(&self) -> &DelegatedCredential {
        &self.credential
    }

    /// The credential's private key.
    pub fn key(&self) -> &Arc<dyn SigningKey> {
        &self.key
    }

    /// When the credential expires.
    pub fn expiry(&self) -> UnixTime {
        self.expiry
    }

    /// Checks whether this staged credential is usable at `now`.
    ///
    /// The validity must be positive, at most seven days from `now`, and
    /// strictly earlier than the parent certificate's expiry.
    pub fn check_usable_at(&self, now: UnixTime) -> Result<(), Error> {
        let now = now.as_secs();
        let expiry = self.expiry.as_secs();
        if now >= expiry {
            return Err(AttachmentError::Expired.into());
        }
        if now < self.not_before.as_secs() || expiry > now.saturating_add(MAX_VALIDITY.as_secs()) {
            return Err(AttachmentError::NotYetUsable.into());
        }
        Ok(())
    }

    /// Whether this credential lets `side` authenticate `end_entity` at
    /// `now` to a peer that offered `dc_schemes` in its
    /// `delegated_credential` extension and `sig_schemes` in
    /// `signature_algorithms` (RFC 9345 §4.1.1, §4.1.2, §4.1.3).
    /// Credentials the peer would reject as expired, valid for too long or
    /// valid beyond the certificate are not used, nor is one whose own
    /// scheme is missing from `signature_algorithms`, which is where a
    /// peer looks up the CertificateVerify scheme (RFC 9846 §4.5.2).
    pub(crate) fn usable(
        &self,
        side: Side,
        end_entity: &CertificateDer<'_>,
        dc_schemes: &[SignatureScheme],
        sig_schemes: &[SignatureScheme],
        now: UnixTime,
    ) -> bool {
        let scheme = self.credential.credential.dc_cert_verify_algorithm;
        self.side == side
            && self.end_entity.as_ref() == end_entity.as_ref()
            && dc_schemes.contains(&scheme)
            && sig_schemes.contains(&scheme)
            && sig_schemes.contains(&self.credential.algorithm)
            && self.check_usable_at(now).is_ok()
    }
}

fn verify_issuer_signature(
    dc: &DelegatedCredential,
    side: Side,
    end_entity: &CertificateDer<'_>,
    provider: &CryptoProvider,
) -> Result<(), Error> {
    let message =
        DelegatedCredential::signed_message(side, end_entity, &dc.credential, dc.algorithm);
    let dss = DigitallySignedStruct::new(dc.algorithm, dc.signature.clone());
    crate::webpki::verify_tls13_signature(
        &message,
        end_entity,
        &dss,
        &provider.signature_verification_algorithms,
    )
    .map_err(|_| AttachmentError::BadIssuerSignature)?;
    Ok(())
}

fn prove_opaque_key(
    signer: &dyn crate::sign::Signer,
    spki: &SubjectPublicKeyInfoDer<'_>,
    provider: &CryptoProvider,
) -> Result<(), Error> {
    const DOMAIN: &[u8] = b"browntls delegated credential key proof v1\0";
    let mut nonce = [0u8; 32];
    provider
        .secure_random
        .fill(&mut nonce)
        .map_err(|_| Error::FailedToGetRandomBytes)?;
    let mut message = Vec::with_capacity(DOMAIN.len() + nonce.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&nonce);
    let signature = signer
        .sign(&message)
        .map_err(|_| AttachmentError::KeyProofFailed)?;
    let dss = DigitallySignedStruct::new(signer.scheme(), signature);
    crate::webpki::verify_tls13_signature_with_raw_key(
        &message,
        spki,
        &dss,
        &provider.signature_verification_algorithms,
    )
    .map_err(|_| InconsistentKeys::KeyMismatch)?;
    Ok(())
}

/// What we offered and the peer presented, for [`validate`].
#[derive(Clone, Copy, Debug)]
pub struct Presented<'a> {
    /// The side that authenticates with the credential (the peer).
    pub side: Side,
    /// The peer's end-entity certificate, whose chain has been verified.
    pub end_entity: &'a CertificateDer<'a>,
    /// The schemes of our `delegated_credential` extension (in the
    /// ClientHello, or in the CertificateRequest for a client's
    /// credential).
    pub offered_dc_schemes: &'a [SignatureScheme],
    /// Our `signature_algorithms`, from the same message.
    pub offered_sig_schemes: &'a [SignatureScheme],
    /// The scheme of the peer's CertificateVerify.
    pub cert_verify_scheme: SignatureScheme,
    /// The current time.
    pub now: UnixTime,
}

/// Validates a received delegated credential (RFC 9345 §4.1.1, §4.1.2,
/// §4.1.3) after the certificate chain itself has been verified.
/// `verify_signature` checks the credential's signature (its second
/// argument, over its first) with the end-entity certificate's key; the
/// handshakes pass the configured certificate verifier's
/// `verify_tls13_signature`. Returns the validated absolute expiry, which
/// the handshakes keep for resumption state.
///
/// The handshakes run this themselves; it is public for callers that
/// handle credentials at a lower level. The CertificateVerify signature
/// itself is not checked here: verify it with the credential's
/// `public_key` afterwards.
///
/// Every failure is a `PeerMisbehaved` error that RFC 9345 §4.1.3 answers
/// with `illegal_parameter`.
pub fn validate(
    dc: &DelegatedCredential,
    presented: &Presented<'_>,
    verify_signature: impl FnOnce(
        &[u8],
        &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>,
) -> Result<UnixTime, Error> {
    let cred = &dc.credential;
    // §4.1.1: both schemes must be ones we offered, in the right list; §4:
    // never an rsaEncryption key, whatever was offered.
    if !credential_scheme_allowed(cred.dc_cert_verify_algorithm)
        || !presented
            .offered_dc_schemes
            .contains(&cred.dc_cert_verify_algorithm)
        || !presented.offered_sig_schemes.contains(&dc.algorithm)
    {
        return Err(PeerMisbehaved::DelegatedCredentialWithUnofferedScheme.into());
    }

    let cert = EndEntityCert::try_from(presented.end_entity)
        .map_err(|_| PeerMisbehaved::DelegatedCredentialWithoutDelegationUsage)?;
    let expiry = expiry_from(cert.not_before(), cred.valid_time);
    let expiry_secs = expiry.as_secs();
    let now = presented.now.as_secs();
    // §4.1.3 check 1: not expired (the start is implied by the
    // certificate's own validity, already checked).
    if now >= expiry_secs {
        return Err(PeerMisbehaved::DelegatedCredentialExpired.into());
    }
    // Check 2: at most seven days left, and not beyond the certificate.
    if expiry_secs > now.saturating_add(MAX_VALIDITY.as_secs())
        || expiry_secs >= cert.not_after().as_secs()
    {
        return Err(PeerMisbehaved::DelegatedCredentialValidityTooLong.into());
    }
    // Check 3: the CertificateVerify uses the credential's scheme.
    if presented.cert_verify_scheme != cred.dc_cert_verify_algorithm {
        return Err(PeerMisbehaved::DelegatedCredentialSchemeMismatch.into());
    }
    // Check 4: the certificate permits delegation (§4.2).
    if !cert.has_delegation_usage() || !cert.has_digital_signature_key_usage() {
        return Err(PeerMisbehaved::DelegatedCredentialWithoutDelegationUsage.into());
    }
    // Check 5: the certificate key signed the credential.
    let message = DelegatedCredential::signed_message(
        presented.side,
        presented.end_entity,
        cred,
        dc.algorithm,
    );
    let dss = DigitallySignedStruct::new(dc.algorithm, dc.signature.clone());
    verify_signature(&message, &dss)
        .map_err(|_| PeerMisbehaved::DelegatedCredentialBadSignature)?;
    Ok(expiry)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[cfg(feature = "native")]
mod validate_tests;
