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
//!   it is used when the client offered a compatible scheme.
//! - A client opts in with `ClientConfig::enable_delegated_credentials`.
//!
//! No other TLS implementation browntls is tested against (rustls, OpenSSL,
//! GnuTLS) supports RFC 9345, so only browntls-to-browntls handshakes are
//! exercised.

use alloc::vec::Vec;
use core::time::Duration;

use browntls_pki::{CertificateDer, EndEntityCert, SubjectPublicKeyInfoDer, UnixTime};

use crate::common_state::Side;
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

const SERVER_CONTEXT: &[u8] = b"TLS, server delegated credentials";
const CLIENT_CONTEXT: &[u8] = b"TLS, client delegated credentials";

/// Whether `scheme` may be a credential's `dc_cert_verify_algorithm`: a
/// TLS 1.3 scheme whose key is not an `rsaEncryption` key. RFC 9345 §4
/// forbids `rsaEncryption` credential keys, so the `rsa_pss_rsae_*` schemes
/// are excluded (`rsa_pss_pss_*` keys are allowed).
pub(crate) fn credential_scheme_allowed(scheme: SignatureScheme) -> bool {
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
                debug_assert!(false, "delegated public key longer than 2^24 - 1 bytes");
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
        Self::read_bytes(bytes)
    }

    /// The wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.get_encoding()
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
        let signature = signer.sign(&Self::signed_message(
            side,
            end_entity,
            &credential,
            algorithm,
        ))?;
        Ok(Self {
            credential,
            algorithm,
            signature,
        })
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
        return Err(Error::General(
            "a delegated credential's scheme must be a TLS 1.3 scheme without an \
             rsaEncryption key (RFC 9345 §4)"
                .into(),
        ));
    }
    let len = credential.public_key.as_ref().len();
    if len == 0 || len > MAX_SPKI_LEN {
        return Err(Error::General(
            "a delegated credential's public key must be 1 to 16384 bytes".into(),
        ));
    }
    Ok(())
}

/// Checks that `end_entity` may sign delegated credentials (RFC 9345
/// §4.2): it has the `DelegationUsage` extension and the `digitalSignature`
/// key usage.
fn check_delegation_certificate(end_entity: &CertificateDer<'_>) -> Result<(), Error> {
    let cert = EndEntityCert::try_from(end_entity).map_err(crate::webpki::pki_error)?;
    if cert.has_delegation_usage() && cert.has_digital_signature_key_usage() {
        Ok(())
    } else {
        Err(Error::General(
            "the certificate lacks the DelegationUsage extension or the digitalSignature \
             key usage (RFC 9345 §4.2)"
                .into(),
        ))
    }
}

/// A delegated credential and its private key, attached to a
/// [`CertifiedKey`](crate::sign::CertifiedKey) with
/// [`with_delegated_credential`](crate::sign::CertifiedKey::with_delegated_credential).
#[derive(Clone, Debug)]
pub struct DelegatedCredentialKey {
    credential: DelegatedCredential,
    key: Arc<dyn SigningKey>,
    end_entity: CertificateDer<'static>,
    expiry: UnixTime,
}

impl DelegatedCredentialKey {
    /// Pairs `credential` with its private `key` for `end_entity`.
    ///
    /// Checks that the certificate permits delegation, that the key can
    /// sign with the credential's scheme (a TLS 1.3 scheme other than
    /// `rsa_pss_rsae_*`, RFC 9345 §4) and, when the
    /// key exposes its public half, that it matches the credential. The
    /// credential's signature is the issuer's responsibility and is not
    /// checked here; peers check it.
    pub fn new(
        end_entity: &CertificateDer<'_>,
        credential: DelegatedCredential,
        key: Arc<dyn SigningKey>,
    ) -> Result<Self, Error> {
        check_delegation_certificate(end_entity)?;
        check_credential(&credential.credential)?;
        let scheme = credential.credential.dc_cert_verify_algorithm;
        if key.choose_scheme(&[scheme]).is_none() {
            return Err(Error::General(
                "the delegated credential key cannot sign with the credential's scheme".into(),
            ));
        }
        if let Some(spki) = key.public_key()
            && spki.as_ref() != credential.credential.public_key.as_ref()
        {
            return Err(InconsistentKeys::KeyMismatch.into());
        }
        let expiry = credential.expiry(end_entity)?;
        Ok(Self {
            credential,
            key,
            end_entity: end_entity.clone().into_owned(),
            expiry,
        })
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

    /// Whether this credential can authenticate `end_entity` at `now` to a
    /// peer that offered `dc_schemes` in its `delegated_credential`
    /// extension and `sig_schemes` in `signature_algorithms` (RFC 9345
    /// §4.1.1, §4.1.3). Credentials the peer would reject as expired or
    /// valid for too long are not used.
    pub(crate) fn usable(
        &self,
        end_entity: &CertificateDer<'_>,
        dc_schemes: &[SignatureScheme],
        sig_schemes: &[SignatureScheme],
        now: UnixTime,
    ) -> bool {
        let scheme = self.credential.credential.dc_cert_verify_algorithm;
        self.end_entity.as_ref() == end_entity.as_ref()
            && dc_schemes.contains(&scheme)
            && sig_schemes.contains(&self.credential.algorithm)
            && now.as_secs() < self.expiry.as_secs()
            && self.expiry.as_secs() <= now.as_secs().saturating_add(MAX_VALIDITY.as_secs())
    }
}

/// What a peer offered and presented, for [`validate`].
pub(crate) struct Presented<'a> {
    /// The side that authenticates with the credential.
    pub(crate) side: Side,
    pub(crate) end_entity: &'a CertificateDer<'a>,
    /// Our `delegated_credential` extension's schemes.
    pub(crate) offered_dc_schemes: &'a [SignatureScheme],
    /// Our `signature_algorithms`.
    pub(crate) offered_sig_schemes: &'a [SignatureScheme],
    /// The peer's CertificateVerify scheme.
    pub(crate) cert_verify_scheme: SignatureScheme,
    pub(crate) now: UnixTime,
}

/// Validates a received delegated credential (RFC 9345 §4.1.1, §4.1.3)
/// after the certificate chain itself has been verified. `verify_signature`
/// checks the credential's signature with the end-entity certificate's key
/// (through the configured certificate verifier).
///
/// Every failure is a `PeerMisbehaved` error that RFC 9345 §4.1.3 answers
/// with `illegal_parameter`.
pub(crate) fn validate(
    dc: &DelegatedCredential,
    presented: &Presented<'_>,
    verify_signature: impl FnOnce(
        &[u8],
        &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>,
) -> Result<HandshakeSignatureValid, Error> {
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
    let expiry = expiry_from(cert.not_before(), cred.valid_time).as_secs();
    let now = presented.now.as_secs();
    // §4.1.3 check 1: not expired (the start is implied by the
    // certificate's own validity, already checked).
    if now >= expiry {
        return Err(PeerMisbehaved::DelegatedCredentialExpired.into());
    }
    // Check 2: at most seven days left, and not beyond the certificate.
    if expiry > now.saturating_add(MAX_VALIDITY.as_secs()) || expiry > cert.not_after().as_secs() {
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
        .map_err(|_| PeerMisbehaved::DelegatedCredentialBadSignature.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DelegatedCredential {
        DelegatedCredential {
            credential: Credential {
                valid_time: 0x0102_0304,
                dc_cert_verify_algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
                public_key: SubjectPublicKeyInfoDer::from(alloc::vec![0x30, 0x01, 0x00]),
            },
            algorithm: SignatureScheme::ED25519,
            signature: alloc::vec![9, 8, 7],
        }
    }

    #[test]
    fn wire_format() {
        let dc = sample();
        let bytes = dc.to_bytes();
        assert_eq!(
            bytes,
            [
                1, 2, 3, 4, // valid_time
                0x04, 0x03, // ecdsa_secp256r1_sha256
                0, 0, 3, 0x30, 0x01, 0x00, // ASN1_subjectPublicKeyInfo
                0x08, 0x07, // ed25519
                0, 3, 9, 8, 7, // signature
            ]
        );
        assert_eq!(DelegatedCredential::from_bytes(&bytes).unwrap(), dc);
    }

    #[test]
    fn rejects_malformed() {
        let bytes = sample().to_bytes();
        // Truncated anywhere.
        for len in 0..bytes.len() {
            assert!(
                DelegatedCredential::from_bytes(&bytes[..len]).is_err(),
                "{len}"
            );
        }
        // Trailing data.
        let mut long = bytes.clone();
        long.push(0);
        assert!(DelegatedCredential::from_bytes(&long).is_err());
        // Empty public key and empty signature.
        let empty_spki = [1, 2, 3, 4, 4, 3, 0, 0, 0, 8, 7, 0, 1, 1];
        assert_eq!(
            DelegatedCredential::from_bytes(&empty_spki),
            Err(InvalidMessage::IllegalEmptyValue)
        );
        let empty_sig = [1, 2, 3, 4, 4, 3, 0, 0, 1, 0, 8, 7, 0, 0];
        assert_eq!(
            DelegatedCredential::from_bytes(&empty_sig),
            Err(InvalidMessage::IllegalEmptyValue)
        );
        // A public key above the local bound.
        let huge = [1, 2, 3, 4, 4, 3, 0, 0x40, 1];
        assert_eq!(
            DelegatedCredential::from_bytes(&huge),
            Err(InvalidMessage::MessageTooLarge)
        );
    }

    #[test]
    fn signed_message_layout() {
        let dc = sample();
        let cert = CertificateDer::from_slice(&[0xaa, 0xbb]);
        let msg =
            DelegatedCredential::signed_message(Side::Server, &cert, &dc.credential, dc.algorithm);
        assert!(msg[..64].iter().all(|b| *b == 0x20));
        let rest = &msg[64..];
        assert!(rest.starts_with(b"TLS, server delegated credentials\0\xaa\xbb"));
        let tail = &rest[SERVER_CONTEXT.len() + 3..];
        assert_eq!(&tail[..tail.len() - 2], dc.credential.get_encoding());
        assert_eq!(&tail[tail.len() - 2..], [0x08, 0x07]);
        let client =
            DelegatedCredential::signed_message(Side::Client, &cert, &dc.credential, dc.algorithm);
        assert!(client[64..].starts_with(CLIENT_CONTEXT));
    }

    #[test]
    fn expiry_arithmetic() {
        let nb = UnixTime::since_unix_epoch(Duration::from_secs(1000));
        assert_eq!(expiry_from(nb, 5).as_secs(), 1005);
        assert_eq!(
            expiry_from(UnixTime::since_unix_epoch(Duration::from_secs(u64::MAX)), 5).as_secs(),
            u64::MAX
        );
    }
}

#[cfg(test)]
#[cfg(feature = "native")]
mod validate_tests {
    use alloc::vec;

    use super::*;
    use crate::crypto::native::sign::any_supported_type;

    const DC_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 44363, 44];

    /// An Ed25519 end-entity certificate (self-signed), with or without the
    /// `DelegationUsage` extension and the `digitalSignature` key usage.
    fn cert(
        delegation: bool,
        digital_signature: bool,
    ) -> (CertificateDer<'static>, Arc<dyn SigningKey>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        // Within `valid_time`'s 32-bit reach of the default notBefore (1975).
        params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        if delegation {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    DC_OID,
                    vec![0x05, 0x00],
                ));
        }
        if digital_signature {
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        }
        let cert = params.self_signed(&key).unwrap();
        let signing = any_supported_type(&browntls_pki::PrivateKeyDer::Pkcs8(
            browntls_pki::PrivatePkcs8KeyDer::from(key.serialize_der()),
        ))
        .unwrap();
        (CertificateDer::from(cert.der().to_vec()), signing)
    }

    fn credential(
        end_entity: &CertificateDer<'_>,
        key: &dyn SigningKey,
        expiry: u64,
    ) -> DelegatedCredential {
        let not_before = EndEntityCert::try_from(end_entity)
            .unwrap()
            .not_before()
            .as_secs();
        let dc_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cred = Credential {
            valid_time: u32::try_from(expiry - not_before).unwrap(),
            dc_cert_verify_algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
            public_key: SubjectPublicKeyInfoDer::from(
                rcgen::PublicKeyData::subject_public_key_info(&dc_key),
            ),
        };
        // Signed directly: `issue` refuses certificates without delegation.
        let algorithm = SignatureScheme::ED25519;
        let signer = key.choose_scheme(&[algorithm]).unwrap();
        let signature = signer
            .sign(&DelegatedCredential::signed_message(
                Side::Server,
                end_entity,
                &cred,
                algorithm,
            ))
            .unwrap();
        DelegatedCredential {
            credential: cred,
            algorithm,
            signature,
        }
    }

    fn check(
        dc: &DelegatedCredential,
        end_entity: &CertificateDer<'_>,
        dc_schemes: &[SignatureScheme],
        cv_scheme: SignatureScheme,
        now: u64,
    ) -> Result<HandshakeSignatureValid, Error> {
        let presented = Presented {
            side: Side::Server,
            end_entity,
            offered_dc_schemes: dc_schemes,
            offered_sig_schemes: &[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ],
            cert_verify_scheme: cv_scheme,
            now: UnixTime::since_unix_epoch(Duration::from_secs(now)),
        };
        let spki = EndEntityCert::try_from(end_entity)
            .unwrap()
            .subject_public_key_info()
            .into_owned();
        validate(dc, &presented, |msg, dss| {
            crate::webpki::verify_tls13_signature_with_raw_key(
                msg,
                &spki,
                dss,
                &crate::crypto::native::SUPPORTED_SIG_ALGS,
            )
        })
    }

    #[test]
    fn checks_in_rfc_order() {
        const P256: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
        let now = UnixTime::now().as_secs();
        let (ee, key) = cert(true, true);
        let dc = credential(&ee, &*key, now + 3600);
        assert!(check(&dc, &ee, &[P256], P256, now).is_ok());

        let err = |e: PeerMisbehaved| Err(Error::PeerMisbehaved(e));
        // §4.1.1: the credential's scheme must be one we offered.
        assert_eq!(
            check(&dc, &ee, &[SignatureScheme::ED25519], P256, now).map(|_| ()),
            err(PeerMisbehaved::DelegatedCredentialWithUnofferedScheme)
        );
        // §4.1.3 1: expired.
        assert_eq!(
            check(&dc, &ee, &[P256], P256, now + 3600).map(|_| ()),
            err(PeerMisbehaved::DelegatedCredentialExpired)
        );
        // 2: more than seven days left.
        assert_eq!(
            check(&dc, &ee, &[P256], P256, now - MAX_VALIDITY.as_secs()).map(|_| ()),
            err(PeerMisbehaved::DelegatedCredentialValidityTooLong)
        );
        // 3: CertificateVerify with another scheme.
        assert_eq!(
            check(&dc, &ee, &[P256], SignatureScheme::ED25519, now).map(|_| ()),
            err(PeerMisbehaved::DelegatedCredentialSchemeMismatch)
        );
        // 4: the certificate must permit delegation.
        for (delegation, ku) in [(false, true), (true, false)] {
            let (ee, key) = cert(delegation, ku);
            let dc = credential(&ee, &*key, now + 3600);
            assert_eq!(
                check(&dc, &ee, &[P256], P256, now).map(|_| ()),
                err(PeerMisbehaved::DelegatedCredentialWithoutDelegationUsage)
            );
        }
        // 5: signed by the certificate key, over this certificate and credential.
        let (other, _) = cert(true, true);
        let mut forged = credential(&other, &*key, now + 3600);
        forged.credential.valid_time = dc.credential.valid_time;
        assert_eq!(
            check(&forged, &ee, &[P256], P256, now).map(|_| ()),
            err(PeerMisbehaved::DelegatedCredentialBadSignature)
        );
        let mut client = dc.clone();
        client.signature = key
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap()
            .sign(&DelegatedCredential::signed_message(
                Side::Client,
                &ee,
                &dc.credential,
                dc.algorithm,
            ))
            .unwrap();
        assert_eq!(
            check(&client, &ee, &[P256], P256, now).map(|_| ()),
            err(PeerMisbehaved::DelegatedCredentialBadSignature)
        );
    }

    #[test]
    fn no_rsa_encryption_keys() {
        const RSAE: [SignatureScheme; 3] = [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ];
        for scheme in RSAE {
            assert!(!credential_scheme_allowed(scheme), "{scheme:?}");
        }
        for scheme in [
            SignatureScheme::RSA_PSS_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ] {
            assert!(credential_scheme_allowed(scheme), "{scheme:?}");
        }

        let now = UnixTime::now().as_secs();
        let (ee, key) = cert(true, true);
        let mut dc = credential(&ee, &*key, now + 3600);
        // Rejected by a validator even when it offered the scheme
        // (illegal_parameter, like every validation failure).
        dc.credential.dc_cert_verify_algorithm = SignatureScheme::RSA_PSS_SHA256;
        assert_eq!(
            check(&dc, &ee, &RSAE, SignatureScheme::RSA_PSS_SHA256, now).map(|_| ()),
            Err(Error::PeerMisbehaved(
                PeerMisbehaved::DelegatedCredentialWithUnofferedScheme
            ))
        );
        // Neither issued nor attached.
        let refused = |r: Result<(), Error>| matches!(r, Err(Error::General(msg)) if msg.contains("rsaEncryption"));
        assert!(refused(
            DelegatedCredential::issue(
                Side::Server,
                &ee,
                &*key,
                &[SignatureScheme::ED25519],
                dc.credential.clone(),
            )
            .map(|_| ())
        ));
        assert!(refused(
            DelegatedCredentialKey::new(&ee, dc, key).map(|_| ())
        ));
    }

    #[test]
    fn not_beyond_the_certificate() {
        let (ee, key) = cert(true, true);
        let not_after = EndEntityCert::try_from(&ee).unwrap().not_after().as_secs();
        let dc = credential(&ee, &*key, not_after + 60);
        assert_eq!(
            check(
                &dc,
                &ee,
                &[SignatureScheme::ECDSA_NISTP256_SHA256],
                SignatureScheme::ECDSA_NISTP256_SHA256,
                not_after - 3600,
            )
            .map(|_| ()),
            Err(Error::PeerMisbehaved(
                PeerMisbehaved::DelegatedCredentialValidityTooLong
            ))
        );
    }
}
