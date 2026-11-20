//! Types shared by the TLS 1.2 and TLS 1.3 server handshakes.

use browntls_pki::{CertificateDer, UnixTime};

use super::server_conn::ServerConfig;
use crate::common_state::CommonState;
use crate::delegated_credential::DelegatedCredential;
use crate::enums::CertificateType;
use crate::error::Error;
use crate::msgs::handshake::{CertificateChain, ClientHelloPayload};
use crate::revocation::{PeerEvidence, RevocationCheck};
use crate::sign::{CertifiedKey, SigningKey};

/// The certificate and key chosen for this connection.
pub(super) struct ActiveCertifiedKey<'a> {
    certified_key: &'a CertifiedKey,
}

impl<'a> ActiveCertifiedKey<'a> {
    pub(super) fn from_certified_key(certkey: &'a CertifiedKey) -> Self {
        Self {
            certified_key: certkey,
        }
    }

    /// The credential itself, with its per-certificate OCSP responses and
    /// SCT list.
    pub(super) fn certified_key(&self) -> &'a CertifiedKey {
        self.certified_key
    }

    pub(super) fn get_cert(&self) -> &'a [CertificateDer<'static>] {
        &self.certified_key.cert
    }

    pub(super) fn get_key(&self) -> &'a dyn SigningKey {
        &*self.certified_key.key
    }

    /// The end entity's OCSP response, if a non-empty one is configured.
    pub(super) fn get_ocsp(&self) -> Option<&'a [u8]> {
        self.certified_key.ocsp_for(0)
    }

    /// The end entity's encoded `SignedCertificateTimestampList`.
    pub(super) fn get_sct_list(&self) -> Option<&'a [u8]> {
        self.certified_key.sct_list()
    }
}

/// The end entity's `TransItemList` to send in `transparency_info` (RFC
/// 9162 §6.5): only to a client that offered the extension, only with an
/// X.509 certificate, and only if one is configured. The callers send it
/// on full handshakes only (§6.5: it is "omitted" when resuming).
pub(super) fn transparency_info_for<'a>(
    key: &'a CertifiedKey,
    client_hello: &ClientHelloPayload,
    server_cert_type: Option<CertificateType>,
) -> Option<&'a [u8]> {
    if client_hello.extensions.transparency_info.is_none()
        || server_cert_type == Some(CertificateType::RawPublicKey)
    {
        return None;
    }
    key.transparency_info()
}

/// Whether the client certificate verifier evaluates revocation afresh for
/// every X.509 client certificate. A verifier that takes only raw public
/// keys (RFC 7250) has no certificate whose status could be checked.
///
/// While this holds, the server asks TLS 1.3 clients for OCSP responses and
/// SCTs and requires a full handshake for certificate authentication.
pub(super) fn client_revocation_enabled(config: &ServerConfig) -> bool {
    config.verifier.revocation_enabled() && !config.verifier.requires_raw_public_keys()
}

/// A client certificate chain that passed the verifier's path validation
/// when its Certificate message arrived. The client has not yet proven
/// that it holds the key, and `revocation` may still need a status lookup:
/// that is only started once the proof (CertificateVerify) has verified, so
/// an unauthenticated peer cannot make us send requests.
pub(super) struct ClientCertAwaitingProof {
    pub(super) chain: CertificateChain<'static>,
    pub(super) revocation: RevocationCheck,
    /// The delegated credential on the end entity's TLS 1.3
    /// CertificateEntry (RFC 9345 §4.1.2), not yet validated: with one,
    /// the proof is made with its key.
    pub(super) delegated_credential: Option<DelegatedCredential>,
}

/// A client's delegated credential that passed validation, and its
/// absolute expiry.
pub(super) type ValidatedCredential = (DelegatedCredential, UnixTime);

/// Runs the client certificate verifier over the non-empty `chain` and
/// the `evidence` stapled to it, sending the alert for a failure.
pub(super) fn verify_client_cert(
    common: &mut CommonState,
    config: &ServerConfig,
    chain: CertificateChain<'static>,
    evidence: PeerEvidence<'_>,
) -> Result<ClientCertAwaitingProof, Error> {
    let Some((end_entity, intermediates)) = chain.0.split_first() else {
        return Err(Error::NoCertificatesPresented);
    };
    let now = config.current_time()?;
    let revocation = config
        .verifier
        .verify_client_cert_with_evidence(end_entity, intermediates, evidence, now)
        .map_err(|err| crate::client::tls13::send_cert_path_error_alert(common, err))?;
    Ok(ClientCertAwaitingProof {
        chain,
        revocation,
        delegated_credential: None,
    })
}
