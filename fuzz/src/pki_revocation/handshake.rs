//! Exercises connection-bound OCSP continuations after a real certificate
//! flight.

use std::sync::{Arc, OnceLock};

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use browntls_core::pki_types::{CertificateDer, ServerName, UnixTime};
use browntls_core::revocation::{
    PeerEvidence, RevocationCheck, RevocationResponse, RevocationStatus,
};
use browntls_core::{
    CertificateError, ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct,
    Error, RootCertStore, ServerConfig, ServerConnection, SideData, SignatureScheme,
};

use crate::connection::{Identity, provider};

#[derive(Debug)]
struct Defer(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for Defer {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        staple: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.0.verify_server_cert(end, chain, name, staple, now)
    }

    fn verify_server_cert_with_evidence(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<RevocationCheck, Error> {
        self.verify_server_cert(end, chain, name, &[], now)?;
        Ok(RevocationCheck::pending(
            [0; 32],
            vec![],
            vec![0x30, 0],
            |response| match response {
                RevocationResponse::Der(bytes) if bytes.first() == Some(&1) => {
                    Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
                }
                RevocationResponse::Der(bytes) if bytes.first() == Some(&2) => Ok(
                    RevocationCheck::pending([1; 32], vec![], vec![0x30, 0], |_| {
                        Ok(RevocationCheck::Complete(Some(
                            RevocationStatus::Indeterminate,
                        )))
                    }),
                ),
                _ => Err(CertificateError::UnknownRevocationStatus.into()),
            },
        ))
    }

    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(msg, cert, sig)
    }

    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(msg, cert, sig)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

fn flight<A: SideData, B: SideData>(from: &mut ConnectionCommon<A>, to: &mut ConnectionCommon<B>) {
    let mut bytes = Vec::new();
    from.write_tls(&mut bytes).unwrap();
    let mut input = bytes.as_slice();
    while !input.is_empty() {
        let Ok(n) = to.read_tls(&mut input) else {
            break;
        };
        if n == 0 || to.process_new_packets().is_err() {
            break;
        }
    }
}

pub(super) fn run(identity: &Identity, commands: &[u8]) {
    static CONFIGS: OnceLock<(Arc<ClientConfig>, Arc<ServerConfig>)> = OnceLock::new();
    let (client, server) = CONFIGS.get_or_init(|| {
        let provider = provider(false);
        let mut roots = RootCertStore::empty();
        roots.add(identity.ca.clone()).unwrap();
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .unwrap();
        let client = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&browntls_core::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Defer(verifier)))
            .with_no_client_auth();
        let server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&browntls_core::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(identity.chain.clone(), identity.key())
            .unwrap();
        (Arc::new(client), Arc::new(server))
    });
    let name = ServerName::try_from("localhost").unwrap();
    let mut client = ClientConnection::new(client.clone(), name).unwrap();
    let mut server = ServerConnection::new(server.clone()).unwrap();
    flight(&mut client, &mut server);
    flight(&mut server, &mut client);
    let mut last = client
        .pending_revocation()
        .expect("valid certificate flight")
        .id();
    for &command in commands.iter().take(16) {
        let current = client
            .pending_revocation()
            .map(|query| query.id())
            .unwrap_or(last);
        let submitted = if command & 8 == 0 {
            current
        } else {
            last.wrapping_add(5)
        };
        let response = match command & 3 {
            0 => RevocationResponse::Unavailable,
            value => RevocationResponse::Der(vec![value]),
        };
        let _ = client.resolve_peer_revocation(submitted, response);
        last = current;
        if client.pending_revocation().is_some() {
            assert!(client.is_handshaking());
            assert!(client.peer_certificates().is_none());
        } else {
            flight(&mut client, &mut server);
        }
    }
}
