//! The legacy schemes, verifier doubles that advertise them on top of the
//! provider's schemes, and a rustls client (an independent peer) whose
//! hello lists them, as an RFC 9963 implementation that does not filter
//! them would send it.

#![allow(unreachable_pub)]

use std::sync::Arc;

use browntls_core::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types as rpki;

use crate::common::{
    Chain, PinnedClientVerifier, PinnedServerVerifier, SchemeRecordingClientVerifier,
    SchemeRecordingServerVerifier,
};
use crate::doubles::default_schemes;

/// The three schemes of RFC 9963, in code point order.
pub const LEGACY: [SignatureScheme; 3] = [
    SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
    SignatureScheme::RSA_PKCS1_SHA384_LEGACY,
    SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
];

/// Their code points.
pub const LEGACY_CODES: [u16; 3] = [0x0420, 0x0520, 0x0620];

/// The same code points as `SignatureScheme::Unknown` values, which an
/// application can construct.
pub const LEGACY_AS_UNKNOWN: [SignatureScheme; 3] = [
    SignatureScheme::Unknown(0x0420),
    SignatureScheme::Unknown(0x0520),
    SignatureScheme::Unknown(0x0620),
];

/// The text of the error of a TLS 1.2 peer whose key chose a scheme
/// defined for TLS 1.3 only.
pub const TLS13_ONLY: &str = "signing key chose a TLS 1.3-only signature scheme";

/// The text of the error of a TLS 1.3 server whose key chose a scheme
/// meant for client authentication only.
pub const CLIENT_AUTH_ONLY: &str =
    "signing key chose a signature scheme for client authentication only";

/// The provider's default schemes followed by the legacy ones, as a
/// verifier whose algorithms map them would list them.
pub fn with_legacy() -> Vec<SignatureScheme> {
    let mut schemes = default_schemes();
    schemes.extend(LEGACY);
    schemes
}

/// Whether `schemes` has a legacy code point, named or `Unknown`.
pub fn has_any_legacy(schemes: &[SignatureScheme]) -> bool {
    schemes
        .iter()
        .any(|scheme| LEGACY_CODES.contains(&u16::from(*scheme)))
}

/// A client's verifier pinning `chain` that advertises the legacy schemes
/// too (it cannot verify a legacy signature, and is never given one).
pub fn legacy_server_verifier(chain: &Chain) -> Arc<SchemeRecordingServerVerifier> {
    SchemeRecordingServerVerifier::new(PinnedServerVerifier::new(chain), &with_legacy())
}

/// A server's client verifier pinning `chain` that advertises the legacy
/// schemes too.
pub fn legacy_client_verifier(
    chain: &Chain,
    mandatory: bool,
) -> Arc<SchemeRecordingClientVerifier> {
    SchemeRecordingClientVerifier::new(PinnedClientVerifier::new(chain, mandatory), &with_legacy())
}

/// The fatal alert among the plaintext records of `flight`, if any.
pub fn plaintext_fatal_alert(flight: &[u8]) -> Option<u8> {
    let mut at = 0;
    while at + 5 <= flight.len() {
        let len = crate::doubles::u16_at(flight, at + 3);
        if flight[at] == 21 && len == 2 && flight[at + 5] == 2 {
            return Some(flight[at + 6]);
        }
        at += 5 + len;
    }
    None
}

// ---------------------------------------------------------------------------
// A rustls TLS 1.3 client listing the legacy schemes
// ---------------------------------------------------------------------------

/// A rustls server verifier that pins the end entity of a chain and lists
/// rustls's own schemes followed by the legacy code points. It is never
/// given a handshake signature to check here.
#[derive(Debug)]
struct ListingLegacy {
    end_entity: Vec<u8>,
    offer: Vec<rustls::SignatureScheme>,
}

impl ServerCertVerifier for ListingLegacy {
    fn verify_server_cert(
        &self,
        end_entity: &rpki::CertificateDer<'_>,
        _intermediates: &[rpki::CertificateDer<'_>],
        _server_name: &rpki::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rpki::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.end_entity {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("not the pinned certificate".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rpki::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("no TLS 1.2 here".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rpki::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(format!(
            "given a server signature with {:?}",
            dss.scheme
        )))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.offer.clone()
    }
}

/// A rustls TLS 1.3 client for `localhost` that pins `chain` and lists
/// rustls's schemes and then the legacy code points in its hello.
pub fn rustls_client(chain: &Chain) -> rustls::ClientConnection {
    let provider = rustls::crypto::ring::default_provider();
    let mut offer = provider
        .signature_verification_algorithms
        .supported_schemes();
    offer.extend(LEGACY_CODES.map(rustls::SignatureScheme::from));
    let verifier = ListingLegacy {
        end_entity: chain.cert_chain()[0].as_ref().to_vec(),
        offer,
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    rustls::ClientConnection::new(
        Arc::new(config),
        rpki::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap()
}

/// Everything the rustls client has queued to send.
pub fn rustls_flight(c: &mut rustls::ClientConnection) -> Vec<u8> {
    let mut buf = Vec::new();
    while c.wants_write() {
        c.write_tls(&mut buf).unwrap();
    }
    buf
}

/// Gives `bytes` to the rustls client and processes them.
pub fn rustls_receive(c: &mut rustls::ClientConnection, mut bytes: &[u8]) -> rustls::Error {
    while !bytes.is_empty() {
        c.read_tls(&mut bytes).unwrap();
        if let Err(err) = c.process_new_packets() {
            return err;
        }
    }
    panic!("the rustls client did not fail")
}
