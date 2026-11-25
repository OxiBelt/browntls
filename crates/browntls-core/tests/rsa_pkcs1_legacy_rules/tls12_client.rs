//! Client authentication and the legacy schemes: what a TLS 1.2
//! CertificateRequest lists, what a TLS 1.2 client's resolver and key see
//! of a request that lists them, and what a client does with a key that
//! names one whatever it is offered (RFC 9963 §3: a client signs with a
//! legacy scheme only in answer to a TLS 1.3 request that listed it).

use std::sync::Arc;

use browntls_core::sign::CertifiedKey;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, ServerConfig, ServerConnection,
    SignatureAlgorithm, SupportedProtocolVersion, version,
};

use crate::common::hello_wire::{fatal_alert, give, take_flight};
use crate::common::{
    Chain, KeyType, PinnedClientVerifier, PinnedServerVerifier, client_chain, do_handshake,
    do_handshake_until_error, provider, server_chain, server_name, transfer,
};
use crate::doubles::*;
use crate::legacy::*;

fn certified_key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

/// A TLS 1.2 server serving `server`, asking for a client certificate with
/// a verifier of `client` that advertises the legacy schemes.
fn tls12_server_asking(server: &Chain, client: &Chain, mandatory: bool) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_client_cert_verifier(legacy_client_verifier(client, mandatory))
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap()
}

/// A client over `versions` pinning `server` whose certificate comes from
/// `resolver`.
fn client_with(
    versions: &[&'static SupportedProtocolVersion],
    server: &Chain,
    resolver: Arc<RecordingClientResolver>,
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(server))
        .with_client_cert_resolver(resolver)
}

/// A TLS 1.2 CertificateRequest lists none of the legacy schemes its
/// verifier advertises: the client's resolver sees the default schemes
/// alone, and so does the request on the wire.
#[test]
fn tls12_certificate_request_leaves_legacy_out() {
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::Ed25519);
    let resolver = RecordingClientResolver::new(Some(certified_key(&client)));
    let (mut c, mut s) = connect(
        client_with(&[&version::TLS12], &server, resolver.clone()),
        tls12_server_asking(&server, &client, true),
    );
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(s.peer_certificates().unwrap(), client.cert_chain());
    let seen = resolver.seen();
    assert_eq!(seen.len(), 1);
    assert!(!has_any_legacy(&seen[0]), "{seen:?}");
    assert_eq!(seen[0], default_schemes());

    // On the wire: the plaintext TLS 1.2 CertificateRequest.
    let resolver = RecordingClientResolver::new(None);
    let (mut c, mut s) = connect(
        client_with(&[&version::TLS12], &server, resolver),
        tls12_server_asking(&server, &client, true),
    );
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut flight = take_flight(&mut s);
    let listed = add_to_tls12_certificate_request(&mut flight, &[]);
    assert_eq!(listed, default_schemes());
}

/// A TLS 1.2 client whose RSA-family key claims a legacy scheme is not
/// offered it even when the server's CertificateRequest lists the legacy
/// schemes: the resolver and the key see the request's other schemes
/// only. The request is altered on the wire (the TLS 1.2 server flight is
/// plaintext), so the handshake then fails on the Finished transcripts.
#[test]
fn tls12_client_keeps_legacy_from_its_resolver_and_key() {
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::Rsa2048);
    for claims in LEGACY {
        let key = ClaimingKey::new(claims, SignatureAlgorithm::RSA);
        let resolver =
            RecordingClientResolver::new(Some(CertifiedKey::new(client.cert_chain(), key.clone())));
        let (mut c, mut s) = connect(
            client_with(&[&version::TLS12], &server, resolver.clone()),
            tls12_server_asking(&server, &client, false),
        );
        transfer(&mut c, &mut s);
        s.process_new_packets().unwrap();
        let mut flight = take_flight(&mut s);
        let listed = add_to_tls12_certificate_request(&mut flight, &LEGACY);
        assert!(!listed.is_empty() && !has_any_legacy(&listed));
        give(&mut c, &flight);
        c.process_new_packets().unwrap();

        assert_eq!(resolver.seen(), std::slice::from_ref(&listed));
        assert_eq!(key.offered(), [listed]);

        // The client answered with an empty Certificate; the server's
        // transcript differs from the client's. With the extended master
        // secret (RFC 7627), whose session hash covers the
        // CertificateRequest, the two sides derive different keys, so the
        // client's encrypted Finished record does not decrypt:
        // bad_record_mac (20), sent in plaintext since the server has not
        // sent its ChangeCipherSpec yet.
        transfer(&mut c, &mut s);
        assert_eq!(
            s.process_new_packets().map(|_| ()),
            Err(Error::DecryptError)
        );
        assert_eq!(fatal_alert(&take_flight(&mut s)), Some(20));
    }
}

/// A client key that returns a signer for a legacy scheme whatever it is
/// offered (here, a default server's request, which lists none) is treated
/// as a key that cannot sign, in TLS 1.2 and in TLS 1.3: the client sends
/// an empty Certificate and no CertificateVerify, and the signer is never
/// asked to sign. A server that makes client authentication mandatory then
/// fails with its no-certificate error (`handshake_failure` in TLS 1.2,
/// `certificate_required` in TLS 1.3); one that makes it optional completes
/// the handshake without a peer certificate. The legacy code points as
/// `Unknown` values fare the same.
#[test]
fn client_key_naming_legacy_anyway_sends_no_certificate() {
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::Rsa2048);
    let claims_all = [&LEGACY[..], &LEGACY_AS_UNKNOWN[..]].concat();
    for (versions, tls12, no_cert_alert) in [
        (
            &[&version::TLS12][..],
            true,
            AlertDescription::HandshakeFailure,
        ),
        (
            &[&version::TLS13][..],
            false,
            AlertDescription::CertificateRequired,
        ),
    ] {
        for &claims in &claims_all {
            for mandatory in [true, false] {
                let key = ClaimingKey::ignoring_offer(claims, SignatureAlgorithm::RSA);
                let resolver = RecordingClientResolver::new(Some(CertifiedKey::new(
                    client.cert_chain(),
                    key.clone(),
                )));
                let server_config = ServerConfig::builder_with_provider(provider())
                    .with_protocol_versions(versions)
                    .unwrap()
                    .with_client_cert_verifier(PinnedClientVerifier::new(&client, mandatory))
                    .with_single_cert(server.cert_chain(), server.private_key())
                    .unwrap();
                let (mut c, mut s) = connect(
                    client_with(versions, &server, resolver.clone()),
                    server_config,
                );
                let what = format!("{versions:?} {claims:?} mandatory={mandatory}");
                if mandatory {
                    let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
                    assert_eq!(server_res, Err(Error::NoCertificatesPresented), "{what}");
                    assert_eq!(
                        client_res,
                        Err(Error::AlertReceived(no_cert_alert)),
                        "{what}"
                    );
                } else {
                    do_handshake(&mut c, &mut s).unwrap();
                    assert!(s.peer_certificates().is_none(), "{what}");
                }
                // The resolver and the key were each asked once.
                assert_eq!(resolver.seen().len(), 1, "{what}");
                let offered = key.offered();
                assert_eq!(offered.len(), 1, "{what}");
                // What a TLS 1.3 client offers its key is left to the
                // TLS 1.3 rules.
                if tls12 {
                    assert!(
                        !offered[0].is_empty() && !has_any_legacy(&offered[0]),
                        "{what}: {offered:?}"
                    );
                }
            }
        }
    }
}
