//! Real TLS and QUIC certificate flights with an application-owned OCSP
//! response.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::pki_types::ServerName;
use browntls_core::revocation::{
    CtLogKey, OcspHttpRequest, RevocationData, RevocationDataError, RevocationDataSource,
    RevocationDigests, RevocationPolicy, RevocationQuery, RevocationResponse, RevocationStatus,
    ServerStapleResolver, SharedRevocationData, StapleInstall,
};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::{
    CertificateError, ClientConfig, ClientConnection, Connection, Error, ServerConfig,
    ServerConnection, SupportedProtocolVersion, quic, version,
};

use crate::connection::provider;

use super::clubcard;
use super::fixtures::{Clock, Fixture, NEXT_UPDATE, NOW, RESPONDER, SCT_TIME, time};

fn policy(fixture: &Fixture) -> RevocationPolicy {
    let digests = RevocationDigests::rustcrypto();
    let spki = &fixture.log_spki;
    let log = CtLogKey::new(spki.clone())
        .with_expected_id((digests.sha256)(spki))
        .with_timestamp_window(SCT_TIME, SCT_TIME + 1);
    let source = Arc::new(SharedRevocationData::new());
    let data = |generation| {
        RevocationData::new(clubcard::snapshot(generation), vec![log.clone()], &digests).unwrap()
    };
    source.replace(data(1)).unwrap();
    source.replace(data(2)).unwrap();
    assert!(matches!(
        source.replace(data(1)),
        Err(RevocationDataError::NotNewer { .. })
    ));
    let current = source.current().unwrap();
    assert_eq!(current.generation(), 2);
    assert_eq!(current.expiry(), time(3000));

    RevocationPolicy::new(digests)
        .check_full_chain()
        .with_revocation_data(source)
        .with_live_ocsp(Arc::new(Clock))
        .with_max_live_queries(2)
}

pub(super) fn configs(
    fixture: &'static Fixture,
    version: &'static SupportedProtocolVersion,
    client_auth: bool,
    best_effort: bool,
) -> (&'static Arc<ClientConfig>, &'static Arc<ServerConfig>) {
    type Configs = (Arc<ClientConfig>, Arc<ServerConfig>);
    static TLS13: OnceLock<Configs> = OnceLock::new();
    static TLS12: OnceLock<Configs> = OnceLock::new();
    static MUTUAL: OnceLock<Configs> = OnceLock::new();
    static BEST_EFFORT: OnceLock<Configs> = OnceLock::new();

    let slot = if client_auth {
        &MUTUAL
    } else if best_effort {
        &BEST_EFFORT
    } else if version == &version::TLS12 {
        &TLS12
    } else {
        &TLS13
    };
    let (client, server) = slot.get_or_init(|| {
        let provider = provider(false);
        let revocation = policy(fixture);
        let revocation = if best_effort {
            revocation.best_effort()
        } else {
            revocation
        };
        let server_verifier =
            WebPkiServerVerifier::builder_with_provider(fixture.roots(), provider.clone())
                .with_revocation_policy(revocation.clone())
                .build()
                .unwrap();
        let client = ClientConfig::builder_with_details(provider.clone(), Arc::new(Clock))
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier);
        let server = ServerConfig::builder_with_details(provider.clone(), Arc::new(Clock))
            .with_protocol_versions(&[version])
            .unwrap();
        let (client, server) = if client_auth {
            let client_verifier =
                WebPkiClientVerifier::builder_with_provider(fixture.roots(), provider)
                    .with_revocation_policy(revocation)
                    .build()
                    .unwrap();
            (
                client
                    .with_client_auth_cert(vec![fixture.leaf.clone()], fixture.key().into())
                    .unwrap(),
                server.with_client_cert_verifier(client_verifier),
            )
        } else {
            (client.with_no_client_auth(), server.with_no_client_auth())
        };
        let server = server
            .with_single_cert(vec![fixture.leaf.clone()], fixture.key().into())
            .unwrap();
        (Arc::new(client), Arc::new(server))
    });
    (client, server)
}

pub(super) fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

fn inspect_query(query: &RevocationQuery, fixture: &Fixture) {
    assert!(
        query
            .responder_urls()
            .iter()
            .map(String::as_str)
            .eq([RESPONDER])
    );
    let issuer = browntls_pki::Cert::try_from(&fixture.ca).unwrap();
    let sha256 = RevocationDigests::native().sha256;
    assert_eq!(
        *query.issuer_key_hash(),
        sha256(issuer.subject_public_key_info().as_ref())
    );
    assert!(!query.request_der().is_empty());
    assert!(matches!(
        query.http_request(RESPONDER),
        Ok(OcspHttpRequest::Get { .. })
    ));
    let long_url = format!("{RESPONDER}{}", "a".repeat(255));
    assert!(matches!(
        query.http_request(&long_url),
        Ok(OcspHttpRequest::Post { body, .. }) if body == query.request_der()
    ));
}

pub(super) fn staple_resolver(fixture: &Fixture) -> ServerStapleResolver {
    let provider = provider(false);
    let mut credential = fixture.certified_key(&provider);
    credential.set_sct_list(Some(fixture.scts.clone())).unwrap();
    assert_eq!(credential.sct_list(), Some(fixture.scts.as_slice()));
    ServerStapleResolver::new(
        credential,
        fixture.roots(),
        provider,
        RevocationDigests::native(),
        Arc::new(Clock),
    )
    .unwrap()
}

fn staple(fixture: &Fixture, bytes: &[u8]) {
    let resolver = staple_resolver(fixture);
    let old = resolver.refresh_query().unwrap().unwrap();
    inspect_query(old.query(), fixture);
    resolver
        .replace(fixture.certified_key(&provider(false)))
        .unwrap();
    assert_eq!(
        resolver.install(&old, fixture.response.clone()).unwrap(),
        StapleInstall::Obsolete
    );
    let query = resolver.refresh_query().unwrap().unwrap();
    let response = if bytes.is_empty() {
        fixture.response.clone()
    } else {
        bytes.to_vec()
    };
    let installed = resolver.install(&query, response);
    if bytes.is_empty() {
        let expires = time(NEXT_UPDATE);
        assert_eq!(installed.unwrap(), StapleInstall::Installed { expires });
        assert_eq!(resolver.staple_expiry(), Some(expires));
        assert_eq!(
            resolver.remaining_lifetime(expires),
            Some(Duration::from_secs(NEXT_UPDATE - NOW))
        );
    }
}

fn transfer(from: &mut Connection, to: &mut Connection) -> bool {
    let mut flight = Vec::new();
    from.write_tls(&mut flight).unwrap();
    let mut reader = flight.as_slice();
    while !reader.is_empty() {
        assert_ne!(to.read_tls(&mut reader).unwrap(), 0);
    }
    to.process_new_packets().unwrap().revocation_pending()
}

fn buffered(fixture: &'static Fixture, mode: u8, bytes: &[u8]) {
    let best_effort = mode & 2 != 0;
    let version = if mode & 1 == 0 || best_effort {
        &version::TLS13
    } else {
        &version::TLS12
    };
    let (client, server) = configs(fixture, version, false, best_effort);
    let mut client =
        Connection::Client(ClientConnection::new(client.clone(), localhost()).unwrap());
    let mut server = Connection::Server(ServerConnection::new(server.clone()).unwrap());
    assert!(!transfer(&mut client, &mut server));
    assert!(transfer(&mut server, &mut client));
    assert!(client.peer_certificates().is_none());
    let query = client.pending_revocation().unwrap();
    inspect_query(query, fixture);
    let id = query.id();
    assert!(
        client
            .resolve_peer_revocation(id.wrapping_add(1), RevocationResponse::Unavailable)
            .is_err()
    );
    assert_eq!(client.pending_revocation().unwrap().id(), id);

    let unavailable = mode & 4 != 0;
    let response = if unavailable {
        RevocationResponse::Unavailable
    } else if bytes.is_empty() {
        RevocationResponse::Der(fixture.response.clone())
    } else {
        RevocationResponse::Der(bytes.to_vec())
    };
    let result = client.resolve_peer_revocation(id, response);
    if unavailable && !best_effort {
        assert!(matches!(
            result,
            Err(Error::InvalidCertificate(
                CertificateError::UnknownRevocationStatus
            ))
        ));
        assert!(client.peer_certificates().is_none());
        return;
    }
    if !bytes.is_empty() && !unavailable && result.is_err() {
        assert!(client.peer_certificates().is_none());
        return;
    }
    result.unwrap();
    for _ in 0..3 {
        assert!(!transfer(&mut client, &mut server));
        assert!(!transfer(&mut server, &mut client));
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    if bytes.is_empty() || unavailable {
        let expected = if unavailable {
            RevocationStatus::Indeterminate
        } else {
            RevocationStatus::Good
        };
        assert_eq!(client.peer_revocation_status(), Some(expected));
    }
}

fn quic_roundtrip(fixture: &'static Fixture, bytes: &[u8]) {
    let (client, server) = configs(fixture, &version::TLS13, false, false);
    let mut client = quic::Connection::Client(
        quic::ClientConnection::new(client.clone(), quic::Version::V1, localhost(), vec![])
            .unwrap(),
    );
    let mut server = quic::Connection::Server(
        quic::ServerConnection::new(server.clone(), quic::Version::V1, vec![]).unwrap(),
    );

    let transfer = |from: &mut quic::Connection, to: &mut quic::Connection| {
        for _ in 0..4 {
            let mut flight = Vec::new();
            let keys = from.write_hs(&mut flight);
            if !flight.is_empty() {
                to.read_hs(&flight).unwrap();
            }
            if keys.is_none() {
                return;
            }
        }
        panic!("too many QUIC handshake levels");
    };
    transfer(&mut client, &mut server);
    transfer(&mut server, &mut client);
    assert!(client.peer_certificates().is_none());
    let id = client.pending_revocation().unwrap().id();
    let response = if bytes.is_empty() {
        fixture.response.clone()
    } else {
        bytes.to_vec()
    };
    let result = client.resolve_peer_revocation(id, RevocationResponse::Der(response));
    if !bytes.is_empty() && result.is_err() {
        assert!(client.peer_certificates().is_none());
        return;
    }
    result.unwrap();
    transfer(&mut client, &mut server);
    transfer(&mut server, &mut client);
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert_eq!(
        client.peer_revocation_status(),
        Some(RevocationStatus::Good)
    );
}

pub(super) fn run(fixture: &'static Fixture, input: &[u8]) {
    let Some((&mode, bytes)) = input.split_first() else {
        return;
    };
    match mode {
        8 => quic_roundtrip(fixture, bytes),
        9 => staple(fixture, bytes),
        _ => buffered(fixture, mode, bytes),
    }
}
