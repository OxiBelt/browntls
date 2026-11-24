//! The exported-authenticator operation of the `tls_auth` target
//! (RFC 9261): requests, answers, spontaneous server authenticators,
//! tampered, replayed and fuzzed messages between a connected client and
//! server, each buffered or unbuffered.

use std::sync::Arc;

use browntls_core::client::UnbufferedClientConnection;
use browntls_core::exported_authenticator::{
    AuthenticatorRequestExtensions, authenticator_context,
};
use browntls_core::pki_types::ServerName;
use browntls_core::server::{UnbufferedServerConnection, WebPkiClientVerifier};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{
    ClientConfig, ClientConnection, DistinguishedName, ServerConfig, ServerConnection,
    SignatureScheme, SupportedProtocolVersion, version,
};

use super::unbuffered::{Client, End, Server, connect};
use super::{State, fixture, ml_dsa_scheme, pick_scheme, tls13_scheme};
use crate::input::Input;

// --------------------------------------------------- exported authenticators

/// A connected pair and what each side has used.
pub(super) struct Ea {
    client: Client,
    server: Server,
    /// Contexts of requests each side made.
    client_requests: Vec<Vec<u8>>,
    server_requests: Vec<Vec<u8>>,
    /// Unanswered requests the client made, for fuzzed answers.
    pending: Vec<Vec<u8>>,
}

/// A connected pair over `versions`; each end uses the unbuffered API when
/// its flag says so.
fn connect_ea(
    versions: &[&'static SupportedProtocolVersion],
    unbuffered_client: bool,
    unbuffered_server: bool,
) -> Ea {
    let fixture = fixture();
    let client_config = ClientConfig::builder_with_provider(fixture.provider.clone())
        .with_protocol_versions(versions)
        .expect("versions")
        .with_root_certificates(fixture.roots.clone())
        .with_no_client_auth();
    let verifier = WebPkiClientVerifier::builder_with_provider(
        fixture.roots.clone(),
        fixture.provider.clone(),
    )
    .allow_unauthenticated()
    .build()
    .expect("client verifier");
    let server_config = ServerConfig::builder_with_provider(fixture.provider.clone())
        .with_protocol_versions(versions)
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(fixture.ea_server.clone())));
    let name = ServerName::try_from("localhost").expect("name");
    let (client_config, server_config) = (Arc::new(client_config), Arc::new(server_config));
    let mut client = if unbuffered_client {
        End::unbuffered(UnbufferedClientConnection::new(client_config, name).expect("client"))
    } else {
        End::Buffered(ClientConnection::new(client_config, name).expect("client"))
    };
    let mut server = if unbuffered_server {
        End::unbuffered(UnbufferedServerConnection::new(server_config).expect("server"))
    } else {
        End::Buffered(ServerConnection::new(server_config).expect("server"))
    };
    let result = connect(&mut client, &mut server);
    assert!(result.is_ok(), "{result:?}");
    Ea {
        client,
        server,
        client_requests: Vec::new(),
        server_requests: Vec::new(),
        pending: Vec::new(),
    }
}

/// Request extensions from the input, and the schemes they leave to sign
/// an authenticator with: the TLS 1.3 ones other than ML-DSA, which nothing
/// specifies for exported authenticators (with `None` the verifier's
/// defaults).
fn pick_extensions(input: &mut Input) -> (AuthenticatorRequestExtensions, Vec<SignatureScheme>) {
    let schemes = (input.choose(3) != 0).then(|| {
        let mut schemes: Vec<SignatureScheme> =
            (0..input.choose(4)).map(|_| pick_scheme(input)).collect();
        if input.bool() {
            schemes.push(SignatureScheme::ECDSA_NISTP256_SHA256);
            schemes.push(SignatureScheme::ED25519);
        }
        schemes
    });
    // At least one authority: `request_authenticator` encodes an empty list
    // as an empty `certificate_authorities` extension, which the peer
    // rejects (a library finding, reported separately; not fuzzed here so
    // that the rest of the exchange stays reachable).
    let authorities = input.bool().then(|| {
        (0..1 + input.choose(3))
            .map(|_| DistinguishedName::in_sequence(input.short_field()))
            .collect()
    });
    let effective = match &schemes {
        Some(s) => s
            .iter()
            .copied()
            .filter(|s| tls13_scheme(*s) && !ml_dsa_scheme(*s))
            .collect(),
        None => vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ],
    };
    (
        AuthenticatorRequestExtensions {
            signature_schemes: schemes,
            certificate_authorities: authorities,
        },
        effective,
    )
}

/// The identity an answer uses: the server's, another name's, the
/// client's, or none (declining).
fn pick_identity(input: &mut Input) -> (usize, Option<&'static CertifiedKey>) {
    let fixture = fixture();
    let index = input.choose(4);
    let key = match index {
        0 => Some(&fixture.ea_server),
        1 => Some(&fixture.ea_other),
        2 => Some(&fixture.ea_client),
        _ => None,
    };
    (index, key)
}

/// The scheme each identity's key signs with.
fn identity_scheme(index: usize) -> Option<SignatureScheme> {
    match index {
        0 | 1 => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
        2 => Some(SignatureScheme::ED25519),
        _ => None,
    }
}

/// Flips a bit of `authenticator` where the input says.
fn tampered(input: &mut Input, authenticator: &[u8]) -> Vec<u8> {
    let mut out = authenticator.to_vec();
    let at = usize::from(input.u16()) % out.len();
    out[at] ^= 1 << (input.byte() % 8);
    out
}

/// Exchange input: on first use a mode byte (bit 0: TLS 1.2, bit 1: an
/// unbuffered client, bit 2: an unbuffered server), then the exchange
/// selector and its arguments.
pub(super) fn exported(input: &mut Input, state: &mut State) {
    if state.ea.is_none() {
        static TLS13: &[&SupportedProtocolVersion] = &[&version::TLS13];
        static TLS12: &[&SupportedProtocolVersion] = &[&version::TLS12];
        let mode = input.byte();
        let versions = if mode & 1 != 0 { TLS12 } else { TLS13 };
        state.ea = Some(connect_ea(versions, mode & 2 != 0, mode & 4 != 0));
    }
    let Some(ea) = state.ea.as_mut() else {
        return;
    };
    let fixture = fixture();
    // Every exchange, finished or refused early, ends with the check
    // below.
    'exchange: {
        match input.choose(5) {
            0 => {
                // The client asks, the server answers.
                let context = input.short_field().to_vec();
                let (extensions, schemes) = pick_extensions(input);
                let (index, identity) = pick_identity(input);
                let tamper = input.bool();
                let request = ea.client.request_authenticator(&context, &extensions);
                let fresh = !context.is_empty() && !ea.client_requests.contains(&context);
                let Ok(request) = request else {
                    assert!(!fresh || schemes.is_empty(), "request refused");
                    break 'exchange;
                };
                assert!(fresh && !schemes.is_empty(), "request made");
                assert_eq!(request[0], 17, "a ClientCertificateRequest");
                ea.client_requests.push(context.clone());
                let auth = ea
                    .server
                    .authenticator(Some(&request), identity)
                    .expect("the server answers");
                let signs = identity_scheme(index).is_some_and(|s| schemes.contains(&s));
                assert_eq!(
                    authenticator_context(&auth).ok(),
                    signs.then(|| context.clone())
                );
                if tamper {
                    let bad = tampered(input, &auth);
                    assert!(
                        ea.client
                            .validate_authenticator(Some(&request), &bad)
                            .is_err(),
                        "a tampered authenticator validated"
                    );
                }
                let result = ea.client.validate_authenticator(Some(&request), &auth);
                match (signs, index) {
                    (false, _) => assert_eq!(result, Ok(None), "declined"),
                    (true, 0) => {
                        assert_eq!(result, Ok(Some(fixture.ea_server.cert.clone())), "answered")
                    }
                    // Wrong name, or a client certificate.
                    (true, _) => assert!(result.is_err(), "{index}: {result:?}"),
                }
                // Never twice.
                assert!(
                    ea.client
                        .validate_authenticator(Some(&request), &auth)
                        .is_err(),
                    "a replayed authenticator validated"
                );
                if result.is_err() && ea.pending.len() < 4 {
                    ea.pending.push(request);
                }
            }
            1 => {
                // The server asks, the client answers.
                let context = input.short_field().to_vec();
                let (extensions, schemes) = pick_extensions(input);
                let (index, identity) = pick_identity(input);
                let tamper = input.bool();
                let request = ea.server.request_authenticator(&context, &extensions);
                let fresh = !context.is_empty() && !ea.server_requests.contains(&context);
                let Ok(request) = request else {
                    assert!(!fresh || schemes.is_empty(), "request refused");
                    break 'exchange;
                };
                assert!(fresh && !schemes.is_empty(), "request made");
                assert_eq!(request[0], 13, "a CertificateRequest");
                ea.server_requests.push(context.clone());
                let auth = ea
                    .client
                    .authenticator(&request, identity)
                    .expect("the client answers");
                let signs = identity_scheme(index).is_some_and(|s| schemes.contains(&s));
                if tamper {
                    let bad = tampered(input, &auth);
                    assert!(
                        ea.server.validate_authenticator(&request, &bad).is_err(),
                        "a tampered authenticator validated"
                    );
                }
                let result = ea.server.validate_authenticator(&request, &auth);
                match (signs, index) {
                    (false, _) => assert_eq!(result, Ok(None), "declined"),
                    (true, 2) => {
                        assert_eq!(result, Ok(Some(fixture.ea_client.cert.clone())), "answered")
                    }
                    // Server certificates lack the clientAuth purpose.
                    (true, _) => assert!(result.is_err(), "{index}: {result:?}"),
                }
                assert!(
                    ea.server.validate_authenticator(&request, &auth).is_err(),
                    "a replayed authenticator validated"
                );
            }
            2 => {
                // A spontaneous server authenticator.
                let (index, identity) = pick_identity(input);
                let tamper = input.bool();
                let auth = ea.server.authenticator(None, identity);
                let Ok(auth) = auth else {
                    assert!(identity.is_none(), "spontaneous authenticator refused");
                    break 'exchange;
                };
                assert!(identity.is_some());
                let context = authenticator_context(&auth).expect("a context");
                assert_eq!(context.len(), 32);
                if tamper {
                    let bad = tampered(input, &auth);
                    assert!(ea.client.validate_authenticator(None, &bad).is_err());
                }
                let result = ea.client.validate_authenticator(None, &auth);
                if index == 0 {
                    assert_eq!(result, Ok(Some(fixture.ea_server.cert.clone())));
                } else {
                    assert!(result.is_err(), "{index}: {result:?}");
                }
                assert!(ea.client.validate_authenticator(None, &auth).is_err());
            }
            3 => {
                // Fuzzed authenticators never validate.
                let auth = input.field();
                let _ = authenticator_context(auth);
                let request = ea.pending.first().cloned();
                if let Some(request) = &request {
                    assert!(
                        ea.client
                            .validate_authenticator(Some(request), auth)
                            .is_err()
                    );
                }
                assert!(ea.client.validate_authenticator(None, auth).is_err());
                let fuzzed_request = input.field();
                assert!(
                    ea.client
                        .validate_authenticator(Some(fuzzed_request), auth)
                        .is_err()
                );
                assert!(
                    ea.server
                        .validate_authenticator(fuzzed_request, auth)
                        .is_err()
                );
            }
            _ => {
                // Fuzzed requests are answered or refused, without panicking;
                // nothing the peer did not ask for validates.
                let request = input.field();
                let (_, identity) = pick_identity(input);
                if let Ok(auth) = ea.server.authenticator(Some(request), identity) {
                    assert!(
                        ea.client
                            .validate_authenticator(Some(request), &auth)
                            .is_err()
                    );
                    assert!(ea.client.validate_authenticator(None, &auth).is_err());
                }
                if let Ok(auth) = ea.client.authenticator(request, identity) {
                    assert!(ea.server.validate_authenticator(request, &auth).is_err());
                }
            }
        }
    }
    // The messages travel over the application protocol: no exchange
    // queues TLS records on either connection.
    assert_eq!(ea.client.take_output().map(|out| out.len()), Ok(0));
    assert_eq!(ea.server.take_output().map(|out| out.len()), Ok(0));
}
