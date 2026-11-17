// Shared cases, included by `tests/exported_authenticators_unbuffered.rs`
// (RustCrypto provider) and `tests/exported_authenticators_unbuffered_native.rs`
// (native provider): RFC 9261 exported authenticators on unbuffered
// connections, against buffered and unbuffered peers.

use std::ops::DerefMut;
use std::sync::Arc;

use browntls::client::UnbufferedClientConnection;
use browntls::exported_authenticator::{AuthenticatorRequestExtensions, authenticator_context};
use browntls::pki_types::CertificateDer;
use browntls::server::UnbufferedServerConnection;
use browntls::sign::CertifiedKey;
use browntls::unbuffered::{
    ConnectionState, EncodeError, InsufficientSizeError, UnbufferedConnectionCommon,
};
use browntls::{
    ClientConfig, ClientConnection, ConnectionCommon, Error, PeerMisbehaved, ServerConfig,
    ServerConnection, SideData, SignatureScheme, SupportedProtocolVersion, version,
};
use common::*;

// ---------------------------------------------------------------- plumbing

/// Which connection API one end uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Api {
    Buffered,
    Unbuffered,
}

/// The (client, server) pairings: each with an unbuffered end, and the
/// buffered pair as a control of this harness.
const PAIRINGS: [(Api, Api); 4] = [
    (Api::Unbuffered, Api::Buffered),
    (Api::Buffered, Api::Unbuffered),
    (Api::Unbuffered, Api::Unbuffered),
    (Api::Buffered, Api::Buffered),
];

/// One end of an in-memory connection.
enum End<B, U> {
    Buffered(B),
    Unbuffered {
        conn: U,
        /// Received TLS bytes not yet discarded.
        incoming: Vec<u8>,
        /// Encoded TLS bytes not yet sent.
        outgoing: Vec<u8>,
    },
}

type Client = End<ClientConnection, UnbufferedClientConnection>;
type Server = End<ServerConnection, UnbufferedServerConnection>;

impl<B, U> End<B, U> {
    fn new(api: Api, buffered: impl FnOnce() -> B, unbuffered: impl FnOnce() -> U) -> Self {
        match api {
            Api::Buffered => Self::Buffered(buffered()),
            Api::Unbuffered => Self::Unbuffered {
                conn: unbuffered(),
                incoming: Vec::new(),
                outgoing: Vec::new(),
            },
        }
    }
}

impl<B, U, D> End<B, U>
where
    B: DerefMut<Target = ConnectionCommon<D>>,
    U: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    /// The TLS bytes this end has to send.
    fn take_output(&mut self) -> Vec<u8> {
        match self {
            Self::Buffered(conn) => {
                let mut out = Vec::new();
                while conn.wants_write() {
                    conn.write_tls(&mut out).unwrap();
                }
                out
            }
            Self::Unbuffered {
                conn,
                incoming,
                outgoing,
            } => {
                drive(conn, incoming, outgoing);
                std::mem::take(outgoing)
            }
        }
    }

    /// Processes TLS bytes from the peer.
    fn give_input(&mut self, mut bytes: &[u8]) {
        match self {
            Self::Buffered(conn) => {
                while !bytes.is_empty() {
                    conn.read_tls(&mut bytes).unwrap();
                    conn.process_new_packets().unwrap();
                }
            }
            Self::Unbuffered {
                conn,
                incoming,
                outgoing,
            } => {
                incoming.extend_from_slice(bytes);
                drive(conn, incoming, outgoing);
            }
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Self::Buffered(conn) => conn.is_handshaking(),
            Self::Unbuffered { conn, .. } => conn.is_handshaking(),
        }
    }
}

/// Runs an unbuffered connection until it needs input, appending what it
/// has to send to `outgoing`.
fn drive<D: SideData>(
    conn: &mut UnbufferedConnectionCommon<D>,
    incoming: &mut Vec<u8>,
    outgoing: &mut Vec<u8>,
) {
    let mut size = 512;
    for _ in 0..1_000 {
        let status = conn.process_tls_records(&mut incoming[..]);
        let discard = status.discard;
        let settled = match status.state {
            Ok(ConnectionState::EncodeTlsData(mut encode)) => {
                let mut buf = vec![0u8; size];
                match encode.encode(&mut buf) {
                    Ok(n) => outgoing.extend_from_slice(&buf[..n]),
                    Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                        size = required_size
                    }
                    Err(e) => panic!("encode: {e:?}"),
                }
                false
            }
            Ok(ConnectionState::TransmitTlsData(transmit)) => {
                transmit.done();
                false
            }
            Ok(ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_)) => true,
            Ok(other) => panic!("unexpected state {other:?}"),
            Err(e) => panic!("unbuffered connection failed: {e:?}"),
        };
        incoming.drain(..discard);
        if settled {
            return;
        }
    }
    panic!("unbuffered connection did not settle");
}

/// The exported-authenticator API, forwarded to whichever connection type
/// each end is.
impl Client {
    fn request_authenticator(
        &mut self,
        context: &[u8],
        extensions: &AuthenticatorRequestExtensions,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => conn.request_authenticator(context, extensions),
            Self::Unbuffered { conn, .. } => conn.request_authenticator(context, extensions),
        }
    }

    fn authenticator(
        &mut self,
        request: &[u8],
        certified_key: Option<&CertifiedKey>,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => conn.authenticator(request, certified_key),
            Self::Unbuffered { conn, .. } => conn.authenticator(request, certified_key),
        }
    }

    fn validate_authenticator(
        &mut self,
        request: Option<&[u8]>,
        authenticator: &[u8],
    ) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
        match self {
            Self::Buffered(conn) => conn.validate_authenticator(request, authenticator),
            Self::Unbuffered { conn, .. } => conn.validate_authenticator(request, authenticator),
        }
    }
}

impl Server {
    fn request_authenticator(
        &mut self,
        context: &[u8],
        extensions: &AuthenticatorRequestExtensions,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => conn.request_authenticator(context, extensions),
            Self::Unbuffered { conn, .. } => conn.request_authenticator(context, extensions),
        }
    }

    fn authenticator(
        &mut self,
        request: Option<&[u8]>,
        certified_key: Option<&CertifiedKey>,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Buffered(conn) => conn.authenticator(request, certified_key),
            Self::Unbuffered { conn, .. } => conn.authenticator(request, certified_key),
        }
    }

    fn validate_authenticator(
        &mut self,
        request: &[u8],
        authenticator: &[u8],
    ) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
        match self {
            Self::Buffered(conn) => conn.validate_authenticator(request, authenticator),
            Self::Unbuffered { conn, .. } => conn.validate_authenticator(request, authenticator),
        }
    }
}

// ------------------------------------------------------------------ set-up

struct Setup {
    server_chain: Chain,
    client_chain: Chain,
    server_key: CertifiedKey,
    client_key: CertifiedKey,
    client: Client,
    server: Server,
}

/// A pair over `versions`, not yet connected, whose server verifies
/// `client_chain` (not requested in the handshake) and whose client pins
/// `server_chain`.
fn pair(pairing: (Api, Api), versions: &[&'static SupportedProtocolVersion]) -> Setup {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
            .with_no_client_auth(),
    );
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, false))
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap(),
    );
    let client = End::new(
        pairing.0,
        || ClientConnection::new(client_config.clone(), server_name()).unwrap(),
        || UnbufferedClientConnection::new(client_config.clone(), server_name()).unwrap(),
    );
    let server = End::new(
        pairing.1,
        || ServerConnection::new(server_config.clone()).unwrap(),
        || UnbufferedServerConnection::new(server_config.clone()).unwrap(),
    );
    Setup {
        server_key: key(&server_chain),
        client_key: key(&client_chain),
        server_chain,
        client_chain,
        client,
        server,
    }
}

/// Moves TLS bytes both ways until neither end has anything to send.
fn connect(client: &mut Client, server: &mut Server) {
    for _ in 0..16 {
        let to_server = client.take_output();
        server.give_input(&to_server);
        let to_client = server.take_output();
        client.give_input(&to_client);
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
}

fn connected(pairing: (Api, Api), versions: &[&'static SupportedProtocolVersion]) -> Setup {
    let mut s = pair(pairing, versions);
    connect(&mut s.client, &mut s.server);
    s
}

fn key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

/// TLS 1.3, and TLS 1.2 (with extended master secret) when built.
fn versions() -> Vec<&'static [&'static SupportedProtocolVersion]> {
    static TLS13: &[&SupportedProtocolVersion] = &[&version::TLS13];
    #[cfg(feature = "tls12")]
    static TLS12: &[&SupportedProtocolVersion] = &[&version::TLS12];
    vec![
        TLS13,
        #[cfg(feature = "tls12")]
        TLS12,
    ]
}

/// Runs `case` for every pairing and version, with a label for messages.
fn each(case: impl Fn((Api, Api), &'static [&'static SupportedProtocolVersion], &str)) {
    for pairing in PAIRINGS {
        for versions in versions() {
            case(pairing, versions, &format!("{pairing:?} {versions:?}"));
        }
    }
}

fn defaults() -> AuthenticatorRequestExtensions {
    AuthenticatorRequestExtensions::default()
}

fn reused() -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
    Err(Error::PeerMisbehaved(
        PeerMisbehaved::ReusedAuthenticatorContext,
    ))
}

/// An empty authenticator: a Finished with any MAC.
const EMPTY: &[u8] = &[20, 0, 0, 1, 0];

// ------------------------------------------------------------------- cases

#[test]
fn server_answers_client_request() {
    each(|pairing, versions, at| {
        let mut s = connected(pairing, versions);
        let request = s
            .client
            .request_authenticator(b"client context", &defaults())
            .unwrap();
        // A ClientCertificateRequest (handshake type 17).
        assert_eq!(request[0], 17, "{at}");
        let auth = s
            .server
            .authenticator(Some(&request), Some(&s.server_key))
            .unwrap();
        assert_eq!(authenticator_context(&auth).unwrap(), b"client context");
        assert_eq!(
            s.client.validate_authenticator(Some(&request), &auth),
            Ok(Some(s.server_chain.cert_chain())),
            "{at}"
        );
        // Validated once only.
        assert_eq!(
            s.client.validate_authenticator(Some(&request), &auth),
            reused(),
            "{at}"
        );
        // The messages travel over the application protocol: nothing was
        // queued for the TLS connection.
        assert!(s.client.take_output().is_empty(), "{at}");
        assert!(s.server.take_output().is_empty(), "{at}");
    });
}

#[test]
fn client_answers_server_request() {
    each(|pairing, versions, at| {
        let mut s = connected(pairing, versions);
        let extensions = AuthenticatorRequestExtensions {
            signature_schemes: Some(vec![SignatureScheme::ED25519]),
            certificate_authorities: None,
        };
        let request = s
            .server
            .request_authenticator(b"server context", &extensions)
            .unwrap();
        // A TLS 1.3 CertificateRequest (handshake type 13).
        assert_eq!(request[0], 13, "{at}");
        let auth = s
            .client
            .authenticator(&request, Some(&s.client_key))
            .unwrap();
        assert_eq!(authenticator_context(&auth).unwrap(), b"server context");
        assert_eq!(
            s.server.validate_authenticator(&request, &auth),
            Ok(Some(s.client_chain.cert_chain())),
            "{at}"
        );
        assert_eq!(
            s.server.validate_authenticator(&request, &auth),
            reused(),
            "{at}"
        );
    });
}

#[test]
fn spontaneous_server_authenticator() {
    each(|pairing, versions, at| {
        let mut s = connected(pairing, versions);
        let auth = s.server.authenticator(None, Some(&s.server_key)).unwrap();
        assert_eq!(authenticator_context(&auth).unwrap().len(), 32, "{at}");
        assert_eq!(
            s.client.validate_authenticator(None, &auth),
            Ok(Some(s.server_chain.cert_chain())),
            "{at}"
        );
        assert_eq!(
            s.client.validate_authenticator(None, &auth),
            reused(),
            "{at}"
        );
        // A spontaneous authenticator needs a certificate.
        assert!(
            matches!(s.server.authenticator(None, None), Err(Error::General(_))),
            "{at}"
        );
    });
}

#[test]
fn empty_authenticators_decline() {
    each(|pairing, versions, at| {
        let mut s = connected(pairing, versions);
        let request = s.server.request_authenticator(b"ctx", &defaults()).unwrap();
        let auth = s.client.authenticator(&request, None).unwrap();
        // A lone Finished (handshake type 20), without a context.
        assert_eq!(auth[0], 20, "{at}");
        assert!(authenticator_context(&auth).is_err(), "{at}");
        assert_eq!(
            s.server.validate_authenticator(&request, &auth),
            Ok(None),
            "{at}"
        );

        let request = s.client.request_authenticator(b"ctx", &defaults()).unwrap();
        let auth = s.server.authenticator(Some(&request), None).unwrap();
        assert_eq!(auth[0], 20, "{at}");
        assert_eq!(
            s.client.validate_authenticator(Some(&request), &auth),
            Ok(None),
            "{at}"
        );
        // A lone Finished never stands for a spontaneous authenticator.
        assert_eq!(
            s.client.validate_authenticator(None, &auth),
            Err(Error::NoCertificatesPresented),
            "{at}"
        );
    });
}

#[test]
fn needs_a_completed_handshake() {
    each(|pairing, versions, at| {
        let other_request = connected(pairing, versions)
            .server
            .request_authenticator(b"other", &defaults())
            .unwrap();
        let mut s = pair(pairing, versions);
        let not_complete = Err(Error::HandshakeNotComplete);

        // Nothing exchanged yet. A client may already request.
        let early = s
            .client
            .request_authenticator(b"early", &defaults())
            .unwrap();
        assert_eq!(
            s.client.authenticator(&other_request, Some(&s.client_key)),
            not_complete,
            "{at}"
        );
        assert_eq!(
            s.client.validate_authenticator(Some(&early), EMPTY),
            Err(Error::HandshakeNotComplete),
            "{at}"
        );
        assert_eq!(
            s.client.validate_authenticator(None, EMPTY),
            Err(Error::HandshakeNotComplete),
            "{at}"
        );
        assert_eq!(
            s.server.request_authenticator(b"server", &defaults()),
            not_complete,
            "{at}"
        );
        assert_eq!(
            s.server.authenticator(Some(&early), Some(&s.server_key)),
            not_complete,
            "{at}"
        );
        assert_eq!(
            s.server.authenticator(None, Some(&s.server_key)),
            not_complete,
            "{at}"
        );
        assert_eq!(
            s.server.validate_authenticator(&other_request, EMPTY),
            Err(Error::HandshakeNotComplete),
            "{at}"
        );

        // The server has the ClientHello: it may request, not answer.
        let hello = s.client.take_output();
        s.server.give_input(&hello);
        assert!(s.server.is_handshaking(), "{at}");
        let server_request = s
            .server
            .request_authenticator(b"server", &defaults())
            .unwrap();
        assert_eq!(
            s.server.authenticator(Some(&early), Some(&s.server_key)),
            not_complete,
            "{at}"
        );
        assert_eq!(
            s.server.authenticator(None, Some(&s.server_key)),
            not_complete,
            "{at}"
        );
        assert_eq!(
            s.server.validate_authenticator(&server_request, EMPTY),
            Err(Error::HandshakeNotComplete),
            "{at}"
        );

        // Requests made before completion are answered after it.
        connect(&mut s.client, &mut s.server);
        let auth = s
            .server
            .authenticator(Some(&early), Some(&s.server_key))
            .unwrap();
        assert_eq!(
            s.client.validate_authenticator(Some(&early), &auth),
            Ok(Some(s.server_chain.cert_chain())),
            "{at}"
        );
        let auth = s
            .client
            .authenticator(&server_request, Some(&s.client_key))
            .unwrap();
        assert_eq!(
            s.server.validate_authenticator(&server_request, &auth),
            Ok(Some(s.client_chain.cert_chain())),
            "{at}"
        );
    });
}

#[test]
fn contexts_are_used_once() {
    each(|pairing, versions, at| {
        let mut s = connected(pairing, versions);

        let request = s
            .client
            .request_authenticator(b"once", &defaults())
            .unwrap();
        assert!(
            matches!(
                s.client.request_authenticator(b"once", &defaults()),
                Err(Error::General(_))
            ),
            "{at}"
        );
        let auth = s
            .server
            .authenticator(Some(&request), Some(&s.server_key))
            .unwrap();
        assert_eq!(
            s.server.authenticator(Some(&request), Some(&s.server_key)),
            Err(PeerMisbehaved::ReusedAuthenticatorContext.into()),
            "{at}"
        );
        assert!(
            s.client
                .validate_authenticator(Some(&request), &auth)
                .is_ok()
        );
        assert_eq!(
            s.client.validate_authenticator(Some(&request), &auth),
            reused(),
            "{at}"
        );

        let request = s
            .server
            .request_authenticator(b"once", &defaults())
            .unwrap();
        assert!(
            matches!(
                s.server.request_authenticator(b"once", &defaults()),
                Err(Error::General(_))
            ),
            "{at}"
        );
        let auth = s
            .client
            .authenticator(&request, Some(&s.client_key))
            .unwrap();
        assert_eq!(
            s.client.authenticator(&request, Some(&s.client_key)),
            Err(PeerMisbehaved::ReusedAuthenticatorContext.into()),
            "{at}"
        );
        assert!(s.server.validate_authenticator(&request, &auth).is_ok());
        assert_eq!(
            s.server.validate_authenticator(&request, &auth),
            reused(),
            "{at}"
        );
    });
}

#[test]
fn only_requests_made_here_validate() {
    each(|pairing, versions, at| {
        let mut s = connected(pairing, versions);
        let mut other = connected(pairing, versions);

        // Another connection's request, answered here: refused before
        // anything else is looked at.
        let foreign = other
            .client
            .request_authenticator(b"foreign", &defaults())
            .unwrap();
        let auth = s
            .server
            .authenticator(Some(&foreign), Some(&s.server_key))
            .unwrap();
        assert!(
            matches!(
                s.client.validate_authenticator(Some(&foreign), &auth),
                Err(Error::General(_))
            ),
            "{at}"
        );
        let foreign = other
            .server
            .request_authenticator(b"foreign", &defaults())
            .unwrap();
        let auth = s
            .client
            .authenticator(&foreign, Some(&s.client_key))
            .unwrap();
        assert!(
            matches!(
                s.server.validate_authenticator(&foreign, &auth),
                Err(Error::General(_))
            ),
            "{at}"
        );

        // The same request bytes made on both connections: an answer from
        // the other connection does not verify here (the exporter differs).
        let ours = s
            .client
            .request_authenticator(b"bound", &defaults())
            .unwrap();
        let theirs = other
            .client
            .request_authenticator(b"bound", &defaults())
            .unwrap();
        assert_eq!(ours, theirs, "{at}");
        let auth = other
            .server
            .authenticator(Some(&theirs), Some(&other.server_key))
            .unwrap();
        assert_eq!(
            s.client.validate_authenticator(Some(&ours), &auth),
            Err(Error::DecryptError),
            "{at}"
        );
        assert!(
            other
                .client
                .validate_authenticator(Some(&theirs), &auth)
                .is_ok(),
            "{at}"
        );
    });
}

#[test]
fn authenticators_from_the_wrong_side_are_rejected() {
    each(|pairing, versions, at| {
        let mut s = connected(pairing, versions);
        let client_request = s
            .client
            .request_authenticator(b"same", &defaults())
            .unwrap();
        let server_request = s
            .server
            .request_authenticator(b"same", &defaults())
            .unwrap();

        // A request goes to the peer, not back to the side that made it.
        assert!(
            matches!(
                s.client.authenticator(&client_request, Some(&s.client_key)),
                Err(Error::InvalidMessage(_))
            ),
            "{at}"
        );
        assert!(
            matches!(
                s.server
                    .authenticator(Some(&server_request), Some(&s.server_key)),
                Err(Error::InvalidMessage(_))
            ),
            "{at}"
        );

        // An authenticator is checked with the exporter keys of the peer:
        // one a side made itself, with the same context, never validates
        // there.
        let from_client = s
            .client
            .authenticator(&server_request, Some(&s.client_key))
            .unwrap();
        let from_server = s
            .server
            .authenticator(Some(&client_request), Some(&s.server_key))
            .unwrap();
        assert_eq!(
            s.client
                .validate_authenticator(Some(&client_request), &from_client),
            Err(Error::DecryptError),
            "{at}"
        );
        assert_eq!(
            s.server
                .validate_authenticator(&server_request, &from_server),
            Err(Error::DecryptError),
            "{at}"
        );

        // Failed validations record nothing: the genuine answers validate.
        assert_eq!(
            s.client
                .validate_authenticator(Some(&client_request), &from_server),
            Ok(Some(s.server_chain.cert_chain())),
            "{at}"
        );
        assert_eq!(
            s.server
                .validate_authenticator(&server_request, &from_client),
            Ok(Some(s.client_chain.cert_chain())),
            "{at}"
        );
    });
}

#[test]
fn tampering_is_detected() {
    each(|pairing, versions, at| {
        let mut s = connected(pairing, versions);
        let request = s
            .client
            .request_authenticator(b"tamper", &defaults())
            .unwrap();
        let auth = s
            .server
            .authenticator(Some(&request), Some(&s.server_key))
            .unwrap();
        for i in 0..auth.len() {
            let mut bad = auth.clone();
            bad[i] ^= 0x01;
            assert!(
                s.client
                    .validate_authenticator(Some(&request), &bad)
                    .is_err(),
                "{at}: byte {i}"
            );
        }
        assert!(
            s.client
                .validate_authenticator(Some(&request), &auth[..auth.len() - 1])
                .is_err(),
            "{at}"
        );
        assert!(
            s.client
                .validate_authenticator(Some(&request), &auth)
                .unwrap()
                .is_some(),
            "{at}"
        );
    });
}
