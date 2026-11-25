//! Encrypted Client Hello (RFC 9849) between a browntls client and server,
//! with the native provider's HPKE suites.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

#[path = "ech_native/key_log.rs"]
mod key_log;
#[path = "ech_native/pem_config.rs"]
mod pem_config;
#[path = "ech_native/shared_mode.rs"]
mod shared_mode;
#[path = "ech_native/split_backend.rs"]
mod split_backend;
#[path = "ech_native/split_mode.rs"]
mod split_mode;

use std::sync::Arc;

use browntls_core::client::{Resumption, WebPkiServerVerifier};
use browntls_core::crypto::hpke::Hpke;
use browntls_core::crypto::native::hpke::{
    ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128,
};
use browntls_core::ech::{
    EchConfig, EchGreaseConfig, EchMode, EchServerConfig, EchServerKey, EchStatus,
};
use browntls_core::pki_types::ServerName;
use browntls_core::server::ResolvesServerCertUsingSni;
use browntls_core::sign::CertifiedKey;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, RootCertStore,
    ServerConfig, ServerConnection, version,
};
use common::*;

const SECRET: &str = "secret.example";
const PUBLIC: &str = "public.example";

/// Certificates for the hidden name and the public name, from separate CAs.
struct Certs {
    secret: Chain,
    public: Chain,
}

impl Certs {
    fn new() -> Self {
        let purpose = rcgen::ExtendedKeyUsagePurpose::ServerAuth;
        Self {
            secret: gen_chain(KeyType::EcdsaP256, &[SECRET], purpose.clone()),
            public: gen_chain(KeyType::Ed25519, &[PUBLIC], purpose),
        }
    }

    fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.secret.ca.clone()).unwrap();
        roots.add(self.public.ca.clone()).unwrap();
        Arc::new(roots)
    }

    fn resolver(&self) -> Arc<ResolvesServerCertUsingSni> {
        let mut resolver = ResolvesServerCertUsingSni::new();
        for (name, chain) in [(SECRET, &self.secret), (PUBLIC, &self.public)] {
            resolver
                .add(
                    name,
                    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider())
                        .unwrap(),
                )
                .unwrap();
        }
        Arc::new(resolver)
    }
}

fn server_key(config_id: u8) -> EchServerKey {
    EchServerKey::generate(config_id, PUBLIC, 32, ALL_SUPPORTED_SUITES).unwrap()
}

fn server_config(
    certs: &Certs,
    ech: Option<&Arc<EchServerConfig>>,
    groups: Option<&[&'static dyn browntls_core::crypto::SupportedKxGroup]>,
) -> ServerConfig {
    let mut provider = prov::default_provider();
    if let Some(groups) = groups {
        provider.kx_groups = groups.to_vec();
    }
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(certs.resolver());
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ech = ech.cloned();
    config.send_tls13_tickets = 2;
    config
}

fn client_config(certs: &Certs, mode: Option<EchMode>) -> ClientConfig {
    let verifier = WebPkiServerVerifier::builder_with_provider(certs.roots(), provider())
        .build()
        .unwrap();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ech_mode = mode;
    config
}

fn enable(list: &[u8]) -> Option<EchMode> {
    Some(EchMode::Enable(
        EchConfig::new(list, ALL_SUPPORTED_SUITES).unwrap(),
    ))
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    connect_arc(Arc::new(client), Arc::new(server))
}

fn connect_arc(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(client, ServerName::try_from(SECRET).unwrap()).unwrap(),
        ServerConnection::new(server).unwrap(),
    )
}

fn assert_accepted(client: &mut ClientConnection, server: &mut ServerConnection) {
    do_handshake(client, server).unwrap();
    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(server.ech_status(), EchStatus::Accepted);
    // The server saw the inner hello: its name and its ALPN offer.
    assert_eq!(server.server_name(), Some(SECRET));
    assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(
        send_and_receive(client, server, b"hidden hello"),
        b"hidden hello"
    );
    assert_eq!(send_and_receive(server, client, b"reply"), b"reply");
}

#[test]
fn rfc9973_offer_and_identity_are_inner_only() {
    use browntls_core::crypto::hash::HashAlgorithm;
    use browntls_core::psk::ExternalPsk;
    use hello_wire::{give, hello_extension_types, take_flight};

    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(19)]).unwrap());
    let mut config = client_config(&certs, enable(ech.ech_config_list()));
    let identity = b"private identity for RFC 9973";
    let key =
        Arc::new(ExternalPsk::new(identity.to_vec(), vec![42; 32], HashAlgorithm::SHA256).unwrap());
    config.external_psks = vec![key.clone()];
    config.cert_with_extern_psk = true;
    let mut server_config = server_config(&certs, Some(&ech), None);
    server_config.external_psks = Some(Arc::new(vec![key]));
    server_config.require_cert_with_extern_psk = true;
    let (mut client, mut server) = connect(config, server_config);
    let outer = take_flight(&mut client);
    assert!(!hello_extension_types(&outer, true).contains(&0x0021));
    assert!(!outer.windows(identity.len()).any(|bytes| bytes == identity));

    give(&mut server, &outer);
    server.process_new_packets().unwrap();
    assert_accepted(&mut client, &mut server);
    assert!(client.negotiated_cert_with_extern_psk());
    assert!(server.negotiated_cert_with_extern_psk());
    assert_eq!(server.external_psk_identity(), Some(identity.as_slice()));
}

/// Runs a handshake the server rejects ECH in; returns the client's error.
fn expect_rejected(client: &mut ClientConnection, server: &mut ServerConnection) -> Error {
    let (client_res, server_res) = do_handshake_until_error(client, server);
    assert_eq!(client.ech_status(), EchStatus::Rejected);
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(
            AlertDescription::EncryptedClientHelloRequired
        ))
    );
    client_res.unwrap_err()
}

/// The offset in `records` (a client flight) of the ECH extension body of
/// its ClientHello.
fn ech_extension_offset(records: &[u8]) -> usize {
    let mut at = 0;
    while at + 5 <= records.len() {
        let len = usize::from(u16::from_be_bytes([records[at + 3], records[at + 4]]));
        let body = at + 5;
        if records[at] == 22 && records[body] == 1 {
            // Handshake header, version, random, session ID, suites,
            // compression methods.
            let mut p = body + 4 + 2 + 32;
            p += 1 + usize::from(records[p]);
            p += 2 + usize::from(u16::from_be_bytes([records[p], records[p + 1]]));
            p += 1 + usize::from(records[p]);
            let end = p + 2 + usize::from(u16::from_be_bytes([records[p], records[p + 1]]));
            p += 2;
            while p < end {
                let typ = u16::from_be_bytes([records[p], records[p + 1]]);
                let ext_len = usize::from(u16::from_be_bytes([records[p + 2], records[p + 3]]));
                if typ == 0xfe0d {
                    return p + 4;
                }
                p += 4 + ext_len;
            }
        }
        at = body + len;
    }
    panic!("no ClientHello with ECH");
}

// ------------------------------------------------------------- split mode

use browntls_core::InvalidMessage;
use browntls_core::ech::split::{ClientFacing, ClientFacingDecision};
use std::io::{Read as _, Write as _};

/// A back-end server of split mode (RFC 9849 §7.2): no keys, the hidden
/// name's certificate.
fn backend_config(
    certs: &Certs,
    groups: Option<&[&'static dyn browntls_core::crypto::SupportedKxGroup]>,
) -> ServerConfig {
    let mut config = server_config(certs, None, groups);
    config.ech_backend = true;
    config
}

/// The first error of each party of a split-mode connection.
#[derive(Debug, Default)]
struct SplitErrors {
    client: Option<Error>,
    front: Option<Error>,
    server: Option<Error>,
}

/// An edit of bytes in flight.
type Edit = Box<dyn FnMut(&mut Vec<u8>)>;

/// A client, a client-facing server, and the server that completes the
/// handshake: the back-end server after `Forward`, a local server after
/// `Local`.
struct Split {
    client: ClientConnection,
    front: Option<ClientFacing>,
    backend: Option<ServerConnection>,
    local: Option<ServerConnection>,
    backend_config: Arc<ServerConfig>,
    local_config: Arc<ServerConfig>,
    /// The largest piece of input the client-facing server gets at once.
    chunk: usize,
    /// Applied to each batch the client-facing server forwards to the
    /// back-end server.
    edit_forwarded: Option<Edit>,
    errors: SplitErrors,
}

fn drain<S: browntls_core::SideData>(conn: &mut browntls_core::ConnectionCommon<S>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

/// Gives `data` to `conn`, processing when its buffer fills up (an error
/// then stays with the connection, for its next `process_new_packets`).
fn feed<S: browntls_core::SideData>(
    conn: &mut browntls_core::ConnectionCommon<S>,
    mut data: &[u8],
) {
    while !data.is_empty() {
        match conn.read_tls(&mut data) {
            Ok(n) if n > 0 => {}
            _ => {
                if conn.process_new_packets().is_err() {
                    break;
                }
            }
        }
    }
}

impl Split {
    fn new(
        certs: &Certs,
        client: ClientConfig,
        ech: &Arc<EchServerConfig>,
        backend: ServerConfig,
    ) -> Self {
        let local_config = Arc::new(server_config(certs, Some(ech), None));
        Self {
            client: ClientConnection::new(Arc::new(client), ServerName::try_from(SECRET).unwrap())
                .unwrap(),
            front: Some(ClientFacing::new(ech.clone())),
            backend: None,
            local: None,
            backend_config: Arc::new(backend),
            local_config,
            chunk: usize::MAX,
            edit_forwarded: None,
            errors: SplitErrors::default(),
        }
    }

    fn front(&self) -> &ClientFacing {
        self.front.as_ref().expect("still client-facing")
    }

    /// The server completing the handshake.
    fn server(&mut self) -> &mut ServerConnection {
        self.backend
            .as_mut()
            .or(self.local.as_mut())
            .expect("a server")
    }

    /// Moves bytes until nothing changes.
    fn pump(&mut self) {
        for _ in 0..64 {
            let mut moved = false;

            // Client to the client-facing server or the local server.
            let out = drain(&mut self.client);
            moved |= !out.is_empty();
            if let Some(local) = &mut self.local {
                feed(local, &out);
            } else if let Some(front) = &mut self.front {
                for piece in out.chunks(self.chunk.max(1)) {
                    if let Err(e) = front.read_client(piece) {
                        self.errors.front.get_or_insert(e);
                        break;
                    }
                }
            }

            // The decision.
            match self.front.as_ref().and_then(ClientFacing::decision) {
                Some(ClientFacingDecision::Local) if self.local.is_none() => {
                    let front = self.front.take().unwrap();
                    self.local = Some(
                        front
                            .into_server_connection(self.local_config.clone())
                            .unwrap(),
                    );
                    moved = true;
                }
                Some(ClientFacingDecision::Forward) if self.backend.is_none() => {
                    self.backend =
                        Some(ServerConnection::new(self.backend_config.clone()).unwrap());
                    moved = true;
                }
                _ => {}
            }
            if let Some(local) = &mut self.local
                && self.errors.server.is_none()
                && let Err(e) = local.process_new_packets()
            {
                self.errors.server = Some(e);
            }

            // Client-facing server and back-end server.
            if let (Some(front), Some(backend)) = (&mut self.front, &mut self.backend) {
                let mut forwarded = front.take_for_backend();
                if let Some(edit) = &mut self.edit_forwarded
                    && !forwarded.is_empty()
                {
                    edit(&mut forwarded);
                }
                moved |= !forwarded.is_empty();
                feed(backend, &forwarded);
                if self.errors.server.is_none()
                    && let Err(e) = backend.process_new_packets()
                {
                    self.errors.server = Some(e);
                }
                let answer = drain(backend);
                moved |= !answer.is_empty();
                for piece in answer.chunks(self.chunk.max(1)) {
                    if let Err(e) = front.read_backend(piece) {
                        self.errors.front.get_or_insert(e);
                        break;
                    }
                }
            }

            // To the client.
            let to_client = match (&mut self.front, &mut self.local) {
                (_, Some(local)) => drain(local),
                (Some(front), None) => front.take_for_client(),
                (None, None) => Vec::new(),
            };
            moved |= !to_client.is_empty();
            feed(&mut self.client, &to_client);
            if self.errors.client.is_none()
                && let Err(e) = self.client.process_new_packets()
            {
                self.errors.client = Some(e);
            }
            if !moved {
                break;
            }
        }
    }

    /// Application data both ways, through the relay.
    fn exchange(&mut self) {
        self.client.writer().write_all(b"hidden hello").unwrap();
        self.pump();
        let mut got = [0u8; 12];
        self.server().reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hidden hello");
        self.server().writer().write_all(b"reply").unwrap();
        let out = drain(self.server());
        match (&mut self.front, &mut self.local) {
            (_, Some(_)) => feed(&mut self.client, &out),
            (Some(front), None) => {
                front.read_backend(&out).unwrap();
                let out = front.take_for_client();
                feed(&mut self.client, &out);
            }
            (None, None) => unreachable!(),
        }
        self.client.process_new_packets().unwrap();
        let mut got = [0u8; 5];
        self.client.reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, b"reply");
    }

    fn assert_forwarded(&mut self) {
        assert!(
            self.errors.client.is_none()
                && self.errors.front.is_none()
                && self.errors.server.is_none(),
            "{:?}",
            self.errors
        );
        assert!(!self.client.is_handshaking());
        let front = self.front();
        assert_eq!(front.decision(), Some(ClientFacingDecision::Forward));
        assert_eq!(front.ech_status(), EchStatus::Accepted);
        assert_eq!(front.server_name(), Some(SECRET));
        assert!(front.is_relaying());
        assert_eq!(self.client.ech_status(), EchStatus::Accepted);
        let backend = self.backend.as_ref().unwrap();
        assert_eq!(backend.ech_status(), EchStatus::Accepted);
        assert_eq!(backend.server_name(), Some(SECRET));
        assert_eq!(self.client.alpn_protocol(), Some(&b"h2"[..]));
        self.exchange();
    }
}
