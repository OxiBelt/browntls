//! The handshake operation of the `tls_ech` target in shared mode: ECH
//! accepted, rejected with retry configurations, rejected by a server
//! without ECH, and GREASE. Split mode is in `split`.

use std::io::{Read, Write};
use std::sync::Arc;

use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use browntls_core::ech::{
    EchConfig, EchGreaseConfig, EchMode, EchServerConfig, EchServerKey, EchStatus,
};
use browntls_core::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::{
    ClientConfig, ClientConnection, Error, ServerConfig, ServerConnection, version,
};

use super::split::split;
use super::{ECH_VERSION, Fields, KEMS, PUBLIC, SECRET, State, config_list, fixture};
use crate::input::Input;

// --------------------------------------------------------------- handshake

/// Moves everything `from` has to send into `to`, through `edit`.
fn send<A: browntls_core::SideData, B: browntls_core::SideData>(
    from: &mut browntls_core::ConnectionCommon<A>,
    to: &mut browntls_core::ConnectionCommon<B>,
    edit: &mut Option<(usize, u8)>,
) {
    let mut buf = Vec::new();
    while from.wants_write() {
        if from.write_tls(&mut buf).is_err() {
            break;
        }
    }
    if let Some((at, x)) = edit.take()
        && !buf.is_empty()
    {
        let at = at % buf.len();
        buf[at] ^= x;
    }
    let mut rest = &buf[..];
    while !rest.is_empty() {
        match to.read_tls(&mut rest) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Runs the handshake, applying `edit` to the client's first flight;
/// returns each side's first error.
fn pump(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    mut edit: Option<(usize, u8)>,
) -> (Result<(), Error>, Result<(), Error>) {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        send(client, server, &mut edit);
        if let Err(e) = server.process_new_packets() {
            send(server, client, &mut None);
            let client_res = client.process_new_packets().map(|_| ());
            return (client_res, Err(e));
        }
        send(server, client, &mut None);
        if let Err(e) = client.process_new_packets() {
            send(client, server, &mut None);
            let server_res = server.process_new_packets().map(|_| ());
            return (Err(e), server_res);
        }
    }
    (Ok(()), Ok(()))
}

pub(super) fn server_config(ech: Option<Arc<EchServerConfig>>, hrr: bool) -> Arc<ServerConfig> {
    let fixture = fixture();
    let mut provider = browntls_core::crypto::native::default_provider();
    if hrr {
        // The client's first key share is not P-256.
        provider.kx_groups = vec![browntls_core::crypto::native::kx_group::SECP256R1];
    }
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            fixture.chain.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture.key.clone())),
        )
        .expect("server certificate");
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ech = ech;
    config.key_log = Arc::new(NoKeyLogCalls);
    Arc::new(config)
}

/// The key log of every party of this target. The fuzz crate builds
/// `browntls-core` without its `key-log` feature, as production does, so
/// whatever the input makes of an ECH offer (accepted, rejected, GREASE, a
/// candidate key that fails, split mode), nothing may reach a key log: not
/// a record, and not the question whether it would take one.
#[derive(Debug)]
pub(super) struct NoKeyLogCalls;

impl browntls_core::KeyLog for NoKeyLogCalls {
    fn log(&self, label: &str, _: &[u8], _: &[u8]) {
        panic!("a build without `key-log` logged {label}");
    }

    fn will_log(&self, label: &str) -> bool {
        panic!("a build without `key-log` asked about {label}");
    }
}

/// A client offering `mode` and a server. The client may fail to start
/// (sealing to an invalid public key) unless `must` says it may not.
pub(super) fn connect(
    mode: EchMode,
    server: &Arc<ServerConfig>,
    must: bool,
) -> Option<(ClientConnection, ServerConnection)> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        browntls_core::crypto::native::default_provider(),
    ))
    .with_protocol_versions(&[&version::TLS13])
    .expect("versions")
    .with_root_certificates(fixture().roots.clone())
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ech_mode = Some(mode);
    config.key_log = Arc::new(NoKeyLogCalls);
    let name = ServerName::try_from(SECRET).expect("name");
    let client = match ClientConnection::new(Arc::new(config), name) {
        Ok(client) => client,
        Err(e) => {
            assert!(!must, "client: {e:?}");
            return None;
        }
    };
    let server = ServerConnection::new(server.clone()).expect("server");
    Some((client, server))
}

/// Both sides accepted ECH: the server saw the inner hello.
fn assert_accepted(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(server.ech_status(), EchStatus::Accepted);
    assert_eq!(server.server_name(), Some(SECRET));
    assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
    client.writer().write_all(b"hidden").expect("write");
    send(client, server, &mut None);
    server.process_new_packets().expect("server reads");
    let mut got = [0u8; 6];
    server.reader().read_exact(&mut got).expect("data");
    assert_eq!(&got, b"hidden");
}

/// The default sound key: X25519, `public.example`.
pub(super) fn default_key(config_id: u8, maximum_name_length: u8) -> EchServerKey {
    let fixture = fixture();
    let fields = Fields {
        version: ECH_VERSION,
        config_id,
        kem: KEMS[0].0,
        public_key: fixture.pairs[0].0.0.clone(),
        suites: vec![(1, 1), (1, 3)],
        maximum_name_length,
        public_name: PUBLIC.as_bytes().to_vec(),
        extensions: Vec::new(),
    };
    EchServerKey::new(
        &fields.encode(),
        fixture.pairs[0].1.clone(),
        ALL_SUPPORTED_SUITES,
    )
    .expect("default key")
}

/// Handshake input: scenario (accepted, stale, no server ECH, GREASE),
/// HelloRetryRequest flag, config id and maximum name length for the
/// default and stale keys, whether to serve the kept keys, the flight edit
/// flag, offset (16 bits) and XOR byte.
pub(super) fn handshake(input: &mut Input, state: &mut State) {
    let scenario = input.choose(6);
    let hrr = input.bool();
    let config_id = input.byte();
    let maximum_name_length = input.byte();
    let use_kept = input.bool();
    let edit = input
        .bool()
        .then(|| (usize::from(input.u16()), input.byte() | 1));
    let edited = edit.is_some();

    // The server's keys: the newest kept one, or the default.
    let (key, sound, public_name) = match state.keys.last() {
        Some(k) if use_kept => (k.key.clone(), k.sound, k.public_name.clone()),
        _ => (
            default_key(config_id, maximum_name_length),
            true,
            PUBLIC.as_bytes().to_vec(),
        ),
    };
    let current = Arc::new(EchServerConfig::new(vec![key.clone()]).expect("one key"));

    match scenario {
        0 => {
            // Accepted.
            let Ok(config) = EchConfig::new(current.ech_config_list(), ALL_SUPPORTED_SUITES) else {
                return;
            };
            let server = server_config(Some(current.clone()), hrr);
            let Some((mut client, mut server)) = connect(EchMode::Enable(config), &server, sound)
            else {
                return;
            };
            assert_eq!(client.ech_status(), EchStatus::Offered);
            let (client_res, server_res) = pump(&mut client, &mut server, edit);
            if sound && !edited {
                assert!(
                    client_res.is_ok() && server_res.is_ok(),
                    "{client_res:?} {server_res:?}"
                );
                assert_accepted(&mut client, &mut server);
            }
        }
        1 => {
            // Rejected: the client has a configuration whose key the
            // server lacks (with a fuzzed id, possibly the server's).
            let fixture = fixture();
            let stale = Fields {
                version: ECH_VERSION,
                config_id,
                kem: KEMS[0].0,
                public_key: fixture.stale.0.clone(),
                suites: vec![(1, 1)],
                maximum_name_length,
                public_name: PUBLIC.as_bytes().to_vec(),
                extensions: Vec::new(),
            };
            let list = config_list([&stale.encode()[..]]);
            let config = EchConfig::new(&list, ALL_SUPPORTED_SUITES).expect("stale config");
            let server = server_config(Some(current.clone()), hrr);
            let (mut client, mut server_conn) =
                connect(EchMode::Enable(config), &server, true).expect("stale client");
            let (client_res, server_res) = pump(&mut client, &mut server_conn, edit);
            if edited {
                return;
            }
            assert_eq!(client.ech_status(), EchStatus::Rejected);
            assert_eq!(server_conn.ech_status(), EchStatus::Rejected);
            assert!(server_res.is_err(), "the server learns of the rejection");
            let Err(Error::RejectedEch(rejected)) = client_res else {
                panic!("expected a rejection: {client_res:?}");
            };
            assert_eq!(rejected.retry_configs(), Some(current.ech_config_list()));
            let usable = EchConfig::new(current.ech_config_list(), ALL_SUPPORTED_SUITES);
            assert!(!usable.is_ok() || rejected.can_retry());
            // The retry with the server's configuration.
            let Ok(retry) = usable else {
                return;
            };
            let Some((mut client, mut server_conn)) =
                connect(EchMode::Enable(retry), &server, sound)
            else {
                return;
            };
            let (client_res, server_res) = pump(&mut client, &mut server_conn, None);
            if sound {
                assert!(
                    client_res.is_ok() && server_res.is_ok(),
                    "{client_res:?} {server_res:?}"
                );
                assert_accepted(&mut client, &mut server_conn);
            }
        }
        2 => {
            // Rejected by a server without ECH.
            let Ok(config) = EchConfig::new(current.ech_config_list(), ALL_SUPPORTED_SUITES) else {
                return;
            };
            let server = server_config(None, hrr);
            let Some((mut client, mut server_conn)) =
                connect(EchMode::Enable(config), &server, sound)
            else {
                return;
            };
            let (client_res, _) = pump(&mut client, &mut server_conn, edit);
            if edited {
                return;
            }
            assert_eq!(server_conn.ech_status(), EchStatus::NotOffered);
            if public_name == PUBLIC.as_bytes() || public_name == SECRET.as_bytes() {
                // The rejection authenticates with the public name.
                let Err(Error::RejectedEch(rejected)) = client_res else {
                    panic!("expected a rejection: {client_res:?}");
                };
                assert_eq!(rejected.retry_configs(), None);
                assert!(!rejected.can_retry());
            } else {
                // No certificate for that name: the client must not
                // complete.
                assert!(client_res.is_err());
            }
            assert_eq!(client.ech_status(), EchStatus::Rejected);
        }
        4 | 5 => split(
            input,
            state,
            &key,
            &current,
            sound,
            hrr,
            scenario == 5,
            edit,
        ),
        _ => {
            // GREASE, against a server with or without ECH.
            let (config, valid) = match &state.grease {
                Some((g, valid)) => (g.clone(), *valid),
                None => (
                    EchGreaseConfig::generate(ALL_SUPPORTED_SUITES[0]).expect("GREASE"),
                    true,
                ),
            };
            let with_ech = config_id & 1 != 0;
            let server = server_config(with_ech.then(|| current.clone()), hrr);
            let Some((mut client, mut server_conn)) =
                connect(EchMode::Grease(config), &server, valid)
            else {
                return;
            };
            let (client_res, server_res) = pump(&mut client, &mut server_conn, edit);
            if !edited {
                assert!(
                    client_res.is_ok() && server_res.is_ok(),
                    "{client_res:?} {server_res:?}"
                );
                assert_eq!(client.ech_status(), EchStatus::Grease);
                let expected = if with_ech {
                    EchStatus::Rejected
                } else {
                    EchStatus::NotOffered
                };
                assert_eq!(server_conn.ech_status(), expected);
                assert_eq!(server_conn.server_name(), Some(SECRET));
            }
        }
    }
}
