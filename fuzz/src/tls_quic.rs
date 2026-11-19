//! QUIC-TLS, RFC 9001 (`fuzz_targets/tls_quic.rs`).
//!
//! Reaches every public function of `browntls_core::quic`: Initial keys from
//! fuzzed connection IDs, keys and secrets built from fuzzed traffic
//! secrets, packet and header protection with fuzzed packets, key updates,
//! the Retry Integrity Tag, CRYPTO_ERROR codes, and QUIC handshakes between
//! a client and a server in the same process on either provider, with
//! fuzz-chosen suites, groups (HelloRetryRequest), ALPN, transport
//! parameters, resumption with 0-RTT, CRYPTO data split into fuzz-chosen
//! pieces and damaged bytes. Fuzzed bytes are also fed to fresh connections
//! and to connections after their handshake.
//!
//! Checked properties: what one side's keys protect, the other side's keys
//! open, and a damaged packet or tag is refused; header protection round
//! trips and needs a 16-byte sample; `nonce_for` is the IV XORed with the
//! packet number; key updates agree between the two sides and change the
//! keys; a Retry tag verifies, refuses any other connection ID or packet,
//! and needs TLS_AES_128_GCM_SHA256; CRYPTO_ERROR codes map back to their
//! alert; an undamaged handshake whose ALPN can agree succeeds, delivers
//! each side's transport parameters to the other and gives both sides the
//! same keys at every level and the same exporter; and every failure is an
//! error, not a panic.
//!
//! Input: up to 32 operations, each an operation byte followed by its
//! arguments (see [`run`]); at most four handshakes per input.

use std::sync::{Arc, OnceLock};

use browntls_core::client::{ClientSessionMemoryCache, ClientSessionStore, Resumption};
use browntls_core::crypto::{CryptoProvider, SupportedKxGroup};
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::quic::{self, Connection, KeyChange, Keys, Secrets, Side, Suite, Version};
use browntls_core::{
    CipherSuite, ClientConfig, Error, HandshakeKind, RootCertStore, ServerConfig,
    SupportedCipherSuite, Tls13CipherSuite, version,
};

use crate::input::{Input, put_field, put_short_field};

mod keys;

use self::keys::{codes, initial, retry, secrets};

/// Operations per input.
const MAX_OPS: usize = 32;

/// Handshakes per input.
const MAX_HANDSHAKES: usize = 4;

/// Rounds of a handshake before it is given up as stalled.
const MAX_ROUNDS: usize = 16;

/// ALPN protocol lists to configure.
const ALPNS: &[&[&[u8]]] = &[&[], &[b"h3"], &[b"hq-interop", b"h3"], &[b"doq"]];

/// The `tls_quic` fuzz target.
///
/// Operations (first byte modulo 5):
///
/// 0. initial keys: provider, suite, side, an 8-bit-prefixed connection ID,
///    then a packet (see [`initial`]);
/// 1. secrets: provider, suite, two 8-bit-prefixed traffic secrets, a key
///    update count and a packet (see [`secrets`]);
/// 2. retry: provider, suite, 8-bit-prefixed connection ID, 16-bit-prefixed
///    Retry packet and a tamper selector (see [`retry`]);
/// 3. codes: a 64-bit CRYPTO_ERROR code and an alert byte;
/// 4. handshake: configuration, delivery and damage (see [`handshake`]).
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut handshakes = 0;
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.choose(5) {
            0 => initial(&mut input),
            1 => secrets(&mut input),
            2 => retry(&mut input),
            3 => codes(&mut input),
            _ => {
                if handshakes < MAX_HANDSHAKES {
                    handshakes += 1;
                    handshake(&mut input);
                }
            }
        }
    }
}

// ------------------------------------------------------------- providers

fn provider(input: &mut Input) -> CryptoProvider {
    if input.bool() {
        browntls_core::crypto::rustcrypto::default_provider()
    } else {
        browntls_core::crypto::native::default_provider()
    }
}

/// The provider's TLS 1.3 suites (with or without a QUIC algorithm).
fn tls13_suites(provider: &CryptoProvider) -> Vec<&'static Tls13CipherSuite> {
    provider
        .cipher_suites
        .iter()
        .filter_map(SupportedCipherSuite::tls13)
        .collect()
}

/// A fuzz-chosen TLS 1.3 suite of `provider` and its QUIC form, if any.
fn suite(
    input: &mut Input,
    provider: &CryptoProvider,
) -> (&'static Tls13CipherSuite, Option<Suite>) {
    let suites = tls13_suites(provider);
    let suite = *input.pick(&suites);
    let quic = suite.quic_suite();
    assert_eq!(
        quic.is_some(),
        SupportedCipherSuite::Tls13(suite).usable_for_quic()
    );
    // RFC 9001 §5.3: CCM_8 has no QUIC header protection.
    if suite.common.suite == CipherSuite::TLS13_AES_128_CCM_8_SHA256 {
        assert!(quic.is_none());
    }
    (suite, quic)
}

fn other(side: Side) -> Side {
    match side {
        Side::Client => Side::Server,
        Side::Server => Side::Client,
    }
}

// ------------------------------------------------------------ packets

/// A short or long header packet: the header (first byte and packet
/// number) and its payload.
struct Packet {
    first: u8,
    packet_number: u64,
    header: Vec<u8>,
    payload: Vec<u8>,
}

fn packet(input: &mut Input) -> Packet {
    let first = input.byte();
    let packet_number = input.u64() & ((1 << 62) - 1);
    let mut header = vec![first];
    header.extend_from_slice(input.short_field());
    let pn_len = usize::from(first & 0x03) + 1;
    header.extend_from_slice(&packet_number.to_be_bytes()[8 - pn_len..]);
    Packet {
        first,
        packet_number,
        header,
        payload: input.field().to_vec(),
    }
}

/// `sender` protects `packet` and `receiver` opens it; damaged copies are
/// refused.
fn check_keys(
    sender: &quic::DirectionalKeys,
    receiver: &quic::DirectionalKeys,
    packet: &Packet,
    input: &mut Input,
) {
    check_packet_keys(&*sender.packet, &*receiver.packet, packet, input);

    // Header protection: a 16-byte sample of the "ciphertext".
    let sample = input.array::<16>();
    assert_eq!(sender.header.sample_len(), quic::SAMPLE_LEN);
    assert_eq!(
        sender.header.mask(&sample).unwrap(),
        receiver.header.mask(&sample).unwrap(),
        "header protection keys differ"
    );
    let pn_len = usize::from(packet.first & 0x03) + 1;
    let mut first = packet.first;
    let mut pn = [0u8; 4];
    pn[..pn_len].copy_from_slice(&packet.header[packet.header.len() - pn_len..]);
    let original = pn;
    sender
        .header
        .encrypt_in_place(&sample, &mut first, &mut pn)
        .unwrap();
    // The header form bit and the bytes past the packet number stay.
    assert_eq!(first & 0x80, packet.first & 0x80);
    assert_eq!(pn[pn_len..], original[pn_len..]);
    receiver
        .header
        .decrypt_in_place(&sample, &mut first, &mut pn)
        .unwrap();
    assert_eq!((first, pn), (packet.first, original));

    // A sample of any other length, and a packet number field shorter than
    // the encoded length.
    let len = input.choose(40);
    if len != quic::SAMPLE_LEN {
        let sample = vec![0x5a; len];
        assert!(sender.header.mask(&sample).is_err());
        assert!(
            sender
                .header
                .encrypt_in_place(&sample, &mut first, &mut pn)
                .is_err()
        );
    }
    if pn_len > 1 {
        let mut first = packet.first;
        assert!(
            sender
                .header
                .encrypt_in_place(&sample, &mut first, &mut pn[..pn_len - 1])
                .is_err()
        );
        assert_eq!(first, packet.first, "first byte changed on failure");
    }
}

fn check_packet_keys(
    sender: &dyn quic::PacketKey,
    receiver: &dyn quic::PacketKey,
    packet: &Packet,
    input: &mut Input,
) {
    assert_eq!(sender.tag_len(), receiver.tag_len());
    assert_eq!(
        sender.confidentiality_limit(),
        receiver.confidentiality_limit()
    );
    assert_eq!(sender.integrity_limit(), receiver.integrity_limit());
    assert!(sender.confidentiality_limit() > 0 && sender.integrity_limit() > 0);

    let mut sealed = packet.payload.clone();
    let tag = sender
        .encrypt_in_place(packet.packet_number, &packet.header, &mut sealed)
        .unwrap();
    sealed.extend_from_slice(tag.as_ref());
    let mut opened = sealed.clone();
    assert_eq!(
        receiver
            .decrypt_in_place(packet.packet_number, &packet.header, &mut opened)
            .unwrap(),
        &packet.payload[..],
        "packet keys differ"
    );

    // A flipped bit anywhere, another packet number or another header.
    let mut damaged = sealed.clone();
    let at = usize::from(input.u16()) % damaged.len();
    damaged[at] ^= 1 << input.choose(8);
    assert!(
        receiver
            .decrypt_in_place(packet.packet_number, &packet.header, &mut damaged)
            .is_err()
    );
    let mut copy = sealed.clone();
    assert!(
        receiver
            .decrypt_in_place(packet.packet_number ^ 1, &packet.header, &mut copy)
            .is_err()
    );
    let mut header = packet.header.clone();
    header.push(input.byte());
    let mut copy = sealed;
    assert!(
        receiver
            .decrypt_in_place(packet.packet_number, &header, &mut copy)
            .is_err()
    );
    // Shorter than a tag.
    let mut short = vec![0u8; usize::from(input.byte()) % sender.tag_len()];
    assert!(
        receiver
            .decrypt_in_place(packet.packet_number, &packet.header, &mut short)
            .is_err()
    );
}

// ------------------------------------------------------------ handshake

/// A CA and a `localhost` certificate, made once per process.
struct Pki {
    roots: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &issuer).expect("certificate");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .expect("root");
        Pki {
            roots: Arc::new(roots),
            chain: vec![CertificateDer::from(cert.der().to_vec())],
            key: key.serialize_der(),
        }
    })
}

/// Encryption levels, as indices.
const HANDSHAKE: usize = 0;
const ONE_RTT: usize = 1;

/// One side of an in-process QUIC handshake.
struct End {
    conn: Connection,
    keys: [Option<Keys>; 2],
    next: Option<Secrets>,
}

impl End {
    fn new(conn: Connection) -> Self {
        Self {
            conn,
            keys: [None, None],
            next: None,
        }
    }
}

/// How handshake bytes travel: chunk sizes and at most one damaged byte.
struct Delivery<'a> {
    input: Input<'a>,
    transfers: usize,
    damage: Option<(usize, usize, u8)>,
    damaged: bool,
}

impl Delivery<'_> {
    /// Splits `bytes` into fuzz-chosen pieces (whole when the input runs
    /// out) and damages the chosen byte of the chosen transfer.
    fn pieces(&mut self, mut bytes: Vec<u8>) -> Vec<Vec<u8>> {
        if let Some((transfer, offset, xor)) = self.damage
            && transfer == self.transfers
            && xor != 0
        {
            let at = offset % bytes.len();
            bytes[at] ^= xor;
            self.damaged = true;
        }
        self.transfers += 1;
        let mut out = Vec::new();
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let n = match self.input.byte() {
                0 => rest.len(),
                n => usize::from(n).min(rest.len()),
            };
            out.push(rest[..n].to_vec());
            rest = &rest[n..];
        }
        out
    }
}

/// Moves what `from` has to send to `to`, collecting `from`'s new keys.
/// Returns whether anything moved, or `to`'s error.
fn pump(from: &mut End, to: &mut End, delivery: &mut Delivery) -> Result<bool, Error> {
    let mut moved = false;
    loop {
        let mut buf = Vec::new();
        let change = from.conn.write_hs(&mut buf);
        if !buf.is_empty() {
            moved = true;
            for piece in delivery.pieces(buf) {
                to.conn.read_hs(&piece)?;
            }
        }
        match change {
            None => return Ok(moved),
            Some(KeyChange::Handshake { keys }) => {
                assert!(from.keys[HANDSHAKE].is_none(), "Handshake keys twice");
                from.keys[HANDSHAKE] = Some(keys);
            }
            Some(KeyChange::OneRtt { keys, next }) => {
                assert!(from.keys[HANDSHAKE].is_some(), "1-RTT before Handshake");
                assert!(from.keys[ONE_RTT].is_none(), "1-RTT keys twice");
                from.keys[ONE_RTT] = Some(keys);
                from.next = Some(next);
            }
        }
    }
}

fn handshaking(end: &End) -> bool {
    match &end.conn {
        Connection::Client(c) => c.is_handshaking(),
        Connection::Server(s) => s.is_handshaking(),
    }
}

/// Runs the handshake; Err holds the error of the side that failed.
fn drive(client: &mut End, server: &mut End, delivery: &mut Delivery) -> Result<(), Error> {
    for _ in 0..MAX_ROUNDS {
        let c = pump(client, server, delivery)?;
        let s = pump(server, client, delivery)?;
        if !c && !s {
            break;
        }
    }
    if handshaking(client) || handshaking(server) {
        return Err(Error::HandshakeNotComplete);
    }
    Ok(())
}

/// The configuration of one handshake, decoded from the input.
struct Setup {
    native: bool,
    suite_mask: u8,
    server_group: Option<usize>,
    client_alpn: usize,
    server_alpn: usize,
    client_params: Vec<u8>,
    server_params: Vec<u8>,
    early_data: u8,
    resume: bool,
    reject_early_data: bool,
    resumption_data: Vec<u8>,
    override_alpn: bool,
    damage: Option<(usize, usize, u8)>,
    after: Vec<u8>,
}

fn setup(input: &mut Input) -> Setup {
    let native = input.bool();
    let suite_mask = input.byte();
    let server_group = match input.byte() {
        0..=127 => None,
        n => Some(usize::from(n)),
    };
    let client_alpn = input.choose(ALPNS.len());
    let server_alpn = input.choose(ALPNS.len());
    let client_params = input.short_field().to_vec();
    let server_params = input.short_field().to_vec();
    let early_data = input.byte();
    let flags = input.byte();
    let resumption_data = input.short_field().to_vec();
    let damage = match input.byte() {
        0 => None,
        transfer => Some((
            usize::from(transfer % 16),
            usize::from(input.u16()),
            input.byte(),
        )),
    };
    let after = input.short_field().to_vec();
    Setup {
        native,
        suite_mask,
        server_group,
        client_alpn,
        server_alpn,
        client_params,
        server_params,
        early_data,
        resume: flags & 1 != 0,
        reject_early_data: flags & 2 != 0,
        override_alpn: flags & 4 != 0,
        resumption_data,
        damage,
        after,
    }
}

fn handshake(input: &mut Input) {
    let setup = setup(input);
    let pki = pki();
    let mut provider = if setup.native {
        browntls_core::crypto::native::default_provider()
    } else {
        browntls_core::crypto::rustcrypto::default_provider()
    };
    // Every TLS 1.3 suite whose bit is set (CCM_8 included, which QUIC
    // never uses).
    let suites: Vec<SupportedCipherSuite> = tls13_suites(&provider)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| setup.suite_mask & (1 << (i % 8)) != 0)
        .map(|(_, s)| SupportedCipherSuite::Tls13(s))
        .collect();
    let usable = suites.iter().any(SupportedCipherSuite::usable_for_quic);
    provider.cipher_suites = suites;
    let client_provider = Arc::new(provider.clone());
    let mut server_provider = provider;
    if let Some(group) = setup.server_group {
        let groups: Vec<&'static dyn SupportedKxGroup> = server_provider.kx_groups.clone();
        server_provider.kx_groups = vec![groups[group % groups.len()]];
    }

    let Ok(builder) = ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(&[&version::TLS13])
    else {
        assert!(!usable);
        return;
    };
    let mut server_config = builder
        .with_no_client_auth()
        .with_single_cert(
            pki.chain.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone())),
        )
        .expect("server certificate");
    server_config.alpn_protocols = ALPNS[setup.server_alpn]
        .iter()
        .map(|p| p.to_vec())
        .collect();
    // RFC 9001 §4.6.1: 0 or u32::MAX; anything else is refused.
    server_config.max_early_data_size = match setup.early_data % 4 {
        0 => 0,
        1 => u32::from(setup.early_data),
        _ => u32::MAX,
    };
    let server_config = Arc::new(server_config);

    let store = Arc::new(ClientSessionMemoryCache::new(4));
    let mut client_config = ClientConfig::builder_with_provider(client_provider)
        .with_protocol_versions(&[&version::TLS13])
        .expect("client versions")
        .with_root_certificates(pki.roots.clone())
        .with_no_client_auth();
    client_config.alpn_protocols = ALPNS[setup.client_alpn]
        .iter()
        .map(|p| p.to_vec())
        .collect();
    client_config.resumption = Resumption::store(store.clone());
    client_config.enable_early_data = setup.early_data & 0x80 != 0;
    let client_config = Arc::new(client_config);
    let name = ServerName::try_from("localhost").expect("name");

    let early_ok = matches!(server_config.max_early_data_size, 0 | u32::MAX);
    let alpn_agrees = {
        let (c, s) = (ALPNS[setup.client_alpn], ALPNS[setup.server_alpn]);
        (c.is_empty() && s.is_empty()) || c.iter().any(|p| s.contains(p))
    };

    let mut delivery = Delivery {
        input: Input::new(input.field()),
        transfers: 0,
        damage: setup.damage,
        damaged: false,
    };
    let connections = if setup.resume { 2 } else { 1 };
    for round in 0..connections {
        let client = if setup.override_alpn {
            quic::ClientConnection::new_with_alpn(
                client_config.clone(),
                Version::V1,
                name.clone(),
                setup.client_params.clone(),
                client_config.alpn_protocols.clone(),
            )
        } else {
            quic::ClientConnection::new(
                client_config.clone(),
                Version::V1,
                name.clone(),
                setup.client_params.clone(),
            )
        };
        let server = quic::ServerConnection::new(
            server_config.clone(),
            Version::V1,
            setup.server_params.clone(),
        );
        let (client, mut server) = match (client, server) {
            (Ok(c), Ok(s)) => {
                assert!(
                    usable && early_ok,
                    "QUIC accepted a configuration it cannot use"
                );
                (c, s)
            }
            (c, s) => {
                assert!(c.is_err() || s.is_err());
                assert_eq!(c.is_ok(), usable, "client: {:?}", c.err());
                assert_eq!(s.is_ok(), usable && early_ok, "server: {:?}", s.err());
                return;
            }
        };
        if round == 0 {
            server.set_resumption_data(&setup.resumption_data);
        } else if setup.reject_early_data {
            server.reject_early_data();
        }
        let zero_rtt = client.zero_rtt_keys();
        assert_eq!(
            zero_rtt.is_some(),
            client.quic_transport_parameters().is_some()
        );

        let mut c = End::new(Connection::Client(client));
        let mut s = End::new(Connection::Server(server));
        let result = drive(&mut c, &mut s, &mut delivery);
        if result.is_err() || delivery.damaged {
            // A failed side reports a TLS alert or a protocol violation;
            // either way nothing more is checked.
            let _ = (c.conn.alert(), s.conn.alert());
            if let Some(alert) = c.conn.alert() {
                assert!(quic::alert_from_crypto_error(quic::crypto_error_code(alert)).is_some());
            }
            return;
        }
        assert!(alpn_agrees, "handshake completed without agreeing on ALPN");
        check_handshake(&mut c, &mut s, &setup, zero_rtt, round, input);

        let (Connection::Client(client), Connection::Server(server)) = (c.conn, s.conn) else {
            unreachable!()
        };
        if round == 1 {
            let resumed = server.handshake_kind() == Some(HandshakeKind::Resumed);
            assert_eq!(
                server.received_resumption_data(),
                resumed.then_some(&setup.resumption_data[..])
            );
        }
        // The ticket remembers the server's transport parameters (RFC 9000
        // §7.4.1) and its early data size.
        if client.tls13_tickets_received() > 0
            && let Some(ticket) = store.take_tls13_ticket(&name)
        {
            assert_eq!(ticket.quic_params(), &setup.server_params[..]);
            store.insert_tls13_ticket(name.clone(), ticket);
        }
        // Fuzzed bytes after the handshake: post-handshake messages, of
        // which QUIC takes only NewSessionTicket from a server.
        post_handshake(client, server, &setup.after);
    }
}

fn check_handshake(
    client: &mut End,
    server: &mut End,
    setup: &Setup,
    zero_rtt: Option<quic::DirectionalKeys>,
    round: usize,
    input: &mut Input,
) {
    assert_eq!(
        client.conn.quic_transport_parameters(),
        Some(&setup.server_params[..])
    );
    assert_eq!(
        server.conn.quic_transport_parameters(),
        Some(&setup.client_params[..])
    );
    assert!(client.conn.alert().is_none() && server.conn.alert().is_none());
    let label = input.short_field();
    let context = input.short_field();
    let context = (!context.is_empty()).then_some(context);
    let a = client
        .conn
        .export_keying_material([0u8; 32], label, context)
        .unwrap();
    let b = server
        .conn
        .export_keying_material([0u8; 32], label, context)
        .unwrap();
    assert_eq!(a, b, "exporters differ");
    let packet = packet(input);
    for level in [HANDSHAKE, ONE_RTT] {
        let c = client.keys[level].as_ref().expect("client keys");
        let s = server.keys[level].as_ref().expect("server keys");
        check_keys(&c.local, &s.remote, &packet, input);
        check_keys(&s.local, &c.remote, &packet, input);
    }
    let (c_next, s_next) = (client.next.as_mut().unwrap(), server.next.as_mut().unwrap());
    let (c_keys, s_keys) = (c_next.next_packet_keys(), s_next.next_packet_keys());
    check_packet_keys(&*c_keys.local, &*s_keys.remote, &packet, input);

    let (Connection::Client(c), Connection::Server(s)) = (&client.conn, &server.conn) else {
        unreachable!()
    };
    assert_eq!(s.server_name(), Some("localhost"));
    assert_eq!(c.is_early_data_accepted(), s.is_early_data_accepted());
    assert_eq!(
        server.conn.zero_rtt_keys().is_some(),
        s.is_early_data_accepted()
    );
    if s.is_early_data_accepted() {
        assert_eq!(round, 1);
        assert!(!setup.reject_early_data);
        let sending = zero_rtt.expect("0-RTT keys offered");
        let receiving = s.zero_rtt_keys().expect("0-RTT keys accepted");
        check_keys(&sending, &receiving, &packet, input);
    } else {
        assert!(s.zero_rtt_keys().is_none());
    }
    // ConnectionCommon accessors, through the connection types.
    assert_eq!(
        c.quic_transport_parameters(),
        Some(&setup.server_params[..])
    );
    assert!(c.alert().is_none() && s.alert().is_none());
    assert_eq!(
        c.export_keying_material([0u8; 16], b"EXPORTER-quic", None)
            .ok(),
        s.export_keying_material([0u8; 16], b"EXPORTER-quic", None)
            .ok()
    );
}

fn post_handshake(
    mut client: quic::ClientConnection,
    mut server: quic::ServerConnection,
    after: &[u8],
) {
    if after.is_empty() {
        return;
    }
    let to_client = after[0] & 1 == 0;
    let bytes = &after[1..];
    let result = if to_client {
        client.read_hs(bytes)
    } else {
        server.read_hs(bytes)
    };
    if result.is_err() {
        let _ = if to_client {
            client.alert()
        } else {
            server.alert()
        };
    }
    let mut buf = Vec::new();
    while client.write_hs(&mut buf).is_some() {}
    while server.write_hs(&mut buf).is_some() {}
}

// ------------------------------------------------------------------ seeds

/// A handshake seed: native, suites, group, client ALPN, server ALPN,
/// early data, flags and damage selectors.
type HandshakeSeed = (u8, u8, u8, u8, u8, u8, u8, u8);

/// Starting inputs for `tls_quic`: one or more per operation.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let mut seeds = Vec::new();

    // 0: Initial keys for the RFC 9001 Appendix A connection ID, both
    // providers, both sides, a long and a short header.
    for (rustcrypto, side, first) in [(0u8, 0u8, 0xc3u8), (1, 1, 0x41), (0, 1, 0x40)] {
        let mut seed = vec![0, rustcrypto, 0, side];
        put_short_field(&mut seed, &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        seed.push(first);
        seed.extend_from_slice(&2u64.to_be_bytes());
        put_short_field(&mut seed, &[0xff, 0x00, 0x00, 0x01]);
        put_field(&mut seed, b"CRYPTO frame payload");
        seed.extend_from_slice(&[7, 3, 1, 0x40, 9, 1]);
        seeds.push(seed);
    }

    // 1: secrets for each suite, with key updates.
    for suite in 0..5u8 {
        let mut seed = vec![1, suite & 1, suite];
        put_short_field(&mut seed, &[0x11; 32]);
        put_short_field(&mut seed, &[0x22; 32]);
        seed.push(3);
        seed.push(0x41);
        seed.extend_from_slice(&0x1234u64.to_be_bytes());
        put_short_field(&mut seed, b"");
        put_field(&mut seed, b"1-RTT payload");
        seeds.push(seed);
    }

    // 2: a Retry tag with the RFC 9001 §A.4 connection ID, and with other
    // suites (refused).
    for suite in 0..4u8 {
        let mut seed = vec![2, 0, suite];
        put_short_field(&mut seed, &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        put_field(
            &mut seed,
            &[0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67],
        );
        seed.push(5);
        seeds.push(seed);
    }

    // 3: CRYPTO_ERROR codes in and around the range.
    for code in [0x0100u64, 0x0178, 0x01ff, 0x0200, 0x00ff] {
        let mut seed = vec![3];
        seed.extend_from_slice(&code.to_be_bytes());
        seed.push(40);
        seeds.push(seed);
    }

    // 4: handshakes on both providers: plain, with a HelloRetryRequest,
    // with resumption and 0-RTT, with mismatched ALPN, with damage, and
    // with pieces of every size.
    let configs: &[HandshakeSeed] = &[
        // native, suites, group, client alpn, server alpn, early, flags, damage
        (1, 0xff, 0, 1, 1, 0x82, 1, 0),
        (0, 0xff, 0, 1, 1, 0x82, 1, 0),
        (1, 0xff, 0x81, 1, 2, 0x82, 1, 0),
        (1, 0x01, 0, 0, 0, 0, 0, 0),
        (1, 0x02, 0, 2, 2, 0x83, 7, 0),
        (0, 0x04, 0x82, 1, 1, 0, 0, 0),
        (1, 0xff, 0, 1, 3, 0, 0, 0),
        (1, 0xff, 0, 1, 0, 0, 0, 0),
        (1, 0xff, 0, 1, 1, 1, 0, 0),
        (1, 0x10, 0, 1, 1, 0, 0, 0),
        (1, 0xff, 0, 1, 1, 0, 0, 2),
        (0, 0xff, 0, 1, 1, 0x82, 3, 4),
    ];
    for &(native, suites, group, calpn, salpn, early, flags, damage) in configs {
        let mut seed = vec![4, native, suites, group, calpn, salpn];
        put_short_field(&mut seed, b"\x01\x04\x80\x00\xea\x60");
        put_short_field(&mut seed, b"\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00");
        seed.extend_from_slice(&[early, flags]);
        put_short_field(&mut seed, b"resumption data");
        seed.push(damage);
        if damage != 0 {
            seed.extend_from_slice(&[0, 9, 0x40]);
        }
        put_short_field(&mut seed, b"\x00\x04\x00\x00\x01\x00");
        // delivery: whole, then one byte at a time, then whole
        let delivery: &[u8] = match flags {
            7 => &[1; 64],
            _ => &[0; 8],
        };
        put_field(&mut seed, delivery);
        put_short_field(&mut seed, b"EXPORTER-test");
        put_short_field(&mut seed, b"ctx");
        seed.push(0x41);
        seed.extend_from_slice(&7u64.to_be_bytes());
        put_short_field(&mut seed, b"");
        put_field(&mut seed, b"stream data");
        seeds.push(seed);
    }
    seeds
}
