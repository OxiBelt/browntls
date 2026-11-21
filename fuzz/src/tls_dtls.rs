//! DTLS 1.3, RFC 9147 (`fuzz_targets/tls_dtls.rs`).
//!
//! Reaches every public function of `browntls_core::dtls`: handshakes
//! between a client and a server in the same process, each on either
//! provider, with fuzz-chosen protocol versions, TLS 1.3 suites (CCM_8,
//! which DTLS 1.3 refuses, included), server key types, key exchange groups
//! and datagram sizes (256 to 1500 bytes), with the cookie exchange on or
//! off, through the stateless `Acceptor` (also with a cookie replayed from
//! another address), with a deferred revocation check, and resumed with a
//! ticket; the network between them drops, duplicates, reorders and damages
//! datagrams and forges new ones, and the virtual clock fires timers early,
//! on time or late. Established connections then exchange application data
//! both ways, update their keys, close, export keying material, change
//! their datagram size, and receive fuzzed datagrams shaped like DTLS
//! records (plaintext headers, unified headers with every flag
//! combination, ACK bodies, fragmented handshake headers) and replays of
//! earlier datagrams. Fuzzed datagrams also go to fresh clients, fresh
//! servers and the `Acceptor`.
//!
//! Checked properties: nothing panics; a connection is refused exactly
//! when its configuration cannot do DTLS 1.3 (no TLS 1.3, only CCM_8, a
//! cookie exchange without a cookie sealer); an undamaged handshake
//! (nothing damaged or forged, at most [`net::MAX_LOSS`] datagrams lost)
//! between compatible configurations completes, and both sides then agree
//! on the protocol version (DTLS 1.3), the suite and the exporter, the
//! server saw the name `localhost`, a cookie exchange shows as a
//! HelloRetryRequest, and a client holding a ticket resumes with the
//! resumption data the server stored; a cookie from another address never
//! completes a handshake; every datagram fits the sender's MTU;
//! application data arrives exactly as sent, once, and never when the
//! datagram was damaged or replayed; application data that does not fit a
//! datagram is refused; an established connection never fails because of
//! damaged, forged or replayed datagrams (none authenticates), and key
//! updates and close_notify complete over a network that loses at most
//! [`net::MAX_LOSS`] datagrams.
//!
//! Input: up to 64 operations, each an operation byte followed by its
//! arguments (see [`run`]); at most three handshakes per input, each run of
//! the network bounded in steps and virtual time.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use browntls_core::{CipherSuite, Error, HandshakeKind, PeerMisbehaved, ProtocolVersion, dtls};

use crate::input::Input;

mod net;
mod seeds;
mod setup;
mod shape;
#[cfg(test)]
mod tests;

use self::net::{Failure, Net, settled};
pub use self::seeds::seeds;
use self::setup::{Choice, Configs, localhost};

/// Operations per input.
const MAX_OPS: usize = 64;

/// Handshakes (including resumptions) per input.
const MAX_HANDSHAKES: usize = 3;

/// The client's transport address as the server sees it.
const PEER: &[u8] = b"192.0.2.1:4433";

/// Another address, from which a stolen cookie is replayed.
const OTHER: &[u8] = b"198.51.100.7:9";

/// Where the virtual clock starts.
const START: Duration = Duration::from_secs(1000);

/// How the server meets the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// `ServerConnection::new`: a cookie exchange on the connection.
    Cookie,
    /// `ServerConnection::new_without_cookie_exchange`.
    NoCookie,
    /// The stateless `Acceptor`, then the connection it returns.
    Acceptor,
    /// The `Acceptor`, with the second ClientHello from another address.
    Stolen,
}

/// A client and server, once created.
struct Pair {
    client: dtls::ClientConnection,
    server: dtls::ServerConnection,
    established: bool,
    client_closed: bool,
    server_closed: bool,
    /// KeyUpdates the client may have requested since the server last
    /// received data: the server fails the connection after eight.
    client_requests: u8,
}

/// The configurations of the current handshakes and their network.
struct Session<'a> {
    configs: Configs,
    mode: Mode,
    mtu: Option<(usize, usize)>,
    resumption_data: Vec<u8>,
    /// Tickets the client holds.
    tickets: u32,
    net: Net<'a>,
    pair: Option<Pair>,
}

/// The `tls_dtls` fuzz target.
///
/// Operations (first byte modulo 10):
///
/// 0. handshake: configurations, then a connection (see [`handshake`]);
/// 1. resume: another connection with the same configurations;
/// 2. data: direction, 16-bit-prefixed payload, fate (see
///    [`application_data`]);
/// 3. key update: side, 8-bit-prefixed network fates and clock;
/// 4. close: side, 8-bit-prefixed network fates;
/// 5. garbage: side, then a shaped datagram for an established connection;
/// 6. replay: a delivered datagram, its receiver and damage;
/// 7. fresh: shaped datagrams for a new client, server or `Acceptor`;
/// 8. misc: MTU, timers and oversized application data;
/// 9. export: label, context and length, on both sides.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut session: Option<Session> = None;
    let mut handshakes = 0;
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        let op = input.choose(10);
        if op <= 1 {
            if handshakes == MAX_HANDSHAKES {
                return;
            }
            handshakes += 1;
        }
        match (op, session.as_mut()) {
            (0, _) => session = handshake(&mut input),
            (1, Some(s)) => connect(s, &mut input),
            (7, _) => fresh(&mut input, session.as_mut()),
            (_, Some(s)) => match s.pair.as_mut() {
                Some(pair) if pair.established => match op {
                    2 => application_data(pair, &mut s.net, &mut input),
                    3 => key_update(pair, &mut s.net, &mut input),
                    4 => close(pair, &mut s.net, &mut input),
                    5 => garbage(pair, &mut s.net, &mut input),
                    6 => replay(pair, &mut s.net, &mut input),
                    8 => misc(pair, &mut s.net, &mut input),
                    _ => export(pair, &mut input),
                },
                _ => return,
            },
            _ => return,
        }
    }
}

// ------------------------------------------------------------- handshake

/// Decodes configurations and runs the first connection:
///
/// client side, server side (each a provider-and-versions byte and a
/// suite mask), key type, server group (0..=127: all), flags (bit 0: no
/// cookie sealer, bits 1-2: [`Mode`], bit 3: deferred revocation check,
/// bit 4: set MTUs), two 16-bit MTUs, 8-bit-prefixed resumption data, then
/// the connection (see [`connect`]).
fn handshake<'a>(input: &mut Input<'a>) -> Option<Session<'a>> {
    let client = setup::Side::read(input);
    let server = setup::Side::read(input);
    let key_type = input.choose(setup::KEY_TYPES);
    let server_group = match input.byte() {
        0..=127 => None,
        n => Some(usize::from(n)),
    };
    let flags = input.byte();
    let (client_mtu, server_mtu) = (input.u16(), input.u16());
    let resumption_data = input.short_field().to_vec();
    let choice = Choice {
        client,
        server,
        key_type,
        server_group,
        cookies: flags & 1 == 0,
        defer: flags & 8 != 0,
    };
    let mode =
        [Mode::Cookie, Mode::NoCookie, Mode::Acceptor, Mode::Stolen][usize::from(flags >> 1 & 3)];
    let mtu = |v: u16| 256 + usize::from(v) % 1245;
    let mut session = Session {
        configs: setup::configs(&choice),
        mode,
        mtu: (flags & 16 != 0).then(|| (mtu(client_mtu), mtu(server_mtu))),
        resumption_data,
        tickets: 0,
        net: Net::new(START),
        pair: None,
    };
    connect(&mut session, input);
    Some(session)
}

/// Creates a client and a server and runs their handshake over a network
/// scripted by three fields: 16-bit-prefixed fates, 8-bit-prefixed clock
/// and 8-bit-prefixed revocation answers.
fn connect<'a>(session: &mut Session<'a>, input: &mut Input<'a>) {
    session.pair = None;
    let fates = input.field();
    let clock = input.short_field();
    let revocation = input.short_field();
    let configs = &session.configs;
    let (Some(client_config), Some(server_config)) = (&configs.client, &configs.server) else {
        return;
    };
    let client = dtls::ClientConnection::new(client_config.clone(), localhost());
    assert_eq!(
        client.is_ok(),
        configs.client_usable,
        "client: {:?}",
        client.as_ref().err()
    );
    let Ok(mut client) = client else { return };
    // A ticket, if the client holds one, went into its ClientHello.
    let offered_ticket = session.tickets > 0;
    session.tickets = session.tickets.saturating_sub(1);
    let mut out = Vec::new();
    assert!(client.send(b"too early", &mut out).is_err() && out.is_empty());
    if let Some((client_mtu, _)) = session.mtu {
        client.set_mtu(client_mtu).expect("MTU in range");
        assert_eq!(client.mtu(), client_mtu);
    }

    let needs_cookies = session.mode != Mode::NoCookie;
    let server_ok = configs.server_usable && (configs.cookies || !needs_cookies);
    let net = &mut session.net;
    net.script(fates, clock, revocation);
    let mut server = match session.mode {
        Mode::Cookie | Mode::NoCookie => {
            let server = if session.mode == Mode::Cookie {
                dtls::ServerConnection::new(server_config.clone(), PEER)
            } else {
                dtls::ServerConnection::new_without_cookie_exchange(server_config.clone(), PEER)
            };
            assert_eq!(server.is_ok(), server_ok, "server: {:?}", server.err());
            let Ok(server) = server else { return };
            server
        }
        Mode::Acceptor | Mode::Stolen => {
            let acceptor = dtls::Acceptor::new(server_config.clone());
            assert_eq!(
                acceptor.is_ok(),
                server_ok,
                "acceptor: {:?}",
                acceptor.err()
            );
            let Ok(acceptor) = acceptor else { return };
            let stolen = session.mode == Mode::Stolen;
            let compatible = configs.compatible;
            let Some(server) = accept(&acceptor, &mut client, stolen, compatible, net.now) else {
                return;
            };
            server
        }
    };
    if let Some((_, server_mtu)) = session.mtu {
        server.set_mtu(server_mtu).expect("MTU in range");
    }
    server.set_resumption_data(&session.resumption_data);
    assert!(server.server_name().is_none() || session.mode != Mode::Cookie);

    let result = net.run(&mut client, &mut server, settled);
    session.tickets += client.tls13_tickets_received();
    let expected = configs.compatible && server_ok && net.undamaged();
    let mut pair = Pair {
        client,
        server,
        established: false,
        client_closed: false,
        server_closed: false,
        client_requests: 0,
    };
    match result {
        Ok(()) => {
            assert_ne!(session.mode, Mode::Stolen, "a stolen cookie was accepted");
            check_established(
                &pair,
                session.mode,
                offered_ticket,
                &session.resumption_data,
            );
            #[cfg(test)]
            tests::established(session.mode, pair.server.handshake_kind());
            pair.established = true;
        }
        Err(failure) => {
            assert!(
                !expected || session.mode == Mode::Stolen,
                "undamaged {:?} handshake failed: {failure:?}",
                session.mode
            );
            net.wind_down(&mut pair.client, &mut pair.server);
        }
    }
    session.pair = Some(pair);
}

/// The stateless exchange: the client's first flight goes to `acceptor`,
/// its HelloRetryRequest back, and the second ClientHello (from another
/// address when `stolen`) yields the server connection. A server that
/// cannot agree with the client (`compatible` false) ignores the
/// ClientHello.
fn accept(
    acceptor: &dtls::Acceptor,
    client: &mut dtls::ClientConnection,
    stolen: bool,
    compatible: bool,
    now: Duration,
) -> Option<dtls::ServerConnection> {
    let first = drain(client, now);
    let mut retry = None;
    for mut datagram in first.iter().cloned() {
        let mut out = Vec::new();
        match acceptor.accept(&mut datagram, PEER, &mut out, now) {
            Ok(dtls::Accepted::Retry) => {
                assert!(!out.is_empty() && out.len() <= 1200, "{}", out.len());
                retry.get_or_insert(out);
            }
            Ok(dtls::Accepted::Ignored) => assert!(out.is_empty()),
            other => panic!("a first ClientHello gave {other:?}"),
        }
    }
    // A first ClientHello that fits one datagram is answered (RFC 9147
    // §5.1); one in pieces is not.
    assert!(
        retry.is_some() || first.len() > 1 || !compatible,
        "unanswered ClientHello"
    );
    let mut retry = retry?;
    client.read_datagram(&mut retry, now).expect("cookie retry");
    let mut second = drain(client, now).into_iter();
    let mut head = second.next().expect("second ClientHello");
    let address = if stolen { OTHER } else { PEER };
    let mut out = Vec::new();
    let mut server = match acceptor.accept(&mut head, address, &mut out, now) {
        Ok(dtls::Accepted::Connection(server)) => *server,
        Ok(dtls::Accepted::Ignored) if stolen => return None,
        other => panic!("a second ClientHello gave {other:?}"),
    };
    for mut datagram in second {
        let result = server.read_datagram(&mut datagram, now);
        if result.is_err() {
            assert!(stolen, "{result:?}");
            return None;
        }
    }
    Some(server)
}

/// Every datagram `conn` has to send now, each within its MTU.
fn drain<D: browntls_core::SideData>(
    conn: &mut dtls::ConnectionCommon<D>,
    now: Duration,
) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    let mut out = Vec::new();
    while let Ok(true) = conn.write_datagram(&mut out, now) {
        assert!(out.len() <= conn.mtu());
        datagrams.push(std::mem::take(&mut out));
    }
    datagrams
}

fn check_established(pair: &Pair, mode: Mode, offered_ticket: bool, resumption_data: &[u8]) {
    let (client, server) = (&pair.client, &pair.server);
    for side in [&***client, &***server] {
        assert_eq!(side.protocol_version(), Some(ProtocolVersion::DTLSv1_3));
        assert!(!side.is_handshaking());
    }
    let suite = client.negotiated_cipher_suite().expect("suite");
    assert_eq!(Some(suite), server.negotiated_cipher_suite());
    assert_ne!(suite.suite(), CipherSuite::TLS13_AES_128_CCM_8_SHA256);
    assert_eq!(server.server_name(), Some("localhost"));
    assert!(!client.peer_has_closed() && !server.peer_has_closed());
    assert!(client.max_application_data().is_some_and(|n| n > 0));
    let a = client.export_keying_material([0u8; 32], b"EXPORTER-dtls-fuzz", Some(b"ctx"));
    let b = server.export_keying_material([0u8; 32], b"EXPORTER-dtls-fuzz", Some(b"ctx"));
    assert_eq!(a.expect("client exporter"), b.expect("server exporter"));

    let resumed = server.handshake_kind() == Some(HandshakeKind::Resumed);
    assert_eq!(
        client.handshake_kind() == Some(HandshakeKind::Resumed),
        resumed
    );
    // Tickets are stored only after a complete handshake; one was offered
    // to the same server configuration, so it must be accepted.
    assert_eq!(resumed, offered_ticket, "ticket offered but not resumed");
    assert_eq!(
        server.received_resumption_data(),
        resumed.then_some(resumption_data)
    );
    if mode != Mode::NoCookie && !resumed {
        assert_eq!(
            client.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
    }
}

// ---------------------------------------------------- established pairs

/// Direction byte, 16-bit-prefixed payload, then a fate: deliver, drop,
/// duplicate or damage (16-bit position, xor byte).
fn application_data(pair: &mut Pair, net: &mut Net, input: &mut Input) {
    let to_server = input.bool();
    let payload = input.field();
    let fate = input.choose(4);
    let closed = pair.client_closed || pair.server_closed;
    let sender_closed = if to_server {
        pair.client_closed
    } else {
        pair.server_closed
    };
    let mut out = Vec::new();
    let (result, max, mtu) = if to_server {
        let max = pair.client.max_application_data().expect("established");
        (pair.client.send(payload, &mut out), max, pair.client.mtu())
    } else {
        let max = pair.server.max_application_data().expect("established");
        (pair.server.send(payload, &mut out), max, pair.server.mtu())
    };
    if payload.len() > max || sender_closed {
        assert!(
            result.is_err() && out.is_empty(),
            "{} > {max}",
            payload.len()
        );
        return;
    }
    result.expect("send");
    assert!(!out.is_empty() && out.len() <= mtu);
    let copies = match fate {
        0 => 1,
        1 => 0,
        2 => 2,
        _ => {
            let at = usize::from(input.u16()) % out.len();
            out[at] ^= input.byte().max(1);
            1
        }
    };
    let mut received = Vec::new();
    for _ in 0..copies {
        received.extend(read(pair, net, to_server, &out).expect("established read"));
    }
    if to_server && received.iter().any(|r| !r.is_empty()) {
        pair.client_requests = 0;
    }
    let expected: &[&[u8]] = match fate {
        0 | 2 if !payload.is_empty() => &[payload],
        _ => &[],
    };
    if closed {
        assert!(received.len() <= 1 && received.iter().all(|r| r == payload));
    } else if payload.is_empty() {
        assert!(received.iter().all(Vec::is_empty) && received.len() <= 1);
    } else {
        assert_eq!(received, expected, "application data");
    }
}

/// Delivers a copy of `datagram` to one side, logging it for replays;
/// returns the application data it carried.
fn read(
    pair: &mut Pair,
    net: &mut Net,
    to_server: bool,
    datagram: &[u8],
) -> Result<Vec<Vec<u8>>, browntls_core::Error> {
    net.remember(to_server, datagram);
    let mut copy = datagram.to_vec();
    let received = if to_server {
        pair.server.read_datagram(&mut copy, net.now)?
    } else {
        pair.client.read_datagram(&mut copy, net.now)?
    };
    Ok(received
        .app_data()
        .iter()
        .map(|range| copy[range.clone()].to_vec())
        .collect())
}

/// Side (client, server, both, client twice), 8-bit-prefixed fates and
/// clock.
fn key_update<'a>(pair: &mut Pair, net: &mut Net<'a>, input: &mut Input<'a>) {
    let side = input.choose(4);
    let fates = input.short_field();
    let clock = input.short_field();
    // After our close_notify a refresh does nothing (RFC 9846 §6.1).
    if side != 1 {
        pair.client
            .refresh_traffic_keys()
            .expect("client key update");
        pair.client_requests = pair.client_requests.saturating_add(1);
    }
    if side == 1 || side == 2 {
        pair.server
            .refresh_traffic_keys()
            .expect("server key update");
    }
    if side == 3 {
        // A second request while the first awaits its ACK just waits.
        let _ = pair.client.refresh_traffic_keys();
        pair.client_requests = pair.client_requests.saturating_add(1);
    }
    settle(pair, net, fates, clock);
}

/// Runs the network until both sides settle; a pair that loses at most
/// [`net::MAX_LOSS`] datagrams must.
fn settle<'a>(pair: &mut Pair, net: &mut Net<'a>, fates: &'a [u8], clock: &'a [u8]) {
    net.script(fates, clock, &[]);
    let result = net.run(&mut pair.client, &mut pair.server, settled);
    if let Err(failure) = result {
        let too_many_requests = matches!(
            failure,
            Failure::Server(Error::PeerMisbehaved(
                PeerMisbehaved::TooManyKeyUpdateRequests
            ))
        );
        assert!(
            !net.lossless() || (too_many_requests && pair.client_requests > 8),
            "established connections failed: {failure:?}"
        );
        net.wind_down(&mut pair.client, &mut pair.server);
        pair.established = false;
    }
}

/// Side, then 8-bit-prefixed fates for the alert.
fn close<'a>(pair: &mut Pair, net: &mut Net<'a>, input: &mut Input<'a>) {
    let client = input.bool();
    let fates = input.short_field();
    // A second close_notify is not sent.
    let first = if client {
        pair.client.send_close_notify();
        !std::mem::replace(&mut pair.client_closed, true)
    } else {
        pair.server.send_close_notify();
        !std::mem::replace(&mut pair.server_closed, true)
    };
    settle(pair, net, fates, &[]);
    if !pair.established {
        return;
    }
    let mut out = Vec::new();
    let sent = if client {
        pair.client.send(b"late", &mut out)
    } else {
        pair.server.send(b"late", &mut out)
    };
    assert!(sent.is_err() && out.is_empty());
    let closed = if client {
        pair.server.peer_has_closed()
    } else {
        pair.client.peer_has_closed()
    };
    // The alert is sent once; when nothing was lost it arrived.
    assert!(closed || !first || net.dropped + net.corrupted > 0);
}

/// Side, then a shaped datagram: dropped silently.
fn garbage(pair: &mut Pair, net: &mut Net, input: &mut Input) {
    let to_server = input.bool();
    let datagram = shape::datagram(input);
    let received = read(pair, net, to_server, &datagram).expect("garbage failed a connection");
    assert!(received.is_empty(), "garbage delivered data");
}

/// A logged datagram (index byte), to its receiver or the other side
/// (bool), optionally damaged (bool, 16-bit position, xor byte).
fn replay(pair: &mut Pair, net: &mut Net, input: &mut Input) {
    let index = usize::from(input.byte());
    let swap = input.bool();
    let damage = input.bool().then(|| (input.u16(), input.byte().max(1)));
    if net.log.is_empty() {
        return;
    }
    let (to_server, mut datagram) = net.log[index % net.log.len()].clone();
    if let Some((at, xor)) = damage
        && !datagram.is_empty()
    {
        let at = usize::from(at) % datagram.len();
        datagram[at] ^= xor;
    }
    let received =
        read(pair, net, to_server ^ swap, &datagram).expect("a replay failed a connection");
    assert!(received.is_empty(), "a replay delivered data");
}

/// Sub-operation (modulo 3): an MTU (16 bits, then side); timers (byte of
/// seconds) and a lossless run; oversized application data (side).
fn misc<'a>(pair: &mut Pair, net: &mut Net<'a>, input: &mut Input<'a>) {
    match input.choose(3) {
        0 => {
            let mtu = usize::from(input.u16());
            let conn: &mut dtls::ConnectionCommon<_> = &mut pair.client;
            let before = conn.mtu();
            let ok = (256..=65_507).contains(&mtu);
            assert_eq!(conn.set_mtu(mtu).is_ok(), ok);
            assert_eq!(conn.mtu(), if ok { mtu } else { before });
            let before = pair.server.mtu();
            assert_eq!(pair.server.set_mtu(mtu).is_ok(), ok);
            assert_eq!(pair.server.mtu(), if ok { mtu } else { before });
        }
        1 => {
            let later = net.now + Duration::from_secs(u64::from(input.byte()));
            let _ = (
                pair.client.wants_write(later),
                pair.server.wants_write(later),
            );
            let _ = (pair.client.next_timeout(), pair.server.next_timeout());
            let _ = pair.client.handle_timeout(later);
            let _ = pair.server.handle_timeout(later);
            net.now = later;
            settle(pair, net, &[], &[]);
        }
        _ => {
            let mut out = Vec::new();
            let max = pair.server.max_application_data().expect("established");
            assert!(pair.server.send(&vec![0; max + 1], &mut out).is_err());
            assert!(out.is_empty());
            let max = pair.client.max_application_data().expect("established");
            assert!(pair.client.send(&vec![0; max + 1], &mut out).is_err());
            assert!(out.is_empty());
        }
    }
}

/// 8-bit-prefixed label and context (absent when empty), and a length up
/// to 63 bytes: both sides agree.
fn export(pair: &mut Pair, input: &mut Input) {
    let label = input.short_field();
    let context = input.short_field();
    let context = (!context.is_empty()).then_some(context);
    let len = input.choose(64);
    let a = pair
        .client
        .export_keying_material(vec![0u8; len], label, context);
    let b = pair
        .server
        .export_keying_material(vec![0u8; len], label, context);
    assert_eq!(a.ok(), b.ok(), "exporters differ");
}

// ------------------------------------------------------ fresh endpoints

/// The configurations fuzzed datagrams go to when no session has usable
/// ones: native provider, P-256, every suite, cookies.
fn default_configs() -> &'static Configs {
    static CONFIGS: OnceLock<Configs> = OnceLock::new();
    CONFIGS.get_or_init(|| {
        let side = setup::Side {
            rustcrypto: false,
            suites: 0xff,
            versions: 0,
        };
        setup::configs(&Choice {
            client: side,
            server: side,
            key_type: 0,
            server_group: None,
            cookies: true,
            defer: false,
        })
    })
}

/// Target (client, server, server without cookies, acceptor), a clock
/// byte, an 8-bit-prefixed address, then one to three shaped datagrams.
fn fresh(input: &mut Input, session: Option<&mut Session>) {
    let (configs, tickets) = match session {
        Some(s) if s.configs.compatible && s.configs.cookies => (&s.configs, Some(&mut s.tickets)),
        _ => (default_configs(), None),
    };
    let target = input.choose(4);
    let now = START + Duration::from_millis(u64::from(input.byte()) * 100);
    let address = input.short_field();
    let count = 1 + input.choose(3);
    let datagrams: Vec<Vec<u8>> = (0..count).map(|_| shape::datagram(input)).collect();
    let client_config = configs.client.clone().expect("client config");
    let server_config: Arc<_> = configs.server.clone().expect("server config");
    match target {
        0 => {
            let mut client =
                dtls::ClientConnection::new(client_config, localhost()).expect("client");
            // It took a ticket of the session's client, if it held one.
            if let Some(tickets) = tickets {
                *tickets = tickets.saturating_sub(1);
            }
            feed(&mut client, datagrams, now);
        }
        1 | 2 => {
            let mut server = if target == 1 {
                dtls::ServerConnection::new(server_config, address)
            } else {
                dtls::ServerConnection::new_without_cookie_exchange(server_config, address)
            }
            .expect("server");
            feed(&mut server, datagrams, now);
        }
        _ => {
            let acceptor = dtls::Acceptor::new(server_config).expect("acceptor");
            let mut datagrams = datagrams.into_iter();
            for mut datagram in datagrams.by_ref() {
                let mut out = Vec::new();
                match acceptor.accept(&mut datagram, address, &mut out, now) {
                    Ok(dtls::Accepted::Retry) => assert!(!out.is_empty() && out.len() <= 1200),
                    Ok(dtls::Accepted::Ignored) => assert!(out.is_empty()),
                    Ok(dtls::Accepted::Connection(mut server)) => {
                        feed(&mut server, datagrams.collect(), now);
                        return;
                    }
                    Err(err) => panic!("the acceptor failed: {err:?}"),
                }
            }
        }
    }
}

/// Feeds `datagrams` to `conn`, sending what it answers and firing its
/// timer; any outcome but a panic will do.
fn feed<D: browntls_core::SideData>(
    conn: &mut dtls::ConnectionCommon<D>,
    datagrams: Vec<Vec<u8>>,
    now: Duration,
) {
    drain(conn, now);
    for mut datagram in datagrams {
        if conn.read_datagram(&mut datagram, now).is_err() {
            drain(conn, now);
            return;
        }
        drain(conn, now);
    }
    if let Some(at) = conn.next_timeout() {
        let _ = conn.handle_timeout(at);
        drain(conn, at);
    }
}
