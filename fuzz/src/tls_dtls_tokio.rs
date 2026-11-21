//! Real Tokio DTLS endpoints on ephemeral IPv4 loopback sockets.
//!
//! Header: constructor modulo four (new, from_connection, connect, cancelled
//! handshake), provider bits 0/1 and key type in bits 2/3, then MTU modulo
//! three (256, 512, 1200; from_connection only). Up to 24 actions follow;
//! see `ops.rs`. Payloads use Input::short_field, never stream framing.
//! Flag bit 5 selects the listener/session program in `sessions.rs`.
//!
//! One current-thread runtime drives both endpoints, with no endpoint tasks.
//! Every wait has an outer two-second bound, and the input has a ten-second
//! bound. API deadlines use real monotonic time, never auto-advancing paused
//! time while a real socket awaits readiness. Keys and handshake randomness
//! are process-local; the API program, rather than ciphertext, replays.

use std::future::{Future, poll_fn};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use browntls_core::dtls::ClientConnection;
use browntls_core::{ClientConfig, ProtocolVersion};
use browntls_tokio::dtls::{ServerEvent, UdpClient, UdpServer};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::input::Input;
use crate::tls_dtls::setup::{self, Choice, Side};

mod ops;
mod seeds;
mod sessions;
#[cfg(test)]
mod tests;

pub use seeds::seeds;

const LIMIT: Duration = Duration::from_secs(2);
const INPUT_LIMIT: Duration = Duration::from_secs(10);
const MAX_ACTIONS: usize = 24;

/// Executes a bounded public API program, without sending outside loopback.
pub fn run(data: &[u8]) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(async {
            timeout(INPUT_LIMIT, exercise(data))
                .await
                .expect("DTLS input deadline");
        });
}

async fn bounded<F: Future>(future: F) -> F::Output {
    timeout(LIMIT, future).await.expect("DTLS action deadline")
}

// Poll both borrowers directly: no macros, spawning or background I/O.
async fn together<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let mut a = pin!(a);
    let mut b = pin!(b);
    let (mut ar, mut br) = (None, None);
    bounded(poll_fn(|cx| {
        if ar.is_none()
            && let Poll::Ready(value) = a.as_mut().poll(cx)
        {
            ar = Some(value);
        }
        if br.is_none()
            && let Poll::Ready(value) = b.as_mut().poll(cx)
        {
            br = Some(value);
        }
        if ar.is_some() && br.is_some() {
            Poll::Ready((ar.take().unwrap(), br.take().unwrap()))
        } else {
            Poll::Pending
        }
    }))
    .await
}

// Poll a real operation once, then drop it. No timer race decides whether
// the cancellation path ran. Call only when no application data is owed.
async fn cancel_pending(future: impl Future) {
    let mut future = pin!(future);
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn socket() -> UdpSocket {
    bounded(UdpSocket::bind("127.0.0.1:0"))
        .await
        .expect("ephemeral loopback socket")
}

async fn connected_socket(server: SocketAddr) -> UdpSocket {
    assert!(server.ip().is_loopback());
    let socket = socket().await;
    bounded(socket.connect(server)).await.expect("connect UDP");
    socket
}

struct Session {
    client: UdpClient,
    server: UdpServer,
    peer: SocketAddr,
    server_addr: SocketAddr,
}

async fn exercise(data: &[u8]) {
    let mut input = Input::new(data);
    let constructor = input.choose(4);
    let flags = input.byte();
    let mtu = [256, 512, 1200][input.choose(3)];
    let side = |bit| Side {
        rustcrypto: flags & bit != 0,
        versions: 0,
        suites: 0xff,
    };
    let configs = setup::configs(&Choice {
        client: side(1),
        server: side(2),
        key_type: usize::from((flags >> 2) & 3) % setup::KEY_TYPES,
        server_group: None,
        cookies: true,
        defer: false,
    });
    assert!(configs.compatible);
    let config = configs.client.expect("verified client config");
    let mut server_config = (*configs.server.expect("cookie server config")).clone();
    // Keep idle checks about application records rather than ticket timers.
    server_config.send_tls13_tickets = 0;
    let server_config = Arc::new(server_config);

    if flags & 0x20 != 0 {
        sessions::exercise(config, server_config, constructor, flags, mtu, input).await;
        return;
    }

    if flags & 0x10 != 0 {
        assert!(UdpClient::new(config.clone(), setup::localhost(), socket().await).is_err());
        let listener = socket().await;
        let connected = connected_socket(listener.local_addr().unwrap()).await;
        assert_eq!(
            UdpServer::new(server_config.clone(), connected)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        let mut no_cookies = (*server_config).clone();
        no_cookies.hello_retry_cookies = None;
        assert!(UdpServer::new(Arc::new(no_cookies), socket().await).is_err());
        reached("constructor rejection");
    }

    let mut server = UdpServer::new(server_config, socket().await).expect("event server");
    server.set_max_handshakes(2);
    server.set_max_peers(2);
    server.set_handshake_timeout(LIMIT);
    server.set_read_timeout(Some(LIMIT));
    let server_addr = server.socket().local_addr().unwrap();
    let transport = connected_socket(server_addr).await;
    let peer = transport.local_addr().unwrap();

    let mut client = if constructor == 2 {
        let (client, event) = together(
            UdpClient::connect(config, setup::localhost(), transport),
            server.next_event(),
        )
        .await;
        connected(event.unwrap(), peer);
        reached("connect");
        client.expect("convenience connect")
    } else {
        let mut client = make_client(constructor, config, transport, mtu);
        if constructor == 3 {
            cancel_pending(client.complete_handshake()).await;
            assert!(client.connection().is_handshaking());
            reached("handshake cancellation");
            // The server has not been polled. A positive API deadline must
            // expire without discarding the in-progress handshake.
            client.set_timeout(Some(Duration::from_millis(2)));
            assert_eq!(
                bounded(client.complete_handshake())
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::TimedOut
            );
            reached("handshake timeout");
        }
        client.set_timeout(Some(LIMIT));
        let (result, event) = together(client.complete_handshake(), server.next_event()).await;
        result.expect("authenticated handshake");
        connected(event.unwrap(), peer);
        client
    };
    client.set_timeout(Some(LIMIT));
    let mut session = Session {
        client,
        server,
        peer,
        server_addr,
    };
    session.inspect(true);
    for _ in 0..MAX_ACTIONS {
        if input.is_empty() {
            break;
        }
        if !session.action(&mut input).await {
            return;
        }
        session.inspect(true);
    }
    // Every accepted plaintext must already have been consumed; an extra
    // event or record here is a duplicate or a broken datagram boundary.
    session.idle(Duration::from_millis(1)).await;
}

fn make_client(
    constructor: usize,
    config: Arc<ClientConfig>,
    socket: UdpSocket,
    mtu: usize,
) -> UdpClient {
    if constructor == 1 {
        let mut conn = ClientConnection::new(config, setup::localhost()).expect("core client");
        conn.set_mtu(mtu).expect("bounded MTU");
        reached("from_connection");
        UdpClient::from_connection(conn, socket).expect("configured client")
    } else {
        reached("new");
        UdpClient::new(config, setup::localhost(), socket).expect("client")
    }
}

fn connected(event: ServerEvent, peer: SocketAddr) {
    assert!(matches!(event, ServerEvent::Connected(addr) if addr == peer));
    reached("connected");
}

fn reached(what: &'static str) {
    #[cfg(test)]
    tests::reached(what);
    #[cfg(not(test))]
    let _ = what;
}
