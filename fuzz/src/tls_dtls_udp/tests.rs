//! The seeds reach what they are meant to reach.

use std::cell::RefCell;
use std::collections::BTreeSet;

thread_local! {
    /// What the inputs run on this thread reached.
    static REACHED: RefCell<BTreeSet<&'static str>> = const { RefCell::new(BTreeSet::new()) };
}

pub(super) fn reached(what: &'static str) {
    REACHED.with(|r| r.borrow_mut().insert(what));
}

#[test]
fn split_a_fresh_client_without_transferring_the_clock() {
    use browntls_core::dtls::{ClientConnection, UdpClient};

    let mut state = super::State::new(&mut crate::input::Input::new(&[0, 0]));
    let (socket, _) = state.client_socket();
    let conn = ClientConnection::new(state.client_config(false), super::setup::localhost())
        .expect("DTLS client");
    let (conn, socket) = UdpClient::from_connection(conn, socket).into_parts();
    assert!(conn.is_handshaking());
    assert_eq!(socket.peer_addr().ok(), Some(state.server_addr));
    assert!(conn.next_timeout().is_none());
}

#[test]
fn seeds_reach_every_operation() {
    REACHED.with(|r| r.borrow_mut().clear());
    for seed in super::seeds() {
        super::run(&seed);
    }
    let reached = REACHED.with(|r| r.take());
    for what in [
        "no cookie sealer",
        "connect",
        "handshake rounds",
        "connected",
        "received",
        "client received",
        "short buffer",
        "too large",
        "not connected",
        "closed",
        "server close",
        "client saw close",
        "client key update",
        "server key update",
        "removed connection",
        "removed handshake",
        "client read timeout",
        "split",
        "accessors",
        "junk to the server",
        "junk to a client",
        "live OCSP refused",
        "wait",
        "migration",
    ] {
        assert!(reached.contains(what), "{what} not reached: {reached:?}");
    }
}
