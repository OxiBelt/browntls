//! Deterministic replay asserts meaningful paths, in addition to LLVM's
//! public-function body coverage. Ordinary seed mutations run in seeds.rs.

use std::cell::RefCell;
use std::collections::BTreeSet;

thread_local! {
    static REACHED: RefCell<BTreeSet<&'static str>> = const { RefCell::new(BTreeSet::new()) };
}

pub(super) fn reached(what: &'static str) {
    REACHED.with(|reached| reached.borrow_mut().insert(what));
}

#[test]
fn seeds_reach_public_api_sequences() {
    REACHED.with(|reached| reached.borrow_mut().clear());
    for seed in super::seeds()
        .into_iter()
        .filter(|seed| seed[1] & 0x20 == 0)
    {
        super::run(&seed);
    }
    let reached = REACHED.with(|reached| reached.take());
    for expected in [
        "new",
        "from_connection",
        "connect",
        "constructor rejection",
        "connected",
        "handshake cancellation",
        "handshake timeout",
        "repeat handshake",
        "client send",
        "server send",
        "empty to client",
        "empty to server",
        "datagram boundaries",
        "short buffer retained",
        "zero deadline",
        "elapsed deadline",
        "receive cancellation",
        "event cancellation",
        "key update",
        "limits",
        "oversized rejected",
        "unknown peer",
        "accessors",
        "client close",
        "server close",
        "close polled once",
        "remove",
    ] {
        assert!(
            reached.contains(expected),
            "{expected} missing: {reached:?}"
        );
    }
}

#[test]
fn session_seeds_reach_public_api_contracts() {
    REACHED.with(|reached| reached.borrow_mut().clear());
    for seed in super::seeds::session_seeds() {
        super::run(&seed);
    }
    let reached = REACHED.with(|reached| reached.take());
    for expected in [
        "listener new",
        "listener versions",
        "session limits rejected",
        "accept cancellation",
        "session accepted",
        "session accessors",
        "session receive",
        "session send",
        "session empty receive",
        "session empty send",
        "session datagram boundaries",
        "session receive cancellation",
        "session command cancellation",
        "session close cancellation",
        "session oversized rejected",
        "second session",
        "session peer isolation",
        "session close isolation",
        "session remote close",
        "session local close",
        "listener drop preserves sessions",
        "session handle drop",
        "driver cancellation",
        "driver shutdown",
    ] {
        assert!(
            reached.contains(expected),
            "{expected} missing: {reached:?}"
        );
    }
}
