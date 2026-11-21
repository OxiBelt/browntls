//! The seeds reach what they are meant to reach.

use std::cell::RefCell;

use browntls_core::HandshakeKind;

use super::Mode;

thread_local! {
    /// The established connections of the current thread: how the server
    /// met the client and the kind of handshake.
    static ESTABLISHED: RefCell<Vec<(Mode, Option<HandshakeKind>)>> =
        const { RefCell::new(Vec::new()) };
}

pub(super) fn established(mode: Mode, kind: Option<HandshakeKind>) {
    ESTABLISHED.with(|e| e.borrow_mut().push((mode, kind)));
}

#[test]
fn seeds_establish_and_resume_connections() {
    ESTABLISHED.with(|e| e.borrow_mut().clear());
    for seed in super::seeds() {
        super::run(&seed);
    }
    let established = ESTABLISHED.with(|e| e.take());
    let count = |mode: Mode| established.iter().filter(|(m, _)| *m == mode).count();
    assert!(count(Mode::Cookie) >= 20, "{established:?}");
    assert!(count(Mode::NoCookie) >= 4, "{established:?}");
    assert!(count(Mode::Acceptor) >= 4, "{established:?}");
    assert_eq!(count(Mode::Stolen), 0);
    let resumed = established
        .iter()
        .filter(|(_, kind)| *kind == Some(HandshakeKind::Resumed))
        .count();
    assert!(resumed >= 8, "{established:?}");
}
