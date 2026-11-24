//! Tests of the ClientHello construction helpers.

#![cfg(feature = "std")]

use alloc::vec::Vec;

use super::*;
use crate::client::ClientSessionMemoryCache;
use crate::msgs::persist::tests::tls13_client_value;

fn name() -> ServerName<'static> {
    ServerName::try_from("example.com").unwrap()
}

fn ticket(id: u8, protocol: Protocol) -> Tls13ClientSessionValue {
    tls13_client_value(id).with_protocol(protocol)
}

/// The ticket bytes left in `store`, newest first.
fn drain(store: &dyn ClientSessionStore) -> Vec<u8> {
    let mut left = Vec::new();
    while let Some(t) = store.take_tls13_ticket(&name()) {
        left.push(t.ticket()[0]);
    }
    left
}

/// TLS and DTLS tickets in one store are each offered only over their own
/// protocol, and tickets of the other protocol stay in the store in order.
#[test]
fn tickets_are_taken_by_protocol() {
    let store = ClientSessionMemoryCache::new(8);
    store.insert_tls13_ticket(name(), ticket(1, Protocol::Dtls13));
    store.insert_tls13_ticket(name(), ticket(2, Protocol::Tls13));
    store.insert_tls13_ticket(name(), ticket(3, Protocol::Tls13));

    let dtls = take_tls13_ticket(&store, &name(), Protocol::Dtls13).unwrap();
    assert_eq!(dtls.ticket(), [1]);
    assert_eq!(dtls.protocol(), Protocol::Dtls13);
    // No DTLS ticket is left, and the TLS ones are untouched.
    assert!(take_tls13_ticket(&store, &name(), Protocol::Dtls13).is_none());
    assert_eq!(drain(&store), [3, 2]);

    store.insert_tls13_ticket(name(), ticket(4, Protocol::Tls13));
    store.insert_tls13_ticket(name(), ticket(5, Protocol::Dtls13));
    let tls = take_tls13_ticket(&store, &name(), Protocol::Tls13).unwrap();
    assert_eq!(tls.ticket(), [4]);
    assert_eq!(drain(&store), [5]);
}

/// An unbounded ticket stack, newest last.
#[derive(Debug, Default)]
struct Stack(std::sync::Mutex<Vec<Tls13ClientSessionValue>>);

impl ClientSessionStore for Stack {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    #[cfg(feature = "tls12")]
    fn set_tls12_session(
        &self,
        _: ServerName<'static>,
        _: crate::msgs::persist::Tls12ClientSessionValue,
    ) {
    }

    #[cfg(feature = "tls12")]
    fn tls12_session(
        &self,
        _: &ServerName<'_>,
    ) -> Option<crate::msgs::persist::Tls12ClientSessionValue> {
        None
    }

    #[cfg(feature = "tls12")]
    fn remove_tls12_session(&self, _: &ServerName<'static>) {}

    fn insert_tls13_ticket(&self, _: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.0.lock().unwrap().push(value);
    }

    fn take_tls13_ticket(&self, _: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.0.lock().unwrap().pop()
    }
}

/// At most `MAX_SKIPPED_TICKETS` tickets of the other protocol are looked
/// past, and all of them are put back in order.
#[test]
fn ticket_search_is_bounded() {
    let store = Stack::default();
    store.insert_tls13_ticket(name(), ticket(0, Protocol::Dtls13));
    for id in 1..=8 {
        store.insert_tls13_ticket(name(), ticket(id, Protocol::Tls13));
    }
    assert!(take_tls13_ticket(&store, &name(), Protocol::Dtls13).is_none());
    // One fewer TLS ticket in the way, and the DTLS ticket is reached.
    assert_eq!(store.take_tls13_ticket(&name()).unwrap().ticket(), [8]);
    let dtls = take_tls13_ticket(&store, &name(), Protocol::Dtls13).unwrap();
    assert_eq!(dtls.ticket(), [0]);
    assert_eq!(drain(&store), [7, 6, 5, 4, 3, 2, 1]);
}
