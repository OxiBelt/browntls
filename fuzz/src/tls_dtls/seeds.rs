//! Starting inputs for `tls_dtls`: programs that reach every operation and
//! every public function of `browntls_core::dtls`.

use super::shape;
use crate::input::{put_field, put_short_field};

/// Side bytes: provider bit, then the versions selector (TLS 1.3 only,
/// both, TLS 1.2 only).
const TLS13: u8 = 0x08;
const BOTH: u8 = 0x02;
const TLS12: u8 = 0x00;

/// Handshake flags.
const NO_SEALER: u8 = 1;
const NO_COOKIE: u8 = 1 << 1;
const ACCEPTOR: u8 = 2 << 1;
const STOLEN: u8 = 3 << 1;
const DEFER: u8 = 8;
const SET_MTU: u8 = 16;

/// A handshake's configuration.
#[derive(Clone, Copy)]
struct Hs {
    client: u8,
    client_suites: u8,
    server: u8,
    server_suites: u8,
    key_type: u8,
    group: u8,
    flags: u8,
    mtu: (u16, u16),
}

const BASE: Hs = Hs {
    client: TLS13,
    client_suites: 0xff,
    server: TLS13,
    server_suites: 0xff,
    key_type: 0,
    group: 0,
    flags: 0,
    mtu: (0, 0),
};

/// The network script of one connection: fates, clock, revocation.
fn connection(seed: &mut Vec<u8>, fates: &[u8], clock: &[u8], revocation: &[u8]) {
    put_field(seed, fates);
    put_short_field(seed, clock);
    put_short_field(seed, revocation);
}

fn handshake(seed: &mut Vec<u8>, hs: Hs, fates: &[u8], revocation: &[u8]) {
    seed.extend_from_slice(&[
        0,
        hs.client,
        hs.client_suites,
        hs.server,
        hs.server_suites,
        hs.key_type,
        hs.group,
        hs.flags,
    ]);
    seed.extend_from_slice(&hs.mtu.0.to_be_bytes());
    seed.extend_from_slice(&hs.mtu.1.to_be_bytes());
    put_short_field(seed, b"resumption data");
    connection(seed, fates, &[], revocation);
}

/// Data both ways: delivered, duplicated, damaged, dropped, empty and
/// too large.
fn traffic(seed: &mut Vec<u8>) {
    for (dir, fate) in [(1u8, 0u8), (0, 0), (1, 2), (0, 1)] {
        seed.extend_from_slice(&[2, dir]);
        put_field(seed, b"application data");
        seed.push(fate);
    }
    seed.extend_from_slice(&[2, 1]);
    put_field(seed, b"damaged");
    seed.extend_from_slice(&[3, 0, 5, 0x40]);
    seed.extend_from_slice(&[2, 0]);
    put_field(seed, b"");
    seed.push(0);
    seed.extend_from_slice(&[2, 1]);
    put_field(seed, &[0x55; 1600]);
    seed.push(0);
}

/// The operations on an established pair, then a resumption and close.
fn program(seed: &mut Vec<u8>) {
    traffic(seed);
    // key updates: client, server, both, client twice; one over a lossy
    // network
    for side in 0..4u8 {
        seed.extend_from_slice(&[3, side]);
        put_short_field(seed, if side == 2 { &[4, 0, 5, 6, 0] } else { &[] });
        put_short_field(seed, if side == 3 { &[1, 200, 0] } else { &[] });
    }
    traffic(seed);
    // exporters, with and without context
    seed.push(9);
    put_short_field(seed, b"EXPORTER-test");
    put_short_field(seed, b"ctx");
    seed.push(32);
    seed.push(9);
    put_short_field(seed, b"EXPORTER-other");
    put_short_field(seed, b"");
    seed.push(0);
    // garbage both ways
    for (side, flags) in [(1u8, 0x0cu8), (0, 0x0f), (1, 0x1c), (0, 0x03)] {
        seed.extend_from_slice(&[5, side]);
        seed.extend_from_slice(&shape::seed(flags));
    }
    // replays: as they were, to the other side, damaged
    seed.extend_from_slice(&[6, 0, 0, 0, 6, 3, 1, 0, 6, 7, 0, 1, 0, 9, 0x80]);
    // MTU (refused, accepted), timers, oversized data
    seed.extend_from_slice(&[8, 0, 0, 100, 8, 0, 0x02, 0x00, 8, 1, 30, 8, 2]);
    traffic(seed);
    // resumption
    seed.push(1);
    connection(seed, &[], &[], &[]);
    traffic(seed);
    // close_notify from each side
    seed.extend_from_slice(&[4, 1]);
    put_short_field(seed, &[]);
    seed.extend_from_slice(&[2, 1]);
    put_field(seed, b"after close");
    seed.push(0);
    seed.extend_from_slice(&[2, 0]);
    put_field(seed, b"to a closed peer");
    seed.push(0);
    seed.extend_from_slice(&[4, 0]);
    put_short_field(seed, &[4]);
}

/// Fuzzed datagrams for a fresh client, server, server without cookies
/// and acceptor.
fn fresh(seeds: &mut Vec<Vec<u8>>) {
    for target in 0..4u8 {
        for flags in (0..32u8).step_by(if target == 3 { 1 } else { 4 }) {
            let mut seed = vec![7, target, 5];
            put_short_field(&mut seed, b"203.0.113.5:1");
            seed.push(1); // two datagrams
            seed.extend_from_slice(&shape::seed(flags));
            seed.extend_from_slice(&shape::seed(flags ^ 0x1f));
            seeds.push(seed);
        }
    }
}

/// Starting inputs for `tls_dtls`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let mut seeds = Vec::new();

    // Full programs: both providers on each side, every key type, cookie
    // exchange on the connection, without it, and through the acceptor.
    for (i, (client, server)) in [(0u8, 0u8), (1, 1), (0, 1), (1, 0)].into_iter().enumerate() {
        for mode in [0, NO_COOKIE, ACCEPTOR] {
            let hs = Hs {
                client: TLS13 | client,
                server: TLS13 | server,
                key_type: i as u8 % 3,
                flags: mode,
                ..BASE
            };
            let mut seed = Vec::new();
            handshake(&mut seed, hs, &[], &[]);
            program(&mut seed);
            seeds.push(seed);
        }
    }

    // Handshakes over a damaged network: losses, duplicates, reordering,
    // damage, forged datagrams; small and large datagrams.
    let lossy: &[&[u8]] = &[
        &[4, 0, 0, 4, 0, 5, 6, 0, 6],
        &[0, 4, 5, 5, 6, 6, 0, 4],
        &[0, 0, 7, 0, 3, 0x10, 0, 7, 0, 40, 1],
        &[8, 1, 1, 2, 0, 4, 0, 0, 1, 0, 2, 2, 40, 0],
    ];
    for (i, fates) in lossy.iter().enumerate() {
        let hs = Hs {
            flags: SET_MTU,
            mtu: [(0, 0), (144, 1244), (1244, 0), (300, 300)][i],
            key_type: i as u8,
            ..BASE
        };
        let mut seed = Vec::new();
        handshake(&mut seed, hs, fates, &[]);
        traffic(&mut seed);
        seeds.push(seed);
    }

    // Deferred revocation: good, asked twice, refused, and a wrong
    // identifier first.
    for revocation in [&[1u8][..], &[2, 0], &[0], &[9], &[3]] {
        let hs = Hs {
            flags: DEFER,
            ..BASE
        };
        let mut seed = Vec::new();
        handshake(&mut seed, hs, &[], revocation);
        traffic(&mut seed);
        seeds.push(seed);
    }

    // Configurations DTLS refuses or cannot agree on: one TLS 1.3 suite
    // at a time (CCM_8 among them), TLS 1.2 only, both versions, no
    // cookie sealer, a stolen cookie, one server group.
    for suite in 0..6u8 {
        for client in [0, 1] {
            let hs = Hs {
                client: TLS13 | client,
                client_suites: 1 << suite,
                server: TLS13 | client,
                server_suites: 1 << suite,
                ..BASE
            };
            let mut seed = Vec::new();
            handshake(&mut seed, hs, &[], &[]);
            traffic(&mut seed);
            seeds.push(seed);
        }
    }
    let configs = [
        Hs {
            client: TLS12,
            ..BASE
        },
        Hs {
            server: TLS12 | 1,
            ..BASE
        },
        Hs {
            client: BOTH,
            server: BOTH | 1,
            ..BASE
        },
        Hs {
            flags: NO_SEALER,
            ..BASE
        },
        Hs {
            flags: NO_SEALER | NO_COOKIE,
            ..BASE
        },
        Hs {
            flags: NO_SEALER | ACCEPTOR,
            ..BASE
        },
        Hs {
            flags: STOLEN,
            ..BASE
        },
        Hs {
            group: 0x81,
            flags: NO_COOKIE,
            ..BASE
        },
        Hs {
            group: 0x82,
            server: TLS13 | 1,
            ..BASE
        },
    ];
    for hs in configs {
        let mut seed = Vec::new();
        handshake(&mut seed, hs, &[], &[]);
        traffic(&mut seed);
        seeds.push(seed);
    }

    fresh(&mut seeds);
    // A CID-enabled, protected path validation and CID update program.
    let mut seed = Vec::new();
    handshake(&mut seed, Hs { flags: 32, ..BASE }, &[], &[]);
    seed.push(10);
    seeds.push(seed);
    seeds.extend(super::cid_api::seeds());
    seeds
}
