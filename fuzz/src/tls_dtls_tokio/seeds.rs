//! Fixed API programs; all cryptography and transport remain genuine.

use crate::input::put_short_field;

/// Inputs covering all constructors and actions without relying on mutations.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    // Cross-provider connections, every key type, small-MTU fragmentation,
    // all constructors, and each terminal action. Bit 4 tests rejected
    // sockets/configuration before the genuine session starts.
    let mut seeds: Vec<_> = [
        (0, 0x10, 2, 11),
        (1, 3, 0, 12),
        (2, 5, 1, 13),
        (3, 10, 2, 14),
    ]
    .into_iter()
    .map(|(constructor, flags, mtu, terminal)| {
        let mut seed = vec![constructor, flags, mtu];
        for (op, data) in [
            (0, b"one client record".as_slice()),
            (1, b"one server record".as_slice()),
            (2, b"retained across a short buffer".as_slice()),
            (0, b"".as_slice()),
            (1, b"".as_slice()),
            (15, b"queued separately".as_slice()),
        ] {
            seed.push(op);
            put_short_field(&mut seed, data);
        }
        seed.extend_from_slice(&[
            3, 0, // zero API deadlines
            3, 2, // positive elapsed deadlines, then reset to None
            4, // poll and cancel idle receive and event futures
            5, // traffic key refresh
            6, // established accessors and matching exporters
            7, 0, 0,  // clamp limits to one; retain established peer
            8,  // both oversized send rejections, then usable traffic
            9,  // unknown-address queries and operation rejection
            10, // repeated complete_handshake on an established client
            terminal,
        ]);
        seed
    })
    .collect();
    seeds.extend(session_seeds());
    // Both selection policies and both receiving-CID directions.
    for constructor in 0..4 {
        seeds.push(vec![constructor, 0x40, 2]);
    }
    seeds
}

/// Replayed by both the fuzzer and the reusable session contract test.
pub(super) fn session_seeds() -> Vec<Vec<u8>> {
    [
        (0, 0x30, 2, &[8][..]),       // remote close, other peer survives
        (1, 0x23, 0, &[7, 0x19][..]), // stop admissions, close second peer
        (2, 0x25, 0, &[10][..]),      // cancel driver with live handles
        (3, 0x2a, 1, &[11][..]),      // drop handle, then driver shutdown
        (0, 0x21, 1, &[7][..]),       // idle checks after listener drop
    ]
    .into_iter()
    .map(|(constructor, flags, mtu, tail)| {
        let mut seed = vec![constructor, flags, mtu];
        for (op, data) in [
            (0, b"session input".as_slice()),
            (1, b"session output".as_slice()),
            (2, &[0x6b; 255][..]),
        ] {
            seed.push(op);
            put_short_field(&mut seed, data);
        }
        seed.extend_from_slice(&[
            13, // empty datagrams both ways
            3,  // cancel receive/accept, then resume
            4,  // cancel queued send and queued/capacity-blocked close
            5,  // reject above the session byte cap, then usable traffic
            6,  // second authenticated peer (at most two per input)
            15, // exercise both distinct sessions
            12, // address and Debug accessors
            14, // cancel a queued close, then prove the session is open
        ]);
        seed.extend_from_slice(tail);
        seed
    })
    .collect()
}
