//! Fixed API programs; all cryptography and transport remain genuine.

use crate::input::put_short_field;

/// Inputs covering all constructors and actions without relying on mutations.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    // Cross-provider connections, every key type, small-MTU fragmentation,
    // all constructors, and each terminal action. Bit 4 tests rejected
    // sockets/configuration before the genuine session starts.
    [
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
    .collect()
}
