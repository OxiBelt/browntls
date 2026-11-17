//! Starting inputs for the `tls_kernel` target.

use super::post::Op;
use super::{KERNEL_SUITES, PreOp};

struct Seed(Vec<u8>);

impl Seed {
    fn new(suite: u8, flags: u8, fragment: u8) -> Self {
        Self(vec![suite, flags, fragment])
    }

    fn pre(mut self, op: PreOp, args: &[u8]) -> Self {
        self.0.push(op as u8);
        self.0.extend_from_slice(args);
        self
    }

    fn post(mut self, op: Op, args: &[u8]) -> Self {
        self.0.push(op as u8);
        self.0.extend_from_slice(args);
        self
    }

    /// The handshake, then the handover.
    fn handed(self) -> Self {
        self.pre(PreOp::Pump, &[])
            .pre(PreOp::Blocker, &[])
            .pre(PreOp::Handover, &[])
    }

    /// Data both ways, key updates both ways, closure.
    fn conversation(self) -> Self {
        self.post(Op::Accessors, &[])
            .post(Op::PeerWrite, &[0, 5, b'h', b'e', b'l', b'l', b'o'])
            .post(Op::PeerToKernel, &[0, 0])
            .post(Op::Send, &[&[200u8, 100][..], &[b'x'; 100]].concat())
            .post(Op::Send, &[0, 0])
            .post(Op::KernelToPeer, &[0, 7])
            .post(Op::KernelToPeer, &[0, 0])
            .post(Op::AppReceived, &[])
            .post(Op::PeerRefresh, &[])
            .post(Op::PeerWrite, &[0, 3, b'a', b'b', b'c'])
            .post(Op::Pump, &[])
            .post(Op::Send, &[0, 2, b'o', b'k'])
            .post(Op::Refresh, &[])
            .post(Op::Send, &[0, 2, b'o', b'k'])
            .post(Op::Pump, &[])
            .post(Op::Check, &[])
            .post(Op::Extras, &[0])
            .post(Op::Accessors, &[])
            .post(Op::Close, &[])
            .post(Op::PeerClose, &[])
            .post(Op::Pump, &[])
            .post(Op::Accessors, &[])
    }
}

/// Starting inputs for `tls_kernel`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // Every suite with a kernel form, both sides, both APIs.
    for suite in 0..KERNEL_SUITES as u8 {
        let flags = suite % 4;
        seeds.push(Seed::new(suite, flags, 0).handed().conversation().0);
    }
    // The suites that cannot be handed over, and extraction disabled.
    for suite in KERNEL_SUITES as u8..16 {
        seeds.push(Seed::new(suite, 0, 0).handed().0);
    }
    seeds.push(Seed::new(0, 4, 0).handed().0);
    // Fragments below what Linux takes: 56 and 60 bytes.
    seeds.push(Seed::new(0, 0, 10).handed().0);
    seeds.push(Seed::new(4, 1, 11).handed().0);
    seeds.push(Seed::new(4, 2 | 4, 0).handed().0);

    // Mid-handshake, then unread data, a partial record read up to its
    // boundary, unsent records, closure: each blocks one connection.
    for flags in [0u8, 1] {
        let seed = Seed::new(0, flags, 0)
            .pre(PreOp::PeerToSubject, &[2, 0, 0])
            .pre(PreOp::Blocker, &[])
            .pre(PreOp::Handover, &[])
            .pre(PreOp::Pump, &[])
            .pre(PreOp::Write, &[1, 4, b'd', b'a', b't', b'a'])
            .pre(PreOp::PeerToSubject, &[2, 0, 0])
            .pre(PreOp::Blocker, &[])
            .pre(PreOp::Handover, &[])
            .pre(PreOp::Pump, &[])
            .pre(PreOp::Write, &[1, 4, b'd', b'a', b't', b'a'])
            .pre(PreOp::PeerToSubject, &[0, 0, 3])
            .pre(PreOp::Blocker, &[])
            .pre(PreOp::PeerToSubject, &[1, 0, 0])
            .pre(PreOp::PeerToSubject, &[1, 0, 0])
            .pre(PreOp::PeerToSubject, &[2 | 4, 0, 0])
            .pre(PreOp::Write, &[0, 1, b'q'])
            .pre(PreOp::Blocker, &[])
            .pre(PreOp::SubjectToPeer, &[1])
            .pre(PreOp::Read, &[])
            .pre(PreOp::Close, &[1])
            .pre(PreOp::Pump, &[])
            .pre(PreOp::Handover, &[])
            .conversation();
        seeds.push(seed.0);
        let seed = Seed::new(9, flags | 2, 0)
            .pre(PreOp::Pump, &[])
            .pre(PreOp::Refresh, &[0])
            .pre(PreOp::Drive, &[])
            .pre(PreOp::Blocker, &[])
            .pre(PreOp::Handover, &[])
            .pre(PreOp::Pump, &[])
            .pre(PreOp::Close, &[0])
            .pre(PreOp::Drive, &[])
            .pre(PreOp::Handover, &[]);
        seeds.push(seed.0);
    }

    // Handed over before the peer's last flight (tickets, or the TLS 1.2
    // server's Finished) arrived.
    for suite in [0u8, 4] {
        let seed = Seed::new(suite, 0, 0)
            .pre(PreOp::PeerToSubject, &[2, 0, 0])
            .pre(PreOp::SubjectToPeer, &[1])
            .pre(PreOp::PeerToSubject, &[2, 0, 0])
            .pre(PreOp::SubjectToPeer, &[1])
            .pre(PreOp::Handover, &[])
            .post(Op::Pump, &[])
            .post(Op::Extras, &[0])
            .post(Op::Check, &[]);
        seeds.push(seed.0);
    }

    // The peer's record size limit and small fragments.
    for (suite, flags, fragment) in [(0u8, 0x20u8, 0u8), (4, 0x11, 0), (7, 0x30, 30), (12, 1, 40)] {
        let seed = Seed::new(suite, flags, fragment).handed().conversation();
        seeds.push(seed.0);
    }

    // Post-handshake client authentication, either side offloaded.
    for flags in [8u8, 9, 10, 11] {
        let seed = Seed::new(0, flags, 0)
            .handed()
            .post(Op::Pump, &[])
            .post(Op::PeerAuth, &[])
            .post(Op::Extras, &[1])
            .post(Op::Pump, &[])
            .post(Op::Extras, &[0])
            .post(Op::Check, &[]);
        seeds.push(seed.0);
    }

    // The confidentiality limit, both versions, and beyond.
    for suite in [0u8, 3, 4, 10] {
        let seed = Seed::new(suite, 0, 0)
            .handed()
            .post(Op::RecordsSent, &[1, 0, 10])
            .post(Op::RecordsSent, &[0, 10])
            .post(Op::Pump, &[])
            .post(Op::Send, &[0, 1, b'z'])
            .post(Op::RecordsSent, &[2, 0, 5])
            .post(Op::RecordsSent, &[4])
            .post(
                Op::RecordsSent,
                &[3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0],
            )
            .post(Op::Pump, &[])
            .post(Op::Accessors, &[]);
        seeds.push(seed.0);
    }

    // Records the peer did not send: application data (refused), a
    // KeyUpdate asking for one back, a warning alert, a partial handshake
    // message then an alert (refused), and what follows the failure.
    for (suite, flags) in [(0u8, 0u8), (4, 1), (2, 3)] {
        let seed = Seed::new(suite, flags, 0)
            .handed()
            .post(Op::Handle, &[2, 0, 1, b'x'])
            .post(Op::Handle, &[0, 1, 1, 1])
            .post(Op::Handle, &[1, 3, 2, 1, 90])
            .post(Op::Handle, &[0, 0, 2, 4, 0])
            .post(Op::Handle, &[1, 3, 2, 1, 90])
            .post(Op::Handle, &[3, 0, 1, 1])
            .post(Op::Refresh, &[])
            .post(Op::RecordsSent, &[0, 1])
            .post(Op::Close, &[])
            .post(Op::Handle, &[1, 3, 2, 1, 0])
            .post(Op::Extras, &[1])
            .post(Op::Accessors, &[]);
        seeds.push(seed.0);
        let seed = Seed::new(suite, flags, 0)
            .handed()
            .post(Op::PeerClose, &[])
            .post(Op::Pump, &[])
            .post(Op::Handle, &[0, 1, 1, 1])
            .post(Op::Handle, &[255, 0, 1, 0])
            .post(Op::Accessors, &[]);
        seeds.push(seed.0);
        // Refused handshake records: a KeyUpdate followed by more, one
        // that does not decode, a part of one, an empty record.
        for payload in [
            &[2u8, 2, 4, 0][..],
            &[0, 5, 24, 0, 0, 1, 5],
            &[0, 2, 24, 0],
            &[0, 0],
        ] {
            let seed = Seed::new(suite, flags, 0)
                .handed()
                .post(Op::Handle, &[&[0u8][..], payload].concat())
                .post(Op::PeerToKernel, &[0, 0])
                .post(Op::Close, &[])
                .post(Op::KernelToPeer, &[0, 0]);
            seeds.push(seed.0);
        }
    }
    // A NewSessionTicket and a KeyUpdate in one record (refused: Linux
    // pauses only on a record that starts with the KeyUpdate).
    let ticket = [4u8, 0, 0, 14, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0xaa, 0, 0];
    let mut handle = vec![0u8, 0, 23];
    handle.extend_from_slice(&ticket);
    handle.extend_from_slice(&[24, 0, 0, 1, 0]);
    let seed = Seed::new(0, 0, 0)
        .handed()
        .post(Op::Handle, &[&[0u8, 0, 18][..], &ticket].concat())
        .post(Op::Pump, &[]);
    seeds.push(seed.0);
    let seed = Seed::new(0, 0, 0)
        .handed()
        .post(Op::Handle, &handle)
        .post(Op::Pump, &[]);
    seeds.push(seed.0);
    seeds
}
