//! Starting inputs of the `tls_conn` target.

use std::sync::Arc;

use browntls::ClientConnection;

use super::setup::{Knobs, server_name};
use super::{ConnectArgs, Op};
use crate::input::{put_field, put_short_field};

// ------------------------------------------------------------------ seeds

/// Builds one seed: knobs, first connection, then operations.
struct Seed(Vec<u8>);

impl Seed {
    fn new(knobs: [u8; 5], connect: &ConnectArgs<'_>) -> Self {
        let mut out = knobs.to_vec();
        connect.write(&mut out);
        Self(out)
    }

    fn op(mut self, op: Op, args: &[u8]) -> Self {
        self.0.push(op as u8);
        self.0.extend_from_slice(args);
        self
    }

    fn write(mut self, side: u8, method: u8, data: &[u8]) -> Self {
        self.0.extend_from_slice(&[Op::Write as u8, side, method]);
        put_short_field(&mut self.0, data);
        self
    }

    /// [`Op::Transfer`] with the given damage, position and read chunk,
    /// write chunk and limit unrestricted.
    fn transfer(self, side: u8, how: u8, pos: u8, read: u8) -> Self {
        self.op(Op::Transfer, &[side, 0, how, 0, pos, 0, read, 0, 0])
    }

    fn reconnect(mut self, args: &ConnectArgs<'_>) -> Self {
        self.0.push(Op::Reconnect as u8);
        args.write(&mut self.0);
        self
    }

    /// A conversation over a connected pair, through most operations.
    fn conversation(self) -> Self {
        self.op(Op::Pump, &[])
            .op(Op::Accessors, &[])
            .write(0, 0, b"hello from the client")
            .write(1, 7, b"hello from the server")
            .transfer(0, 0, 0, 0)
            .transfer(1, 0, 0, 3)
            .op(Op::Read, &[1, 0, 4])
            .op(Op::Read, &[1, 3, 2])
            .op(Op::Read, &[1, 1, 0])
            .op(Op::Read, &[0, 2, 0])
            .op(
                Op::Export,
                &[4, b't', b'e', b's', b't', 1, 2, b'c', b'x', 0, 32],
            )
            .op(Op::Export, &[0, 0, 0, 0, 0])
            .op(Op::ChannelBinding, &[])
            .op(Op::RefreshKeys, &[0])
            .op(Op::Pump, &[])
            .op(Op::Check, &[])
    }
}

/// Starting inputs for `tls_conn`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let plain = ConnectArgs::default();
    let resume = ConnectArgs {
        flags: 4 | 2,
        alpn: b"\x04fuzz\x02h2",
        resumption_data: b"state",
    };
    let accept = ConnectArgs {
        flags: 1 | 0x30,
        ..ConnectArgs::default()
    };
    let mut seeds = Vec::new();

    // Each version, provider pair and builder entry point.
    let flags = [0x00u8, 0x01, 0x02, 0x05, 0x0a, 0x1d, 0x2e, 0x33];
    let auth = [0x40u8, 0x41, 0x80, 0x0e, 0x13, 0x22, 0xc0, 0x00];
    for (flags, auth) in flags.into_iter().zip(auth) {
        seeds.push(Seed::new([flags, auth, 0, 0, 0], &plain).conversation().0);
    }

    // Single suites, group choices, fragment sizes.
    for (suite, groups, fragment) in [
        (1u8, 0x23u8, 0u8),
        (2, 0x31, 20),
        (3, 0x44, 255),
        (4, 0, 1),
        (5, 0, 0),
        (6, 0, 0),
        (7, 0x88, 0),
        (8, 0, 0),
    ] {
        let seed = Seed::new([0x00, 0x40, suite, groups, fragment], &plain).conversation();
        seeds.push(seed.0);
    }

    // Resumption with 0-RTT, read on the server; the Acceptor path.
    let seed = Seed::new([0x41 | 0x80, 0x44, 0, 0, 0], &resume)
        .conversation()
        .op(Op::CloseNotify, &[0])
        .op(Op::CloseNotify, &[1])
        .op(Op::Pump, &[])
        .reconnect(&resume)
        .op(Op::EarlyWrite, &[5, b'e', b'a', b'r', b'l', b'y'])
        .op(Op::Export, &[1, b'x', 2, 0, 0, 16])
        .transfer(0, 0, 0, 0)
        .op(Op::EarlyRead, &[3])
        .op(Op::EarlyRead, &[200])
        .op(Op::Export, &[1, b'x', 2, 0, 0, 16])
        .op(Op::Accessors, &[])
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[])
        .op(Op::Check, &[])
        .op(Op::Extract, &[0])
        .reconnect(&accept)
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[])
        .op(Op::Extract, &[1]);
    seeds.push(seed.0);
    let seed = Seed::new([0x41, 0x04, 0, 0, 0], &accept)
        .conversation()
        .op(Op::Extract, &[1]);
    seeds.push(seed.0);
    let seed = Seed::new([0x41, 0x00, 0, 0, 0], &plain)
        .op(Op::Pump, &[])
        .reconnect(&ConnectArgs {
            flags: 8,
            ..ConnectArgs::default()
        })
        .op(Op::EarlyWrite, &[2, b'h', b'i'])
        .op(Op::Pump, &[])
        .op(Op::EarlyRead, &[9])
        .op(Op::Check, &[]);
    seeds.push(seed.0);

    // Post-handshake authentication, with and without a certificate.
    for auth in [0x03u8, 0x02, 0x01] {
        let seed = Seed::new([0x01, auth, 0, 0, 0], &plain)
            .op(Op::Pump, &[])
            .op(Op::PostHandshakeAuth, &[])
            .op(Op::Pump, &[])
            .op(Op::Accessors, &[])
            .op(Op::PostHandshakeAuth, &[])
            .op(Op::Check, &[]);
        seeds.push(seed.0);
    }

    // complete_io and the stream adapters, borrowed and owned.
    let mut seed = Seed::new([0x00, 0x40, 0, 0, 0], &plain);
    for (side, args) in [
        (0u8, [0u8, 0, 0]),
        (1, [0, 0, 0]),
        (0, [0, 0, 0]),
        (1, [7, 3, 1]),
    ] {
        seed = seed.op(Op::CompleteIo, &[side, args[0], args[1], args[2]]);
    }
    for (side, owned, action) in [
        (0u8, 0u8, 0x80u8),
        (1, 0, 0x80),
        (0, 0, 0),
        (0, 1, 2 | 8),
        (1, 1, 1),
        (1, 0, 3),
        (1, 0, 0),
        (0, 1, 1),
        (0, 0, 1),
    ] {
        seed = seed.op(
            Op::Stream,
            &[side, owned, action, 4, b'd', b'a', b't', b'a', 0, 0, 0],
        );
    }
    seeds.push(seed.op(Op::Check, &[]).0);

    // Buffer limits, damaged and invented bytes, resumption data.
    let seed = Seed::new([0x00, 0x00, 0, 0, 0], &plain)
        .op(Op::BufferLimit, &[0, 3, 0, 10])
        .op(Op::BufferLimit, &[1, 1, 0, 0])
        .op(Op::BufferLimit, &[0, 0, 0, 0])
        .op(Op::ResumptionData, &[3, b'a', b'b', b'c'])
        .write(0, 0, b"limited")
        .op(Op::Pump, &[])
        .op(Op::BufferLimit, &[1, 2, 0, 0])
        .write(1, 0, b"unlimited")
        .transfer(1, 4, 9, 0)
        .transfer(0, 5 | 8, 1, 0)
        .transfer(1, 6, 0, 0)
        .transfer(0, 7, 2, 0)
        .op(Op::Inject, &[0, 0, 5, 0x15, 3, 3, 0, 2])
        .op(Op::Accessors, &[]);
    let mut bytes = seed.0;
    // The inserted bytes of the last transfer follow its arguments.
    let at = bytes.len() - 10;
    bytes.splice(at..at, [2, 0x17, 0x03]);
    seeds.push(bytes);
    let seed = Seed::new([0x02, 0x00, 0, 0, 0], &plain)
        .transfer(0, 4, 50, 0)
        .op(Op::Pump, &[]);
    seeds.push(seed.0);

    // A genuine ClientHello for the standalone acceptor, and garbage.
    let hello = {
        let config = Knobs::default().client_config().expect("client config");
        let mut client = ClientConnection::new(Arc::new(config), server_name()).expect("client");
        let mut out = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut out).expect("write");
        }
        out
    };
    for (chunk, into) in [(0u8, 1u8), (40, 0), (3, 1)] {
        let mut seed = Seed::new([0; 5], &plain).0;
        seed.extend_from_slice(&[Op::Acceptor as u8, chunk, into]);
        put_field(&mut seed, &hello);
        seeds.push(seed);
    }
    for garbage in [&[0x16, 3, 1, 0, 4, 1, 0, 0, 0][..], &[0x17, 3, 3, 0, 1, 0]] {
        let mut seed = Seed::new([0; 5], &plain).0;
        seed.extend_from_slice(&[Op::Acceptor as u8, 0, 1]);
        put_field(&mut seed, garbage);
        seeds.push(seed);
    }

    // The acceptor path with a refused configuration (an invalid fragment
    // size), and a client refused by `new_with_alpn` (an empty protocol).
    seeds.push(Seed::new([0, 0, 0, 0, 1], &accept).op(Op::Pump, &[]).0);
    let refused = ConnectArgs {
        flags: 2,
        alpn: b"\x00",
        ..ConnectArgs::default()
    };
    seeds.push(Seed::new([0; 5], &refused).0);
    seeds
}
