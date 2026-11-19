//! Starting inputs for the `tls_unbuffered` target.

use super::{Op, RETRY, StepArgs};

pub(super) struct Seed(pub(super) Vec<u8>);

impl Seed {
    pub(super) fn new(knobs: [u8; 5], connect: &[u8]) -> Self {
        Self([&knobs[..], connect].concat())
    }

    pub(super) fn op(mut self, op: Op, args: &[u8]) -> Self {
        self.0.push(op as u8);
        self.0.extend_from_slice(args);
        self
    }

    pub(super) fn step(mut self, op: Op, side: u8, flags: u8, cap: u16, data: &[u8]) -> Self {
        self.0.extend_from_slice(&[op as u8, side]);
        StepArgs { flags, cap, data }.write(&mut self.0);
        self
    }

    /// Drives the handshake to completion, then exchanges data, rotates
    /// keys, exports and checks.
    pub(super) fn conversation(self) -> Self {
        self.op(Op::Pump, &[])
            .op(Op::Accessors, &[])
            .step(Op::Drive, 0, RETRY | 0x10, 0, b"ping")
            .step(Op::Drive, 1, RETRY | 0x10 | 0x80, 0, b"pong")
            .op(Op::Deliver, &[0, 0, 3, 0, 0, 0])
            .op(Op::Deliver, &[1, 0, 0, 0, 0, 0])
            .step(Op::Step, 1, 0x80, 0, b"")
            .step(Op::Drive, 0, RETRY | 0x80, 0, b"")
            .step(Op::Drive, 1, 0x80, 0, b"")
            .op(Op::Export, &[4, b't', b'e', b's', b't', 1, 1, b'c', 0, 48])
            .op(Op::Export, &[0, 0, 0, 0, 0])
            .step(Op::Drive, 1, RETRY | 0x50, 0, b"rekey")
            .op(Op::Pump, &[])
            .op(Op::Check, &[])
    }
}

/// Starting inputs for `tls_unbuffered`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    let flags = [0x00u8, 0x01, 0x02, 0x05, 0x0a, 0x1d, 0x2e, 0x33];
    let auth = [0x40u8, 0x41, 0x80, 0x06, 0x13, 0x22, 0x00, 0x00];
    for (flags, auth) in flags.into_iter().zip(auth) {
        seeds.push(Seed::new([flags, auth, 0, 0, 0], &[0]).conversation().0);
    }

    // Small output buffers, with and without retrying; no done().
    let seed = Seed::new([0x01, 0x40, 0, 0, 0], &[0])
        .step(Op::Step, 0, 0, 10, b"")
        .step(Op::Step, 0, RETRY, 10, b"")
        .step(Op::Step, 0, 2, 0, b"")
        .step(Op::Step, 0, 0, 0, b"")
        .op(Op::Deliver, &[0, 0, 100, 0, 0, 0])
        .step(Op::Drive, 1, RETRY, 0, b"")
        .op(Op::Deliver, &[0, 0, 0, 0, 0, 0])
        .step(Op::Drive, 1, RETRY, 0, b"")
        .op(Op::Pump, &[])
        .step(Op::Drive, 0, 0x10, 5, b"too large for five bytes")
        .step(Op::Drive, 0, 0x10 | RETRY, 5, b"retried")
        .step(Op::Drive, 1, 0x20, 3, b"")
        .step(Op::Drive, 1, 0x20 | RETRY, 3, b"")
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[])
        .op(Op::Check, &[]);
    seeds.push(seed.0);

    // Half-RTT data from the server through TransmitTlsData, then 0-RTT
    // on a resumed connection, then extraction.
    let resume = [2u8, 5, b's', b't', b'a', b't', b'e'];
    let seed = Seed::new([0x41 | 0x80, 0x44, 0, 0, 0], &resume)
        .step(Op::Drive, 0, RETRY, 0, b"")
        .op(Op::Deliver, &[0, 0, 0, 0, 0, 0])
        .step(Op::Drive, 1, RETRY | 4 | 0x10, 0, b"half")
        .op(Op::Pump, &[])
        .op(Op::Check, &[])
        .op(
            Op::Reconnect,
            &[1 | 2, 5, 4, b'f', b'u', b'z', b'z', 1, b'x'],
        )
        .step(Op::Drive, 0, RETRY | 8, 0, b"early")
        .op(Op::Export, &[2, b'e', b'x', 0, 0, 0, 32])
        .op(Op::Deliver, &[0, 0, 0, 0, 0, 0])
        .step(Op::Drive, 1, RETRY | 0x80, 0, b"")
        .op(Op::Export, &[2, b'e', b'x', 1, 1, b'c', 0, 32])
        .op(Op::Pump, &[])
        .op(Op::Export, &[0, 0, 0, 0, 16])
        .op(Op::Accessors, &[])
        .op(Op::Check, &[])
        .op(Op::Extract, &[])
        .op(Op::Reconnect, &[4])
        .op(Op::RejectEarlyData, &[])
        .op(Op::ResumptionData, &[1, b'y'])
        .step(Op::Drive, 0, RETRY | 8 | 2, 3, &[7; 200])
        .op(Op::Pump, &[])
        .op(Op::Check, &[]);
    seeds.push(seed.0);

    // A backlog of half-RTT records (knob 0x80) longer than one 64-step
    // drive: the server encrypts on every TransmitTlsData without calling
    // done(), so each Drive queues 64 records. Check must read them all.
    let mut seed = Seed::new([0x81, 0x40, 0, 0, 0], &[0])
        .step(Op::Drive, 0, RETRY, 0, b"")
        .op(Op::Deliver, &[0, 0, 0, 0, 0, 0]);
    for _ in 0..4 {
        seed = seed.step(Op::Drive, 1, RETRY | 4 | 2, 0, &[7; 255]);
    }
    seeds.push(seed.op(Op::Check, &[]).0);

    let seed = Seed::new([0x41, 0x04, 0, 0, 0], &[0])
        .conversation()
        .op(Op::Extract, &[]);
    seeds.push(seed.0);

    // Damage, replay and invented bytes; closing.
    let seed = Seed::new([0x00, 0x00, 0, 0, 0], &[0])
        .op(Op::Pump, &[])
        .step(Op::Drive, 0, RETRY | 0x10, 0, b"one")
        .step(Op::Drive, 0, RETRY | 0x10, 0, b"two")
        .op(Op::Deliver, &[0, 0, 0, 6, 0, 30])
        .op(Op::Pump, &[])
        .step(Op::Drive, 1, RETRY | 0x10, 0, b"three")
        .op(Op::Deliver, &[1, 0, 0, 4, 0, 9])
        .op(Op::Pump, &[])
        .op(Op::Inject, &[0, 0, 7, 0x17, 3, 3, 0, 2, 1, 2])
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[]);
    seeds.push(seed.0);
    let seed = Seed::new([0x00, 0x00, 0, 0, 0], &[0])
        .op(Op::Pump, &[])
        .step(Op::Drive, 0, RETRY | 0x40, 0, b"bye")
        .op(Op::Pump, &[])
        .step(Op::Drive, 1, RETRY | 0x20, 0, b"")
        .op(Op::Pump, &[])
        .op(Op::Check, &[]);
    seeds.push(seed.0);
    seeds.push(Seed::new([0x02, 0x00, 0, 0, 0], &[0]).op(Op::Pump, &[]).0);

    // Post-handshake client authentication in TLS 1.3 (deferred client
    // authentication), refused while handshaking, then answered twice;
    // and refused in TLS 1.2.
    let seed = Seed::new([0x01, 0x03, 0, 0, 0], &[0])
        .op(Op::PostHandshakeAuth, &[])
        .op(Op::Pump, &[])
        .op(Op::PostHandshakeAuth, &[])
        .op(Op::PostHandshakeAuth, &[])
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[])
        .step(Op::Drive, 0, RETRY | 0x10, 0, b"authenticated")
        .op(Op::PostHandshakeAuth, &[])
        .step(Op::Drive, 1, RETRY, 0, b"")
        .op(Op::Deliver, &[1, 0, 0, 0, 0, 0])
        .step(Op::Drive, 0, RETRY, 0, b"")
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[])
        .op(Op::Check, &[]);
    seeds.push(seed.0);
    let seed = Seed::new([0x02, 0x03, 0, 0, 0], &[0])
        .op(Op::Pump, &[])
        .op(Op::PostHandshakeAuth, &[])
        .op(Op::Accessors, &[]);
    seeds.push(seed.0);
    seeds.extend(super::acceptor::seeds());
    seeds
}
