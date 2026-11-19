//! Starting inputs for the `tls_tokio` target.

use super::{CLIENT, Op, SERVER, SPLIT_DATA, SPLIT_ROUNDS};
use crate::input::put_short_field;

/// Seeds: every creation mode with a full exchange, 0-RTT on a resumed
/// connection (read after the handshake, and before its end by a server
/// that returns early), a refused plain-text request, damaged handshakes,
/// and an exchange through split halves.
pub fn seeds() -> Vec<Vec<u8>> {
    let op = |out: &mut Vec<u8>, op: Op, side: usize| {
        out.push(op as u8);
        out.push(side as u8);
    };
    let exchange = |out: &mut Vec<u8>| {
        op(out, Op::Accessors, CLIENT);
        op(out, Op::Accessors, SERVER);
        op(out, Op::Pump, 0);
        for side in [CLIENT, SERVER] {
            op(out, Op::Write, side);
            out.push(u8::from(side == SERVER));
            put_short_field(out, b"hello through tokio");
        }
        op(out, Op::Pump, 0);
        op(out, Op::KeyUpdate, SERVER);
        op(out, Op::Write, SERVER);
        out.push(0);
        put_short_field(out, b"after a key update");
        op(out, Op::Pump, 0);
        op(out, Op::Read, CLIENT);
        out.extend([1, 7]);
        op(out, Op::Accessors, CLIENT);
        op(out, Op::Accessors, SERVER);
        op(out, Op::Shutdown, CLIENT);
        op(out, Op::Pump, 0);
        op(out, Op::Shutdown, SERVER);
        op(out, Op::Pump, 0);
    };
    let mut seeds = Vec::new();
    // TLS 1.3 then TLS 1.2, every creation mode, plain and choppy transport.
    for versions in [1u8, 2] {
        for mode in [0u8, 1, 2, 3, 4, 8, 0x0d, 0x10, 0x18, 0x20, 0x33] {
            for transport in [[255u8, 0, 255, 0], [16, 0b0101_0101, 3, 0b0011_0011]] {
                let mut s = vec![versions, 0, 0, 0, 0, mode];
                s.extend(transport);
                exchange(&mut s);
                seeds.push(s);
            }
        }
    }
    // 0-RTT: a first connection leaves a ticket, the second writes early.
    let mut s = vec![0x41, 0, 0, 0, 0, 0x40, 255, 0, 255, 0];
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::Write, SERVER);
    s.push(0);
    put_short_field(&mut s, b"ticket");
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::Reconnect, 0);
    // The connect future returns at once, before the handshake.
    op(&mut s, Op::Poll, CLIENT);
    op(&mut s, Op::Write, CLIENT);
    s.push(0);
    put_short_field(&mut s, b"early request");
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::EarlyRead, SERVER);
    op(&mut s, Op::Write, CLIENT);
    s.push(1);
    put_short_field(&mut s, b"later");
    op(&mut s, Op::Pump, 0);
    seeds.push(s);
    // 0-RTT read before the handshake completes: the server's accept
    // returns early (mode bit 7), from each way of creating it, with and
    // without 0.5-RTT data (configuration bit 7).
    for (flags, mode) in [
        (0x41u8, 0xc0u8),
        (0xc1, 0xc0),
        (0xc1, 0xe8),
        (0x41, 0xd0),
        (0xc1, 0xd8),
    ] {
        let mut s = vec![flags, 0, 0, 0, 0, mode, 255, 0, 255, 0];
        op(&mut s, Op::Pump, 0);
        op(&mut s, Op::Write, SERVER);
        s.push(0);
        put_short_field(&mut s, b"ticket");
        op(&mut s, Op::Pump, 0);
        op(&mut s, Op::Reconnect, 0);
        op(&mut s, Op::Poll, CLIENT);
        op(&mut s, Op::Write, CLIENT);
        s.push(0);
        put_short_field(&mut s, b"early request");
        // The ClientHello and the early data go out; the lazy acceptor
        // takes one poll more than the acceptor.
        op(&mut s, Op::Flush, CLIENT);
        op(&mut s, Op::Poll, SERVER);
        op(&mut s, Op::Poll, SERVER);
        op(&mut s, Op::Accessors, SERVER);
        op(&mut s, Op::EarlyRead, SERVER);
        // Sent at once as 0.5-RTT data, or waiting for the handshake.
        op(&mut s, Op::Write, SERVER);
        s.push(0);
        put_short_field(&mut s, b"reply");
        op(&mut s, Op::Pump, 0);
        op(&mut s, Op::Write, SERVER);
        s.push(1);
        put_short_field(&mut s, b"reply");
        op(&mut s, Op::Write, CLIENT);
        s.push(1);
        put_short_field(&mut s, b"later");
        op(&mut s, Op::Pump, 0);
        op(&mut s, Op::EarlyRead, SERVER);
        op(&mut s, Op::EarlyRead, CLIENT);
        op(&mut s, Op::Shutdown, SERVER);
        op(&mut s, Op::Pump, 0);
        seeds.push(s);
    }
    // Split halves, of the unified stream and of each side's own, in every
    // way to write and to reunite; each side reads what the peer's halves
    // wrote in the round before.
    for versions in [1u8, 2] {
        let mut s = vec![versions, 0, 0, 0, 0, 0, 255, 0, 255, 0];
        op(&mut s, Op::Pump, 0);
        for how in 0..SPLIT_ROUNDS {
            for side in [CLIENT, SERVER] {
                op(&mut s, Op::Split, side);
                s.push(how);
                put_short_field(&mut s, SPLIT_DATA);
                s.push(64);
            }
        }
        op(&mut s, Op::Pump, 0);
        seeds.push(s);
    }
    // A lazy acceptor refusing a plain-text request, then giving the
    // transport back.
    let mut s = vec![1, 0, 0, 0, 0, 0x10, 255, 0, 255, 0];
    op(&mut s, Op::Inject, CLIENT);
    put_short_field(&mut s, b"GET / HTTP/1.1\r\n\r\n");
    op(&mut s, Op::Poll, SERVER);
    op(&mut s, Op::TakeIo, SERVER);
    seeds.push(s);
    // Damaged handshakes, an early end of file, a lazy acceptor's refusal of
    // the configuration.
    for (lane, damage) in [
        (CLIENT, Op::Damage),
        (SERVER, Op::Damage),
        (CLIENT, Op::Close),
    ] {
        let mut s = vec![1, 0, 0, 0, 0, 0x24, 255, 0, 255, 0];
        op(&mut s, Op::Poll, CLIENT);
        op(&mut s, Op::Poll, SERVER);
        op(&mut s, damage, lane);
        if matches!(damage, Op::Damage) {
            s.extend([0, 40, 0x55]);
        }
        op(&mut s, Op::Pump, 0);
        op(&mut s, Op::Read, CLIENT);
        s.extend([0, 16]);
        seeds.push(s);
    }
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_tokio::{Client, Server, play};

    /// The seeds do what they are meant to, so the harness's checks run on
    /// real traffic: data both ways, 0-RTT accepted, the lazy acceptor's
    /// refusal.
    #[test]
    fn seeds_exchange_data() {
        let seeds = seeds();
        let mut exchanged = 0;
        for seed in &seeds {
            let Some(world) = play(seed) else { continue };
            if world.received[CLIENT].ends_with(b"after a key update")
                && world.received[SERVER] == b"hello through tokio"
            {
                exchanged += 1;
            }
        }
        // Every TLS 1.3 and TLS 1.2 creation-mode seed (11 modes, two
        // transports each).
        assert_eq!(exchanged, 44);

        let early = seeds.iter().find(|s| s[5] == 0x40).expect("0-RTT seed");
        let world = play(early).expect("configurations");
        assert!(world.early_attempted);
        assert_eq!(world.early, b"early request");
        assert_eq!(world.received[SERVER], b"later");
        assert_eq!(world.server_returned_early, 0);

        // The server that returns early reads the 0-RTT data before its
        // handshake completes, and answers at once with 0.5-RTT data.
        let mut returned_early = 0;
        for seed in seeds.iter().filter(|s| s[5] & 0x80 != 0) {
            let half_rtt = seed[0] & 0x80 != 0;
            let cut = seed
                .windows(8)
                .position(|w| w == [Op::Write as u8, SERVER as u8, 0, 5, b'r', b'e', b'p', b'l'])
                .expect("the first answer");
            // Up to the early read, then up to the answer.
            let world = play(&seed[..cut]).expect("configurations");
            assert_eq!(world.server_returned_early, 1, "{seed:02x?}");
            assert_eq!(world.early, b"early request");
            let world = play(&seed[..cut + 9]).expect("configurations");
            let Server::Ready(server) = &world.server else {
                panic!("no server stream");
            };
            assert!(server.get_ref().1.is_handshaking());
            assert_eq!(world.sent[SERVER].len(), if half_rtt { 5 } else { 0 });

            let world = play(seed).expect("configurations");
            assert_eq!(world.early, b"early request");
            assert_eq!(world.received[SERVER], b"later");
            assert!(world.received[CLIENT].ends_with(b"reply"));
            returned_early += world.server_returned_early;
        }
        assert_eq!(returned_early, 5);

        let split: Vec<_> = seeds
            .iter()
            .filter(|s| s.get(12) == Some(&(Op::Split as u8)))
            .collect();
        assert_eq!(split.len(), 2);
        for seed in split {
            let world = play(seed).expect("configurations");
            let all = SPLIT_DATA.repeat(usize::from(SPLIT_ROUNDS));
            assert_eq!(world.received[CLIENT], all);
            assert_eq!(world.received[SERVER], all);
            assert!(matches!(world.client, Client::Ready(_)));
            assert!(matches!(world.server, Server::Ready(_)));
        }

        let refused = seeds
            .iter()
            .find(|s| s[5] == 0x10 && s.len() < 40)
            .expect("lazy seed");
        let world = play(refused).expect("configurations");
        assert!(matches!(world.server, Server::Gone));
        assert!(!world.lanes.borrow()[SERVER].bytes.is_empty(), "no alert");
    }
}
