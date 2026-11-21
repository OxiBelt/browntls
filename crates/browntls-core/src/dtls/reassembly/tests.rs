//! Tests of handshake message reassembly.

use alloc::vec;
use alloc::vec::Vec;

use super::*;

const LARGE: usize = 1 << 20;

/// The body of a test message: distinct bytes for every offset and seq.
fn body(seq: u16, len: usize) -> Vec<u8> {
    (0..len)
        .map(|at| (at as u8).wrapping_mul(7) ^ (seq as u8))
        .collect()
}

/// The TLS encoding `peek` should return.
fn encoded(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![typ];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn header(typ: u8, seq: u16, length: usize, range: &Range<usize>) -> HandshakeHeader {
    HandshakeHeader {
        typ,
        length: length as u32,
        message_seq: seq,
        fragment_offset: range.start as u32,
        fragment_length: range.len() as u32,
    }
}

/// Pushes `body[range]` as a fragment of message `seq`.
fn push(
    r: &mut Reassembler,
    typ: u8,
    seq: u16,
    body: &[u8],
    range: Range<usize>,
    epoch: u64,
) -> Fragment {
    r.push(&header(typ, seq, body.len(), &range), &body[range], epoch)
}

/// Pushes a whole message in one fragment.
fn push_whole(r: &mut Reassembler, typ: u8, seq: u16, body: &[u8], epoch: u64) -> Fragment {
    push(r, typ, seq, body, 0..body.len(), epoch)
}

/// Pops the next message, checking its epoch and encoding.
fn expect_pop(r: &mut Reassembler, epoch: u64, typ: u8, body: &[u8]) {
    let seq = r.next_receive_seq();
    assert_eq!(r.peek(), Some((epoch, &encoded(typ, body)[..])), "{seq}");
    r.pop();
    assert_eq!(r.next_receive_seq(), seq + 1);
}

#[test]
fn single_messages_in_order() {
    let mut r = Reassembler::new(LARGE, LARGE);
    assert_eq!(r.next_receive_seq(), 0);
    assert_eq!(r.peek(), None);
    assert!(!r.has_buffered() && !r.has_gap());
    for seq in 0..5 {
        let msg = body(seq, 10 + usize::from(seq));
        assert_eq!(push_whole(&mut r, 2, seq, &msg, 0), Fragment::Accepted);
        assert!(r.has_buffered() && !r.has_gap());
        // The TLS encoding: type, 24-bit length, body.
        let (epoch, out) = r.peek().unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(out[..4], [2, 0, 0, 10 + seq as u8]);
        assert_eq!(out[4..], msg[..]);
        r.pop();
        assert_eq!(r.next_receive_seq(), seq + 1);
        assert!(!r.has_buffered());
    }
    // Popping with nothing complete does nothing.
    r.pop();
    assert_eq!(r.next_receive_seq(), 5);
}

#[test]
fn reordered_fragments() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let msg = body(0, 300);
    assert_eq!(push(&mut r, 11, 0, &msg, 200..300, 2), Fragment::Accepted);
    assert_eq!(r.peek(), None);
    assert!(r.has_gap());
    assert_eq!(push(&mut r, 11, 0, &msg, 0..100, 2), Fragment::Accepted);
    assert_eq!(r.peek(), None);
    assert_eq!(push(&mut r, 11, 0, &msg, 100..200, 2), Fragment::Accepted);
    assert!(!r.has_gap());
    expect_pop(&mut r, 2, 11, &msg);
}

#[test]
fn duplicates_and_retransmissions() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let msg = body(0, 50);
    assert_eq!(push(&mut r, 1, 0, &msg, 0..20, 0), Fragment::Accepted);
    assert_eq!(push(&mut r, 1, 0, &msg, 0..20, 0), Fragment::Accepted);
    assert_eq!(push(&mut r, 1, 0, &msg, 5..10, 0), Fragment::Accepted);
    assert_eq!(push(&mut r, 1, 0, &msg, 20..50, 0), Fragment::Accepted);
    // A duplicate of a complete message not yet popped.
    assert_eq!(push_whole(&mut r, 1, 0, &msg, 0), Fragment::Accepted);
    expect_pop(&mut r, 0, 1, &msg);
    // Once delivered, any fragment of it is a retransmission.
    assert_eq!(push_whole(&mut r, 1, 0, &msg, 0), Fragment::Old);
    assert_eq!(push(&mut r, 1, 0, &msg, 3..4, 0), Fragment::Old);
    assert_eq!(push(&mut r, 9, 0, &msg, 3..4, 2), Fragment::Old);
    // But a malformed one is not.
    let mut bad = header(1, 0, 50, &(0..10));
    bad.fragment_length = 11;
    assert_eq!(r.push(&bad, &msg[..10], 0), Fragment::Dropped);
    assert!(!r.has_buffered());
}

#[test]
fn overlapping_fragments_keep_first_bytes() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let msg = body(0, 300);
    assert_eq!(push(&mut r, 8, 0, &msg, 100..150, 2), Fragment::Accepted);
    // Overlapping on both sides, with different bytes in the overlap.
    let mut other = msg.clone();
    other[100..150].fill(0xee);
    assert_eq!(push(&mut r, 8, 0, &other, 50..200, 2), Fragment::Accepted);
    assert_eq!(push(&mut r, 8, 0, &other, 190..300, 2), Fragment::Accepted);
    assert_eq!(r.peek(), None);
    // Spanning several holes at once.
    let mut r2 = Reassembler::new(LARGE, LARGE);
    for range in [10..20, 30..40, 50..60, 280..290] {
        assert_eq!(push(&mut r2, 8, 0, &msg, range, 2), Fragment::Accepted);
    }
    assert_eq!(push(&mut r2, 8, 0, &msg, 0..300, 2), Fragment::Accepted);
    expect_pop(&mut r2, 2, 8, &msg);

    assert_eq!(push(&mut r, 8, 0, &other, 0..60, 2), Fragment::Accepted);
    expect_pop(&mut r, 2, 8, &msg);
}

#[test]
fn future_message_waits_for_the_gap() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let (m0, m1, m2) = (body(0, 40), body(1, 30), body(2, 20));
    assert_eq!(push_whole(&mut r, 2, 1, &m1, 2), Fragment::Accepted);
    assert_eq!(push(&mut r, 8, 2, &m2, 0..10, 2), Fragment::Accepted);
    assert_eq!(r.peek(), None);
    assert!(r.has_gap() && r.has_buffered());
    assert_eq!(push(&mut r, 1, 0, &m0, 0..20, 0), Fragment::Accepted);
    assert!(r.has_gap());
    assert_eq!(push(&mut r, 1, 0, &m0, 20..40, 0), Fragment::Accepted);
    assert!(!r.has_gap());
    expect_pop(&mut r, 0, 1, &m0);
    expect_pop(&mut r, 2, 2, &m1);
    // The next message is partial.
    assert_eq!(r.peek(), None);
    assert!(r.has_gap());
    assert_eq!(push(&mut r, 8, 2, &m2, 10..20, 2), Fragment::Accepted);
    expect_pop(&mut r, 2, 8, &m2);
    assert!(!r.has_buffered() && !r.has_gap());
}

#[test]
fn malformed_and_over_bounds_are_dropped() {
    let mut r = Reassembler::new(100, 150);
    let msg = body(0, 100);
    let ok = header(1, 0, 100, &(10..20));
    let fragment = &msg[10..20];

    // The fragment is not `fragment_length` bytes.
    assert_eq!(r.push(&ok, &msg[10..19], 0), Fragment::Dropped);
    assert_eq!(r.push(&ok, &msg[10..21], 0), Fragment::Dropped);
    // It reaches past the end of the message.
    let past = HandshakeHeader { length: 15, ..ok };
    assert_eq!(r.push(&past, fragment, 0), Fragment::Dropped);
    // Its end overflows.
    let overflow = HandshakeHeader {
        fragment_offset: u32::MAX - 5,
        ..ok
    };
    assert_eq!(r.push(&overflow, fragment, 0), Fragment::Dropped);
    // The message is too large.
    let msg101 = body(0, 101);
    assert_eq!(push_whole(&mut r, 1, 0, &msg101, 0), Fragment::Dropped);
    // Too large to encode, whatever the limit.
    let mut huge = Reassembler::new(usize::MAX, usize::MAX);
    let too_long = HandshakeHeader {
        length: MAX_ENCODABLE + 1,
        ..ok
    };
    assert_eq!(huge.push(&too_long, fragment, 0), Fragment::Dropped);
    assert!(!r.has_buffered() && !huge.has_buffered());

    // Beyond the window, and its last slot.
    let small = body(0, 1);
    assert_eq!(push_whole(&mut r, 1, WINDOW, &small, 0), Fragment::Dropped);
    assert_eq!(
        push_whole(&mut r, 1, u16::MAX, &small, 0),
        Fragment::Dropped
    );
    assert_eq!(
        push_whole(&mut r, 1, WINDOW - 1, &small, 0),
        Fragment::Accepted
    );

    // Over the buffered total: 1 + 100 + 50 > 150.
    assert_eq!(r.push(&ok, fragment, 0), Fragment::Accepted);
    let m1 = body(1, 50);
    assert_eq!(push(&mut r, 1, 1, &m1, 0..1, 0), Fragment::Dropped);
    let m1 = body(1, 49);
    assert_eq!(push(&mut r, 1, 1, &m1, 0..1, 0), Fragment::Accepted);

    // Disagreeing with the buffered type or length; the first stays.
    let typ = HandshakeHeader { typ: 2, ..ok };
    assert_eq!(r.push(&typ, fragment, 0), Fragment::Dropped);
    let length = HandshakeHeader { length: 99, ..ok };
    assert_eq!(r.push(&length, fragment, 0), Fragment::Dropped);
    assert_eq!(push(&mut r, 1, 0, &msg, 0..10, 0), Fragment::Accepted);
    assert_eq!(push(&mut r, 1, 0, &msg, 20..100, 0), Fragment::Accepted);
    expect_pop(&mut r, 0, 1, &msg);
}

#[test]
fn buffered_bytes_are_released() {
    let mut r = Reassembler::new(100, 100);
    let (m0, m1) = (body(0, 100), body(1, 1));
    assert_eq!(push_whole(&mut r, 1, 0, &m0, 0), Fragment::Accepted);
    assert_eq!(push_whole(&mut r, 1, 1, &m1, 0), Fragment::Dropped);
    r.pop();
    assert_eq!(push_whole(&mut r, 1, 1, &m1, 0), Fragment::Accepted);
    // Dropping releases them too.
    r.drop_next();
    assert_eq!(push_whole(&mut r, 1, 1, &m0, 0), Fragment::Accepted);
    // As does a replacement under a higher epoch.
    assert_eq!(push_whole(&mut r, 2, 1, &m0, 2), Fragment::Accepted);
    expect_pop(&mut r, 2, 2, &m0);
}

#[test]
fn too_many_holes() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let msg = body(0, 200);
    // Fragments at even offsets each split the last hole.
    for at in 0..MAX_HOLES {
        let at = 2 * at;
        assert_eq!(push(&mut r, 1, 0, &msg, at..at + 1, 0), Fragment::Accepted);
    }
    let at = 2 * MAX_HOLES;
    assert_eq!(push(&mut r, 1, 0, &msg, at..at + 1, 0), Fragment::Dropped);
    // Filling or shrinking holes is still fine, splitting none is too.
    assert_eq!(push(&mut r, 1, 0, &msg, 1..2, 0), Fragment::Accepted);
    assert_eq!(push(&mut r, 1, 0, &msg, at..at + 1, 0), Fragment::Accepted);
    assert_eq!(push(&mut r, 1, 0, &msg, 199..200, 0), Fragment::Accepted);
    assert_eq!(push(&mut r, 1, 0, &msg, 0..200, 0), Fragment::Accepted);
    expect_pop(&mut r, 0, 1, &msg);
}

#[test]
fn a_higher_epoch_replaces_a_buffered_message() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let fake = body(9, 60);
    let real = body(0, 80);
    // A plaintext injection, partial.
    assert_eq!(push(&mut r, 2, 0, &fake, 0..30, 0), Fragment::Accepted);
    // The real message differs in type and length, under epoch 2.
    assert_eq!(push(&mut r, 8, 0, &real, 0..40, 2), Fragment::Accepted);
    // Lower epochs no longer get in.
    assert_eq!(push(&mut r, 2, 0, &fake, 30..60, 0), Fragment::Dropped);
    assert_eq!(push(&mut r, 8, 0, &real, 40..80, 0), Fragment::Dropped);
    assert_eq!(r.peek(), None);
    assert_eq!(push(&mut r, 8, 0, &real, 40..80, 2), Fragment::Accepted);
    expect_pop(&mut r, 2, 8, &real);

    // So is a complete message not yet popped.
    let m1 = body(1, 10);
    assert_eq!(push_whole(&mut r, 2, 1, &fake, 0), Fragment::Accepted);
    assert_eq!(push(&mut r, 11, 1, &m1, 0..5, 3), Fragment::Accepted);
    assert_eq!(push(&mut r, 11, 1, &m1, 5..10, 3), Fragment::Accepted);
    expect_pop(&mut r, 3, 11, &m1);
}

#[test]
fn a_lower_epoch_does_not_replace() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let msg = body(0, 50);
    assert_eq!(push(&mut r, 8, 0, &msg, 0..25, 2), Fragment::Accepted);
    assert_eq!(push_whole(&mut r, 2, 0, &body(0, 3), 0), Fragment::Dropped);
    assert_eq!(push(&mut r, 8, 0, &msg, 25..50, 0), Fragment::Dropped);
    assert_eq!(r.peek(), None);
    assert_eq!(push(&mut r, 8, 0, &msg, 25..50, 2), Fragment::Accepted);
    expect_pop(&mut r, 2, 8, &msg);
}

#[test]
fn drop_next_discards_without_advancing() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let (m0, m1) = (body(0, 30), body(1, 30));
    // Nothing buffered: nothing happens.
    r.drop_next();
    assert_eq!(r.next_receive_seq(), 0);

    assert_eq!(push_whole(&mut r, 2, 0, &m0, 0), Fragment::Accepted);
    assert_eq!(push_whole(&mut r, 8, 1, &m1, 2), Fragment::Accepted);
    // Message 0 came under the wrong epoch, say.
    assert_eq!(r.peek().map(|(epoch, _)| epoch), Some(0));
    r.drop_next();
    assert_eq!(r.next_receive_seq(), 0);
    assert_eq!(r.peek(), None);
    assert!(r.has_gap() && r.has_buffered());
    // Only the next message goes: message 1 stays.
    r.drop_next();
    assert!(r.has_buffered());
    // The retransmission is accepted afresh, also under a lower epoch.
    assert_eq!(push(&mut r, 2, 0, &m0, 0..10, 0), Fragment::Accepted);
    r.drop_next();
    assert_eq!(push_whole(&mut r, 2, 0, &m0, 2), Fragment::Accepted);
    expect_pop(&mut r, 2, 2, &m0);
    expect_pop(&mut r, 2, 8, &m1);
    assert!(!r.has_buffered());
}

#[test]
fn starting_after_a_stateless_retry() {
    let mut r = Reassembler::new(LARGE, LARGE);
    r.set_next_receive_seq(1);
    assert_eq!(r.next_receive_seq(), 1);
    let (m0, m1) = (body(0, 5), body(1, 5));
    assert_eq!(push_whole(&mut r, 1, 0, &m0, 0), Fragment::Old);
    assert_eq!(push_whole(&mut r, 1, WINDOW + 1, &m1, 0), Fragment::Dropped);
    assert_eq!(push_whole(&mut r, 1, WINDOW, &m1, 0), Fragment::Accepted);
    assert_eq!(push_whole(&mut r, 1, 1, &m1, 0), Fragment::Accepted);
    expect_pop(&mut r, 0, 1, &m1);
    // Setting it again discards what is outside the new window.
    r.set_next_receive_seq(WINDOW + 1);
    assert!(!r.has_buffered());
}

#[test]
fn has_gap_semantics() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let (m0, m1) = (body(0, 10), body(1, 10));
    assert!(!r.has_gap());
    // A complete next message is no gap, even with others behind it.
    assert_eq!(push_whole(&mut r, 1, 0, &m0, 0), Fragment::Accepted);
    assert!(!r.has_gap());
    assert_eq!(push(&mut r, 1, 1, &m1, 0..5, 0), Fragment::Accepted);
    assert!(!r.has_gap());
    r.pop();
    // Now the next message is partial.
    assert!(r.has_gap());
    assert_eq!(push(&mut r, 1, 1, &m1, 5..10, 0), Fragment::Accepted);
    assert!(!r.has_gap());
    r.pop();
    // A later message while the next is missing.
    assert_eq!(push_whole(&mut r, 1, 3, &m1, 0), Fragment::Accepted);
    assert!(r.has_gap());
}

#[test]
fn empty_messages_and_fragments() {
    let mut r = Reassembler::new(LARGE, 0);
    // An empty message fits even when nothing else would.
    assert_eq!(push_whole(&mut r, 14, 0, &[], 0), Fragment::Accepted);
    assert!(!r.has_gap());
    assert_eq!(push_whole(&mut r, 14, 0, &[], 0), Fragment::Accepted);
    expect_pop(&mut r, 0, 14, &[]);
    assert_eq!(push_whole(&mut r, 14, 0, &[], 0), Fragment::Old);

    // An empty fragment of a non-empty message stores nothing.
    let msg = body(1, 10);
    let mut r = Reassembler::new(LARGE, LARGE);
    assert_eq!(push(&mut r, 1, 0, &msg, 4..4, 0), Fragment::Accepted);
    assert!(!r.has_buffered());
    assert_eq!(push(&mut r, 1, 0, &msg, 10..10, 0), Fragment::Accepted);
    assert!(!r.has_buffered());
    assert_eq!(push(&mut r, 1, 0, &msg, 0..10, 0), Fragment::Accepted);
    expect_pop(&mut r, 0, 1, &msg);
}

#[test]
fn message_seq_near_the_top() {
    let mut r = Reassembler::new(LARGE, LARGE);
    let top = u16::MAX - (WINDOW - 1);
    r.set_next_receive_seq(top);
    let msg = body(0, 3);
    // The whole window up to 0xffff, in reverse order.
    for seq in (top..=u16::MAX).rev() {
        assert_eq!(push_whole(&mut r, 1, seq, &msg, 0), Fragment::Accepted);
    }
    for seq in top..u16::MAX {
        assert_eq!(r.next_receive_seq(), seq);
        expect_pop(&mut r, 0, 1, &msg);
    }
    assert_eq!(r.next_receive_seq(), u16::MAX);
    assert!(r.peek().is_some());
    r.pop();
    // Nothing can follow message 0xffff.
    assert_eq!(r.next_receive_seq(), u16::MAX);
    assert!(!r.has_buffered());
    assert_eq!(push_whole(&mut r, 1, u16::MAX, &msg, 0), Fragment::Old);
    assert_eq!(push_whole(&mut r, 1, 0, &msg, 0), Fragment::Old);
}

/// A small deterministic generator (xorshift64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn shuffled_fragments_reassemble_exactly() {
    for round in 0..200u64 {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ round);
        let lens = [0, 1, 300, 2000, 17, 1200];
        let messages: Vec<(u8, Vec<u8>)> = lens
            .iter()
            .enumerate()
            .map(|(seq, &len)| (seq as u8 + 1, body(seq as u16 + 3, len)))
            .collect();

        // Contiguous fragments of random sizes, some widened to overlap
        // their neighbours, some duplicated.
        let mut fragments = Vec::new();
        for (seq, (_, msg)) in messages.iter().enumerate() {
            let mut at = 0;
            loop {
                let end = (at + 1 + rng.below(400)).min(msg.len());
                let start = at.saturating_sub(rng.below(3) * rng.below(50));
                let stop = (end + rng.below(3) * rng.below(50)).min(msg.len());
                fragments.push((seq, start..stop));
                if rng.below(4) == 0 {
                    fragments.push((seq, start..stop));
                }
                at = end;
                if at >= msg.len() {
                    break;
                }
            }
        }
        for i in (1..fragments.len()).rev() {
            fragments.swap(i, rng.below(i + 1));
        }

        let mut r = Reassembler::new(4096, 8192);
        let mut out = Vec::new();
        // Lost fragments are retransmitted: push everything until done.
        for _ in 0..4 {
            for (seq, range) in &fragments {
                let (typ, msg) = &messages[*seq];
                let result = push(&mut r, *typ, *seq as u16, msg, range.clone(), 2);
                if usize::from(r.next_receive_seq()) > *seq {
                    assert_eq!(result, Fragment::Old, "round {round}");
                } else {
                    assert_ne!(result, Fragment::Old, "round {round}");
                }
                while let Some((epoch, message)) = r.peek() {
                    assert_eq!(epoch, 2);
                    out.push(message.to_vec());
                    r.pop();
                }
            }
        }
        let expected: Vec<Vec<u8>> = messages
            .iter()
            .map(|(typ, msg)| encoded(*typ, msg))
            .collect();
        assert_eq!(out, expected, "round {round}");
        assert!(!r.has_buffered() && !r.has_gap());
    }
}
