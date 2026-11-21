use super::*;
use crate::crypto::GetRandomFailed;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct CountingRandom(AtomicUsize);

impl SecureRandom for CountingRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        let value = self.0.fetch_add(1, Ordering::Relaxed) as u64;
        output.copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}

#[derive(Debug)]
struct FailingRandom;

impl SecureRandom for FailingRandom {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        Err(GetRandomFailed)
    }
}

static RANDOM: CountingRandom = CountingRandom(AtomicUsize::new(1));
static FAILING: FailingRandom = FailingRandom;
const RECORD_BYTES: usize = 32;

fn at(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

fn state(selection: Selection) -> Validation<u8> {
    Validation::new(1, selection, at(900), &RANDOM).unwrap()
}

fn observe(v: &mut Validation<u8>, path: u8, bytes: usize, now: u64) {
    assert_eq!(
        v.receive(
            path,
            at(now),
            Record::AuthenticatedFresh {
                dtls_bytes: bytes,
                rrc: None,
            },
            true,
            RECORD_BYTES,
        ),
        Ok(Action::None)
    );
}

fn deliver(
    v: &mut Validation<u8>,
    path: u8,
    now: u64,
    message: Message,
    preferred: bool,
) -> Action<u8> {
    v.receive(
        path,
        at(now),
        Record::AuthenticatedFresh {
            dtls_bytes: RECORD_BYTES,
            rrc: Some(&message.encode()),
        },
        preferred,
        RECORD_BYTES,
    )
    .unwrap()
}

fn probe(v: &mut Validation<u8>, path: u8, now: u64) -> Message {
    let Action::Send { path: got, message } = v.poll(at(now), RECORD_BYTES).unwrap() else {
        panic!("expected a probe");
    };
    assert_eq!(got, path);
    assert_eq!(message.kind, MessageType::Challenge);
    message
}

fn reply(challenge: Message, kind: MessageType) -> Message {
    Message { kind, ..challenge }
}

#[test]
fn exact_wire_vectors_and_extension() {
    assert_eq!(EXTENSION_TYPE, 61);
    assert_eq!(CONTENT_TYPE, 27);
    assert_eq!(WIRE_LEN, 9);
    assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(1));
    assert_eq!(decode_extension(&[]), Ok(()));
    assert_eq!(decode_extension(&[0]), Err(Error::InvalidEncoding));
    for (tag, kind) in [
        MessageType::Challenge,
        MessageType::Response,
        MessageType::Drop,
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = [tag as u8, 1, 2, 3, 4, 5, 6, 7, 8];
        let message = Message {
            kind,
            cookie: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(message.encode(), bytes);
        assert_eq!(Message::decode(&bytes), Ok(Some(message)));
        for len in 1..WIRE_LEN {
            assert_eq!(Message::decode(&bytes[..len]), Err(Error::InvalidEncoding));
        }
        let mut excess = [0; WIRE_LEN + 1];
        excess[..WIRE_LEN].copy_from_slice(&bytes);
        assert_eq!(Message::decode(&excess), Err(Error::InvalidEncoding));
    }
    assert_eq!(Message::decode(&[]), Err(Error::InvalidEncoding));
    for tag in 3..=u8::MAX {
        assert_eq!(Message::decode(&[tag]), Ok(None));
        assert_eq!(Message::decode(&[tag; 32]), Ok(None));
    }
}

#[test]
fn basic_adopts_only_matching_address_bound_response() {
    let mut v = state(Selection::Basic);
    observe(&mut v, 2, 100, 0);
    let challenge = probe(&mut v, 2, 0);
    let response = reply(challenge, MessageType::Response);
    assert_eq!(deliver(&mut v, 3, 1, response, true), Action::None);
    assert_eq!(deliver(&mut v, 1, 2, response, true), Action::None);
    let mut wrong = response;
    wrong.cookie[0] ^= 1;
    assert_eq!(deliver(&mut v, 2, 3, wrong, true), Action::None);
    assert_eq!(
        deliver(&mut v, 2, 4, reply(challenge, MessageType::Drop), true),
        Action::None
    );
    assert_eq!(*v.bound_path(), 1);
    assert_eq!(
        deliver(&mut v, 2, 5, response, true),
        Action::Adopt { path: 2 }
    );
    assert_eq!(*v.bound_path(), 2);
    assert_eq!(v.pending_path(), None);
    assert_eq!(deliver(&mut v, 2, 6, response, true), Action::None);
}

#[test]
fn enhanced_probes_old_and_keeps_it_on_valid_response() {
    let mut v = state(Selection::Enhanced);
    observe(&mut v, 2, 100, 0);
    let old = probe(&mut v, 1, 0);
    let response = reply(old, MessageType::Response);
    assert_eq!(deliver(&mut v, 2, 1, response, true), Action::None);
    assert_eq!(
        deliver(&mut v, 1, 2, response, true),
        Action::Keep { path: 1 }
    );
    assert_eq!(*v.bound_path(), 1);
    assert_eq!(v.pending_path(), None);
    assert_eq!(v.poll(at(300), RECORD_BYTES), Ok(Action::None));
    assert!(!v.reserve_send(&2, 1));
}

#[test]
fn enhanced_old_drop_starts_basic_new_with_new_cookie() {
    let mut v = state(Selection::Enhanced);
    observe(&mut v, 2, 100, 0);
    let old = probe(&mut v, 1, 0);
    let drop = reply(old, MessageType::Drop);
    assert_eq!(deliver(&mut v, 2, 1, drop, true), Action::None);
    assert_eq!(deliver(&mut v, 1, 2, drop, true), Action::None);
    let new = probe(&mut v, 2, 2);
    assert_ne!(old.cookie, new.cookie);
    assert_eq!(
        deliver(&mut v, 2, 3, reply(old, MessageType::Response), true),
        Action::None
    );
    assert_eq!(
        deliver(&mut v, 2, 4, reply(new, MessageType::Response), true),
        Action::Adopt { path: 2 }
    );
}

#[test]
fn lost_old_probes_timeout_into_basic_and_lost_new_probes_fail() {
    let mut v = state(Selection::Enhanced);
    observe(&mut v, 2, 100, 0);
    let first = probe(&mut v, 1, 0);
    let second = probe(&mut v, 1, 300);
    let third = probe(&mut v, 1, 600);
    assert_ne!(first.cookie, second.cookie);
    assert_ne!(second.cookie, third.cookie);
    assert_eq!(v.poll(at(899), RECORD_BYTES), Ok(Action::None));
    let new = probe(&mut v, 2, 900);
    assert_ne!(third.cookie, new.cookie);
    assert_eq!(*v.bound_path(), 1);
    probe(&mut v, 2, 1200);
    probe(&mut v, 2, 1500);
    assert_eq!(
        v.poll(at(1800), RECORD_BYTES),
        Ok(Action::Failed { path: 2 })
    );
    assert_eq!(*v.bound_path(), 1);
    assert_eq!(v.pending_path(), None);
    assert_eq!(v.poll(at(1900), RECORD_BYTES), Ok(Action::None));
}

#[test]
fn old_reply_at_deadline_is_ignored_and_new_is_still_probed() {
    let mut v = state(Selection::Enhanced);
    observe(&mut v, 2, 100, 0);
    let old = probe(&mut v, 1, 0);
    assert_eq!(
        deliver(&mut v, 1, 900, reply(old, MessageType::Response), true),
        Action::None
    );
    let new = probe(&mut v, 2, 900);
    assert_eq!(
        deliver(&mut v, 1, 901, reply(old, MessageType::Response), true),
        Action::None
    );
    assert_eq!(
        deliver(&mut v, 2, 902, reply(new, MessageType::Response), true),
        Action::Adopt { path: 2 }
    );
}

#[test]
fn expired_new_reply_cannot_adopt_or_restart_validation() {
    let mut v = state(Selection::Basic);
    observe(&mut v, 2, 100, 0);
    let challenge = probe(&mut v, 2, 0);
    let response = reply(challenge, MessageType::Response);
    assert_eq!(deliver(&mut v, 2, 900, response, true), Action::None);
    assert_eq!(
        v.poll(at(900), RECORD_BYTES),
        Ok(Action::Failed { path: 2 })
    );
    assert_eq!(deliver(&mut v, 2, 901, response, true), Action::None);
    assert_eq!(v.pending_path(), None);
    assert_eq!(*v.bound_path(), 1);
    observe(&mut v, 2, 100, 902);
    let fresh = probe(&mut v, 2, 902);
    assert_ne!(fresh.cookie, challenge.cookie);
    assert_eq!(deliver(&mut v, 2, 903, response, true), Action::None);
}

#[test]
fn completing_validation_discards_unused_candidate_credit() {
    let mut v = state(Selection::Basic);
    observe(&mut v, 2, 1000, 0);
    probe(&mut v, 2, 0);
    assert_eq!(
        v.poll(at(900), RECORD_BYTES),
        Ok(Action::Failed { path: 2 })
    );
    assert!(!v.reserve_send(&2, 1));
    observe(&mut v, 2, 1, 901);
    assert_eq!(v.poll(at(901), RECORD_BYTES), Ok(Action::None));
    assert!(v.reserve_send(&2, 3));
    assert!(!v.reserve_send(&2, 1));
}

#[test]
fn paced_probe_bound_and_any_outstanding_cookie_can_answer() {
    let mut v = state(Selection::Basic);
    observe(&mut v, 2, 100, 0);
    let first = probe(&mut v, 2, 0);
    assert_eq!(v.poll(at(0), RECORD_BYTES), Ok(Action::None));
    assert_eq!(v.poll(at(299), RECORD_BYTES), Ok(Action::None));
    probe(&mut v, 2, 300);
    probe(&mut v, 2, 600);
    assert_eq!(v.poll(at(899), RECORD_BYTES), Ok(Action::None));
    assert_eq!(v.candidate.as_ref().unwrap().phase.sent, MAX_PROBES);
    assert_eq!(
        deliver(&mut v, 2, 899, reply(first, MessageType::Response), true),
        Action::Adopt { path: 2 }
    );
}

#[test]
fn challenge_replies_echo_on_actual_path_and_consume_credit() {
    for preferred in [false, true] {
        let mut v = state(Selection::Basic);
        let challenge = Message {
            kind: MessageType::Challenge,
            cookie: [7; 8],
        };
        assert_eq!(
            deliver(&mut v, 2, 0, challenge, preferred),
            Action::Send {
                path: 2,
                message: reply(
                    challenge,
                    if preferred {
                        MessageType::Response
                    } else {
                        MessageType::Drop
                    },
                ),
            }
        );
        assert_eq!(*v.bound_path(), 1);
        assert!(v.reserve_send(&2, 2 * RECORD_BYTES));
        assert!(!v.reserve_send(&2, 1));
        // A challenge is not an implicit response to our own challenge.
        assert_eq!(v.poll(at(0), RECORD_BYTES), Ok(Action::None));
    }
}

#[test]
fn discarded_records_neither_echo_nor_credit_nor_validate() {
    let mut v = state(Selection::Basic);
    assert_eq!(
        v.receive(2, Duration::MAX, Record::Discarded, true, RECORD_BYTES),
        Ok(Action::None)
    );
    assert_eq!(v.pending_path(), None);
    observe(&mut v, 2, 11, 0);
    probe(&mut v, 2, 0);
    assert_eq!(v.deadline(), Some(at(900)));
    assert_eq!(
        v.receive(2, at(1), Record::Discarded, true, RECORD_BYTES),
        Ok(Action::None)
    );
    assert_eq!(*v.bound_path(), 1);
    assert!(v.reserve_send(&2, 1));
    assert!(!v.reserve_send(&2, 1));
}

#[test]
fn all_candidate_sends_share_exact_three_times_allowance() {
    let mut v = state(Selection::Basic);
    observe(&mut v, 2, 10, 0);
    assert_eq!(v.poll(at(0), RECORD_BYTES), Ok(Action::None));
    assert!(v.reserve_send(&2, 30));
    assert!(!v.reserve_send(&2, 1));
    assert!(!v.reserve_send(&3, 1));
    assert!(v.reserve_send(&1, usize::MAX));
    observe(&mut v, 2, 20, 1);
    probe(&mut v, 2, 1);
    assert!(v.reserve_send(&2, 28));
    assert!(!v.reserve_send(&2, 1));
    assert_eq!(v.poll(at(301), RECORD_BYTES), Ok(Action::None));
}

#[test]
fn third_path_cannot_replace_candidate_or_borrow_its_allowance() {
    let mut v = state(Selection::Basic);
    observe(&mut v, 2, 100, 0);
    observe(&mut v, 3, 10000, 1);
    assert_eq!(v.pending_path(), Some(&2));
    assert_eq!(v.candidate.as_ref().unwrap().allowance, 300);
    let challenge = Message {
        kind: MessageType::Challenge,
        cookie: [5; 8],
    };
    assert_eq!(
        deliver(&mut v, 3, 2, challenge, true),
        Action::Send {
            path: 3,
            message: reply(challenge, MessageType::Response)
        }
    );
    assert!(!v.reserve_send(&3, 1));
    assert_eq!(v.candidate.as_ref().unwrap().allowance, 300);
    let bytes = challenge.encode();
    assert_eq!(
        v.receive(
            3,
            at(3),
            Record::AuthenticatedFresh {
                dtls_bytes: 9,
                rrc: Some(&bytes)
            },
            true,
            28,
        ),
        Ok(Action::None)
    );
    assert_eq!(v.pending_path(), Some(&2));
}

#[test]
fn timer_begins_only_when_first_probe_is_emitted() {
    let mut v = state(Selection::Basic);
    observe(&mut v, 2, 1, 0);
    assert_eq!(v.poll(at(1000), RECORD_BYTES), Ok(Action::None));
    assert_eq!(v.deadline(), None);
    observe(&mut v, 2, 10, 1000);
    let challenge = probe(&mut v, 2, 1000);
    assert_eq!(
        deliver(
            &mut v,
            2,
            1899,
            reply(challenge, MessageType::Response),
            true
        ),
        Action::Adopt { path: 2 }
    );
}

#[test]
fn randomness_failure_is_explicit_and_does_not_spend_credit() {
    let mut v = Validation::new(1, Selection::Basic, at(900), &FAILING).unwrap();
    observe(&mut v, 2, 100, 0);
    assert_eq!(v.poll(at(0), RECORD_BYTES), Err(Error::RandomFailed));
    let candidate = v.candidate.as_ref().unwrap();
    assert_eq!(candidate.allowance, 300);
    assert_eq!(candidate.phase.sent, 0);
    assert_eq!(candidate.phase.deadline, None);
    assert_eq!(*v.bound_path(), 1);
}

#[test]
fn malformed_records_and_undersized_costs_grant_no_credit() {
    let mut v = state(Selection::Basic);
    for (dtls_bytes, payload, expected) in [
        (0, None, Error::InvalidRecordSize),
        (1, Some(&[0, 1][..]), Error::InvalidRecordSize),
        (32, Some(&[0; 9][..]), Error::InvalidRecordSize),
    ] {
        assert_eq!(
            v.receive(
                2,
                at(0),
                Record::AuthenticatedFresh {
                    dtls_bytes,
                    rrc: payload
                },
                true,
                8,
            ),
            Err(expected)
        );
        assert_eq!(v.pending_path(), None);
    }
    for payload in [&[0, 1][..], &[1, 1], &[2; 10], &[255]] {
        assert_eq!(
            v.receive(
                2,
                at(0),
                Record::AuthenticatedFresh {
                    dtls_bytes: 32,
                    rrc: Some(payload),
                },
                true,
                RECORD_BYTES,
            ),
            Ok(Action::None),
        );
        assert_eq!(v.pending_path(), None);
    }
    observe(&mut v, 2, 100, 0);
    assert_eq!(v.poll(at(0), 8), Err(Error::InvalidRecordSize));
    assert_eq!(v.candidate.as_ref().unwrap().phase.sent, 0);
}

#[test]
fn clock_configuration_and_accounting_bounds_fail_safely() {
    for timeout in [Duration::ZERO, Duration::from_nanos(2)] {
        assert!(matches!(
            Validation::new(1, Selection::Basic, timeout, &RANDOM),
            Err(Error::InvalidTimeout)
        ));
    }
    let mut v = state(Selection::Basic);
    observe(&mut v, 2, usize::MAX, 10);
    assert_eq!(v.poll(at(9), RECORD_BYTES), Err(Error::TimeWentBackwards));
    let before = v.candidate.as_ref().unwrap().allowance;
    observe(&mut v, 2, usize::MAX, 10);
    assert!(v.candidate.as_ref().unwrap().allowance >= before);
    assert_eq!(
        v.poll(Duration::MAX, RECORD_BYTES),
        Err(Error::TimeOverflow)
    );
    let candidate = v.candidate.as_ref().unwrap();
    assert_eq!(candidate.phase.sent, 0);
    assert_eq!(candidate.phase.deadline, None);
    assert_eq!(*v.bound_path(), 1);
}

#[test]
fn unknown_types_are_ignored_without_echoing() {
    let mut v = state(Selection::Basic);
    assert_eq!(
        v.receive(
            1,
            at(0),
            Record::AuthenticatedFresh {
                dtls_bytes: 32,
                rrc: Some(&[255])
            },
            true,
            RECORD_BYTES,
        ),
        Ok(Action::None)
    );
    assert_eq!(v.pending_path(), None);
}

#[test]
fn non_copy_opaque_path_identity_is_used_in_full() {
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Path {
        peer: u8,
        local: u8,
    }
    let bound = Path { peer: 1, local: 1 };
    let candidate = Path { peer: 1, local: 2 };
    let mut v = Validation::new(bound.clone(), Selection::Basic, at(900), &RANDOM).unwrap();
    assert_eq!(
        v.receive(
            candidate.clone(),
            at(0),
            Record::AuthenticatedFresh {
                dtls_bytes: 100,
                rrc: None,
            },
            true,
            RECORD_BYTES,
        ),
        Ok(Action::None)
    );
    let Action::Send { path, message } = v.poll(at(0), RECORD_BYTES).unwrap() else {
        panic!("expected probe");
    };
    assert_eq!(path, candidate);
    let response = reply(message, MessageType::Response).encode();
    assert_eq!(
        v.receive(
            bound.clone(),
            at(1),
            Record::AuthenticatedFresh {
                dtls_bytes: 32,
                rrc: Some(&response)
            },
            true,
            RECORD_BYTES,
        ),
        Ok(Action::None)
    );
    assert_eq!(v.bound_path(), &bound);
}
