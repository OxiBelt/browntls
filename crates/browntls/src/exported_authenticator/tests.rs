//! Unit tests of the per-connection context lists.

use alloc::vec;

use super::*;

#[test]
fn context_lists_are_capped_separately() {
    let mut state = AuthenticatorState::default();
    state.add_request(b"ours", vec![1]);
    // A peer fills the list of spontaneous authenticators...
    for i in 0..MAX_CONTEXTS {
        let context = (i as u32).to_be_bytes().to_vec();
        state.check_spontaneous(&context).unwrap();
        state.record(Answered::Spontaneous(context));
    }
    assert!(matches!(
        state.check_spontaneous(b"one more"),
        Err(Error::General(_))
    ));
    // ...and of authenticators we made (one per request it sends).
    for i in 0..MAX_CONTEXTS {
        let context = (i as u32).to_be_bytes().to_vec();
        state.check_make(&context).unwrap();
        state.made.push(context);
    }
    assert!(state.check_make(b"one more").is_err());
    // Answers to our own request still validate, once.
    let index = state.find_request(&[1]).unwrap();
    state.record(Answered::Request(index));
    assert_eq!(
        state.find_request(&[1]),
        Err(PeerMisbehaved::ReusedAuthenticatorContext.into())
    );
    // A request we did not make is refused.
    assert!(matches!(state.find_request(&[2]), Err(Error::General(_))));
    // A spontaneous authenticator may not take a requested context.
    let mut state = AuthenticatorState::default();
    state.add_request(b"ours", vec![1]);
    assert_eq!(
        state.check_spontaneous(b"ours"),
        Err(PeerMisbehaved::ReusedAuthenticatorContext.into())
    );
}
