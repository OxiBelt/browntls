use super::TlsState;

#[test]
fn shutting_down_both_directions_in_either_order_closes_the_stream() {
    let mut state = TlsState::Stream;
    state.shutdown_read();
    assert_eq!(state, TlsState::ReadShutdown);
    assert!(!state.readable() && state.writeable());
    state.shutdown_write();
    assert_eq!(state, TlsState::FullyShutdown);

    let mut state = TlsState::Stream;
    state.shutdown_write();
    assert_eq!(state, TlsState::WriteShutdown);
    assert!(state.readable() && !state.writeable());
    state.shutdown_read();
    assert_eq!(state, TlsState::FullyShutdown);
    assert!(!state.readable() && !state.writeable());
}
