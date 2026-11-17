//! Unit tests of [`super::CommonState`].

use super::*;

fn tls13_state() -> CommonState {
    let mut common = CommonState::new(Side::Client);
    common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
    common
}

fn alert(level: AlertLevel, description: AlertDescription) -> AlertMessagePayload {
    AlertMessagePayload { level, description }
}

#[test]
fn tls13_user_canceled_is_ignored_at_any_level() {
    // RFC 9846 §6.1: the receiver keeps reading until close_notify; the
    // level carries no meaning in TLS 1.3 (§6).
    let mut common = tls13_state();
    for level in [AlertLevel::Warning, AlertLevel::Fatal] {
        assert_eq!(
            common.process_alert(&alert(level, AlertDescription::UserCanceled)),
            Ok(())
        );
    }
    assert!(!common.has_received_close_notify);
    assert_eq!(
        common.process_alert(&alert(AlertLevel::Warning, AlertDescription::CloseNotify)),
        Ok(())
    );
    assert!(common.has_received_close_notify);
}

#[test]
fn repeated_user_canceled_is_bounded() {
    let mut common = tls13_state();
    let user_canceled = alert(AlertLevel::Warning, AlertDescription::UserCanceled);
    for _ in 0..MAX_WARNING_ALERTS {
        assert_eq!(common.process_alert(&user_canceled), Ok(()));
    }
    assert_eq!(
        common.process_alert(&user_canceled),
        Err(PeerMisbehaved::TooManyWarningAlertsReceived.into())
    );
}

#[test]
fn tls13_error_alerts_are_fatal_at_warning_level() {
    let mut common = tls13_state();
    assert_eq!(
        common.process_alert(&alert(AlertLevel::Warning, AlertDescription::GeneralError)),
        Err(Error::AlertReceived(AlertDescription::GeneralError))
    );
}

#[test]
fn key_update_request_not_repeated_until_peer_updates() {
    // RFC 9846 §4.7.3: until a KeyUpdate arrives from the peer, the
    // sender MUST NOT send another update_requested.
    let mut common = tls13_state();
    let requested = KeyUpdateRequest::UpdateRequested;
    assert_eq!(common.key_update_to_send(requested), Some(requested));
    common.key_update_request_outstanding = true;
    assert_eq!(
        common.key_update_to_send(requested),
        Some(KeyUpdateRequest::UpdateNotRequested)
    );
    common
        .received_key_update(KeyUpdateRequest::UpdateNotRequested, 8)
        .unwrap();
    assert_eq!(common.key_update_to_send(requested), Some(requested));
}

#[test]
fn key_updates_stop_at_the_epoch_limit() {
    // RFC 9846 §4.7.3: no more than 2^48-1 key updates are sent; at the
    // limit a peer's update_requested is ignored.
    let mut common = tls13_state();
    common.sent_key_updates = MAX_KEY_UPDATES - 1;
    assert!(
        common
            .key_update_to_send(KeyUpdateRequest::UpdateNotRequested)
            .is_some()
    );
    common.sent_key_updates = MAX_KEY_UPDATES;
    assert_eq!(
        common.key_update_to_send(KeyUpdateRequest::UpdateNotRequested),
        None
    );
    assert_eq!(MAX_KEY_UPDATES, (1u64 << 48) - 1);
}

#[test]
fn several_requests_owe_one_response() {
    let mut common = tls13_state();
    for _ in 0..3 {
        common
            .received_key_update(KeyUpdateRequest::UpdateRequested, 8)
            .unwrap();
    }
    assert!(common.key_update_owed);
    // Sending any KeyUpdate pays the debt. Without a record encrypter
    // the message is dropped, but the bookkeeping is what is checked.
    common.send_key_update(KeyUpdateRequest::UpdateNotRequested);
    assert!(!common.key_update_owed);
    assert_eq!(common.sent_key_updates, 1);
    assert!(!common.key_update_request_outstanding);
}
