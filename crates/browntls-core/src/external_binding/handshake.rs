//! RFC 8844 in the handshake: what the client offers, what the server
//! answers, and the checks of what the peer sent (see the
//! [module documentation](super)).

use alloc::boxed::Box;

use super::{ExternalBinding, ExternalIdHash, ExternalSessionId, PeerExternalBinding};
use crate::common_state::CommonState;
use crate::enums::AlertDescription;
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::msgs::handshake::{ClientExtensions, ServerExtensions};

/// Checks a client configuration when a connection is created: a client
/// that expects the server's `external_session_id` must send its own, or
/// the expectation could never be met.
pub(crate) fn check_client_config(binding: Option<&ExternalBinding>) -> Result<(), Error> {
    match binding {
        Some(b) if b.peer_session_id.is_some() && b.session_id.is_none() => {
            Err(Error::InconsistentExternalBinding)
        }
        _ => Ok(()),
    }
}

/// Adds the client's extensions to a ClientHello being built (the first,
/// or the second after a HelloRetryRequest: the same values).
pub(crate) fn client_offer(binding: Option<&ExternalBinding>, exts: &mut ClientExtensions) {
    let Some(binding) = binding else {
        return;
    };
    exts.external_id_hash = Some(binding.id_hash_to_send());
    exts.external_session_id = binding.session_id.clone();
}

/// Removes the extensions from a ClientHello sent in the clear beside an
/// Encrypted Client Hello offer (RFC 9849): they belong to the inner one.
pub(crate) fn strip_from_outer(exts: &mut ClientExtensions) {
    exts.external_id_hash = None;
    exts.external_session_id = None;
}

/// Checks the server's answer in the TLS 1.2 ServerHello or the TLS 1.3
/// EncryptedExtensions and records it.
///
/// The unsolicited-extension check has run: the server only sent an
/// extension we did. After an Encrypted Client Hello rejection the
/// handshake runs with the outer ClientHello, which carried neither
/// extension, only to authenticate the retry configurations, and is then
/// failed with `ech_required`: nothing is checked.
pub(crate) fn client_check(
    common: &mut CommonState,
    binding: Option<&ExternalBinding>,
    exts: &ServerExtensions,
    tls13: bool,
    ech_rejected: bool,
) -> Result<(), Error> {
    let Some(binding) = binding else {
        return Ok(());
    };
    if ech_rejected {
        return Ok(());
    }
    check_peer(
        common,
        binding,
        exts.external_id_hash.as_ref(),
        exts.external_session_id.as_ref(),
        tls13,
    )?;
    common.peer_external_binding = Some(Box::new(PeerExternalBinding {
        id_hash: exts.external_id_hash,
        session_id: exts.external_session_id.clone(),
    }));
    Ok(())
}

/// Checks the client's extensions in a ClientHello (each one, the second
/// after a HelloRetryRequest included) and records them.
///
/// A server that rejects Encrypted Client Hello cannot tell a GREASE offer
/// (whose ClientHello is the client's real one) from a real offer under
/// keys it does not hold (whose outer ClientHello carries neither
/// extension): it checks the ClientHello it answers as any other, so
/// [`ExternalBinding::require_peer_support`] stays enforced, at the cost
/// of refusing the second kind with `missing_extension` instead of sending
/// it retry configurations.
pub(crate) fn server_check(
    common: &mut CommonState,
    binding: Option<&ExternalBinding>,
    exts: &ClientExtensions,
    tls13: bool,
) -> Result<(), Error> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let received = PeerExternalBinding {
        id_hash: exts.external_id_hash,
        session_id: exts.external_session_id.clone(),
    };
    // RFC 9846 §4.1.2: the second ClientHello repeats the first's
    // extensions but for those a HelloRetryRequest may change.
    if let Some(first) = &common.peer_external_binding
        && **first != received
    {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::ExternalBindingChangedOnRetry,
        ));
    }
    check_peer(
        common,
        binding,
        received.id_hash.as_ref(),
        received.session_id.as_ref(),
        tls13,
    )?;
    common.peer_external_binding = Some(Box::new(received));
    Ok(())
}

/// Adds the server's answers to the extensions the client sent.
pub(crate) fn server_answer(
    binding: Option<&ExternalBinding>,
    client: &ClientExtensions,
    exts: &mut ServerExtensions,
) {
    let Some(binding) = binding else {
        return;
    };
    if client.external_id_hash.is_some() {
        exts.external_id_hash = Some(binding.id_hash_to_send());
    }
    if client.external_session_id.is_some() {
        exts.external_session_id = binding.session_id.clone();
    }
}

/// Compares what the peer sent with the expectations (RFC 8844 §3.2,
/// §4.3).
fn check_peer(
    common: &mut CommonState,
    binding: &ExternalBinding,
    id_hash: Option<&ExternalIdHash>,
    session_id: Option<&ExternalSessionId>,
    tls13: bool,
) -> Result<(), Error> {
    if let Some(expected) = &binding.peer_id_hash {
        match id_hash {
            Some(got) if got != expected => {
                return Err(common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::ExternalIdHashMismatch,
                ));
            }
            None if binding.require_peer_support => {
                return Err(missing(
                    common,
                    PeerIncompatible::ExternalIdHashExtensionRequired,
                    tls13,
                ));
            }
            _ => {}
        }
    }
    if let Some(expected) = &binding.peer_session_id {
        match session_id {
            Some(got) if got != expected => {
                return Err(common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::ExternalSessionIdMismatch,
                ));
            }
            None if binding.require_peer_support => {
                return Err(missing(
                    common,
                    PeerIncompatible::ExternalSessionIdExtensionRequired,
                    tls13,
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// A required extension the peer did not send: `missing_extension` is a
/// TLS 1.3 alert (RFC 9846 §6.2); TLS 1.2 uses `handshake_failure`, as for
/// the other extensions a configuration requires.
fn missing(common: &mut CommonState, why: PeerIncompatible, tls13: bool) -> Error {
    let alert = if tls13 {
        AlertDescription::MissingExtension
    } else {
        AlertDescription::HandshakeFailure
    };
    common.send_fatal_alert(alert, why)
}
