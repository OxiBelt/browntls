use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::common_state::CommonState;
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::PskKeyExchangeMode;
use crate::msgs::handshake::ClientExtensions;
use crate::msgs::persist::ServerSessionValue;
use crate::server::ServerConfig;

/// RFC 9973 §§4–5.1, on the effective (inner if ECH was accepted) hello.
pub(super) fn check_client_hello(
    common: &mut CommonState,
    exts: &ClientExtensions,
    previous_offer: Option<bool>,
) -> Result<(), Error> {
    let offered = exts.cert_with_extern_psk.is_some();
    if previous_offer.is_some_and(|previous| previous != offered) {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::CertWithExternPskChangedOnRetry,
        ));
    }
    if !offered {
        return Ok(());
    }
    if exts.early_data.is_some() {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidCertWithExternPskOffer,
        ));
    }
    let Some(modes) = &exts.psk_modes else {
        return Err(common.missing_extension(PeerMisbehaved::MissingPskModesExtension));
    };
    let Some(offer) = &exts.preshared_key else {
        return Err(common.missing_extension(PeerMisbehaved::MissingCertWithExternPskCompanion));
    };
    if exts.key_shares.is_none() || exts.named_groups.is_none() || exts.signature_schemes.is_none()
    {
        return Err(common.missing_extension(PeerMisbehaved::MissingCertWithExternPskCompanion));
    }
    if !modes.contains(&PskKeyExchangeMode::PSK_DHE_KE) {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidCertWithExternPskOffer,
        ));
    }
    if offer.identities.len() != offer.binders.len() {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::PskExtensionWithMismatchedIdsAndBinders,
        ));
    }
    Ok(())
}

/// RFC 9973 §5.1 excludes every resumption identity, even one we would
/// never select. Check the entire wire-bounded list without consuming
/// stateful tickets or invoking the external PSK resolver.
pub(super) fn reject_tickets(
    common: &mut CommonState,
    config: &ServerConfig,
    exts: &ClientExtensions,
) -> Result<(), Error> {
    let Some(offer) = exts
        .preshared_key
        .as_ref()
        .filter(|_| exts.cert_with_extern_psk.is_some())
    else {
        return Ok(());
    };
    let stateless = config.ticketer.enabled();
    let mut checked = BTreeSet::new();
    for identity in offer
        .identities
        .iter()
        .map(|candidate| candidate.identity.0.as_slice())
    {
        if !checked.insert(identity) {
            continue;
        }
        if is_tls13_ticket(config.session_storage.get(identity))
            || (stateless && is_tls13_ticket(config.ticketer.decrypt(identity)))
        {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::ResumptionPskOfferedWithCertWithExternPsk,
            ));
        }
    }
    Ok(())
}

fn is_tls13_ticket(plaintext: Option<Vec<u8>>) -> bool {
    let Some(mut plaintext) = plaintext else {
        return false;
    };
    let version = ServerSessionValue::encoded_version(&plaintext);
    crate::crypto::zeroize_vec(&mut plaintext);
    matches!(
        version,
        Some(ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3)
    )
}
