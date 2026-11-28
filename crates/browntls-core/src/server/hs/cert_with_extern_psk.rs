use crate::common_state::CommonState;
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::PskKeyExchangeMode;
use crate::msgs::handshake::ClientExtensions;
use crate::msgs::persist::ServerSessionValue;
use crate::psk::MAX_PSK_IDENTITIES_CONSIDERED;
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
/// never select. Bound the distinct identities before any ticket work, then
/// check them all without consuming stateful tickets or resolving external
/// PSKs.
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
    // A later ticket check must not be skipped: RFC 9973 requires rejecting
    // any offered resumption PSK, including one past the selection limit.
    // Preserve first-seen order and repeated-identity behavior while keeping
    // both the scratch space and subsequent backend calls bounded.
    let mut distinct: [&[u8]; MAX_PSK_IDENTITIES_CONSIDERED] = [&[]; MAX_PSK_IDENTITIES_CONSIDERED];
    let mut count = 0;
    for identity in offer
        .identities
        .iter()
        .map(|candidate| candidate.identity.0.as_slice())
    {
        if distinct[..count].contains(&identity) {
            continue;
        }
        if count == MAX_PSK_IDENTITIES_CONSIDERED {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::TooManyCertWithExternPskIdentities,
            ));
        }
        distinct[count] = identity;
        count += 1;
    }
    let stateless = config.ticketer.enabled();
    for &identity in &distinct[..count] {
        if is_tls13_version(config.session_storage.session_version(identity))
            || (stateless && is_tls13_version(stateless_ticket_version(config, identity)))
        {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::ResumptionPskOfferedWithCertWithExternPsk,
            ));
        }
    }
    Ok(())
}

fn stateless_ticket_version(config: &ServerConfig, identity: &[u8]) -> Option<ProtocolVersion> {
    let mut plaintext = config.ticketer.decrypt(identity)?;
    let version = ServerSessionValue::encoded_version(&plaintext);
    crate::crypto::zeroize_vec(&mut plaintext);
    version
}

fn is_tls13_version(version: Option<ProtocolVersion>) -> bool {
    matches!(
        version,
        Some(ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3)
    )
}
