use crate::common_state::CommonState;
use crate::enums::AlertDescription;
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::PskKeyExchangeMode;
use crate::msgs::handshake::ClientExtensions;

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
    if exts.key_shares.is_none() || exts.named_groups.is_none() || exts.preshared_key.is_none() {
        return Err(common.missing_extension(PeerMisbehaved::MissingCertWithExternPskCompanion));
    }
    if exts.signature_schemes.is_none() {
        return Err(common.missing_extension(PeerMisbehaved::MissingCertWithExternPskCompanion));
    }
    if !modes.contains(&PskKeyExchangeMode::PSK_DHE_KE) {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidCertWithExternPskOffer,
        ));
    }
    Ok(())
}
