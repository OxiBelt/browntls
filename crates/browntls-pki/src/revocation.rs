//! Revocation checking during path validation (RFC 5280 §6.3, simplified to
//! CRLs supplied by the caller).

use crate::UnixTime;
use crate::cert::Cert;
use crate::crl::{ExpirationPolicy, RevocationCheckDepth, RevocationOptions, UnknownStatusPolicy};
use crate::error::Error;
use crate::path::{Budget, Role};
use crate::signed_data::Spki;
use crate::types::SignatureVerificationAlgorithm;

impl RevocationOptions<'_> {
    /// Determines the revocation status of `cert`, issued by the holder of
    /// `issuer_spki`.
    ///
    /// Every applicable CRL (issuer match and scope) is consulted: its
    /// signature must verify, the issuer must be allowed to sign CRLs, and a
    /// listed serial means the certificate is revoked. Under
    /// [`ExpirationPolicy::Enforce`] an expired CRL is set aside; it only
    /// decides the outcome ([`Error::CrlExpired`]) when no current CRL
    /// confirms the status. With no applicable CRL, the status policy decides.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check(
        &self,
        cert: &Cert<'_>,
        role: Role,
        issuer_spki: &Spki<'_>,
        issuer_may_sign_crls: bool,
        algs: &[&dyn SignatureVerificationAlgorithm],
        budget: &mut Budget,
        time: UnixTime,
    ) -> Result<(), Error> {
        if self.depth == RevocationCheckDepth::EndEntity && role == Role::Issuer {
            return Ok(());
        }

        let mut confirmed_not_revoked = false;
        let mut expired = None;
        for crl in self
            .crls
            .iter()
            .filter(|crl| crl.issuer() == cert.issuer && crl.scope_covers(cert, role))
        {
            crl.verify_signature_budgeted(algs, issuer_spki, budget)?;
            let next_update = crl.next_update();
            if self.expiration_policy == ExpirationPolicy::Enforce && time >= next_update {
                expired.get_or_insert(Error::CrlExpired { time, next_update });
                continue;
            }
            if !issuer_may_sign_crls {
                return Err(Error::IssuerNotCrlSigner);
            }
            if crl.find_serial(cert.serial)?.is_some() {
                return Err(Error::CertRevoked);
            }
            confirmed_not_revoked = true;
        }

        if confirmed_not_revoked {
            return Ok(());
        }
        if let Some(expired) = expired {
            return Err(expired);
        }
        match self.status_policy {
            UnknownStatusPolicy::Allow => Ok(()),
            UnknownStatusPolicy::Deny => Err(Error::UnknownRevocationStatus),
        }
    }
}
