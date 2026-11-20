//! Atomically refreshed OCSP staples for a server credential.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::{fmt, time::Duration};
use std::sync::RwLock;

use browntls_pki::ocsp::{
    CertId, CertIdHash, CertIdHashers, CertStatus, OcspIssuer, OcspPolicy, encode_request,
    must_staple, ocsp_responder_uris, verify_response,
};
use browntls_pki::{Cert, EndEntityCert, KeyUsage, UnixTime};

use super::{RevocationDigests, RevocationQuery};
use crate::crypto::CryptoProvider;
use crate::error::{CertificateError, Error, InconsistentKeys};
use crate::server::{ClientHello, ResolvesServerCert};
use crate::sign::CertifiedKey;
use crate::sync::Arc;
use crate::time_provider::TimeProvider;
use crate::webpki::{RootCertStore, pki_error};
use crate::x509::wrap_in_sequence;

/// An OCSP query for the leaf of one installed server credential.
pub struct StapleQuery {
    credential: Arc<Credential>,
    query: RevocationQuery,
}

impl StapleQuery {
    /// Returns the request and candidate responder endpoints.
    pub fn query(&self) -> &RevocationQuery {
        &self.query
    }
}

impl fmt::Debug for StapleQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StapleQuery")
            .field("query", &self.query)
            .finish_non_exhaustive()
    }
}

/// The result of validating and installing the response to a refresh query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StapleInstall {
    /// The fresh response is serving for the current credential.
    Installed {
        /// The first instant at which the staple is unusable.
        expires: UnixTime,
    },
    /// The credential rotated or already had newer status evidence.
    Obsolete,
    /// The response revoked the current credential and removed it from service.
    Revoked,
}

struct Credential {
    key: Arc<CertifiedKey>,
    issuer_subject: Vec<u8>,
    issuer_spki: Vec<u8>,
    not_after: UnixTime,
    must_staple: bool,
}

struct Staple {
    key: Arc<CertifiedKey>,
    this_update: UnixTime,
    expires: UnixTime,
}

struct Current {
    credential: Arc<Credential>,
    staple: Option<Staple>,
    revoked: bool,
}

/// A certificate resolver with an atomically refreshed leaf OCSP staple.
///
/// Each refresh query belongs to the installed credential. Only authenticated
/// and current responses are installed. Rotating a credential invalidates
/// outstanding queries. The resolver uses a fresh staple when it has one,
/// and withholds an expired or revoked credential and a Must-Staple
/// credential without a fresh staple. Configured intermediate staples are
/// managed by the application.
pub struct ServerStapleResolver {
    current: RwLock<Current>,
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    digests: RevocationDigests,
    clock: Arc<dyn TimeProvider>,
}

impl fmt::Debug for ServerStapleResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerStapleResolver")
            .finish_non_exhaustive()
    }
}

impl ServerStapleResolver {
    /// Validates the credential and its existing leaf staple, if supplied.
    ///
    /// The roots are the trust anchors for the server's own chain, used to
    /// identify the issuer that is authorized to sign its OCSP response.
    pub fn new(
        credential: CertifiedKey,
        roots: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
        digests: RevocationDigests,
        clock: Arc<dyn TimeProvider>,
    ) -> Result<Self, Error> {
        let now = clock.current_time().ok_or(Error::FailedToGetCurrentTime)?;
        let state = Self::validate_credential(credential, &roots, &provider, digests, now)?;
        Ok(Self {
            current: RwLock::new(state),
            roots,
            provider,
            digests,
            clock,
        })
    }

    /// Validates and installs a replacement credential.
    pub fn replace(&self, credential: CertifiedKey) -> Result<(), Error> {
        let next = Self::validate_credential(
            credential,
            &self.roots,
            &self.provider,
            self.digests,
            self.now()?,
        )?;
        let mut current = self.current.write().map_err(|_| lock_error())?;
        // A retry using the same certificate cannot clear an authenticated
        // revocation. Install a different certificate to restore service.
        if current.revoked
            && current.credential.key.cert.first() == next.credential.key.cert.first()
        {
            return Err(CertificateError::Revoked.into());
        }
        *current = next;
        Ok(())
    }

    /// Builds an OCSP query for the current usable leaf.
    ///
    /// The application must authorize the endpoint before resolving or dialing
    /// it. It may select a configured responder when the certificate lists no
    /// URL.
    pub fn refresh_query(&self) -> Result<Option<StapleQuery>, Error> {
        let now = self.now()?;
        let credential = {
            let current = self.current.read().map_err(|_| lock_error())?;
            if current.revoked || now >= current.credential.not_after {
                return Ok(None);
            }
            current.credential.clone()
        };
        let cert = Cert::try_from(credential.key.end_entity_cert()?).map_err(pki_error)?;
        let urls: Vec<_> = ocsp_responder_uris(&cert)
            .map_err(pki_error)?
            .filter(|url| {
                url.len() <= 2048
                    && (url.starts_with("http://") || url.starts_with("https://"))
                    && url.bytes().all(|byte| byte.is_ascii_graphic())
            })
            .take(8)
            .map(ToString::to_string)
            .collect();
        let hash = if self.digests.sha1.is_some() {
            CertIdHash::Sha1
        } else {
            CertIdHash::Sha256
        };
        let cert_id = CertId::new(hash, &hashers(self.digests), &cert, &credential.issuer_spki)
            .map_err(|_| CertificateError::InvalidOcspResponse)?;
        let query = RevocationQuery::new(
            (self.digests.sha256)(&credential.issuer_spki),
            urls,
            encode_request(&cert_id, None).map_err(|_| CertificateError::InvalidOcspResponse)?,
        );
        Ok(Some(StapleQuery { credential, query }))
    }

    /// Validates a fetched response and atomically installs its result.
    ///
    /// A failed validation leaves the previous staple available through its
    /// own deadline. A response for an older credential cannot change the
    /// current credential.
    pub fn install(
        &self,
        query: &StapleQuery,
        response_der: Vec<u8>,
    ) -> Result<StapleInstall, Error> {
        {
            let current = self.current.read().map_err(|_| lock_error())?;
            if !Arc::ptr_eq(&current.credential, &query.credential) {
                return Ok(StapleInstall::Obsolete);
            }
        }
        let now = self.now()?;
        let mut policy = OcspPolicy::stapled(
            self.provider.signature_verification_algorithms.all,
            hashers(self.digests),
            now,
        );
        policy.require_next_update = true;
        let cert = Cert::try_from(query.credential.key.end_entity_cert()?).map_err(pki_error)?;
        let issuer = OcspIssuer::new(
            &query.credential.issuer_subject,
            &query.credential.issuer_spki,
        );
        let response = verify_response(&response_der, &cert, &issuer, &policy)
            .map_err(|_| CertificateError::InvalidOcspResponse)?;
        let status = response.status;
        let this_update = response.this_update;
        let expires = response.expires.min(query.credential.not_after);
        let mut current = self.current.write().map_err(|_| lock_error())?;
        if !Arc::ptr_eq(&current.credential, &query.credential) {
            return Ok(StapleInstall::Obsolete);
        }
        if matches!(status, CertStatus::Revoked { .. }) {
            current.staple = None;
            current.revoked = true;
            return Ok(StapleInstall::Revoked);
        }
        if current.revoked
            || current.staple.as_ref().is_some_and(|staple| {
                (this_update, expires) <= (staple.this_update, staple.expires)
            })
        {
            return Ok(StapleInstall::Obsolete);
        }
        if status != CertStatus::Good || now >= expires {
            return Err(CertificateError::UnknownRevocationStatus.into());
        }
        let mut key = (*current.credential.key).clone();
        key.set_ocsp_for(0, Some(response_der))?;
        current.staple = Some(Staple {
            key: Arc::new(key),
            this_update,
            expires,
        });
        Ok(StapleInstall::Installed { expires })
    }

    /// The remaining lifetime of a response, according to the resolver's clock.
    pub fn remaining_lifetime(&self, expires: UnixTime) -> Option<Duration> {
        let now = self.clock.current_time()?;
        Some(Duration::from_secs(
            expires.as_secs().saturating_sub(now.as_secs()),
        ))
    }

    /// The deadline of the installed leaf staple, if any.
    pub fn staple_expiry(&self) -> Option<UnixTime> {
        self.current
            .read()
            .ok()?
            .staple
            .as_ref()
            .map(|staple| staple.expires)
    }

    fn now(&self) -> Result<UnixTime, Error> {
        self.clock
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)
    }

    fn validate_credential(
        mut key: CertifiedKey,
        roots: &RootCertStore,
        provider: &CryptoProvider,
        digests: RevocationDigests,
        now: UnixTime,
    ) -> Result<Current, Error> {
        match key.keys_match() {
            Ok(()) | Err(Error::InconsistentKeys(InconsistentKeys::Unknown)) => {}
            Err(err) => return Err(err),
        }
        let initial = key.ocsp.take();
        let (leaf, chain) = key
            .cert
            .split_first()
            .ok_or(Error::NoCertificatesPresented)?;
        let cert = EndEntityCert::try_from(leaf).map_err(pki_error)?;
        let algorithms = provider.signature_verification_algorithms.all;
        let path = cert
            .verify_for_usage(
                algorithms,
                &roots.roots,
                chain,
                now,
                KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(pki_error)?;
        let (issuer_subject, issuer_spki) =
            if let Some(issuer) = path.intermediate_certificates().next() {
                let issuer = Cert::try_from(issuer).map_err(pki_error)?;
                (
                    issuer.subject().to_vec(),
                    issuer.subject_public_key_info().as_ref().to_vec(),
                )
            } else {
                (
                    path.anchor().subject.as_ref().to_vec(),
                    wrap_in_sequence(path.anchor().subject_public_key_info.as_ref()),
                )
            };
        let must_staple = must_staple(&cert).map_err(pki_error)?;
        let not_after = cert.not_after();
        let mut staple = None;
        let mut revoked = false;
        if let Some(initial) = initial {
            let issuer = OcspIssuer::new(&issuer_subject, &issuer_spki);
            let policy = OcspPolicy::stapled(algorithms, hashers(digests), now);
            let response = verify_response(&initial, &cert, &issuer, &policy)
                .map_err(|_| CertificateError::InvalidOcspResponse)?;
            match response.status {
                CertStatus::Good => {
                    let this_update = response.this_update;
                    let expires = response.expires.min(not_after);
                    let mut stapled = key.clone();
                    stapled.set_ocsp_for(0, Some(initial))?;
                    staple = Some(Staple {
                        key: Arc::new(stapled),
                        this_update,
                        expires,
                    });
                }
                CertStatus::Revoked { .. } => revoked = true,
                _ => return Err(CertificateError::UnknownRevocationStatus.into()),
            }
        }
        let credential = Arc::new(Credential {
            key: Arc::new(key),
            issuer_subject,
            issuer_spki,
            not_after,
            must_staple,
        });
        Ok(Current {
            credential,
            staple,
            revoked,
        })
    }
}

impl ResolvesServerCert for ServerStapleResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let now = self.clock.current_time()?;
        let current = self.current.read().ok()?;
        if current.revoked || now >= current.credential.not_after {
            return None;
        }
        if let Some(staple) = &current.staple
            && now < staple.expires
        {
            return Some(staple.key.clone());
        }
        (!current.credential.must_staple).then(|| current.credential.key.clone())
    }
}

fn hashers(digests: RevocationDigests) -> CertIdHashers {
    CertIdHashers {
        sha1: digests.sha1,
        sha256: Some(digests.sha256),
    }
}

fn lock_error() -> Error {
    Error::general("server staple state lock is poisoned")
}
