//! Completing a verification whose paths lack local evidence: live OCSP
//! queries, one at a time, or the outcome without them.

use alloc::string::String;
use alloc::vec::Vec;

use browntls_pki::crl::CertRevocationList;
use browntls_pki::{Cert, CertificateDer, SignatureVerificationAlgorithm};

use super::sources::{
    DeliveredScts, OcspContext, OcspVerdict, OwnedIssuer, crlite_revoked, ocsp_query,
};
use super::{RevocationData, RevocationPolicy};
use crate::error::{CertificateError, Error};
use crate::revocation::{RevocationCheck, RevocationResponse, RevocationStatus};
use crate::sync::Arc;

/// Responder URLs passed on for one certificate.
const MAX_RESPONDER_URLS: usize = 4;

/// Longest responder URL passed on, in octets.
const MAX_RESPONDER_URL_LEN: usize = 2048;

/// A covered certificate without local evidence, and its issuer in the path
/// that was validated.
pub(super) struct PendingCert {
    pub(super) der: CertificateDer<'static>,
    pub(super) issuer: OwnedIssuer,
    pub(super) end_entity: bool,
    pub(super) tls_scts: Option<Vec<u8>>,
}

/// The certificates of one otherwise valid path that lack local evidence,
/// starting nearest the end entity. Never empty.
pub(super) type DeferredPath = Vec<PendingCert>;

/// What a live query established about one certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Good,
    Revoked,
    /// No query was possible, or it produced no usable response.
    Unavailable,
}

/// A query ready for transport.
struct Query {
    issuer_key_hash: [u8; 32],
    responder_urls: Vec<String>,
    request_der: Vec<u8>,
}

/// The remaining work of a suspended verification. It owns everything it
/// needs, so it can wait for a transport result.
pub(super) struct Live {
    policy: RevocationPolicy,
    algs: &'static [&'static dyn SignatureVerificationAlgorithm],
    crls: Arc<Vec<CertRevocationList<'static>>>,
    data: Option<RevocationData>,
    paths: Vec<DeferredPath>,
    /// The path being decided, and the next certificate in it.
    path: usize,
    cert: usize,
    /// Whether a certificate of the current path stayed without an answer.
    path_indeterminate: bool,
    /// Whether an abandoned path contained a revoked certificate.
    saw_revoked: bool,
    queries_left: usize,
    /// Answers already obtained, reused by every path with the certificate.
    answers: Vec<(CertificateDer<'static>, [u8; 32], Answer)>,
}

impl Live {
    pub(super) fn new(
        policy: RevocationPolicy,
        algs: &'static [&'static dyn SignatureVerificationAlgorithm],
        crls: Arc<Vec<CertRevocationList<'static>>>,
        data: Option<RevocationData>,
        paths: Vec<DeferredPath>,
        allow_live: bool,
    ) -> Self {
        let queries_left = match (&policy.live_clock, allow_live) {
            (Some(_), true) => policy.max_live_queries,
            _ => 0,
        };
        Self {
            policy,
            algs,
            crls,
            data,
            paths,
            path: 0,
            cert: 0,
            path_indeterminate: false,
            saw_revoked: false,
            queries_left,
            answers: Vec::new(),
        }
    }

    /// Decides the paths in order until one is acceptable, a query has to
    /// be made, or none is left.
    pub(super) fn advance(mut self) -> Result<RevocationCheck, Error> {
        loop {
            let Some(path) = self.paths.get(self.path) else {
                return Err(match self.saw_revoked {
                    true => CertificateError::Revoked.into(),
                    false => CertificateError::UnknownRevocationStatus.into(),
                });
            };
            let Some(subject) = path.get(self.cert) else {
                let status = match self.path_indeterminate {
                    true => RevocationStatus::Indeterminate,
                    false => RevocationStatus::Good,
                };
                return Ok(RevocationCheck::Complete(Some(status)));
            };
            let end_entity = subject.end_entity;
            let known = self.issuer_id(subject).and_then(|issuer_id| {
                self.answers
                    .iter()
                    .find(|(der, issuer, _)| *der == subject.der && *issuer == issuer_id)
                    .map(|(_, _, answer)| *answer)
            });
            let answer = match known {
                Some(answer) => answer,
                None => match self.query(subject) {
                    Some(query) => {
                        self.queries_left = self.queries_left.saturating_sub(1);
                        return Ok(RevocationCheck::pending(
                            query.issuer_key_hash,
                            query.responder_urls,
                            query.request_der,
                            move |response| self.resume(response),
                        ));
                    }
                    None => Answer::Unavailable,
                },
            };
            match answer {
                Answer::Good => self.cert = self.cert.saturating_add(1),
                // The end entity is part of every path.
                Answer::Revoked if end_entity => return Err(CertificateError::Revoked.into()),
                Answer::Revoked => {
                    self.saw_revoked = true;
                    self.next_path();
                }
                Answer::Unavailable if self.policy.best_effort => {
                    // Keep going: a later certificate may still be revoked.
                    self.path_indeterminate = true;
                    self.cert = self.cert.saturating_add(1);
                }
                Answer::Unavailable => self.next_path(),
            }
        }
    }

    fn next_path(&mut self) {
        self.path = self.path.saturating_add(1);
        self.cert = 0;
        self.path_indeterminate = false;
    }

    /// Records the transport result for the certificate that was asked
    /// about and continues.
    fn resume(mut self, response: RevocationResponse) -> Result<RevocationCheck, Error> {
        let asked = self
            .paths
            .get(self.path)
            .and_then(|path| path.get(self.cert));
        if let Some(subject) = asked
            && let Some(issuer_id) = self.issuer_id(subject)
        {
            let answer = self.judge(subject, response)?;
            let der = subject.der.clone();
            self.answers.push((der, issuer_id, answer));
        }
        self.advance()
    }

    fn issuer_id(&self, subject: &PendingCert) -> Option<[u8; 32]> {
        subject
            .issuer
            .with(|issuer| (self.policy.digests.sha256)(&issuer.spki_der()))
    }

    /// The query for `subject`, unless the budget is spent. The application
    /// can map a verified issuer to a responder even without an AIA URL.
    fn query(&self, subject: &PendingCert) -> Option<Query> {
        if self.queries_left == 0 {
            return None;
        }
        let cert = Cert::try_from(&subject.der).ok()?;
        let responder_urls: Vec<String> = browntls_pki::ocsp::ocsp_responder_uris(&cert)
            .ok()?
            .filter(|url| url.len() <= MAX_RESPONDER_URL_LEN && is_http_url(url))
            .take(MAX_RESPONDER_URLS)
            .map(String::from)
            .collect();
        let request = subject
            .issuer
            .with(|issuer| ocsp_query(&self.policy.digests, &cert, issuer))??;
        Some(Query {
            issuer_key_hash: request.issuer_key_hash,
            responder_urls,
            request_der: request.request_der,
        })
    }

    /// Authenticates a transport result for `subject` at the current time.
    fn judge(&self, subject: &PendingCert, response: RevocationResponse) -> Result<Answer, Error> {
        let RevocationResponse::Der(response) = response else {
            return Ok(Answer::Unavailable);
        };
        let now = self
            .policy
            .live_clock
            .as_ref()
            .and_then(|clock| clock.current_time());
        let (Some(now), Ok(cert)) = (now, Cert::try_from(&subject.der)) else {
            return Ok(Answer::Unavailable);
        };
        let crls: Vec<&CertRevocationList<'static>> = self.crls.iter().collect();
        let context = OcspContext {
            digests: &self.policy.digests,
            algs: self.algs,
            crls: &crls,
            now,
        };
        subject
            .issuer
            .with(|issuer| {
                let verdict = context.fetched(&response, &cert, issuer);
                let (ocsp_good, sct_list) = match verdict {
                    OcspVerdict::Good { sct_list } => (true, sct_list),
                    OcspVerdict::Unknown { sct_list } => (false, sct_list),
                    OcspVerdict::Revoked => return Ok(Answer::Revoked),
                    OcspVerdict::Unusable => return Ok(Answer::Unavailable),
                    OcspVerdict::Invalid => {
                        return Err(CertificateError::InvalidOcspResponse.into());
                    }
                };
                if subject.end_entity
                    && let Some(data) = &self.data
                    && sct_list.is_some()
                {
                    let delivered = DeliveredScts {
                        tls: subject.tls_scts.as_deref(),
                        ocsp: sct_list,
                    };
                    match crlite_revoked(
                        data,
                        &self.policy.digests,
                        self.algs,
                        &cert,
                        issuer,
                        delivered,
                        now,
                    )
                    .map_err(crate::webpki::pki_error)?
                    {
                        Some(true) => return Ok(Answer::Revoked),
                        Some(false) => return Ok(Answer::Good),
                        None => {}
                    }
                }
                Ok(if ocsp_good {
                    Answer::Good
                } else {
                    Answer::Unavailable
                })
            })
            .unwrap_or(Ok(Answer::Unavailable))
    }
}

/// Whether `url` uses the `http` or `https` scheme.
fn is_http_url(url: &str) -> bool {
    ["http://", "https://"].iter().any(|scheme| {
        url.get(..scheme.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responder_url_schemes() {
        assert!(is_http_url("http://ocsp.example/"));
        assert!(is_http_url("HTTPS://ocsp.example/"));
        assert!(!is_http_url("ldap://ocsp.example/"));
        assert!(!is_http_url("http:/"));
        assert!(!is_http_url(""));
    }
}
