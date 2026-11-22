// A CT 2.0 policy beside a revocation policy: the verifier validates the
// path through the revocation policy and still enforces Certificate
// Transparency, on every entry point and while a live OCSP query is
// pending. Included by `cases/transparency.rs`.

/// A verifier with both a revocation policy (stapled OCSP required, or a
/// live query when `live`) and a CT 2.0 policy trusting `log`.
fn revocation_and_ct(pki: &CtPki, log: &Log, live: bool) -> Arc<WebPkiServerVerifier> {
    let mut policy = browntls_core::revocation::RevocationPolicy::new(digests());
    if live {
        policy = policy.with_live_ocsp(Arc::new(browntls_core::time_provider::DefaultTimeProvider));
    }
    WebPkiServerVerifier::builder_with_provider(pki.roots(), provider())
        .with_revocation_policy(policy)
        .with_certificate_transparency(CtV2Requirements::new(digests(), vec![log.config()]))
        .build()
        .unwrap()
}

#[test]
fn revocation_policy_keeps_the_transparency_policy() {
    use browntls_core::client::danger::ServerCertVerifier;
    use browntls_core::pki_types::UnixTime;
    use browntls_core::revocation::{CertificateEvidence, RevocationStatus};

    let fx = Fixture::new();
    let verifier = revocation_and_ct(&fx.pki, &fx.log_a, false);
    let ee = &fx.chain.end_entity;
    let items = list(&[fx.sct(&fx.log_a)]);
    let plain_staple = fx.pki.ocsp(ee, None);
    let ct_staple = fx.pki.ocsp(ee, Some(&items));
    let now = UnixTime::now();
    let refused = Error::InvalidCertificate(insufficient(0, 0));

    fn evidence<'a>(ocsp: &'a [u8], info: Option<&'a [u8]>) -> [CertificateEvidence<'a>; 1] {
        [CertificateEvidence {
            ocsp: Some(ocsp),
            transparency_info: info,
            ..Default::default()
        }]
    }
    let (without, with) = (
        evidence(&plain_staple, None),
        evidence(&plain_staple, Some(&items)),
    );
    let name = server_name();
    let check = |evidence: &[CertificateEvidence<'_>]| {
        verifier.verify_server_cert_with_context(
            ee,
            &[],
            CertificateIdentity::Name(&name),
            evidence,
            now,
            ServerCertVerificationContext::LocalEvidence { allow_live: false },
        )
    };
    assert_eq!(check(&without).unwrap_err(), refused);
    for evidence in [with, evidence(&ct_staple, None)] {
        let verified = check(&evidence).unwrap();
        assert!(matches!(
            verified.revocation,
            browntls_core::revocation::RevocationCheck::Complete(Some(RevocationStatus::Good))
        ));
        assert_eq!(verified.transparency, Some(status(1, 1, 0)));
    }

    // Handshakes: the staple satisfies revocation; CT needs the list too.
    for v in VERSIONS {
        let config = |verifier| {
            Arc::new(
                ClientConfig::builder_with_provider(provider())
                    .with_protocol_versions(&[v])
                    .unwrap()
                    .with_webpki_verifier(verifier)
                    .with_no_client_auth(),
            )
        };
        let client = config(revocation_and_ct(&fx.pki, &fx.log_a, false));
        let without = server(&fx.chain, None, Some(plain_staple.clone()), v);
        let (_c, _s, cr, sr) = connect(&client, &without);
        assert_refused(cr, sr, insufficient(0, 0));
        let client = config(revocation_and_ct(&fx.pki, &fx.log_a, false));
        let with = server(
            &fx.chain,
            Some(items.clone()),
            Some(plain_staple.clone()),
            v,
        );
        let (c, _s, cr, sr) = connect(&client, &with);
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_revocation_status(), Some(RevocationStatus::Good));
        assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)), "{v:?}");
    }
}

#[test]
fn transparency_is_decided_before_a_live_query() {
    use browntls_core::client::danger::ServerCertVerifier;
    use browntls_core::pki_types::UnixTime;
    use browntls_core::revocation::{CertificateEvidence, RevocationCheck};

    let fx = Fixture::new();
    // A server certificate naming an OCSP responder, so that the policy can
    // ask for its status instead of failing (Authority Information Access,
    // RFC 5280 §4.2.2.1: id-ad-ocsp, a URI).
    let mut aia = vec![0x06, 8, 0x2b, 6, 1, 5, 5, 7, 0x30, 1, 0x86];
    let uri = b"http://ocsp.invalid/";
    aia.push(u8::try_from(uri.len()).unwrap());
    aia.extend_from_slice(uri);
    let access = [&[0x30, u8::try_from(aia.len()).unwrap()][..], &aia].concat();
    let value = [&[0x30, u8::try_from(access.len()).unwrap()][..], &access].concat();
    let chain = fx.pki.chain_with(&[(&[1, 3, 6, 1, 5, 5, 7, 1, 1], value)]);
    let ee = &chain.end_entity;
    let items = list(&[fx.pki.x509_sct(&fx.log_a, ee)]);

    let verifier = revocation_and_ct(&fx.pki, &fx.log_a, true);
    let now = UnixTime::now();
    fn evidence(info: Option<&[u8]>) -> [CertificateEvidence<'_>; 1] {
        [CertificateEvidence {
            transparency_info: info,
            ..Default::default()
        }]
    }
    let check = |info, offered_transparency_info| {
        verifier.verify_server_cert_with_context(
            ee,
            &[],
            CertificateIdentity::Name(&server_name()),
            &evidence(info),
            now,
            ServerCertVerificationContext::TlsHandshake {
                offered_transparency_info,
                offered_status_request: true,
            },
        )
    };
    // The offer and evidence must both pass before a live query is returned.
    assert_eq!(
        check(Some(&items), false).unwrap_err(),
        Error::InvalidCertificate(CertificateError::TransparencyOfferRequired)
    );
    assert_eq!(
        check(None, true).unwrap_err(),
        Error::InvalidCertificate(insufficient(0, 0))
    );
    let verified = check(Some(&items), true).unwrap();
    assert!(matches!(verified.revocation, RevocationCheck::Pending(_)));
    assert_eq!(verified.transparency, Some(status(1, 1, 0)));
}
