// The issuer an SCT binds (RFC 9162 §4.7) is the end entity's issuer in
// the validated path: an intermediate CA when there is one, not the trust
// anchor. Included by `cases/transparency.rs`.

#[test]
fn sct_binds_the_intermediate_issuer() {
    use browntls_core::client::danger::ServerCertVerifier;
    use browntls_core::pki_types::UnixTime;
    use browntls_core::revocation::CertificateEvidence;

    let pki = CtPki::with_intermediate(digests().sha256);
    let chain = pki.chain();
    assert_ne!(pki.ca_spki, pki.root_spki);
    let log = Log::ecdsa(1);
    let requirements = || CtV2Requirements::new(digests(), vec![log.config()]);
    let ts = sct_time_ms();
    let tbs = CtPki::tbs(&chain.end_entity);
    let sct_over = |spki: &[u8]| log.sct(false, ts, &entry(pki.sha256, false, ts, spki, &tbs));

    let verifier = verifier(&pki, Some(requirements()));
    let check = |sct: Vec<u8>| {
        let items = list(&[sct]);
        let evidence = [CertificateEvidence {
            transparency_info: Some(&items),
            ..Default::default()
        }];
        verifier
            .verify_server_cert_with_context(
                &chain.end_entity,
                std::slice::from_ref(&chain.ca),
                CertificateIdentity::Name(&server_name()),
                &evidence,
                UnixTime::now(),
                ServerCertVerificationContext::LocalEvidence { allow_live: false },
            )
            .map(|verification| verification.transparency)
    };
    assert_eq!(check(sct_over(&pki.ca_spki)), Ok(Some(status(1, 1, 0))));
    assert_eq!(
        check(sct_over(&pki.root_spki)),
        Err(Error::InvalidCertificate(insufficient(0, 0)))
    );

    // A full handshake with the intermediate in the chain.
    let items = list(&[sct_over(&pki.ca_spki)]);
    for v in VERSIONS {
        let client = Arc::new(client_with(&pki, Some(requirements()), v));
        let (c, _s, cr, sr) = connect(&client, &server(&chain, Some(items.clone()), None, v));
        cr.unwrap();
        sr.unwrap();
        assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)), "{v:?}");
    }
}
