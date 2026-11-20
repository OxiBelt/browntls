//! Server and client authentication with RSASSA-PSS keys: the schemes a key
//! signs with and the offers it refuses.

use super::*;

// ---------------------------------------------------------------------------
// Signing with RSASSA-PSS keys

#[test]
fn pss_server_signs_with_every_pss_pss_scheme() {
    init_logging();
    let chain = server_with_key(UNRESTRICTED);
    let mut handshakes = 0;
    for v in VERSIONS {
        for scheme in PSS_PSS {
            let seen = server_signs(v, &chain, &[scheme])
                .unwrap_or_else(|e| panic!("{v:?} {scheme:?}: {e:?}"));
            assert_eq!(seen, [scheme], "{v:?}");
            handshakes += 1;
        }
        // Offered everything, the key prefers the largest hash.
        let mut offer = RSAE.to_vec();
        offer.extend(PSS_PSS);
        assert_eq!(
            server_signs(v, &chain, &offer).unwrap(),
            [S::RSA_PSS_PSS_SHA512],
            "{v:?}"
        );
    }
    // Three schemes in each enabled version.
    assert_eq!(handshakes, 3 * VERSIONS.len());
}

#[cfg(feature = "tls12")]
#[cfg(feature = "tls12")]
#[test]
fn pss_server_signs_with_every_tls12_rsa_suite() {
    init_logging();
    let chain = server_with_key(UNRESTRICTED);
    let suites: Vec<_> = prov::ALL_CIPHER_SUITES
        .iter()
        .filter(|s| s.tls13().is_none() && format!("{:?}", s.suite()).contains("_RSA_"))
        .copied()
        .collect();
    // 3 AEAD and 4 CBC `ECDHE_RSA` suites.
    assert_eq!(suites.len(), 7);
    for suite in suites {
        let mut provider = prov::default_provider();
        provider.cipher_suites = vec![suite];
        let verifier = SchemeRecordingServerVerifier::new(
            pinned_server_verifier(&chain),
            &[S::RSA_PSS_PSS_SHA256],
        );
        let client = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&TLS12_ONLY)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let (mut client, mut server) = connect(client, server_for(&chain));
        do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{suite:?}: {e}"));
        assert_eq!(
            server.negotiated_cipher_suite().unwrap().suite(),
            suite.suite()
        );
        assert_eq!(verifier.seen(), [S::RSA_PSS_PSS_SHA256]);
        round_trip(&mut client, &mut server);
    }
}

#[test]
fn restricted_pss_server_signs_only_with_its_hash() {
    init_logging();
    for hash in [Sha256, Sha384, Sha512] {
        let chain = server_with_key(restricted(hash));
        for v in VERSIONS {
            // Everything RSA offered: only the key's own scheme is usable.
            let mut offer = RSAE.to_vec();
            offer.extend(PSS_PSS);
            assert_eq!(
                server_signs(v, &chain, &offer).unwrap(),
                [pss_pss_scheme(hash)],
                "{v:?} {hash:?}"
            );
            // Only the other hashes offered: no signature can be made.
            let others: Vec<_> = PSS_PSS
                .into_iter()
                .filter(|s| *s != pss_pss_scheme(hash))
                .collect();
            let (client_res, server_res) = server_signs(v, &chain, &others).unwrap_err();
            assert_no_common_scheme(v, client_res, server_res);
        }
    }
}

#[test]
fn pss_key_refuses_rsae_and_pkcs1_schemes() {
    init_logging();
    // RFC 9846 §4.3.3: rsa_pss_rsae_* (and PKCS #1 v1.5) need an
    // rsaEncryption key; an RSASSA-PSS key only signs RSASSA-PSS (RFC 4055
    // §1.2).
    for algorithm in [UNRESTRICTED, restricted(Sha256)] {
        let chain = server_with_key(algorithm);
        for v in VERSIONS {
            let (client_res, server_res) = server_signs(v, &chain, &RSAE).unwrap_err();
            assert_no_common_scheme(v, client_res, server_res);
        }
    }
}

#[test]
fn rsae_key_refuses_pss_pss_schemes() {
    init_logging();
    let chain = server_with_key(RSAE_KEY);
    for v in VERSIONS {
        let (client_res, server_res) = server_signs(v, &chain, &PSS_PSS).unwrap_err();
        assert_no_common_scheme(v, client_res, server_res);
        // With the rsae schemes offered too, it uses those.
        let mut offer = PSS_PSS.to_vec();
        offer.push(S::RSA_PSS_SHA256);
        assert_eq!(
            server_signs(v, &chain, &offer).unwrap(),
            [S::RSA_PSS_SHA256]
        );
    }
}

#[test]
fn pss_client_auth_with_every_scheme() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    for (algorithm, schemes) in [
        (UNRESTRICTED, &PSS_PSS[..]),
        (restricted(Sha384), &[S::RSA_PSS_PSS_SHA384][..]),
    ] {
        let client_chain = client_with_key(algorithm);
        for v in VERSIONS {
            for scheme in schemes {
                let verifier = SchemeRecordingClientVerifier::new(
                    pinned_client_verifier(&client_chain),
                    &[*scheme],
                );
                let client_config = ClientConfig::builder_with_provider(provider())
                    .with_protocol_versions(versions(v))
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
                    .with_client_auth_cert(client_chain.chain.clone(), client_chain.private_key())
                    .unwrap();
                let server_config = ServerConfig::builder_with_provider(provider())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_client_cert_verifier(verifier.clone())
                    .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
                    .unwrap();
                let (mut client, mut server) = connect(client_config, server_config);
                do_handshake(&mut client, &mut server)
                    .unwrap_or_else(|e| panic!("{algorithm:?} {v:?} {scheme:?}: {e}"));
                assert_eq!(client.protocol_version(), Some(v));
                assert_eq!(verifier.seen(), [*scheme], "{algorithm:?} {v:?}");
                assert_eq!(
                    server.peer_certificates().unwrap(),
                    client_chain.chain.as_slice()
                );
                round_trip(&mut client, &mut server);
            }
        }
    }
}

#[test]
fn restricted_pss_client_cannot_answer_other_hashes() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_with_key(restricted(Sha256));
    for v in VERSIONS {
        let verifier = SchemeRecordingClientVerifier::new(
            pinned_client_verifier(&client_chain),
            &[
                S::RSA_PSS_PSS_SHA384,
                S::RSA_PSS_PSS_SHA512,
                S::RSA_PSS_SHA256,
            ],
        );
        let client_config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions(v))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
            .with_client_auth_cert(client_chain.chain.clone(), client_chain.private_key())
            .unwrap();
        let server_config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap();
        let (mut client, mut server) = connect(client_config, server_config);
        let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
        // The client sends no certificate; client authentication is
        // mandatory.
        assert_eq!(server_res, Err(Error::NoCertificatesPresented), "{v:?}");
        assert!(verifier.seen().is_empty());
    }
}
