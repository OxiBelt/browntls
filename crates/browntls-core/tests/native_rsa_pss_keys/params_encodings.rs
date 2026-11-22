//! Equivalent and rejected encodings of `RSASSA-PSS-params` in keys, key
//! files and certificate signatures.

use super::*;

// ---------------------------------------------------------------------------
// Equivalent and rejected encodings of RSASSA-PSS-params

/// A self-signed root with `root`'s key, and an end entity with `ee`'s key
/// whose certificate signature identifier is written as `sig_alg`.
fn direct_chain(root: &TestKey, ee: &TestKey, role: Role, sig_alg: PssParams) -> PssChain {
    // A trust anchor's own signature is not validated; it uses the root
    // key's hash, if restricted.
    let root_hash = match root.algorithm {
        RsaKeyAlgorithm::RsassaPss(Some(hash)) => hash,
        _ => sig_alg.hash,
    };
    let root_cert = issue("PSS root", root, Role::Ca, "PSS root", root, root_hash);
    PssChain {
        root: root_cert,
        chain: vec![issue_with(
            "end entity",
            ee,
            role,
            "PSS root",
            root,
            sig_alg,
        )],
        key: ee.clone(),
    }
}

/// Runs a handshake with web-PKI verifiers on both sides where the client
/// offers `offer`, and returns the schemes of the server signatures the
/// client checked.
fn webpki_server_signs(
    v: ProtocolVersion,
    server: &PssChain,
    client: &PssChain,
    offer: &[SignatureScheme],
) -> Result<Vec<SignatureScheme>, Failure> {
    let (_, server_config) = webpki_configs(v, server, client);
    let webpki = WebPkiServerVerifier::builder_with_provider(server.roots(), provider())
        .build()
        .unwrap();
    let verifier = SchemeRecordingServerVerifier::new(webpki, offer);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(v))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_client_auth_cert(client.chain.clone(), client.private_key())
        .unwrap();
    let (mut client_conn, mut server_conn) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client_conn, &mut server_conn);
    if client_res.is_err() || server_res.is_err() {
        return Err((client_res, server_res));
    }
    do_handshake(&mut client_conn, &mut server_conn).unwrap();
    assert_eq!(
        server_conn.peer_certificates().unwrap(),
        client.chain.as_slice()
    );
    round_trip(&mut client_conn, &mut server_conn);
    Ok(verifier.seen())
}

#[test]
fn equivalent_key_encodings_sign_only_their_scheme() {
    init_logging();
    // Keys restricted to one hash, identified in every accepted way in
    // their key files and certificates, sign and verify exactly as the
    // canonical form does: only `rsa_pss_pss_<hash>`, with a salt of the
    // digest length, which meets any minimum up to that length (RFC 4055
    // §3.3, RFC 9846 §4.3.3).
    let mut all = RSAE.to_vec();
    all.extend(PSS_PSS);
    for hash in [Sha256, Sha384, Sha512] {
        let own = pss_pss_scheme(hash);
        let others: Vec<_> = PSS_PSS.into_iter().filter(|s| *s != own).collect();
        for form in equivalent_key_forms(hash) {
            let server_key = TestKey::server(UNRESTRICTED).encoded(form);
            let client_key = TestKey::client(UNRESTRICTED).encoded(form);
            let root = TestKey::root(RSAE_KEY);
            let server = direct_chain(
                &root,
                &server_key,
                Role::Server,
                PssParams::canonical(Sha256),
            );
            let client = direct_chain(
                &root,
                &client_key,
                Role::Client,
                PssParams::canonical(Sha256),
            );
            // The loaded key keeps the identifier of its key file.
            let loaded = prov::KEY_PROVIDER
                .load_private_key(server_key.private_key())
                .unwrap();
            assert_eq!(
                loaded.public_key().unwrap().as_ref(),
                server.spki().as_ref()
            );
            for v in VERSIONS {
                // Pinned key (the raw-key verification path).
                assert_eq!(
                    server_signs(v, &server, &all).unwrap(),
                    [own],
                    "{form:?} {v:?}"
                );
                let (client_res, server_res) = server_signs(v, &server, &others).unwrap_err();
                assert_no_common_scheme(v, client_res, server_res);
                // Certificate paths and the certificate verification path,
                // with the client authenticating with the same form.
                assert_eq!(
                    webpki_server_signs(v, &server, &client, &all).unwrap(),
                    [own],
                    "{form:?} {v:?}"
                );
            }
        }
    }
}

#[test]
fn equivalent_identifiers_in_certificate_chains_validate() {
    init_logging();
    // CA keys and certificate signature identifiers in equivalent forms:
    // absent hash parameters and an explicit trailer field 1 in the
    // signature identifiers (whose salt stays the digest length), and CA
    // keys with short minimum salts.
    let sha256 = PssParams::canonical(Sha256);
    let sha384 = PssParams::canonical(Sha384);
    let root_forms = [
        sha256.salt(Salt::Omitted),
        sha256.salt(Salt::Explicit(0)).absent_hash_params(),
        sha256.trailer(1),
    ];
    let sig_forms = [
        sha256,
        sha256.absent_hash_params(),
        sha256.trailer(1),
        sha256.absent_hash_params().trailer(1),
    ];
    for root_form in root_forms {
        for sig_form in sig_forms {
            let root = TestKey::root(RSAE_KEY).encoded(root_form);
            let ica = TestKey::intermediate(RSAE_KEY).encoded(sha384.salt(Salt::Omitted));
            let ica_cert = issue_with("PSS CA", &ica, Role::Ca, "PSS root", &root, sig_form);
            let root_cert = issue("PSS root", &root, Role::Ca, "PSS root", &root, Sha256);
            let chain = |key: TestKey, role| PssChain {
                root: root_cert.clone(),
                chain: vec![
                    issue_with(
                        "end entity",
                        &key,
                        role,
                        "PSS CA",
                        &ica,
                        sha384.absent_hash_params().trailer(1),
                    ),
                    ica_cert.clone(),
                ],
                key,
            };
            let server = chain(TestKey::server(UNRESTRICTED), Role::Server);
            let client = chain(TestKey::client(restricted(Sha512)), Role::Client);
            for v in VERSIONS {
                let (client_config, server_config) = webpki_configs(v, &server, &client);
                let (mut client_conn, mut server_conn) = connect(client_config, server_config);
                do_handshake(&mut client_conn, &mut server_conn)
                    .unwrap_or_else(|e| panic!("{root_form:?} {sig_form:?} {v:?}: {e}"));
                assert_eq!(
                    client_conn.peer_certificates().unwrap(),
                    server.chain.as_slice()
                );
                round_trip(&mut client_conn, &mut server_conn);
            }
        }
    }
}

#[test]
fn certificate_signature_identifiers_can_use_distinct_der_encodings() {
    let root = TestKey::root(RSAE_KEY);
    let key = TestKey::server(UNRESTRICTED);
    let pss = PssParams::canonical(Sha256);
    let mut server = direct_chain(&root, &key, Role::Server, pss);
    server.chain[0] = issue_with_identifiers(
        "end entity",
        &key,
        Role::Server,
        "PSS root",
        &root,
        (pss.absent_hash_params(), pss),
    );
    for v in VERSIONS {
        webpki_client_result(v, &server).unwrap();
    }
}

/// The client's result of a handshake against `server`, validated with
/// web-PKI verifiers.
fn webpki_client_result(v: ProtocolVersion, server: &PssChain) -> Result<(), Error> {
    let client = ChainSpec::direct(RSAE_KEY, Sha256, RSAE_KEY).build(Role::Client);
    let (client_config, server_config) = webpki_configs(v, server, &client);
    let (mut client_conn, mut server_conn) = connect(client_config, server_config);
    do_handshake_until_error(&mut client_conn, &mut server_conn).0
}

#[test]
fn certificate_signatures_need_a_digest_length_salt_and_the_key_hash() {
    init_logging();
    let unsupported = Err(Error::InvalidCertificate(
        CertificateError::UnsupportedSignatureAlgorithm,
    ));
    let sha256 = PssParams::canonical(Sha256);
    let server_key = TestKey::server(UNRESTRICTED);
    for (root_form, sig_alg, ok) in [
        // A key with a minimum salt of 20 or 0 bytes verifies signatures
        // with a salt of 32 bytes (RFC 4055 §3.3)...
        (sha256.salt(Salt::Omitted), sha256, true),
        (sha256.salt(Salt::Explicit(0)), sha256, true),
        // ...but signature identifiers stating another salt describe no
        // TLS scheme (RFC 9846 §4.3.3) and match no algorithm, whatever
        // the key allows; the signatures here use 32 bytes anyway.
        (
            sha256.salt(Salt::Omitted),
            sha256.salt(Salt::Omitted),
            false,
        ),
        (
            sha256.salt(Salt::Explicit(0)),
            sha256.salt(Salt::Explicit(0)),
            false,
        ),
        (sha256, sha256.salt(Salt::Explicit(31)), false),
        (sha256, sha256.salt(Salt::Explicit(33)), false),
        // A trailer field other than 1.
        (sha256, sha256.trailer(2), false),
        // A key with a short minimum salt is still restricted to its hash.
        (
            sha256.salt(Salt::Omitted).absent_hash_params(),
            PssParams::canonical(Sha384),
            false,
        ),
        (
            PssParams::canonical(Sha512).salt(Salt::Explicit(0)),
            PssParams::canonical(Sha512).absent_hash_params(),
            true,
        ),
    ] {
        let root = TestKey::root(RSAE_KEY).encoded(root_form);
        let server = direct_chain(&root, &server_key, Role::Server, sig_alg);
        let expected = if ok { Ok(()) } else { unsupported.clone() };
        for v in VERSIONS {
            assert_eq!(
                webpki_client_result(v, &server),
                expected,
                "{root_form:?} {sig_alg:?} {v:?}"
            );
        }
    }
}

#[test]
fn unsupported_and_non_der_key_parameters_stay_rejected() {
    init_logging();
    let sha256 = PssParams::canonical(Sha256);
    // (identifier, whether it is well formed but unsupported).
    let rejected = [
        (sha256.salt(Salt::Explicit(33)), true),
        (PssParams::canonical(Sha384).salt(Salt::Explicit(49)), true),
        (sha256.trailer(2), true),
        (sha256.trailer(0), true),
        // An explicit DEFAULT salt length is not DER (X.690 §11.5).
        (sha256.salt(Salt::Explicit(20)), false),
    ];
    let unsupported = Err(Error::InvalidCertificate(
        CertificateError::UnsupportedSignatureAlgorithm,
    ));
    for (form, well_formed) in rejected {
        // As a CA key: the chain does not validate.
        let root = TestKey::root(RSAE_KEY).encoded(form);
        let server = direct_chain(&root, &TestKey::server(UNRESTRICTED), Role::Server, sha256);
        for v in VERSIONS {
            assert_eq!(
                webpki_client_result(v, &server),
                unsupported,
                "{form:?} {v:?}"
            );
        }
        // As a key file: loading fails, saying why when the parameters are
        // merely unsupported.
        let err = prov::KEY_PROVIDER
            .load_private_key(TestKey::server(UNRESTRICTED).encoded(form).private_key())
            .unwrap_err()
            .to_string();
        assert_eq!(
            err.contains("unsupported RSASSA-PSS key parameters"),
            well_formed,
            "{form:?}: {err}"
        );
        // As a raw public key: no scheme verifies with it.
        let key = TestKey::server(UNRESTRICTED).encoded(form);
        let mut sig = vec![0u8; 256];
        key.key.sign_pss(Sha256, b"msg", &OsRng, &mut sig).unwrap();
        for scheme in PSS_PSS {
            assert_eq!(
                verify_raw(&key.spki(), scheme, b"msg", &sig),
                Err(CertificateError::UnsupportedSignatureAlgorithm.into()),
                "{form:?} {scheme:?}"
            );
        }
    }
    // OpenSSL's `rsa_pss_keygen_md:sha256` alone (MGF1 with SHA-1 by
    // default) is unsupported too.
    let mgf1_sha1 = TestKey {
        encoding: Some(
            hex::decode("06092a864886f70d01010a3011a00f300d06096086480165030402010500").unwrap(),
        ),
        ..TestKey::server(UNRESTRICTED)
    };
    let err = prov::KEY_PROVIDER
        .load_private_key(mgf1_sha1.private_key())
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("unsupported RSASSA-PSS key parameters"),
        "{err}"
    );
}

#[test]
fn key_file_and_certificate_must_encode_the_key_alike() {
    init_logging();
    // The loaded key's SPKI is its key file's, byte for byte, and the
    // certificate/key consistency check compares bytes: equivalent but
    // differently written identifiers are reported as a mismatch.
    let canonical = TestKey::server(restricted(Sha256));
    let omitted = canonical
        .clone()
        .encoded(PssParams::canonical(Sha256).salt(Salt::Omitted));
    let root = TestKey::root(RSAE_KEY);
    for (cert_key, file_key, ok) in [
        (&omitted, &omitted, true),
        (&canonical, &canonical, true),
        (&omitted, &canonical, false),
        (&canonical, &omitted, false),
    ] {
        let chain = direct_chain(&root, cert_key, Role::Server, PssParams::canonical(Sha256));
        let result = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.chain.clone(), file_key.private_key())
            .map(|_| ());
        if ok {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err(),
                Error::InconsistentKeys(browntls_core::InconsistentKeys::KeyMismatch)
            );
        }
    }
}

#[test]
fn scheme_table_canonicalises_equivalent_key_encodings() {
    // The raw-key path: each accepted form of a key restricted to one hash
    // verifies that hash's `rsa_pss_pss_*` scheme only.
    let mut sig = vec![0u8; 256];
    for hash in [Sha256, Sha384, Sha512] {
        for form in equivalent_key_forms(hash) {
            let key = TestKey::server(UNRESTRICTED).encoded(form);
            for scheme in RSAE[..3].iter().chain(&PSS_PSS) {
                key.key
                    .sign_pss(scheme_hash(*scheme), b"msg", &OsRng, &mut sig)
                    .unwrap();
                let res = verify_raw(&key.spki(), *scheme, b"msg", &sig);
                if *scheme == pss_pss_scheme(hash) {
                    res.unwrap();
                    assert_eq!(
                        verify_raw(&key.spki(), *scheme, b"msh", &sig),
                        Err(CertificateError::BadSignature.into())
                    );
                } else {
                    assert_eq!(
                        res,
                        Err(CertificateError::UnsupportedSignatureAlgorithm.into()),
                        "{form:?} {scheme:?}"
                    );
                }
            }
        }
    }
}
