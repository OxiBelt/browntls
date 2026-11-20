// Cases included by `cases/delegated_credentials.rs`, which holds the imports
// and the shared helpers: which key answers a request when the certificate
// key cannot sign, or a credential outlives its certificate.

/// A certificate key that is not available for handshake signatures, as
/// when it is kept offline and only issues credentials: it offers no
/// scheme.
#[derive(Debug)]
struct OfflineKey(Arc<dyn SigningKey>);

impl SigningKey for OfflineKey {
    fn choose_scheme(
        &self,
        _offered: &[SignatureScheme],
    ) -> Option<Box<dyn browntls_core::sign::Signer>> {
        None
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }

    fn algorithm(&self) -> browntls_core::SignatureAlgorithm {
        self.0.algorithm()
    }
}

/// RFC 9345 §1: the point of a credential is that the certificate key
/// need not be on the endpoint. A client whose certificate key cannot sign
/// still authenticates with a credential the request accepts, and sends no
/// certificate when the server does not ask for credentials.
#[test]
fn client_credential_answers_when_the_certificate_key_cannot_sign() {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let (dc, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let cert_key = provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    let ck = CertifiedKey::new(chain.cert_chain(), Arc::new(OfflineKey(cert_key)))
        .with_client_delegated_credential(dc.clone(), key)
        .unwrap();

    let verifier = recording_verifier(&chain);
    let (mut client, mut server) = connect(
        client_with(&server_chain, ck.clone()),
        dc_server(&server_chain, verifier.clone()),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.client_delegated_credential(), Some(&dc));
    assert_eq!(verifier.seen(), [dc.algorithm, SignatureScheme::ED25519]);
    assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);

    // No credential asked for: nothing can sign, so no certificate is
    // sent, which this verifier refuses (RFC 9846 §4.5.2).
    let mut config = dc_server(&server_chain, recording_verifier(&chain));
    config.enable_delegated_credentials = false;
    let (mut client, mut server) = connect(client_with(&server_chain, ck), config);
    let (_, server_result) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(server_result, Err(Error::NoCertificatesPresented));
}

/// RFC 9345 §4.1.3 check 2: a credential must expire before its
/// certificate does. One that does not would be refused by the peer, so
/// neither side sends it: the certificate key signs instead.
#[test]
fn credential_valid_beyond_its_certificate_is_not_sent() {
    let two_days = shifted(2 * 24 * 3600);
    let five_days = shifted(5 * 24 * 3600);

    // A client's credential.
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_chain_expiring(KeyType::EcdsaP256, true, two_days);
    let beyond = issue_for(Side::Client, &chain, SignatureScheme::ED25519, five_days);
    let verifier = recording_verifier(&chain);
    let (mut client, mut server) = connect(
        client_with(&server_chain, with_client_credentials(&chain, vec![beyond])),
        dc_server(&server_chain, verifier.clone()),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.client_delegated_credential().is_none());
    assert_eq!(verifier.seen(), [chain.key_type.schemes()[0]]);
    // One within the certificate's validity is sent.
    let (within, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(24 * 3600),
    );
    let (mut client, mut server) = connect(
        client_with(
            &server_chain,
            with_client_credentials(&chain, vec![(within.clone(), key)]),
        ),
        dc_server(&server_chain, recording_verifier(&chain)),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.client_delegated_credential(), Some(&within));

    // A server's credential.
    let chain = delegation_chain_expiring(KeyType::EcdsaP256, false, two_days);
    let (beyond, key) = issue(&chain, SignatureScheme::ED25519, five_days);
    let ck = certified_key(&chain)
        .with_delegated_credential(beyond, key)
        .unwrap();
    let (mut client, mut server) = connect(dc_client(&chain), server_with(ck));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.delegated_credential().is_none());
}
