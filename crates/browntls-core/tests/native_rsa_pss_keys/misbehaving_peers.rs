//! Peers that sign with a scheme their key's algorithm does not allow.

use super::*;

// ---------------------------------------------------------------------------
// Peers that sign with schemes their key does not allow

/// A signing key that signs RSASSA-PSS with any hash and offers every RSA
/// scheme, whatever its certificate's key algorithm says.
#[derive(Debug)]
struct UnrestrictedSigner {
    key: Arc<RsaPrivateKey>,
    schemes: Vec<SignatureScheme>,
}

#[derive(Debug)]
struct UnrestrictedPss {
    key: Arc<RsaPrivateKey>,
    scheme: SignatureScheme,
}

impl SigningKey for UnrestrictedSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = *self.schemes.iter().find(|s| offered.contains(s))?;
        Some(Box::new(UnrestrictedPss {
            key: self.key.clone(),
            scheme,
        }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Signer for UnrestrictedPss {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0u8; self.key.modulus_len_bytes()];
        self.key
            .sign_pss(scheme_hash(self.scheme), message, &OsRng, &mut sig)
            .map_err(|_| Error::General("signing failed".into()))?;
        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl browntls_core::server::ResolvesServerCert for FixedCert {
    fn resolve(&self, _: browntls_core::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl browntls_core::client::ResolvesClientCert for FixedCert {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// `chain`'s certificates with a signer that uses `scheme` regardless.
fn misbehaving(chain: &PssChain, scheme: SignatureScheme) -> Arc<FixedCert> {
    Arc::new(FixedCert(Arc::new(CertifiedKey::new(
        chain.chain.clone(),
        Arc::new(UnrestrictedSigner {
            key: chain.key.key.clone(),
            schemes: vec![scheme],
        }),
    ))))
}

/// (key algorithm, scheme it must not sign with).
const MISUSES: [(RsaKeyAlgorithm, SignatureScheme); 4] = [
    (UNRESTRICTED, S::RSA_PSS_SHA256),
    (restricted(Sha256), S::RSA_PSS_PSS_SHA384),
    (restricted(Sha512), S::RSA_PSS_SHA512),
    (RSAE_KEY, S::RSA_PSS_PSS_SHA256),
];

#[test]
fn client_rejects_a_server_signing_outside_its_key_algorithm() {
    init_logging();
    for (algorithm, scheme) in MISUSES {
        let chain = ChainSpec::direct(UNRESTRICTED, Sha256, algorithm).build(Role::Server);
        for v in VERSIONS {
            let verifier = WebPkiServerVerifier::builder_with_provider(chain.roots(), provider())
                .build()
                .unwrap();
            let client_config = ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(versions(v))
                .unwrap()
                .with_webpki_verifier(verifier)
                .with_no_client_auth();
            let server_config = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(misbehaving(&chain, scheme));
            let (mut client, mut server) = connect(client_config, server_config);
            let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                client_res,
                Err(Error::InvalidCertificate(
                    CertificateError::UnsupportedSignatureAlgorithm
                )),
                "{algorithm:?} {scheme:?} {v:?}"
            );
        }
    }
}

#[test]
fn server_rejects_a_client_signing_outside_its_key_algorithm() {
    init_logging();
    let server_chain = server_with_key(RSAE_KEY);
    for (algorithm, scheme) in MISUSES {
        let client_chain = ChainSpec::direct(UNRESTRICTED, Sha256, algorithm).build(Role::Client);
        for v in VERSIONS {
            let client_verifier =
                WebPkiClientVerifier::builder_with_provider(client_chain.roots(), provider())
                    .build()
                    .unwrap();
            let client_config = ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(versions(v))
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(pinned_server_verifier(&server_chain))
                .with_client_cert_resolver(misbehaving(&client_chain, scheme));
            let server_config = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(server_chain.chain.clone(), server_chain.private_key())
                .unwrap();
            let (mut client, mut server) = connect(client_config, server_config);
            let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                server_res,
                Err(Error::InvalidCertificate(
                    CertificateError::UnsupportedSignatureAlgorithm
                )),
                "{algorithm:?} {scheme:?} {v:?}"
            );
        }
    }
}
