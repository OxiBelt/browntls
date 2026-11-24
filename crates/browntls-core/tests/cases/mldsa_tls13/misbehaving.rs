// Cases included by `cases/mldsa_tls13.rs`, which holds the imports and the
// shared helpers: peers whose `CertificateVerify` does not match their
// certificate, the offered schemes or the draft's signing rules.

/// How a misbehaving signer signs.
#[derive(Debug)]
enum SignWith {
    /// Hedged pure ML-DSA with the empty context.
    Hedged(Arc<MlKey>),
    /// Deterministic pure ML-DSA with the empty context.
    Deterministic(Arc<MlKey>),
    /// Hedged pure ML-DSA with this FIPS 204 context string.
    Context(Arc<MlKey>, &'static [u8]),
    /// A provider-loaded key with its own scheme.
    Key(Arc<dyn SigningKey>, SignatureScheme),
}

/// What happens to the signature afterwards.
#[derive(Clone, Copy, Debug)]
enum Damage {
    None,
    FlipBit,
    Truncate,
    Extend,
}

/// A key that signs with `with`, claims `claims` whatever the peer
/// offered, and damages the signature as `damage` says.
#[derive(Debug)]
struct Misbehaving {
    claims: SignatureScheme,
    with: Arc<SignWith>,
    damage: Damage,
}

impl Misbehaving {
    fn new(claims: SignatureScheme, with: SignWith, damage: Damage) -> Arc<Self> {
        Arc::new(Self {
            claims,
            with: Arc::new(with),
            damage,
        })
    }
}

impl SigningKey for Misbehaving {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        Some(Box::new(MisbehavingSigner {
            claims: self.claims,
            with: self.with.clone(),
            damage: self.damage,
        }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(0xff)
    }
}

#[derive(Debug)]
struct MisbehavingSigner {
    claims: SignatureScheme,
    with: Arc<SignWith>,
    damage: Damage,
}

impl Signer for MisbehavingSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signature = match &*self.with {
            SignWith::Hedged(key) => key.sign_hedged(message),
            SignWith::Deterministic(key) => key.sign(Impl::Native, message),
            SignWith::Context(key, ctx) => key.sign_with_context(message, ctx),
            SignWith::Key(key, scheme) => key.choose_scheme(&[*scheme]).unwrap().sign(message)?,
        };
        match self.damage {
            Damage::None => {}
            Damage::FlipBit => signature[17] ^= 0x10,
            Damage::Truncate => {
                signature.pop();
            }
            Damage::Extend => signature.push(0),
        }
        Ok(signature)
    }

    fn scheme(&self) -> SignatureScheme {
        self.claims
    }
}

fn ml(id: &Identity) -> Arc<MlKey> {
    id.ml.clone().unwrap()
}

/// The outcome of a handshake whose server presents `server`'s chain and
/// signs with `key`, against an opt-in client offering `offer` (its
/// verifier's schemes when `None`): both results and the schemes the
/// client's verifier was asked to check.
fn server_signs_with(
    server: &Identity,
    key: Arc<Misbehaving>,
    offer: Option<&[SignatureScheme]>,
) -> (Result<(), Error>, Result<(), Error>, Vec<SignatureScheme>) {
    let verifier = match offer {
        Some(offer) => server_verifier_offering(prov::provider_with_ml_dsa(), server, offer),
        None => server_verifier(prov::provider_with_ml_dsa(), server),
    };
    let server_config = ServerConfig::builder_with_provider(arc(prov::provider_with_ml_dsa()))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_certified_key(CertifiedKey::new(server.chain.clone(), key));
    let (mut c, mut s) = connect(
        client_config(prov::provider_with_ml_dsa(), verifier.clone(), None),
        server_config,
    );
    let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
    (client_res, server_res, verifier.seen())
}

/// As [`server_signs_with`], for a client presenting `client`'s chain and
/// signing with `key` to a server with mandatory client authentication.
fn client_signs_with(
    client: &Identity,
    key: Arc<Misbehaving>,
) -> (Result<(), Error>, Result<(), Error>, Vec<SignatureScheme>) {
    let server = server_id(Alg::P256);
    let verifier = client_verifier(prov::provider_with_ml_dsa(), client, true);
    let client_config = ClientConfig::builder_with_provider(arc(prov::provider_with_ml_dsa()))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(prov::provider_with_ml_dsa(), &server))
        .with_client_auth_certified_key(CertifiedKey::new(client.chain.clone(), key));
    let (mut c, mut s) = connect(
        client_config,
        server_config(
            prov::provider_with_ml_dsa(),
            &server,
            Some(verifier.clone()),
        ),
    );
    let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
    (client_res, server_res, verifier.seen())
}

const BAD_SIGNATURE: Error = Error::InvalidCertificate(CertificateError::BadSignature);
const UNSUPPORTED: Error =
    Error::InvalidCertificate(CertificateError::UnsupportedSignatureAlgorithm);

/// A `CertificateVerify` that names a scheme whose key type is not the
/// certificate's: another ML-DSA parameter set (both ways), a classical
/// scheme for an ML-DSA certificate, and an ML-DSA scheme for a classical
/// one. Each signature is valid under the scheme it names, made by another
/// key of that type. The verifier refuses the scheme for the certificate's
/// key, and the client sends `decrypt_error`.
#[test]
fn certificate_verify_scheme_must_match_the_certificate_key() {
    let ml44 = server_id(Alg::Ml(Set::MlDsa44));
    let ml65 = server_id(Alg::Ml(Set::MlDsa65));
    let p256 = server_id(Alg::P256);
    let other_p256 = server_id(Alg::P256).signing_key(&prov::provider_with_ml_dsa());
    let cases = [
        (
            "44 under a 65 certificate",
            &ml65,
            SignatureScheme::ML_DSA_44,
            SignWith::Hedged(ml(&ml44)),
        ),
        (
            "65 under a 44 certificate",
            &ml44,
            SignatureScheme::ML_DSA_65,
            SignWith::Hedged(ml(&ml65)),
        ),
        (
            "ECDSA under an ML-DSA certificate",
            &ml65,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignWith::Key(other_p256, SignatureScheme::ECDSA_NISTP256_SHA256),
        ),
        (
            "ML-DSA under an ECDSA certificate",
            &p256,
            SignatureScheme::ML_DSA_65,
            SignWith::Hedged(ml(&ml65)),
        ),
    ];
    for (what, cert, claims, with) in cases {
        let (client_res, server_res, seen) =
            server_signs_with(cert, Misbehaving::new(claims, with, Damage::None), None);
        assert_eq!(client_res, Err(UNSUPPORTED), "{what}");
        assert_eq!(
            server_res,
            Err(Error::AlertReceived(AlertDescription::DecryptError)),
            "{what}"
        );
        assert_eq!(seen, [claims], "{what}");
    }
}

/// An ML-DSA scheme the client did not offer is refused before the
/// signature is checked, with `illegal_parameter` (RFC 9846 §4.5.2).
#[test]
fn certificate_verify_with_an_unoffered_ml_dsa_scheme() {
    let server = server_id(Alg::Ml(Set::MlDsa44));
    let mut offer = prov::provider()
        .signature_verification_algorithms
        .supported_schemes();
    offer.extend([SignatureScheme::ML_DSA_65, SignatureScheme::ML_DSA_87]);
    let key = Misbehaving::new(
        SignatureScheme::ML_DSA_44,
        SignWith::Hedged(ml(&server)),
        Damage::None,
    );
    let (client_res, server_res, seen) = server_signs_with(&server, key, Some(&offer));
    assert_eq!(
        client_res,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme
        ))
    );
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
    assert!(seen.is_empty());
}

/// Signatures under the right scheme and key that are not what the draft
/// specifies: one bit flipped, one byte short or long (each ML-DSA
/// signature has a fixed length), and a signature with a non-empty FIPS 204
/// context string (§3.2: the context is empty) are refused with
/// `decrypt_error`, from the server and from the client. A deterministic
/// signature with the empty context is a valid pure ML-DSA signature and
/// is accepted (the verifier cannot tell it from a hedged one).
#[test]
fn damaged_and_non_conforming_signatures() {
    for set in ml_dsa::SETS {
        let server = server_id(Alg::Ml(set));
        let client = client_id(Alg::Ml(set));
        let scheme = scheme_of(set);
        let bad = [
            ("bit flipped", Damage::FlipBit, false),
            ("truncated", Damage::Truncate, false),
            ("extended", Damage::Extend, false),
            ("context \"x\"", Damage::None, true),
        ];
        for (what, damage, context) in bad {
            let with = |id: &Identity| match context {
                true => SignWith::Context(ml(id), b"x"),
                false => SignWith::Hedged(ml(id)),
            };
            let (client_res, server_res, seen) = server_signs_with(
                &server,
                Misbehaving::new(scheme, with(&server), damage),
                None,
            );
            assert_eq!(client_res, Err(BAD_SIGNATURE), "server {set:?} {what}");
            assert_eq!(
                server_res,
                Err(Error::AlertReceived(AlertDescription::DecryptError)),
                "server {set:?} {what}"
            );
            assert_eq!(seen, [scheme]);

            let (client_res, server_res, seen) =
                client_signs_with(&client, Misbehaving::new(scheme, with(&client), damage));
            assert_eq!(server_res, Err(BAD_SIGNATURE), "client {set:?} {what}");
            assert_eq!(
                client_res,
                Err(Error::AlertReceived(AlertDescription::DecryptError)),
                "client {set:?} {what}"
            );
            assert_eq!(seen, [scheme]);
        }

        let key = Misbehaving::new(scheme, SignWith::Deterministic(ml(&server)), Damage::None);
        let (client_res, server_res, seen) = server_signs_with(&server, key, None);
        assert_eq!((client_res, server_res), (Ok(()), Ok(())), "{set:?}");
        assert_eq!(seen, [scheme]);
        let key = Misbehaving::new(scheme, SignWith::Deterministic(ml(&client)), Damage::None);
        let (client_res, server_res, seen) = client_signs_with(&client, key);
        assert_eq!((client_res, server_res), (Ok(()), Ok(())), "{set:?}");
        assert_eq!(seen, [scheme]);
    }
}
