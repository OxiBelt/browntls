//! Client authentication with an RSA key against a server with or without
//! the RFC 9963 opt-in: the PKCS #1-only key, an ordinary key, or a key
//! that names a fuzz-chosen RSA scheme over a signature of a fuzz-chosen
//! form, in TLS 1.3 or TLS 1.2, with either provider on each side.
//!
//! Checked against a model of RFC 9963 §3 and §4: a legacy scheme signs
//! only a TLS 1.3 client's `CertificateVerify`, only when the server's
//! request listed it, and only as RSASSA-PKCS1-v1_5 with the scheme's
//! hash. A client offered no scheme its key signs with, or whose key names
//! a legacy scheme the request did not list, sends no certificate; a
//! signature of another form or hash, or a tampered one, is a bad
//! signature; `rsa_pkcs1_*` in TLS 1.3 is refused as unadvertised. The
//! scheme the client signed under is recorded and compared with the
//! model's: the PKCS #1-only key takes the largest hash the request lists
//! a scheme for, and an ordinary key never takes a legacy scheme.

use std::sync::{Arc, Mutex, OnceLock};

use browntls_core::crypto::{CryptoProvider, native};
use browntls_core::pki_types::{ServerName, SubjectPublicKeyInfoDer};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use browntls_core::{
    CertificateError, ClientConfig, ClientConnection, Error, PeerMisbehaved, ProtocolVersion,
    ServerConfig, ServerConnection, SignatureAlgorithm, SignatureScheme, SupportedProtocolVersion,
    version,
};

use super::config::{pump, root_store};
use super::fixtures::{self, P256, RSA, RSA_PKCS1};
use super::provider;
use super::sign::{LEGACY_SCHEMES, key_schemes, legacy_algs, load, tls13_scheme};
use crate::input::Input;

/// The schemes a claiming key names. The last six are also the schemes an
/// ordinary RSA key makes its signature with.
const CLAIMS: [SignatureScheme; 9] = [
    SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
    SignatureScheme::RSA_PKCS1_SHA384_LEGACY,
    SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// The padding and hash of the signature one of [`CLAIMS`] stands for:
/// whether it is RSASSA-PSS, and the hash's `HashAlgorithm` code point
/// (the first byte of the `rsa_pkcs1_*` and legacy schemes, the second of
/// `rsa_pss_rsae_*`).
fn form(scheme: SignatureScheme) -> (bool, u8) {
    match u16::from(scheme).to_be_bytes() {
        [8, hash] => (true, hash),
        [hash, _] => (false, hash),
    }
}

/// An RSA key that names `claims` whatever it is offered, over a signature
/// its real key makes for `real`, with one bit flipped if `flip` says so.
#[derive(Debug)]
struct Claiming {
    key: Arc<dyn SigningKey>,
    claims: SignatureScheme,
    real: SignatureScheme,
    flip: Option<(u16, u8)>,
}

impl SigningKey for Claiming {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        Some(Box::new(ClaimingSigner {
            real: self.key.choose_scheme(&[self.real])?,
            claims: self.claims,
            flip: self.flip,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.key.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct ClaimingSigner {
    real: Box<dyn Signer>,
    claims: SignatureScheme,
    flip: Option<(u16, u8)>,
}

impl Signer for ClaimingSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signature = self.real.sign(message)?;
        if let Some((at, bit)) = self.flip {
            let at = usize::from(at) % signature.len();
            signature[at] ^= 1 << bit;
        }
        Ok(signature)
    }

    fn scheme(&self) -> SignatureScheme {
        self.claims
    }
}

/// A key that records the scheme of every signature its signers make: the
/// scheme of each `CertificateVerify` the client sent.
#[derive(Debug)]
struct Recording {
    key: Arc<dyn SigningKey>,
    signed: Arc<Mutex<Vec<SignatureScheme>>>,
}

impl SigningKey for Recording {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        Some(Box::new(RecordingSigner {
            signer: self.key.choose_scheme(offered)?,
            signed: self.signed.clone(),
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.key.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.key.algorithm()
    }
}

#[derive(Debug)]
struct RecordingSigner {
    signer: Box<dyn Signer>,
    signed: Arc<Mutex<Vec<SignatureScheme>>>,
}

impl Signer for RecordingSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.signed
            .lock()
            .expect("no panic while recording")
            .push(self.signer.scheme());
        self.signer.sign(message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.signer.scheme()
    }
}

/// RSA key `k` ([`RSA`] or [`RSA_PKCS1`]) as the PKCS #1-only loader and
/// as the default loader give it, loaded once: loading checks the key,
/// which costs more than a handshake.
fn keys(k: usize) -> [Arc<dyn SigningKey>; 2] {
    static KEYS: OnceLock<[[Arc<dyn SigningKey>; 2]; 2]> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        [RSA, RSA_PKCS1].map(|k| {
            let der = fixtures::get().keys[k].der();
            [
                native::sign::any_rsa_pkcs1_legacy_type(&der).expect("an rsaEncryption key"),
                load(0, k).expect("an RSA key"),
            ]
        })
    });
    keys[usize::from(k == RSA_PKCS1)].clone()
}

/// How a handshake of [`rsa_pkcs1_legacy_handshake_op`] ended, as the
/// model expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The sides offer no version in common.
    NoVersion,
    /// The server refused a scheme its request did not list.
    Unadvertised,
    /// The server refused the signature.
    BadSignature,
    /// The client sent no certificate to a server that requires one.
    NoCertificate,
    /// The client sent no certificate, and the handshake completed.
    Anonymous,
    /// The server authenticated the client under this scheme.
    Authenticated(SignatureScheme),
}

/// The `tls_config` operation: see [`handshake`].
pub(super) fn rsa_pkcs1_legacy_handshake_op(input: &mut Input<'_>) {
    handshake(input);
}

/// Input: the server's and the client's provider, whether the server opts
/// in and whether it requires a client certificate, the client's and the
/// server's versions, the RSA key, the kind of client key (the PKCS #1-only
/// key, the ordinary key, a claiming key), the scheme a claiming key names
/// and the one its signature is made for, and a bit to flip in it.
fn handshake(input: &mut Input<'_>) -> Outcome {
    const CLIENT_VERSIONS: [&[&SupportedProtocolVersion]; 3] = [
        &[&version::TLS13],
        &[&version::TLS13, &version::TLS12],
        &[&version::TLS12],
    ];
    const SERVER_VERSIONS: [&[&SupportedProtocolVersion]; 2] =
        [&[&version::TLS13], &[&version::TLS13, &version::TLS12]];
    let fx = fixtures::get();
    let ps = input.choose(2);
    let pc = input.choose(2);
    let opt_in = input.bool();
    let mandatory = input.bool();
    let cv = *input.pick(&CLIENT_VERSIONS);
    let sv = *input.pick(&SERVER_VERSIONS);
    let k = *input.pick(&[RSA, RSA_PKCS1]);
    let kind = input.choose(3);
    let claims = *input.pick(&CLAIMS);
    let real = *input.pick(&CLAIMS[3..]);
    let flip = input.bool().then(|| (input.u16(), input.choose(8) as u8));

    let [legacy, ordinary] = keys(k);
    let key: Arc<dyn SigningKey> = match kind {
        0 => legacy,
        1 => ordinary,
        _ => Arc::new(Claiming {
            key: ordinary,
            claims,
            real,
            flip,
        }),
    };
    let signed = Arc::new(Mutex::new(Vec::new()));
    let key = Arc::new(Recording {
        key,
        signed: signed.clone(),
    });

    let server_provider = if opt_in {
        Arc::new(CryptoProvider {
            signature_verification_algorithms: legacy_algs(ps),
            ..(*provider(ps)).clone()
        })
    } else {
        provider(ps)
    };
    let verifier =
        WebPkiClientVerifier::builder_with_provider(root_store(), server_provider.clone());
    let verifier = if mandatory {
        verifier.build()
    } else {
        verifier.allow_unauthenticated().build()
    }
    .expect("verifier");
    // The opt-in table, and it alone, makes a verifier list the schemes.
    let listed = verifier.supported_verify_schemes();
    for scheme in LEGACY_SCHEMES {
        assert_eq!(listed.contains(&scheme), opt_in, "{scheme:?}");
    }
    let server_config = ServerConfig::builder_with_provider(server_provider)
        .with_protocol_versions(sv)
        .expect("default provider supports every version")
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(CertifiedKey::new(
            fx.keys[P256].chain.clone(),
            load(ps, P256).expect("P-256 loads everywhere"),
        ))));
    let client_config = ClientConfig::builder_with_provider(provider(pc))
        .with_protocol_versions(cv)
        .expect("default provider supports every version")
        .with_root_certificates(root_store())
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(CertifiedKey::new(
            fx.keys[k].chain.clone(),
            key,
        ))));

    // The model. Every server here offers TLS 1.3, which is negotiated
    // when the client offers it too.
    let tls13 = cv.contains(&&version::TLS13);
    let version_in_common = tls13 || sv.contains(&&version::TLS12);
    // What the CertificateRequest lists: in TLS 1.3 the TLS 1.3 schemes
    // and the legacy ones, in TLS 1.2 everything but the legacy ones.
    let offered: Vec<SignatureScheme> = listed
        .iter()
        .copied()
        .filter(|scheme| {
            let legacy = LEGACY_SCHEMES.contains(scheme);
            if tls13 {
                legacy || tls13_scheme(*scheme)
            } else {
                !legacy
            }
        })
        .collect();
    let first = |schemes: &[SignatureScheme]| {
        schemes
            .iter()
            .copied()
            .find(|scheme| offered.contains(scheme))
            .map(|scheme| (scheme, scheme, false))
    };
    // The scheme the client names, the one its signature is made for, and
    // whether the signature is tampered; none when it sends no
    // certificate.
    let signs = match kind {
        0 => first(&[&key_schemes(k)[3..], &LEGACY_SCHEMES[..]].concat()),
        1 => first(key_schemes(k)),
        // A key naming a legacy scheme that was not listed is taken as
        // one that cannot sign.
        _ if LEGACY_SCHEMES.contains(&claims) && !offered.contains(&claims) => None,
        _ => Some((claims, real, flip.is_some())),
    };

    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(Arc::new(client_config), name).expect("client");
    let mut server = ServerConnection::new(Arc::new(server_config)).expect("server");
    let result = pump(&mut client, &mut server);
    let ctx = format!(
        "server {ps} opt-in {opt_in} mandatory {mandatory} {sv:?}, client {pc} {cv:?}, key \
         {} kind {kind} {claims:?}/{real:?}/{flip:?}: {result:?}",
        fx.keys[k].name
    );
    // The client signed once, under the scheme the model names, or not at
    // all.
    let signed = signed.lock().expect("no panic while recording").clone();
    let named = signs
        .filter(|_| version_in_common)
        .map(|(named, _, _)| named);
    assert_eq!(signed, Vec::from_iter(named), "{ctx}");
    if !version_in_common {
        assert!(result.is_err(), "{ctx}");
        return Outcome::NoVersion;
    }
    let authenticated = match signs {
        None => None,
        Some((named, _, _)) if !offered.contains(&named) => {
            assert_eq!(
                result,
                Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into()),
                "{ctx}"
            );
            return Outcome::Unadvertised;
        }
        Some((named, made, tampered)) if form(named) != form(made) || tampered => {
            assert_eq!(
                result,
                Err(Error::InvalidCertificate(CertificateError::BadSignature)),
                "{ctx}"
            );
            return Outcome::BadSignature;
        }
        Some((named, _, _)) => Some(named),
    };
    if authenticated.is_none() && mandatory {
        assert_eq!(result, Err(Error::NoCertificatesPresented), "{ctx}");
        return Outcome::NoCertificate;
    }
    assert_eq!(result, Ok(()), "{ctx}");
    assert!(
        !client.is_handshaking() && !server.is_handshaking(),
        "{ctx}"
    );
    let version = if tls13 {
        ProtocolVersion::TLSv1_3
    } else {
        ProtocolVersion::TLSv1_2
    };
    assert_eq!(server.protocol_version(), Some(version), "{ctx}");
    assert_eq!(
        server.peer_certificates(),
        authenticated.map(|_| &fx.keys[k].chain[..]),
        "{ctx}"
    );
    authenticated.map_or(Outcome::Anonymous, Outcome::Authenticated)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds reach every outcome of the model, each legacy scheme and
    /// the schemes the other keys keep to.
    #[test]
    fn seeds_reach_every_outcome() {
        crate::init();
        let outcomes: Vec<Outcome> = super::super::seeds()
            .iter()
            .filter(|seed| seed[0] == super::super::op::RSA_PKCS1_LEGACY_HANDSHAKE)
            .map(|seed| handshake(&mut Input::new(&seed[1..])))
            .collect();
        for expected in [
            Outcome::NoVersion,
            Outcome::Unadvertised,
            Outcome::BadSignature,
            Outcome::NoCertificate,
            Outcome::Anonymous,
            Outcome::Authenticated(SignatureScheme::RSA_PKCS1_SHA256_LEGACY),
            Outcome::Authenticated(SignatureScheme::RSA_PKCS1_SHA384_LEGACY),
            Outcome::Authenticated(SignatureScheme::RSA_PKCS1_SHA512_LEGACY),
            Outcome::Authenticated(SignatureScheme::RSA_PSS_SHA512),
            Outcome::Authenticated(SignatureScheme::RSA_PSS_SHA256),
            Outcome::Authenticated(SignatureScheme::RSA_PKCS1_SHA512),
            Outcome::Authenticated(SignatureScheme::RSA_PKCS1_SHA256),
        ] {
            assert!(outcomes.contains(&expected), "{expected:?} in {outcomes:?}");
        }
        let count = |outcome| outcomes.iter().filter(|o| **o == outcome).count();
        assert_eq!(count(Outcome::BadSignature), 6, "{outcomes:?}");
    }
}
