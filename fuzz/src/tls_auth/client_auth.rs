//! The client-authentication operation of the `tls_auth` target: a TLS 1.3
//! client that authenticates with a delegated credential (RFC 9345
//! §4.1.2), in the handshake or after it, to a buffered or unbuffered
//! server, with the credential's validity, the peers' clocks, the server's
//! opt-in and schemes, and the way the credential is issued and attached
//! fuzz-chosen.

use std::sync::Arc;

use browntls_core::client::UnbufferedClientConnection;
use browntls_core::client::danger::HandshakeSignatureValid;
use browntls_core::delegated_credential::{
    Credential, DelegatedCredential, DelegatedCredentialKey, MAX_VALIDITY,
};
use browntls_core::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use browntls_core::server::danger::{ClientCertVerified, ClientCertVerifier};
use browntls_core::server::{
    PostHandshakeAuthStatus, UnbufferedServerConnection, WebPkiClientVerifier,
};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{
    ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, Error, HandshakeKind,
    ServerConfig, ServerConnection, Side, SignatureScheme, version,
};

use super::unbuffered::{Client, End, Server, connect};
use super::{
    FixedTime, Offer, credential_refused, credential_scheme_ok, expected_validation, fixture,
    tls13_scheme, unix,
};
use crate::input::Input;

/// The schemes a fuzzed mask selects from for the server's
/// CertificateRequest.
const CANDIDATES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_PSS_SHA256,
    SignatureScheme::ED448,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP521_SHA512,
];

/// A client certificate verifier that offers only some of its inner
/// verifier's schemes.
#[derive(Debug)]
struct Filtered {
    inner: Arc<dyn ClientCertVerifier>,
    schemes: Vec<SignatureScheme>,
}

impl ClientCertVerifier for Filtered {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner
            .supported_verify_schemes()
            .into_iter()
            .filter(|scheme| self.schemes.contains(scheme))
            .collect()
    }

    fn verify_tls13_signature_with_delegated_key(
        &self,
        message: &[u8],
        public_key: &SubjectPublicKeyInfoDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner
            .verify_tls13_signature_with_delegated_key(message, public_key, dss)
    }
}

/// How the client's credential is made and attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    /// Issued for the client, attached as a client's.
    Sound,
    /// Issued for the server, attached as a client's: its signature does
    /// not cover the client's context.
    WrongSide,
    /// Issued for the client, attached as a server's: never presented.
    ServerSlot,
    /// A bit of the signature flipped.
    BadSignature,
    /// The valid time moved by a second after signing.
    BadValidTime,
    /// A server's credential attached first, then the sound one.
    AfterServerCredential,
}

impl Variant {
    fn pick(input: &mut Input) -> Self {
        match input.choose(8) {
            0 => Self::WrongSide,
            1 => Self::ServerSlot,
            2 => Self::BadSignature,
            3 => Self::BadValidTime,
            4 => Self::AfterServerCredential,
            _ => Self::Sound,
        }
    }
}

/// The client's credential and the identity that carries it.
fn credential(
    input: &mut Input,
    variant: Variant,
    valid_time: u32,
    dc_key: &super::DcKey,
) -> Option<(DelegatedCredential, CertifiedKey)> {
    let fixture = fixture();
    let end_entity = &fixture.client_delegation;
    let issue = |side| {
        DelegatedCredential::issue(
            side,
            end_entity,
            &*fixture.client_delegation_key,
            &[SignatureScheme::ECDSA_NISTP256_SHA256],
            Credential {
                valid_time,
                dc_cert_verify_algorithm: dc_key.scheme,
                public_key: dc_key.spki.clone(),
            },
        )
        .expect("issue")
    };
    let mut dc = issue(match variant {
        Variant::WrongSide => Side::Server,
        _ => Side::Client,
    });
    match variant {
        Variant::BadSignature => {
            let at = usize::from(input.u16()) % dc.signature.len();
            dc.signature[at] ^= 1 << (input.byte() % 8);
        }
        Variant::BadValidTime => {
            dc.credential.valid_time = dc.credential.valid_time.wrapping_add(1);
        }
        _ => {}
    }

    // Attachment checks the signature and the role named by the caller.
    let side = match variant {
        Variant::ServerSlot => Side::Server,
        _ => Side::Client,
    };
    let paired = DelegatedCredentialKey::new_for(
        side,
        end_entity,
        dc.clone(),
        dc_key.key.clone(),
        &fixture.provider,
    );
    if !matches!(variant, Variant::Sound | Variant::AfterServerCredential)
        || fixture.not_before + u64::from(valid_time) >= fixture.not_after
    {
        assert!(paired.is_err());
        return None;
    }
    let paired = paired.expect("the credential pairs with its key");
    assert_eq!(paired.side(), side);
    assert_eq!(paired.credential(), &dc);

    let mut certified = CertifiedKey::from_der(
        vec![end_entity.clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fixture.client_delegation_pkcs8.clone(),
        )),
        &fixture.provider,
    )
    .expect("certified key");
    let mut sides = Vec::new();
    if variant == Variant::AfterServerCredential {
        certified = certified
            .with_delegated_credential(issue(Side::Server), dc_key.key.clone(), &fixture.provider)
            .expect("credential attaches");
        sides.push(Side::Server);
    }
    certified = match side {
        Side::Client => certified.with_client_delegated_credential(
            dc.clone(),
            dc_key.key.clone(),
            &fixture.provider,
        ),
        Side::Server => {
            certified.with_delegated_credential(dc.clone(), dc_key.key.clone(), &fixture.provider)
        }
    }
    .expect("credential attaches");
    sides.push(side);
    let attached: Vec<Side> = certified
        .delegated_credentials()
        .iter()
        .map(|dc| dc.side())
        .collect();
    assert_eq!(attached, sides);
    Some((dc, certified))
}

/// Exchanges what both ends have to send until neither has anything.
fn exchange(client: &mut Client, server: &mut Server) -> Result<(), Error> {
    for _ in 0..16 {
        let to_server = client.take_output()?;
        server.give_input(&to_server)?;
        let to_client = server.take_output()?;
        client.give_input(&to_client)?;
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
    Ok(())
}

/// Client-authentication input: mode flags (bit 0: an unbuffered client,
/// bit 1: an unbuffered server, bit 2: the server does not ask for
/// credentials, bit 3: authentication after the handshake, bit 4: a
/// resumed connection afterwards), the client's clock (offset into the
/// certificate's validity, 32 bits), the server's skew selector and value,
/// the expiry relative to the client's clock (selector and value), the
/// credential key, the variant (with its arguments), and the scheme
/// selector (with a mask over [`CANDIDATES`]).
pub(super) fn client_auth(input: &mut Input) {
    let fixture = fixture();
    let nb = fixture.not_before;
    let na = fixture.not_after;
    let week = MAX_VALIDITY.as_secs();
    let mode = input.byte();
    let unbuffered_client = mode & 1 != 0;
    let unbuffered_server = mode & 2 != 0;
    let opt_in = mode & 4 == 0;
    let after_handshake = mode & 8 != 0;
    let resume = mode & 16 != 0;

    let now = nb + u64::from(input.u32()) % (na - nb);
    let skew: i64 = match input.choose(4) {
        0 | 1 => 0,
        2 => i64::from(input.byte()) - 128,
        _ => i64::from(input.u32() as i32) % (2 * 86_400),
    };
    let server_now = now.saturating_add_signed(skew);
    let delta: i64 = match input.choose(8) {
        0 => 0,
        1 => 1,
        2 => -1,
        3 => week as i64,
        4 => week as i64 + 1,
        5 => week as i64 - 1,
        _ => i64::from(input.u32() % (9 * 86_400)) - 86_400,
    };
    let Some(valid_time) = now
        .saturating_add_signed(delta)
        .checked_sub(nb)
        .filter(|d| *d > 0)
        .and_then(|d| u32::try_from(d).ok())
    else {
        return;
    };
    let dc_key = &fixture.dc_keys[input.choose(fixture.dc_keys.len())];
    let variant = Variant::pick(input);
    let Some((dc, certified)) = credential(input, variant, valid_time, dc_key) else {
        return;
    };
    let mask = (input.choose(4) == 0).then(|| input.byte());

    let webpki = WebPkiClientVerifier::builder_with_provider(
        fixture.roots.clone(),
        fixture.provider.clone(),
    )
    .build()
    .expect("client verifier");
    let verifier: Arc<dyn ClientCertVerifier> = match mask {
        None => webpki,
        Some(mask) => Arc::new(Filtered {
            inner: webpki,
            schemes: CANDIDATES
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, scheme)| *scheme)
                .collect(),
        }),
    };
    // What the server's CertificateRequest offers.
    let offered: Vec<SignatureScheme> = verifier
        .supported_verify_schemes()
        .into_iter()
        .filter(|scheme| tls13_scheme(*scheme))
        .collect();
    let dc_offered: Vec<SignatureScheme> = offered
        .iter()
        .copied()
        .filter(|scheme| opt_in && credential_scheme_ok(*scheme))
        .collect();

    let mut server_config = ServerConfig::builder_with_details(
        fixture.provider.clone(),
        Arc::new(FixedTime(unix(server_now))),
    )
    .with_protocol_versions(&[&version::TLS13])
    .expect("versions")
    .with_client_cert_verifier(verifier)
    .with_cert_resolver(Arc::new(SingleCertAndKey::from(fixture.ea_server.clone())));
    server_config.enable_delegated_credentials = opt_in;
    server_config.request_client_auth_after_handshake = after_handshake;
    let mut client_config = ClientConfig::builder_with_details(
        fixture.provider.clone(),
        Arc::new(FixedTime(unix(now))),
    )
    .with_protocol_versions(&[&version::TLS13])
    .expect("versions")
    .with_root_certificates(fixture.roots.clone())
    .with_client_auth_certified_key(certified);
    client_config.enable_post_handshake_auth = after_handshake;
    let (client_config, server_config) = (Arc::new(client_config), Arc::new(server_config));
    let pair = || {
        let name = ServerName::try_from("localhost").expect("name");
        let client: Client = if unbuffered_client {
            End::unbuffered(
                UnbufferedClientConnection::new(client_config.clone(), name).expect("client"),
            )
        } else {
            End::Buffered(ClientConnection::new(client_config.clone(), name).expect("client"))
        };
        let server: Server = if unbuffered_server {
            End::unbuffered(UnbufferedServerConnection::new(server_config.clone()).expect("server"))
        } else {
            End::Buffered(ServerConnection::new(server_config.clone()).expect("server"))
        };
        (client, server)
    };

    // The client presents the credential when the request asks for one it
    // has (RFC 9345 §4.1.2), as seen at its own clock.
    let expiry = nb + u64::from(dc.credential.valid_time);
    let presented = variant != Variant::ServerSlot
        && dc_offered.contains(&dc.credential.dc_cert_verify_algorithm)
        && offered.contains(&dc.credential.dc_cert_verify_algorithm)
        && offered.contains(&dc.algorithm)
        && now < expiry
        && expiry <= now + week
        && expiry <= na;
    // The server's verdict, worked out independently.
    let accepted = expected_validation(
        &dc,
        &Offer {
            side: Side::Client,
            end_entity: &fixture.client_delegation,
            dc_schemes: &dc_offered,
            sig_schemes: &offered,
            cert_verify_scheme: dc.credential.dc_cert_verify_algorithm,
            now: server_now,
        },
    );
    // The certificate itself is certainly valid at the server's clock, and
    // its key can sign for the request: the outcome then depends on the
    // credential alone.
    let settled = nb + 1 < server_now
        && server_now + 1 < na
        && offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256);

    let (mut client, mut server) = pair();
    let mut result = connect(&mut client, &mut server);
    if after_handshake && result.is_ok() {
        assert!(server.client_delegated_credential().is_none());
        assert!(server.peer_certificates().is_none());
        result = server
            .request_client_auth()
            .and_then(|()| exchange(&mut client, &mut server));
        if result.is_ok() {
            assert_eq!(
                server.post_handshake_auth_status(),
                Some(PostHandshakeAuthStatus::Authenticated)
            );
        }
    }

    // Soundness: a reported credential is the one presented, and valid.
    if let Some(got) = server.client_delegated_credential() {
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(got, &dc);
        assert!(presented, "a credential the client should not send");
        assert!(accepted.is_some(), "an invalid credential was accepted");
        assert_eq!(
            server.peer_certificates().map(|c| c[0].clone()),
            Some(fixture.client_delegation.clone())
        );
    }
    // Completeness, when nothing but the credential decides.
    match (settled, presented, accepted) {
        (false, ..) => {}
        (true, true, Some(_)) => {
            assert!(result.is_ok(), "a valid credential was refused: {result:?}");
            assert_eq!(server.client_delegated_credential(), Some(&dc));
        }
        (true, true, None) => {
            let error = result
                .as_ref()
                .expect_err("an invalid credential was accepted");
            assert!(credential_refused(error), "{error:?}");
        }
        (true, false, _) => {
            assert!(result.is_ok(), "{result:?}");
            assert!(server.client_delegated_credential().is_none());
            assert_eq!(
                server.peer_certificates().map(|c| c[0].clone()),
                Some(fixture.client_delegation.clone())
            );
        }
    }

    // A resumed connection reports no credential.
    if resume && !after_handshake && result.is_ok() {
        let (mut client, mut server) = pair();
        let result = connect(&mut client, &mut server);
        if result.is_ok() && server.handshake_kind() == Some(HandshakeKind::Resumed) {
            assert!(server.client_delegated_credential().is_none());
        }
    }
}
