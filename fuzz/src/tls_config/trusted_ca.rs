//! The `trusted_ca_keys` extension (RFC 6066 §6): identifiers built from
//! fuzzed certificate DER, a client list of fuzzed identifiers, and a
//! server whose resolver follows the list, over a handshake.

use std::sync::Arc;

use browntls_core::client::{Resumption, UnbufferedClientConnection};
use browntls_core::crypto::{native, rustcrypto};
use browntls_core::pki_types::{CertificateDer, ServerName, anchor_from_trusted_cert};
use browntls_core::server::ResolvesServerCertUsingTrustedCaKeys;
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{
    ClientConfig, ClientConnection, DistinguishedName, HandshakeKind, ProtocolVersion,
    ServerConfig, ServerConnection, SupportedProtocolVersion, TrustedAuthority, version,
};

use super::config::{pump, root_store};
use super::fixtures::{self, ED25519, P256, P384};
use super::provider;
use super::sign::load;
use crate::input::Input;

type Sha1 = fn(&[u8]) -> [u8; 20];

/// The certificate the identifiers are derived from: a fixture, possibly
/// with one byte changed, or fuzzed bytes.
fn certificate(input: &mut Input<'_>) -> CertificateDer<'static> {
    let fx = fixtures::get();
    let mut der = match input.choose(5) {
        0 => fx.ca.to_vec(),
        1 => fx.other_ca.to_vec(),
        2 => fx.intermediate.to_vec(),
        3 => fx.keys[P256].chain[0].to_vec(),
        _ => input.field().to_vec(),
    };
    let flip = usize::from(input.u16());
    let mask = input.byte();
    if let Some(byte) = der.get_mut(flip) {
        *byte ^= mask;
    }
    CertificateDer::from(der)
}

/// Every constructor over `cert`: malformed input is an error, never a
/// panic, and the certificate, trust anchor and SPKI routes agree.
fn identifiers(cert: &CertificateDer<'_>, sha1: Sha1) {
    let by_cert = TrustedAuthority::cert_sha1_hash(cert, sha1);
    // The certificate hash is the same whichever provider computes it.
    assert_eq!(
        by_cert,
        TrustedAuthority::cert_sha1_hash(cert, native::sha1)
    );
    assert_eq!(
        by_cert,
        TrustedAuthority::cert_sha1_hash(cert, rustcrypto::sha1)
    );
    assert!(by_cert.matches_certificate(cert, sha1));
    assert!(!TrustedAuthority::PreAgreed.matches_certificate(cert, sha1));

    let key = TrustedAuthority::key_sha1_hash(cert, sha1);
    let name = TrustedAuthority::x509_name(cert);
    let anchor = anchor_from_trusted_cert(cert);
    // Both parse the certificate as a trust anchor.
    assert_eq!(name.is_ok(), anchor.is_ok(), "{name:?} {anchor:?}");
    if let Ok(key) = &key {
        assert!(key.matches_certificate(cert, sha1));
    }
    if let Ok(name) = &name {
        assert!(name.matches_certificate(cert, sha1));
    }
    if let Ok(anchor) = &anchor {
        assert_eq!(Ok(TrustedAuthority::x509_name_of_anchor(anchor)), name);
        assert_eq!(
            TrustedAuthority::key_sha1_hash_of_anchor(anchor, sha1),
            key.clone()
        );
    }
    if let Ok(parsed) = browntls_core::pki_types::Cert::try_from(cert) {
        // A certificate that parses strictly also parses as an anchor, and
        // its SPKI names the same key.
        assert!(anchor.is_ok());
        let spki = parsed.subject_public_key_info();
        assert_eq!(TrustedAuthority::key_sha1_hash_of_spki(&spki, sha1), key);
    }
}

/// A list of up to eight identifiers, or `None`.
fn client_list(input: &mut Input<'_>, sha1: Sha1) -> Option<Vec<TrustedAuthority>> {
    let fx = fixtures::get();
    let count = input.byte();
    if count >= 0x80 {
        return None;
    }
    let mut list = Vec::new();
    for _ in 0..count % 9 {
        list.push(match input.choose(7) {
            0 => TrustedAuthority::PreAgreed,
            1 => TrustedAuthority::key_sha1_hash(&fx.ca, sha1).expect("fixture"),
            2 => TrustedAuthority::x509_name(&fx.ca).expect("fixture"),
            3 => TrustedAuthority::cert_sha1_hash(&fx.ca, sha1),
            4 => TrustedAuthority::cert_sha1_hash(&fx.other_ca, sha1),
            5 => TrustedAuthority::KeySha1Hash(input.array()),
            _ => TrustedAuthority::X509Name(DistinguishedName::new(input.short_field().to_vec())),
        });
    }
    Some(list)
}

/// Identifiers, then a handshake between a client with a fuzzed list and a
/// server whose [`ResolvesServerCertUsingTrustedCaKeys`] serves the
/// Ed25519 chain under the root's identifiers (and, optionally, the P-384
/// chain under `pre_agreed`), with the P-256 chain as its fallback; then a
/// second connection, which may resume.
///
/// Connection creation fails exactly for a list holding an empty name. The
/// server acknowledges exactly when TLS 1.2 is negotiated in a full
/// handshake and a registered chain was served, which needs a listed
/// identifier the resolver registered; a resumed handshake never is.
pub(super) fn trusted_ca_op(input: &mut Input<'_>) {
    acknowledged_rounds(input);
}

/// [`trusted_ca_op`], returning how many connections the server
/// acknowledged.
fn acknowledged_rounds(input: &mut Input<'_>) -> usize {
    const VERSIONS: [&[&SupportedProtocolVersion]; 3] = [
        &[&version::TLS13, &version::TLS12],
        &[&version::TLS12],
        &[&version::TLS13],
    ];
    let fx = fixtures::get();
    let sha1: Sha1 = if input.bool() {
        native::sha1
    } else {
        rustcrypto::sha1
    };
    identifiers(&certificate(input), sha1);

    let p = input.choose(2);
    let cv = *input.pick(&VERSIONS);
    let sv = *input.pick(&VERSIONS);
    let pre_agreed = input.bool();
    let list = client_list(input, sha1);

    let (Some(ed), Some(fallback), Some(p384)) = (load(p, ED25519), load(p, P256), load(p, P384))
    else {
        return 0;
    };
    let ck = |k: usize, key| Arc::new(CertifiedKey::new(fx.keys[k].chain.clone(), key));
    let mut resolver = ResolvesServerCertUsingTrustedCaKeys::new(Arc::new(SingleCertAndKey::from(
        ck(P256, fallback),
    )));
    resolver
        .add_for_root(&fx.ca, sha1, ck(ED25519, ed))
        .expect("the root parses");
    let mut registered = vec![
        TrustedAuthority::cert_sha1_hash(&fx.ca, sha1),
        TrustedAuthority::key_sha1_hash(&fx.ca, sha1).expect("fixture"),
        TrustedAuthority::x509_name(&fx.ca).expect("fixture"),
    ];
    if pre_agreed {
        resolver.add(vec![TrustedAuthority::PreAgreed], ck(P384, p384));
        registered.push(TrustedAuthority::PreAgreed);
    }
    // A malformed root registers nothing.
    assert!(
        resolver
            .add_for_root(
                &CertificateDer::from(&b"\x30\x00"[..]),
                sha1,
                ck(P256, load(p, P256).expect("loaded"))
            )
            .is_err()
    );
    let server_config: Arc<ServerConfig> = Arc::new(
        ServerConfig::builder_with_provider(provider(p))
            .with_protocol_versions(sv)
            .expect("default provider supports every version")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver)),
    );

    let mut client_config = ClientConfig::builder_with_provider(provider(p))
        .with_protocol_versions(cv)
        .expect("default provider supports every version")
        .with_root_certificates(root_store())
        .with_no_client_auth();
    client_config.trusted_ca_keys = list.clone();
    client_config.resumption = Resumption::in_memory_sessions(4);
    let client_config = Arc::new(client_config);
    let name = ServerName::try_from("localhost").expect("name");

    // RFC 6066 §6: DistinguishedName<1..2^16-1>; nothing else in a list of
    // at most eight short entries can be refused.
    let refused = list.as_ref().is_some_and(|l| {
        l.iter()
            .any(|id| matches!(id, TrustedAuthority::X509Name(n) if n.as_ref().is_empty()))
    });
    let unbuffered = UnbufferedClientConnection::new(client_config.clone(), name.clone());
    assert_eq!(unbuffered.is_err(), refused);
    if let Ok(unbuffered) = unbuffered {
        assert!(!unbuffered.trusted_ca_keys_acknowledged());
    }
    let listed = list
        .as_ref()
        .is_some_and(|l| l.iter().any(|id| registered.contains(id)));
    let versions_meet = cv.iter().any(|v| sv.contains(v));
    let registered_ees = [&fx.keys[ED25519].chain[0], &fx.keys[P384].chain[0]];

    let mut count = 0;
    for round in 0..2 {
        let client = ClientConnection::new(client_config.clone(), name.clone());
        assert_eq!(client.is_err(), refused);
        let Ok(mut client) = client else {
            return 0;
        };
        assert!(!client.trusted_ca_keys_acknowledged());
        let mut server = ServerConnection::new(server_config.clone()).expect("server");
        let result = pump(&mut client, &mut server);
        let done = result.is_ok() && !client.is_handshaking() && !server.is_handshaking();
        assert_eq!(done, versions_meet, "round {round}: {result:?}");
        if !done {
            return 0;
        }
        let acknowledged = client.trusted_ca_keys_acknowledged();
        let tls12 = client.protocol_version() == Some(ProtocolVersion::TLSv1_2);
        let full = client.handshake_kind() == Some(HandshakeKind::Full);
        let served = &client.peer_certificates().expect("certificates")[0];
        if acknowledged {
            assert!(tls12 && full && listed, "round {round}");
            count += 1;
        }
        if tls12 && full {
            assert_eq!(acknowledged, registered_ees.contains(&served));
        }
        if !listed {
            assert_eq!(served, &fx.keys[P256].chain[0]);
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds reach both answers: the root's certificate hash, key hash
    /// and name, and `pre_agreed`, are acknowledged in TLS 1.2; nothing is
    /// in TLS 1.3, without a list, or with a list naming nothing
    /// registered.
    #[test]
    fn seeds_reach_an_acknowledgement() {
        crate::init();
        let none = [0xff, 0xff, 0];
        let run = |seed: &[u8]| acknowledged_rounds(&mut Input::new(seed));
        let with = |prefix: &[u8], rest: &[u8]| {
            let mut seed = prefix.to_vec();
            seed.extend_from_slice(rest);
            run(&seed)
        };
        assert!(with(&[1, 0], &[none, [0, 1, 1], [0, 1, 3]].concat()) >= 1);
        assert!(with(&[1, 0], &[none, [0, 1, 1], [0, 1, 1]].concat()) >= 1);
        assert!(with(&[0, 2], &[none, [1, 1, 1], [0, 1, 2]].concat()) >= 1);
        assert!(with(&[1, 1], &[none, [0, 0, 1], [1, 1, 0]].concat()) >= 1);
        assert_eq!(run(&[0, 3, 0, 10, 0x40, 1, 0, 0, 1, 1, 0]), 0);
        assert_eq!(with(&[1, 0], &[none, [0, 1, 1], [0, 0x80, 0]].concat()), 0);
        assert_eq!(with(&[1, 0], &[none, [0, 1, 1], [0, 1, 4]].concat()), 0);
    }
}
