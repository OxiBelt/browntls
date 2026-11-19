//! `RootCertStore` and the WebPKI server and client certificate verifiers.

use std::sync::Arc;

use browntls_core::client::danger::ServerCertVerifier;
use browntls_core::client::{
    WebPkiServerVerifier, verify_server_cert_signed_by_trust_anchor, verify_server_name,
};
use browntls_core::pki_types::{
    CertificateDer, CertificateRevocationListDer, EndEntityCert, ServerName, UnixTime,
};
use browntls_core::server::{ParsedCertificate, WebPkiClientVerifier};
use browntls_core::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};

use super::fixtures::{self, MISMATCHED, P256, P256_SEC1, P384};
use super::{NOW, provider};
use crate::input::Input;

/// How a server name relates to the fixtures' certificates (SANs
/// `localhost`, `*.wild.example`, `127.0.0.1`): `Some(true)` must match,
/// `Some(false)` must not, `None` is left to the implementation (a trailing
/// dot, unusual label characters).
pub(crate) fn name_verdict(name: &ServerName<'_>) -> Option<bool> {
    match name {
        ServerName::IpAddress(ip) => Some(ip.as_bytes() == [127, 0, 0, 1]),
        ServerName::DnsName(dns) => {
            let s = dns.as_ref().to_ascii_lowercase();
            let bare = s.strip_suffix('.').unwrap_or(&s);
            let wild_label = bare.strip_suffix(".wild.example");
            let lenient = bare == "localhost"
                || wild_label.is_some_and(|l| !l.is_empty() && !l.contains('.'));
            let strict = lenient
                && bare.len() == s.len()
                && wild_label.is_none_or(|l| l.bytes().all(|b| b.is_ascii_alphanumeric()));
            if strict {
                Some(true)
            } else if lenient {
                None
            } else {
                Some(false)
            }
        }
        _ => None,
    }
}

/// A server name: one of the interesting ones, or fuzzed.
pub(crate) fn server_name<'a>(input: &mut Input<'a>) -> Option<ServerName<'a>> {
    const NAMES: [&str; 9] = [
        "localhost",
        "LocalHost",
        "a.wild.example",
        "b.c.wild.example",
        "wild.example",
        "127.0.0.1",
        "::1",
        "localhost.",
        "other.example",
    ];
    let choice = input.choose(NAMES.len() + 1);
    match NAMES.get(choice) {
        Some(name) => Some(ServerName::try_from(*name).expect("valid name")),
        None => ServerName::try_from(input.short_field()).ok(),
    }
}

/// A fixed time, or a fuzzed one.
fn now(input: &mut Input<'_>) -> (UnixTime, bool) {
    if input.bool() {
        (
            UnixTime::since_unix_epoch(core::time::Duration::from_secs(input.u64())),
            false,
        )
    } else {
        (NOW, true)
    }
}

/// Roots and what the model knows about them.
struct Roots {
    store: Arc<RootCertStore>,
    /// The fixtures' root is trusted.
    ca: bool,
    /// Only `ca` and the unrelated root may be present.
    modelled: bool,
}

fn roots(input: &mut Input<'_>) -> Roots {
    let fx = fixtures::get();
    let flags = input.byte();
    let mut store = RootCertStore::empty();
    let mut modelled = true;
    if flags & 1 != 0 {
        store.add(fx.ca.clone()).expect("root");
    }
    if flags & 2 != 0 {
        store.add(fx.other_ca.clone()).expect("unrelated root");
    }
    if flags & 4 != 0 {
        store
            .add(fx.intermediate.clone())
            .expect("intermediate as a root");
        modelled = false;
    }
    if flags & 8 != 0
        && store
            .add(CertificateDer::from(input.field().to_vec()))
            .is_ok()
    {
        modelled = false;
    }
    Roots {
        store: Arc::new(store),
        ca: flags & 1 != 0,
        modelled,
    }
}

/// Which CRL: 0 none, 1 clean, 2 revoking the P-256 end entity, 3 fuzzed.
fn crls(input: &mut Input<'_>) -> (usize, Vec<CertificateRevocationListDer<'static>>) {
    let fx = fixtures::get();
    let choice = input.choose(4);
    let list = match choice {
        0 => Vec::new(),
        1 => vec![fx.crl_clean.clone()],
        2 => vec![fx.crl_revoking.clone()],
        _ => vec![input.field().to_vec()],
    };
    (
        choice,
        list.into_iter()
            .map(CertificateRevocationListDer::from)
            .collect(),
    )
}

/// The outcome of path validation for the genuine chain of key `k` under
/// the model's assumptions.
fn expected_path(
    roots: &Roots,
    k: usize,
    with_intermediate: bool,
    crl: usize,
    only_end_entity: bool,
    allow_unknown: bool,
) -> bool {
    let _ = only_end_entity;
    let chained = roots.ca && (k != P384 || with_intermediate);
    let revoked = crl == 2 && matches!(k, P256 | P256_SEC1 | MISMATCHED);
    // The P-384 end entity's issuer (the intermediate) publishes no CRL.
    let unknown = crl != 0 && k == P384;
    chained && !revoked && !(unknown && !allow_unknown)
}

/// A fixture chain, optionally without its intermediate, optionally with
/// one byte of the end entity changed. Returns the key index too.
fn chain(input: &mut Input<'_>) -> (usize, Vec<CertificateDer<'static>>, bool, bool) {
    let fx = fixtures::get();
    let with_chain: Vec<usize> = (0..fx.keys.len())
        .filter(|k| !fx.keys[*k].chain.is_empty())
        .collect();
    let k = *input.pick(&with_chain);
    let mut chain = fx.keys[k].chain.clone();
    let with_intermediate = !input.bool();
    if !with_intermediate {
        chain.truncate(1);
    }
    let mutated = input.bool();
    if mutated {
        let mut ee = chain[0].as_ref().to_vec();
        let at = usize::from(input.u16()) % ee.len();
        ee[at] ^= 1 << input.choose(8);
        chain[0] = CertificateDer::from(ee);
    }
    (k, chain, with_intermediate, mutated)
}

/// `RootCertStore`: single and bulk insertion of genuine, corrupted and
/// fuzzed certificates.
pub(super) fn root_store_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let empty = RootCertStore::empty();
    assert!(empty.is_empty() && empty.subjects().is_empty());
    assert_eq!(empty.len(), 0);
    let n = input.choose(5);
    let mut certs = Vec::new();
    let mut genuine = Vec::new();
    for _ in 0..n {
        let cert = match input.choose(4) {
            0 => fx.ca.clone(),
            1 => fx.intermediate.clone(),
            2 => fx.keys[input.choose(4)].chain[0].clone(),
            _ => CertificateDer::from(input.field().to_vec()),
        };
        genuine.push(fx_cert(&cert));
        certs.push(cert);
    }
    let mut bulk = RootCertStore::empty();
    let (valid, invalid) = bulk.add_parsable_certificates(certs.clone());
    assert_eq!(valid + invalid, n);
    assert_eq!(bulk.len(), valid);
    let mut single = RootCertStore::empty();
    for (cert, genuine) in certs.into_iter().zip(genuine) {
        let before = single.len();
        match single.add(cert) {
            Ok(()) => assert_eq!(single.len(), before + 1),
            Err(e) => {
                assert!(!genuine, "a genuine certificate was refused: {e:?}");
                assert_eq!(single.len(), before);
            }
        }
    }
    assert_eq!(single.len(), bulk.len());
    assert_eq!(single.is_empty(), matches!(single.len(), 0));
    let subjects = single.subjects();
    assert_eq!(subjects.len(), single.len());
    let bulk_subjects = bulk.subjects();
    for (a, b) in subjects.iter().zip(&bulk_subjects) {
        assert_eq!(a.as_ref(), b.as_ref());
        assert_eq!(a.as_ref().first(), Some(&0x30));
    }
    let dn = DistinguishedName::in_sequence(input.short_field());
    assert_eq!(dn.as_ref().first(), Some(&0x30));
}

fn fx_cert(cert: &CertificateDer<'_>) -> bool {
    let fx = fixtures::get();
    *cert == fx.ca
        || *cert == fx.intermediate
        || fx.keys.iter().any(|k| k.chain.first() == Some(cert))
}

/// A WebPKI server verifier with fuzzed roots, CRLs and options, against
/// fixture chains, server names and times.
pub(super) fn server_verifier_op(input: &mut Input<'_>) {
    let roots = roots(input);
    let p = input.choose(3);
    let mut builder = if p == 2 {
        WebPkiServerVerifier::builder(roots.store.clone())
    } else {
        WebPkiServerVerifier::builder_with_provider(roots.store.clone(), provider(p))
    };
    let (crl, list) = crls(input);
    if !list.is_empty() {
        builder = builder.with_crls(list);
    }
    let flags = input.byte();
    if flags & 1 != 0 {
        builder = builder.only_check_end_entity_revocation();
    }
    if flags & 2 != 0 {
        builder = builder.allow_unknown_revocation_status();
    }
    if flags & 4 != 0 {
        builder = builder.enforce_revocation_expiration();
    }
    let verifier = match builder.build() {
        Ok(v) => v,
        Err(e) => {
            assert!(roots.store.is_empty() || crl == 3, "{e:?}");
            return;
        }
    };
    assert!(!roots.store.is_empty());
    let algs = provider(p % 2).signature_verification_algorithms;
    assert_eq!(
        verifier.supported_verify_schemes(),
        algs.supported_schemes()
    );
    let _ = verifier.requires_raw_public_keys();

    let (k, chain, with_intermediate, mutated) = chain(input);
    let Some(name) = server_name(input) else {
        return;
    };
    let (now, fixed_time) = now(input);
    let ocsp = input.short_field();
    let result = verifier.verify_server_cert(&chain[0], &chain[1..], &name, ocsp, now);
    if mutated {
        assert!(result.is_err(), "a corrupted end entity verified");
    } else if roots.modelled && fixed_time && crl != 3 {
        let path = expected_path(
            &roots,
            k,
            with_intermediate,
            crl,
            flags & 1 != 0,
            flags & 2 != 0,
        );
        match name_verdict(&name) {
            Some(name_ok) => assert_eq!(
                result.is_ok(),
                path && name_ok,
                "key {k} name {name:?}: {result:?}"
            ),
            None => assert!(result.is_err() || path),
        }
    }

    // The free functions behind the verifier.
    let Ok(parsed) = ParsedCertificate::try_from(&chain[0]) else {
        assert!(mutated);
        return;
    };
    let spki = parsed.subject_public_key_info();
    if let Ok(ee) = EndEntityCert::try_from(&chain[0]) {
        assert_eq!(ee.subject_public_key_info(), spki);
    }
    let by_name = verify_server_name(&parsed, &name);
    if !mutated && let Some(name_ok) = name_verdict(&name) {
        assert_eq!(by_name.is_ok(), name_ok, "{name:?}");
    }
    let anchored = verify_server_cert_signed_by_trust_anchor(
        &parsed,
        &roots.store,
        &chain[1..],
        now,
        algs.all,
    );
    if mutated {
        assert!(anchored.is_err());
    } else if roots.modelled && fixed_time {
        assert_eq!(
            anchored.is_ok(),
            expected_path(&roots, k, with_intermediate, 0, false, false)
        );
    }

    // Signatures with fuzzed contents through the verifier.
    let dss =
        DigitallySignedStruct::new(SignatureScheme::from(input.u16()), input.field().to_vec());
    let msg = input.short_field();
    let _ = verifier.verify_tls12_signature(msg, &chain[0], &dss);
    let _ = verifier.verify_tls13_signature(msg, &chain[0], &dss);
    let _ = verifier.verify_tls13_signature_with_delegated_key(msg, &spki, &dss);
    let _ = verifier.root_hint_subjects();
}

/// A WebPKI client verifier with fuzzed roots, hints, CRLs and options.
pub(super) fn client_verifier_op(input: &mut Input<'_>) {
    let roots = roots(input);
    let p = input.choose(3);
    let mut builder = if p == 2 {
        WebPkiClientVerifier::builder(roots.store.clone())
    } else {
        WebPkiClientVerifier::builder_with_provider(roots.store.clone(), provider(p))
    };
    let mut hints = roots.store.len();
    let flags = input.byte();
    if flags & 1 != 0 {
        builder = builder.clear_root_hint_subjects();
        hints = 0;
    }
    if flags & 2 != 0 {
        let extra: Vec<DistinguishedName> = (0..input.choose(3))
            .map(|_| DistinguishedName::new(input.short_field().to_vec()))
            .collect();
        hints += extra.len();
        builder = builder.add_root_hint_subjects(extra);
    }
    let (crl, list) = crls(input);
    if !list.is_empty() {
        builder = builder.with_crls(list);
    }
    if flags & 4 != 0 {
        builder = builder.only_check_end_entity_revocation();
    }
    if flags & 8 != 0 {
        builder = builder.allow_unauthenticated();
    }
    if flags & 16 != 0 {
        builder = builder.allow_unknown_revocation_status();
    }
    if flags & 32 != 0 {
        builder = builder.enforce_revocation_expiration();
    }
    let verifier = match builder.build() {
        Ok(v) => v,
        Err(e) => {
            assert!(roots.store.is_empty() || crl == 3, "{e:?}");
            return;
        }
    };
    assert!(verifier.offer_client_auth());
    assert_eq!(verifier.client_auth_mandatory(), flags & 8 == 0);
    assert_eq!(verifier.root_hint_subjects().len(), hints);
    let algs = provider(p % 2).signature_verification_algorithms;
    assert_eq!(
        verifier.supported_verify_schemes(),
        algs.supported_schemes()
    );
    let _ = verifier.requires_raw_public_keys();

    let (k, chain, with_intermediate, mutated) = chain(input);
    let (now, fixed_time) = now(input);
    let result = verifier.verify_client_cert(&chain[0], &chain[1..], now);
    if mutated {
        assert!(result.is_err(), "a corrupted end entity verified");
    } else if roots.modelled && fixed_time && crl != 3 {
        let path = expected_path(
            &roots,
            k,
            with_intermediate,
            crl,
            flags & 4 != 0,
            flags & 16 != 0,
        );
        assert_eq!(result.is_ok(), path, "key {k}: {result:?}");
    }
    let dss =
        DigitallySignedStruct::new(SignatureScheme::from(input.u16()), input.field().to_vec());
    let _ = verifier.verify_tls12_signature(b"m", &chain[0], &dss);
    let _ = verifier.verify_tls13_signature(b"m", &chain[0], &dss);

    let none = WebPkiClientVerifier::no_client_auth();
    assert!(!none.offer_client_auth());
    let _ = none.verify_client_cert(&chain[0], &[], now);
    let _ = none.supported_verify_schemes();
}
