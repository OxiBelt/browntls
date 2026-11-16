//! Certificates, path validation, signatures and CRLs with real signature
//! algorithms, over the `tls_config` fixtures.

use std::cell::Cell;
use std::sync::OnceLock;

use browntls::SignatureScheme;
use browntls::crypto::{WebPkiSupportedAlgorithms, native, rustcrypto};
use browntls_pki::{
    BorrowedCertRevocationList, CertRevocationList, CertificateDer, CrlsRequired, EndEntityCert,
    Error, ExpirationPolicy, KeyUsage, OwnedCertRevocationList, RawPublicKeyEntity,
    RevocationCheckDepth, RevocationOptionsBuilder, RevocationReason,
    SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, TrustAnchor, UnixTime,
    UnknownStatusPolicy, VerifiedPath, anchor_from_trusted_cert,
};

use super::{tlv, unix_date};
use crate::input::Input;
use crate::tls_config::fixtures::{
    self, ED25519, KEY_COUNT, P256, P256_SERIAL, P384, RSA, RSA_PKCS1,
};
use crate::tls_config::sign::key_schemes;
use crate::tls_config::verifiers::{name_verdict, server_name};

type Alg = &'static dyn SignatureVerificationAlgorithm;

fn supported(p: usize) -> &'static WebPkiSupportedAlgorithms {
    [&native::SUPPORTED_SIG_ALGS, &rustcrypto::SUPPORTED_SIG_ALGS][p]
}

/// Keys whose fixture certificates end the paths, in end-entity choice
/// order; choices 4 and 5 are the root and the intermediate.
const END_ENTITIES: [usize; 4] = [P256, P384, ED25519, RSA];

/// The serial number the clean CRL lists.
const CLEAN_SERIAL: &[u8] = &[0x7b, 4, 5, 6];

/// rcgen's default validity: 1975-01-01 to 4096-01-01.
const NOT_BEFORE: u64 = unix_date(1975, 1, 1);
const NOT_AFTER: u64 = unix_date(4096, 1, 1);

/// The fixture CRLs' `thisUpdate` and `nextUpdate`.
const CRL_THIS_UPDATE: u64 = unix_date(2026, 11, 1);
const CRL_NEXT_UPDATE: u64 = unix_date(2027, 11, 1);

fn secs(t: u64) -> UnixTime {
    UnixTime::since_unix_epoch(core::time::Duration::from_secs(t))
}

fn fixture_cert(which: usize) -> &'static CertificateDer<'static> {
    let fx = fixtures::get();
    match END_ENTITIES.get(which) {
        Some(&k) => &fx.keys[k].chain[0],
        None if which == 4 => &fx.ca,
        None => &fx.intermediate,
    }
}

fn parse(der: &'static CertificateDer<'static>) -> EndEntityCert<'static> {
    EndEntityCert::try_from(der).expect("fixture certificate")
}

/// The `algorithm` contents of a `SubjectPublicKeyInfo` SEQUENCE.
fn spki_algorithm(spki: &[u8]) -> Vec<u8> {
    let (_, contents, _) = tlv(spki).expect("SPKI");
    let (_, algorithm, _) = tlv(contents).expect("SPKI algorithm");
    algorithm.to_vec()
}

/// The `signatureAlgorithm` contents of a certificate or CRL.
fn signature_algorithm(signed: &[u8]) -> Vec<u8> {
    let (_, contents, _) = tlv(signed).expect("signed structure");
    let (_, _, rest) = tlv(contents).expect("signed data");
    let (_, algorithm, _) = tlv(rest).expect("signature algorithm");
    algorithm.to_vec()
}

/// Whether `algs` has an algorithm for a signature with `signature` made
/// by a key with SPKI algorithm `key`.
fn covered(algs: &[&dyn SignatureVerificationAlgorithm], signature: &[u8], key: &[u8]) -> bool {
    algs.iter().any(|a| {
        a.signature_alg_id().matches_signature(signature)
            && a.public_key_alg_id().matches_public_key(key)
    })
}

fn corrupt(input: &mut Input<'_>, bytes: &mut [u8]) {
    let at = usize::from(input.u16()) % bytes.len();
    bytes[at] ^= input.byte() | 1;
}

/// A fixture certificate, optionally corrupted: its accessors, its trust
/// anchor form and name matching.
pub(super) fn cert_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let which = input.choose(6);
    let mut bytes = fixture_cert(which).to_vec();
    let corrupted = input.bool();
    if corrupted {
        corrupt(input, &mut bytes);
    }
    let name = server_name(input);
    let der = CertificateDer::from(bytes);
    let anchor = anchor_from_trusted_cert(&der);
    let Ok(cert) = EndEntityCert::try_from(&der) else {
        assert!(corrupted);
        return;
    };
    assert_eq!(cert.der(), der);
    let spki = cert.subject_public_key_info();
    let raw = RawPublicKeyEntity::try_from(&spki);
    let name_ok = name
        .as_ref()
        .map(|n| cert.verify_is_valid_for_subject_name(n));
    let usages = (
        cert.has_delegation_usage(),
        cert.has_digital_signature_key_usage(),
    );
    let window = (cert.not_before().as_secs(), cert.not_after().as_secs());
    if corrupted {
        return;
    }

    assert!(raw.is_ok());
    assert_eq!(window, (NOT_BEFORE, NOT_AFTER));
    let end_entity = which < 4;
    assert_eq!(usages, (matches!(which, 0 | 2), end_entity));
    if which == 0 {
        assert_eq!(cert.serial(), P256_SERIAL);
    }
    let issuer = if which == 1 { &fx.intermediate } else { &fx.ca };
    assert_eq!(cert.issuer(), parse(issuer).subject());
    if let (Some(name), Some(result)) = (&name, name_ok) {
        match name_verdict(name) {
            Some(expected) => assert_eq!(result.is_ok(), expected && end_entity, "{name:?}"),
            None => assert!(end_entity || result.is_err()),
        }
    }

    let anchor = anchor.expect("anchor from a genuine certificate");
    assert_eq!(anchor.subject.as_ref(), cert.subject());
    let (_, spki_contents, _) = tlv(spki.as_ref()).expect("SPKI");
    assert_eq!(anchor.subject_public_key_info.as_ref(), spki_contents);
    assert!(anchor.name_constraints.is_none());
    assert_eq!(anchor.to_owned(), anchor);
}

/// The usages a path may be checked for: the convenience constructors and
/// both kinds for a purpose the end entities have and one they lack.
fn usage(choice: usize) -> KeyUsage {
    const SERVER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    const CLIENT: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    let (usage, oid, if_present) = match choice {
        0 => (KeyUsage::server_auth(), SERVER, true),
        1 => (KeyUsage::client_auth(), CLIENT, true),
        2 => (KeyUsage::required(SERVER), SERVER, false),
        3 => (KeyUsage::required(CLIENT), CLIENT, false),
        4 => (KeyUsage::required(CODE_SIGNING), CODE_SIGNING, false),
        _ => (
            KeyUsage::required_if_present(CODE_SIGNING),
            CODE_SIGNING,
            true,
        ),
    };
    assert_eq!(usage.oid(), oid);
    assert_eq!(usage.is_required_if_present(), if_present);
    usage
}

/// A candidate path in the model: through the intermediate certificate or
/// not, to the root or to the intermediate as a trust anchor.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Candidate {
    via_intermediate: bool,
    to_intermediate: bool,
}

/// Revocation settings in the model.
struct Revocation {
    clean: bool,
    revoking: bool,
    chain: bool,
    allow_unknown: bool,
    enforce_expiry: bool,
}

impl Revocation {
    /// Whether a certificate with `serial`, issued by the root or not,
    /// passes revocation checking at `time`.
    fn passes(&self, serial: &[u8], issued_by_root: bool, time: u64) -> bool {
        if !issued_by_root || !(self.clean || self.revoking) {
            return self.allow_unknown;
        }
        if self.enforce_expiry && time >= CRL_NEXT_UPDATE {
            return false;
        }
        !(self.revoking && serial == P256_SERIAL || self.clean && serial == CLEAN_SERIAL)
    }
}

/// `EndEntityCert::verify_for_usage` over the fixture chains against a
/// model of path validation.
pub(super) fn path_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let which = input.choose(6);
    let mut ee_bytes = fixture_cert(which).to_vec();
    let corrupted = input.bool();
    if corrupted {
        corrupt(input, &mut ee_bytes);
    }

    // Trust anchors: the root, an unrelated root, the intermediate.
    let roots = input.byte();
    let mut anchors: Vec<TrustAnchor<'static>> = Vec::new();
    for (bit, cert) in [&fx.ca, &fx.other_ca, &fx.intermediate]
        .into_iter()
        .enumerate()
    {
        if roots >> bit & 1 != 0 {
            anchors.push(anchor_from_trusted_cert(cert).expect("fixture anchor"));
        }
    }
    // Intermediates: the intermediate, the unrelated root, a corrupted
    // intermediate, the intermediate again.
    let ints = input.byte();
    let mut intermediates: Vec<CertificateDer<'static>> = Vec::new();
    if ints & 1 != 0 {
        intermediates.push(fx.intermediate.clone());
    }
    if ints & 2 != 0 {
        intermediates.push(fx.other_ca.clone());
    }
    if ints & 4 != 0 {
        let mut bytes = fx.intermediate.to_vec();
        corrupt(input, &mut bytes);
        intermediates.push(CertificateDer::from(bytes));
    }
    if ints & 8 != 0 {
        intermediates.push(fx.intermediate.clone());
    }

    let time = match input.choose(10) {
        0 => crate::tls_config::NOW.as_secs(),
        1 => NOT_BEFORE - 1,
        2 => NOT_BEFORE,
        3 => NOT_AFTER,
        4 => NOT_AFTER + 1,
        5 => CRL_NEXT_UPDATE - 1,
        6 => CRL_NEXT_UPDATE,
        7 => 0,
        8 => u64::MAX,
        _ => input.u64(),
    };
    let usage_choice = input.choose(6);
    let key_usage = usage(usage_choice);

    // Algorithms: either provider's, or a subset of the native ones (then
    // without revocation, whose CRL signatures the model does not cover).
    let (algs, all): (Vec<&dyn SignatureVerificationAlgorithm>, bool) = match input.choose(3) {
        p @ (0 | 1) => (supported(p).all.to_vec(), true),
        _ => {
            let mask = input.u32();
            let algs = native::SUPPORTED_SIG_ALGS
                .all
                .iter()
                .enumerate()
                .filter(|(i, _)| mask >> i & 1 != 0)
                .map(|(_, a)| *a)
                .collect();
            (algs, false)
        }
    };

    // CRLs: clean, revoking, corrupted clean; borrowed or owned.
    let crl_mask = if all { input.byte() } else { 0 };
    let corrupted_crl = (crl_mask & 4 != 0).then(|| {
        let mut bytes = fx.crl_clean.clone();
        corrupt(input, &mut bytes);
        bytes
    });
    let owned = input.bool();
    let revocation = Revocation {
        clean: crl_mask & 1 != 0,
        revoking: crl_mask & 2 != 0,
        chain: input.bool(),
        allow_unknown: input.bool(),
        enforce_expiry: input.bool(),
    };
    let callback = input.choose(4);

    let mut crls: Vec<CertRevocationList<'_>> = Vec::new();
    let mut modelled = true;
    let mut sources: Vec<(&[u8], bool)> = Vec::new();
    if revocation.clean {
        sources.push((&fx.crl_clean, false));
    }
    if revocation.revoking {
        sources.push((&fx.crl_revoking, false));
    }
    if let Some(bytes) = &corrupted_crl {
        sources.push((bytes, true));
    }
    for (bytes, is_corrupted) in sources {
        let parsed = if owned {
            OwnedCertRevocationList::from_der(bytes).map(CertRevocationList::from)
        } else {
            BorrowedCertRevocationList::from_der(bytes).map(CertRevocationList::from)
        };
        match parsed {
            // A corrupted CRL that still parses is outside the model.
            Ok(crl) => {
                modelled &= !is_corrupted;
                crls.push(crl);
            }
            Err(_) => assert!(is_corrupted),
        }
    }
    let crl_refs: Vec<&CertRevocationList<'_>> = crls.iter().collect();
    assert_eq!(RevocationOptionsBuilder::new(&[]).err(), Some(CrlsRequired));
    let options = RevocationOptionsBuilder::new(&crl_refs)
        .ok()
        .map(|builder| {
            builder
                .with_depth(if revocation.chain {
                    RevocationCheckDepth::Chain
                } else {
                    RevocationCheckDepth::EndEntity
                })
                .with_status_policy(if revocation.allow_unknown {
                    UnknownStatusPolicy::Allow
                } else {
                    UnknownStatusPolicy::Deny
                })
                .with_expiration_policy(if revocation.enforce_expiry {
                    ExpirationPolicy::Enforce
                } else {
                    ExpirationPolicy::Ignore
                })
                .build()
        });

    let ee_der = CertificateDer::from(ee_bytes);
    let calls = Cell::new(0u32);
    let verify_path = |path: &VerifiedPath<'_>| -> Result<(), Error> {
        calls.set(calls.get() + 1);
        assert_eq!(path.end_entity().der(), ee_der);
        match callback {
            2 => Err(Error::UnknownIssuer),
            3 if path.intermediate_certificates().count() == 0 => Err(Error::UnknownIssuer),
            _ => Ok(()),
        }
    };
    let Ok(ee) = EndEntityCert::try_from(&ee_der) else {
        assert!(corrupted);
        return;
    };
    let result = ee.verify_for_usage(
        &algs,
        &anchors,
        &intermediates,
        secs(time),
        key_usage,
        options,
        (callback != 0).then_some(&verify_path as _),
    );

    // The model.
    let has = |bit: u8, mask: u8| mask >> bit & 1 != 0;
    let candidates: Vec<Candidate> = match END_ENTITIES.get(which) {
        _ if corrupted => Vec::new(),
        Some(&P384) => [
            (
                has(2, roots),
                Candidate {
                    via_intermediate: false,
                    to_intermediate: true,
                },
            ),
            (
                has(0, roots) && ints & 9 != 0,
                Candidate {
                    via_intermediate: true,
                    to_intermediate: false,
                },
            ),
        ]
        .into_iter()
        .filter_map(|(present, c)| present.then_some(c))
        .collect(),
        Some(_) if has(0, roots) => vec![Candidate {
            via_intermediate: false,
            to_intermediate: false,
        }],
        _ => Vec::new(),
    };
    let int = parse(&fx.intermediate);
    let ca = parse(&fx.ca);
    let ee_issuer = if which == 1 { &int } else { &ca };
    let ee_usage_ok = usage_choice < 4;
    let valid = |cert: &EndEntityCert<'_>| {
        (cert.not_before().as_secs()..=cert.not_after().as_secs()).contains(&time)
    };
    let passes = |c: &Candidate| {
        let ee_sig = covered(
            &algs,
            &signature_algorithm(&ee_der),
            &spki_algorithm(&ee_issuer.subject_public_key_info()),
        );
        let int_sig = covered(
            &algs,
            &signature_algorithm(&fx.intermediate),
            &spki_algorithm(&ca.subject_public_key_info()),
        );
        if all {
            assert!(ee_sig && int_sig, "the providers verify the fixtures");
        }
        let revoked_ok = crl_refs.is_empty()
            || revocation.passes(ee.serial(), which != 1, time)
                && (!c.via_intermediate
                    || !revocation.chain
                    || revocation.passes(int.serial(), true, time));
        valid(&ee)
            && ee_usage_ok
            && ee_sig
            && (!c.via_intermediate || valid(&int) && key_usage.is_required_if_present() && int_sig)
            && revoked_ok
            && (callback != 2 && (callback != 3 || c.via_intermediate))
    };
    let passing: Vec<Candidate> = candidates.iter().copied().filter(passes).collect();

    match &result {
        Ok(path) => {
            assert!(!corrupted && which < 4);
            assert_eq!(path.end_entity().der(), ee_der);
            let via: Vec<_> = path.intermediate_certificates().collect();
            assert!(via.iter().all(|c| **c == fx.intermediate));
            let taken = Candidate {
                via_intermediate: !via.is_empty(),
                to_intermediate: path.anchor().subject.as_ref() == int.subject(),
            };
            assert!(
                !modelled || passing.contains(&taken),
                "{taken:?} not in {passing:?}"
            );
            assert_eq!(callback != 0, calls.get() > 0);
        }
        Err(e) => assert!(
            !modelled || passing.is_empty(),
            "{e:?}, expected one of {passing:?}"
        ),
    }
}

/// A signature by a fixture key over [`MESSAGE`].
struct Signed {
    key: usize,
    scheme: SignatureScheme,
    spki: Vec<u8>,
    signature: Vec<u8>,
}

const MESSAGE: &[u8] = b"pki_api signature";

/// Signatures by every fixture key with each of its schemes (native), and
/// with its first scheme by RustCrypto where that loads the key.
fn signatures() -> &'static [Signed] {
    static SIGNED: OnceLock<Vec<Signed>> = OnceLock::new();
    SIGNED.get_or_init(|| {
        let fx = fixtures::get();
        let mut out = Vec::new();
        for k in 0..KEY_COUNT {
            let der = fx.keys[k].der();
            let mut keys = vec![native::sign::any_supported_type(&der).expect("native key")];
            if fx.keys[k].rustcrypto {
                keys.push(rustcrypto::sign::any_supported_type(&der).expect("RustCrypto key"));
            }
            for (i, key) in keys.iter().enumerate() {
                let schemes = key_schemes(k);
                let schemes = if i == 1 || k == RSA_PKCS1 {
                    &schemes[..1]
                } else {
                    schemes
                };
                for &scheme in schemes {
                    let signer = key.choose_scheme(&[scheme]).expect("the key's scheme");
                    out.push(Signed {
                        key: k,
                        scheme,
                        spki: key.public_key().expect("public key").to_vec(),
                        signature: signer.sign(MESSAGE).expect("signing"),
                    });
                }
            }
        }
        out
    })
}

/// The number of signatures [`signature_op`] chooses from.
pub(super) fn signature_count() -> usize {
    signatures().len()
}

/// A signature, possibly tampered with, through `RawPublicKeyEntity` and
/// the key's certificate with every algorithm of both providers.
pub(super) fn signature_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let signed = input.pick(signatures());
    let mut message = MESSAGE.to_vec();
    let mut signature = signed.signature.clone();
    let tamper = input.choose(6);
    match tamper {
        0 => {}
        1 => corrupt(input, &mut signature),
        2 => corrupt(input, &mut message),
        3 => signature.truncate(usize::from(input.u16()) % signature.len()),
        4 => signature = input.field().to_vec(),
        _ => {
            // A fuzzed key and signature: only that nothing panics.
            let spki = SubjectPublicKeyInfoDer::from(input.field());
            let signature = input.field();
            if let Ok(raw) = RawPublicKeyEntity::try_from(&spki) {
                for p in 0..2 {
                    for alg in supported(p).all {
                        let _ = raw.verify_signature(*alg, &message, signature);
                    }
                }
            }
            return;
        }
    }
    let genuine = tamper == 0;

    let spki = SubjectPublicKeyInfoDer::from(signed.spki.as_slice());
    let raw = RawPublicKeyEntity::try_from(&spki).expect("a signing key's SPKI");
    let key_algorithm = spki_algorithm(&signed.spki);
    let cert = fx.keys[signed.key].chain.first().map(parse);
    let cert_is_key = cert
        .as_ref()
        .map(|c| c.subject_public_key_info().as_ref() == signed.spki.as_slice());
    // One provider's algorithms per operation, for time.
    let p = input.choose(2);
    let mapped: &[Alg] = supported(p)
        .mapping
        .iter()
        .find(|(s, _)| *s == signed.scheme)
        .map_or(&[], |(_, algs)| *algs);
    for &alg in supported(p).all {
        let result = raw.verify_signature(alg, &message, &signature);
        let matches_key = alg.public_key_alg_id().matches_public_key(&key_algorithm);
        if let Some(cert) = &cert {
            let via_cert = cert.verify_signature(alg, &message, &signature);
            if cert_is_key == Some(true) {
                assert_eq!(via_cert, result);
            } else {
                assert!(via_cert.is_err());
            }
        }
        let for_scheme = mapped.iter().any(|m| {
            m.public_key_alg_id() == alg.public_key_alg_id()
                && m.signature_alg_id() == alg.signature_alg_id()
        });
        if result.is_ok() {
            assert!(
                genuine && matches_key,
                "{alg:?} accepted {:?}",
                signed.scheme
            );
        } else {
            assert!(
                !(genuine && for_scheme && matches_key),
                "{alg:?} refused {:?}",
                signed.scheme
            );
        }
    }
}

/// The fixture CRLs, borrowed or owned, possibly corrupted: contents,
/// lookups and signatures.
pub(super) fn crl_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let which = input.choose(4);
    let revoking = which >= 2;
    let owned_form = which & 1 != 0;
    let mut bytes = if revoking {
        fx.crl_revoking.clone()
    } else {
        fx.crl_clean.clone()
    };
    let corrupted = input.bool();
    if corrupted {
        corrupt(input, &mut bytes);
    }
    let serial = input.short_field();
    let p = input.choose(2);

    let owned = OwnedCertRevocationList::from_der(&bytes);
    let Ok(borrowed) = BorrowedCertRevocationList::from_der(&bytes) else {
        assert!(corrupted && owned.is_err());
        return;
    };
    assert_eq!(borrowed.to_owned().is_ok(), owned.is_ok());
    let entries = (&borrowed).into_iter().count();
    let crl = match owned {
        Ok(owned) if owned_form => {
            assert_eq!(owned.revoked_certs().count(), entries);
            CertRevocationList::from(owned)
        }
        _ => CertRevocationList::from(borrowed),
    };
    let found = crl.find_serial(serial);
    let ca = parse(&fx.ca);
    let verified = crl.verify_signature(supported(p).all, ca.subject_public_key_info().as_ref());
    if corrupted {
        assert!(verified.is_err());
        return;
    }

    assert_eq!(crl.issuer(), ca.subject());
    assert!(crl.issuing_distribution_point().is_none());
    assert_eq!(crl.this_update().as_secs(), CRL_THIS_UPDATE);
    assert_eq!(crl.next_update().as_secs(), CRL_NEXT_UPDATE);
    let listed = if revoking { P256_SERIAL } else { CLEAN_SERIAL };
    assert_eq!(entries, 1);
    let entry = crl
        .find_serial(listed)
        .expect("well-formed")
        .expect("listed");
    assert_eq!(entry.serial_number, listed);
    assert_eq!(entry.revocation_date.as_secs(), CRL_THIS_UPDATE);
    assert_eq!(entry.reason_code, Some(RevocationReason::KeyCompromise));
    assert_eq!(entry.to_owned().borrow(), entry);
    let found = found.expect("well-formed");
    assert_eq!(found.is_some(), serial == listed);

    // The issuer's key verifies, as a whole SPKI or its contents; other keys
    // and algorithm sets without the issuer's algorithm do not.
    assert_eq!(verified, Ok(()));
    let ca_spki = ca.subject_public_key_info();
    let (_, contents, _) = tlv(ca_spki.as_ref()).expect("SPKI");
    assert_eq!(crl.verify_signature(supported(1 - p).all, contents), Ok(()));
    for other in [&fx.other_ca, &fx.intermediate] {
        let spki = parse(other).subject_public_key_info();
        assert!(
            crl.verify_signature(supported(p).all, spki.as_ref())
                .is_err()
        );
    }
    let signature = signature_algorithm(&bytes);
    let key = spki_algorithm(ca_spki.as_ref());
    let without: Vec<&dyn SignatureVerificationAlgorithm> = supported(p)
        .all
        .iter()
        .copied()
        .filter(|a| !covered(&[*a], &signature, &key))
        .collect();
    assert!(crl.verify_signature(&without, ca_spki.as_ref()).is_err());
}
