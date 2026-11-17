//! `SignedData`: the fixture and generated certificates and the fixture
//! CRLs, possibly corrupted, verified with their issuer's key, another key
//! or a fuzzed one, against the algorithm model and path validation; and
//! raw signatures by every fixture key against `RawPublicKeyEntity`.

use browntls::crypto::native;
use browntls_pki::{
    CertificateDer, EndEntityCert, Error, KeyUsage, RawPublicKeyEntity,
    SignatureVerificationAlgorithm, SignedData, SubjectPublicKeyInfoDer, anchor_from_trusted_cert,
};

use super::chains::{
    MESSAGE, corrupt, covered, fixture_cert, parse, signature_algorithm, signatures,
    spki_algorithm, supported,
};
use super::{inspect, tlv};
use crate::input::Input;
use crate::tls_config::fixtures;

/// The number of signed structures [`structure_op`] chooses from: the six
/// fixture certificates, the unrelated root, the two CRLs, and the three
/// generated certificates.
pub(super) const STRUCTURES: usize = 12;

/// A signed structure and its issuer's certificate.
fn structure(which: usize) -> (&'static [u8], &'static CertificateDer<'static>) {
    let fx = fixtures::get();
    let rich = inspect::rich();
    match which {
        1 => (fixture_cert(1), &fx.intermediate),
        0..6 => (fixture_cert(which), &fx.ca),
        6 => (&fx.other_ca, &fx.other_ca),
        7 => (&fx.crl_clean, &fx.ca),
        8 => (&fx.crl_revoking, &fx.ca),
        9 => (&rich.ca, &rich.ca),
        _ => (&rich.end_entities[(which - 10) % 2], &rich.ca),
    }
}

/// A signed structure, possibly corrupted, verified with a key and a set
/// of algorithms chosen by the input.
pub(super) fn structure_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let which = input.choose(STRUCTURES);
    let (bytes, issuer) = structure(which);
    let mut bytes = bytes.to_vec();
    let corrupted = input.bool();
    if corrupted {
        corrupt(input, &mut bytes);
    }
    let issuer_spki = parse(issuer).subject_public_key_info();
    let key_choice = input.choose(3);
    let spki: SubjectPublicKeyInfoDer<'_> = match key_choice {
        0 => issuer_spki.clone(),
        1 if issuer == &fx.other_ca => parse(&fx.ca).subject_public_key_info(),
        1 => parse(&fx.other_ca).subject_public_key_info(),
        _ => SubjectPublicKeyInfoDer::from(input.field()),
    };
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

    let Ok(signed) = SignedData::from_der(&bytes) else {
        assert!(corrupted);
        return;
    };
    let result = signed.verify_signature(&algs, &spki);
    let _ = format!("{signed:?}");

    // The parts are the structure's three elements.
    let (_, outer, _) = tlv(&bytes).unwrap();
    let (tbs_tag, tbs, rest) = tlv(outer).unwrap();
    assert_eq!(tbs_tag, 0x30);
    assert_eq!(signed.message().len(), outer.len() - rest.len());
    assert!(signed.message().ends_with(tbs));
    assert_eq!(signed.algorithm(), signature_algorithm(&bytes));
    let (_, _, sig) = tlv(rest).unwrap();
    let (_, bits, _) = tlv(sig).unwrap();
    assert_eq!(signed.signature(), &bits[1..]);

    if corrupted {
        assert!(result.is_err(), "a corrupted structure verified");
    } else {
        let key_alg = spki_algorithm(&issuer_spki);
        match key_choice {
            0 => {
                let expected = if covered(&algs, signed.algorithm(), &key_alg) {
                    Ok(())
                } else if algs
                    .iter()
                    .any(|a| a.signature_alg_id().matches_signature(signed.algorithm()))
                {
                    Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
                } else {
                    Err(Error::UnsupportedSignatureAlgorithm)
                };
                assert_eq!(result, expected);
                if all {
                    assert_eq!(result, Ok(()), "the providers verify the fixtures");
                }
            }
            1 => assert!(result.is_err()),
            _ => assert!(result.is_err() || spki.as_ref() == issuer_spki.as_ref()),
        }
    }

    // For the end entities: path validation accepts only what the
    // signature check accepts, and with a provider's algorithms both
    // accept a genuine certificate.
    if which < 4 && key_choice == 0 {
        let der = CertificateDer::from(bytes.as_slice());
        let Ok(ee) = EndEntityCert::try_from(&der) else {
            assert!(corrupted);
            return;
        };
        let anchors = [anchor_from_trusted_cert(&fx.ca).unwrap()];
        let intermediates = [fx.intermediate.clone()];
        let path = ee.verify_for_usage(
            &algs,
            &anchors,
            &intermediates,
            crate::tls_config::NOW,
            KeyUsage::server_auth(),
            None,
            None,
        );
        assert!(path.is_err() || result.is_ok());
        if all && !corrupted {
            assert!(path.is_ok());
        }
    }
}

/// A signature by a fixture key over [`MESSAGE`], possibly tampered with,
/// as a raw (message, algorithm, signature) triple.
pub(super) fn parts_op(input: &mut Input<'_>) {
    let signed = input.pick(signatures());
    let p = input.choose(2);
    let all = supported(p).all;
    let mut message = MESSAGE.to_vec();
    let mut signature = signed.signature.clone();
    let tamper = input.choose(4);
    match tamper {
        0 => {}
        1 => corrupt(input, &mut signature),
        2 => corrupt(input, &mut message),
        _ => signature.truncate(usize::from(input.u16()) % signature.len()),
    }
    let genuine = tamper == 0;
    let spki = SubjectPublicKeyInfoDer::from(signed.spki.as_slice());
    let raw = RawPublicKeyEntity::try_from(&spki).expect("a signing key's SPKI");
    let key_alg = spki_algorithm(&signed.spki);

    // One algorithm: the same verdict as `RawPublicKeyEntity`.
    let alg = *input.pick(all);
    let parts = SignedData::from_parts(&message, alg.signature_alg_id().as_bytes(), &signature);
    assert_eq!(parts.message(), message);
    assert_eq!(parts.algorithm(), alg.signature_alg_id().as_bytes());
    assert_eq!(parts.signature(), signature);
    assert_eq!(
        parts.verify_signature(&[alg], &spki),
        raw.verify_signature(alg, &message, &signature)
    );

    // Every algorithm, with the scheme's identifier: the verdict of the
    // first algorithm matching both identifiers.
    let mapped = supported(p)
        .mapping
        .iter()
        .find(|(s, _)| *s == signed.scheme)
        .map_or(&[][..], |(_, algs)| *algs);
    if let Some(first) = mapped.first() {
        let id = first.signature_alg_id();
        let result = SignedData::from_parts(&message, id.as_bytes(), &signature)
            .verify_signature(all, &spki);
        let chosen = all.iter().find(|a| {
            a.signature_alg_id().matches_signature(id.as_bytes())
                && a.public_key_alg_id().matches_public_key(&key_alg)
        });
        match chosen {
            None => assert!(result.is_err()),
            Some(a) => {
                assert_eq!(result, raw.verify_signature(*a, &message, &signature));
                let for_scheme = mapped.iter().any(|m| {
                    m.public_key_alg_id() == a.public_key_alg_id()
                        && m.signature_alg_id() == a.signature_alg_id()
                });
                if genuine && for_scheme {
                    assert_eq!(result, Ok(()), "{:?}", signed.scheme);
                }
            }
        }
        assert!(genuine || result.is_err());
    }

    // A fuzzed identifier never verifies a tampered signature.
    let fuzzed = input.short_field();
    let result = SignedData::from_parts(&message, fuzzed, &signature).verify_signature(all, &spki);
    assert!(genuine || result.is_err());
}
